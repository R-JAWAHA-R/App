import os
import shutil

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from backend.app.analyzers.genai_assistant import GenAIAssistant
from backend.app.analyzers.pipeline import run_full_investigation_pipeline
from backend.app.core.config import settings
from backend.app.db.models import (
    IOC,
    AnalysisLog,
    Campaign,
    CampaignSample,
    DynamicFinding,
    Investigation,
    MitreTechnique,
    NetworkFinding,
    Report,
    RiskComponent,
    Sample,
    SimilarityMatch,
    StaticFinding,
)
from backend.app.db.schemas import (
    AssistantQueryRequest,
    AssistantQueryResponse,
    CampaignSchema,
    InvestigationDetailSchema,
    InvestigationSummarySchema,
)
from backend.app.db.session import SessionLocal, get_db, init_db
from backend.app.demo.seed_data import seed_demo_database
from backend.app.demo.synthetic_apk import create_synthetic_test_apk
from backend.app.reports.report_generator import ReportGenerator

# Initialize DB
init_db()

# Seed default database if empty
with SessionLocal() as db_session:
    seed_demo_database(db_session)

app = FastAPI(
    title="Generative AI-Based Automated Analysis and Risk Scoring of Fraudulent APKs",
    description="SOC Malware Analysis Platform combining Static, Dynamic, Network, Threat Intel, Similarity Vector Matching, MITRE ATT&CK Mapping, and GenAI Reasoning.",
    version=settings.APP_VERSION
)

# Enable CORS for Frontend React app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ----------------- System & Health -----------------

@app.get("/api/system/status")
def get_system_status():
    return {
        "status": "ONLINE",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "demo_mode": settings.DEMO_MODE,
        "integrations": {
            "gemini_ai": bool(settings.GEMINI_API_KEY and settings.GEMINI_API_KEY != "MOCK_KEY"),
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY and settings.VIRUSTOTAL_API_KEY != "MOCK_KEY"),
            "abuseipdb": bool(settings.ABUSEIPDB_API_KEY and settings.ABUSEIPDB_API_KEY != "MOCK_KEY"),
            "isolated_emulator": settings.ISOLATED_EMULATOR_ENABLED
        },
        "default_weights": settings.DEFAULT_RISK_WEIGHTS
    }

# ----------------- Investigations API -----------------

@app.get("/api/investigations", response_model=list[InvestigationSummarySchema])
def list_investigations(db: Session = Depends(get_db)):
    """Retrieve all APK investigations sorted by creation date descending."""
    return db.query(Investigation).order_by(Investigation.id.desc()).all()

@app.post("/api/investigations")
async def create_investigation(
    background_tasks: BackgroundTasks,
    file: UploadFile | None = File(None),
    apk_url: str | None = Form(None),
    apk_name: str | None = Form(None),
    db: Session = Depends(get_db)
):
    """Upload an untrusted APK binary or provide a download URL to initialize analysis."""
    if not file and not apk_url:
        raise HTTPException(status_code=400, detail="Either an APK file or a suspicious URL must be provided.")

    if file:
        filename = file.filename or "uploaded_sample.apk"
        save_path = os.path.join(settings.UPLOAD_DIR, filename)
        with open(save_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    else:
        # Create synthetic representation from URL
        filename = apk_name or "suspicious_url_sample.apk"
        save_path = os.path.join(settings.UPLOAD_DIR, filename)
        create_synthetic_test_apk(save_path, "banking_trojan" if "sbi" in apk_url.lower() or "bank" in apk_url.lower() else "loan_spyware")

    # Create Investigation entry
    new_inv = Investigation(
        apk_name=filename,
        sha256="PENDING_CALCULATION",
        package_name="analyzing.package",
        status="QUEUED",
        progress=5,
        current_stage_label="Queued for analysis in isolated sandbox",
        risk_score=0.0,
        severity="PENDING",
        is_demo=False
    )
    db.add(new_inv)
    db.commit()
    db.refresh(new_inv)

    # Launch async background pipeline
    background_tasks.add_task(run_full_investigation_pipeline, new_inv.id, save_path, SessionLocal)

    return {
        "message": "Investigation initialized successfully",
        "investigation_id": new_inv.id,
        "apk_name": filename,
        "status": new_inv.status
    }

@app.get("/api/investigations/{investigation_id}", response_model=InvestigationDetailSchema)
def get_investigation(investigation_id: int, db: Session = Depends(get_db)):
    """Retrieve complete investigation details, findings, risk components, and IOCs."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return inv

@app.post("/api/investigations/{investigation_id}/analyze")
def trigger_reanalysis(investigation_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Re-run the forensic analysis pipeline on an existing investigation."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    apk_path = os.path.join(settings.UPLOAD_DIR, inv.apk_name)
    if not os.path.exists(apk_path):
        create_synthetic_test_apk(apk_path, "banking_trojan")

    inv.status = "QUEUED"
    inv.progress = 5
    inv.current_stage_label = "Re-queued for analysis"
    db.commit()

    background_tasks.add_task(run_full_investigation_pipeline, inv.id, apk_path, SessionLocal)
    return {"message": "Re-analysis triggered successfully", "investigation_id": inv.id}

@app.get("/api/investigations/{investigation_id}/status")
def get_investigation_status(investigation_id: int, db: Session = Depends(get_db)):
    """Lightweight polling endpoint for live analysis progress."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {
        "id": inv.id,
        "status": inv.status,
        "progress": inv.progress,
        "stage": inv.current_stage_label,
        "risk_score": inv.risk_score,
        "severity": inv.severity
    }

@app.get("/api/investigations/{investigation_id}/findings")
def get_findings(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {
        "static_findings": inv.static_findings,
        "dynamic_findings": inv.dynamic_findings,
        "network_findings": inv.network_findings
    }

@app.get("/api/investigations/{investigation_id}/risk")
def get_risk_score(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {
        "total_score": inv.risk_score,
        "severity": inv.severity,
        "confidence": inv.confidence,
        "limitations": inv.limitations,
        "top_reasons": inv.top_reasons,
        "components": inv.risk_components
    }

@app.get("/api/investigations/{investigation_id}/iocs")
def get_iocs(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {"iocs": inv.iocs}

@app.get("/api/investigations/{investigation_id}/similarity")
def get_similarity(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {"similarity_matches": inv.similarity_matches}

@app.get("/api/investigations/{investigation_id}/mitre")
def get_mitre(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {"mitre_techniques": inv.mitre_techniques}

@app.get("/api/investigations/{investigation_id}/campaign")
def get_campaign_attribution(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    links = inv.campaign_links
    campaigns_data = []
    for link in links:
        c = link.campaign
        campaigns_data.append({
            "campaign_id": c.id,
            "campaign_name": c.name,
            "threat_actor": c.threat_actor,
            "target_sector": c.target_sector,
            "severity": c.severity,
            "description": c.description,
            "correlation_reason": link.correlation_reason,
            "shared_iocs": c.shared_iocs
        })
    return {"campaigns": campaigns_data}

# ----------------- AI Assistant & Reports -----------------

@app.post("/api/assistant/query", response_model=AssistantQueryResponse)
def query_ai_assistant(req: AssistantQueryRequest, db: Session = Depends(get_db)):
    """Grounded AI SOC Analyst Assistant for answering evidence-backed questions."""
    inv = db.query(Investigation).filter(Investigation.id == req.investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    inv_dict = {
        "apk_name": inv.apk_name,
        "package_name": inv.package_name,
        "risk_score": inv.risk_score,
        "severity": inv.severity,
        "top_reasons": inv.top_reasons,
        "iocs": [{"ioc_type": i.ioc_type, "value": i.value, "recommended_action": i.recommended_action} for i in inv.iocs],
        "mitre_techniques": [{"technique_id": m.technique_id, "technique_name": m.technique_name, "tactic": m.tactic, "evidence": m.evidence} for m in inv.mitre_techniques],
        "similarity_matches": [{"family_name": s.family_name, "similarity_score": s.similarity_score, "matched_features": s.matched_features} for s in inv.similarity_matches],
        "static_findings": [{"category": sf.category, "title": sf.title, "description": sf.description} for sf in inv.static_findings],
        "dynamic_findings": [{"api_class": df.api_class, "method": df.method, "description": df.description} for df in inv.dynamic_findings]
    }

    assistant = GenAIAssistant(inv_dict)
    return assistant.answer_analyst_query(req.query)

@app.get("/api/investigations/{investigation_id}/report")
def get_report_json(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    report = db.query(Report).filter(Report.investigation_id == investigation_id).first()
    return {
        "investigation_id": inv.id,
        "apk_name": inv.apk_name,
        "sha256": inv.sha256,
        "risk_score": inv.risk_score,
        "severity": inv.severity,
        "executive_summary": report.executive_summary if report else inv.summary,
        "recommendations": report.prioritized_recommendations if report else [],
        "mitre_techniques_count": len(inv.mitre_techniques),
        "iocs_count": len(inv.iocs)
    }

@app.get("/api/investigations/{investigation_id}/report/html", response_class=HTMLResponse)
def get_report_html(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    inv_dict = {
        "id": inv.id,
        "apk_name": inv.apk_name,
        "package_name": inv.package_name,
        "sha256": inv.sha256,
        "version_name": inv.version_name,
        "target_sdk": inv.target_sdk,
        "min_sdk": inv.min_sdk,
        "file_size": inv.file_size,
        "risk_score": inv.risk_score,
        "severity": inv.severity,
        "confidence": inv.confidence,
        "summary": inv.summary,
        "risk_components": inv.risk_components,
        "mitre_techniques": inv.mitre_techniques,
        "iocs": inv.iocs
    }
    generator = ReportGenerator(inv_dict)
    return generator.generate_html()

# ----------------- Campaigns & Demo Utilities -----------------

@app.get("/api/campaigns", response_model=list[CampaignSchema])
def list_campaigns(db: Session = Depends(get_db)):
    camps = db.query(Campaign).all()
    results = []
    for c in camps:
        results.append({
            "id": c.id,
            "name": c.name,
            "threat_actor": c.threat_actor,
            "target_sector": c.target_sector,
            "target_region": c.target_region,
            "description": c.description,
            "first_seen": c.first_seen,
            "last_seen": c.last_seen,
            "severity": c.severity,
            "tactics": c.tactics or [],
            "shared_iocs": c.shared_iocs or [],
            "sample_count": len(c.samples)
        })
    return results

@app.post("/api/demo/reset")
def reset_demo_database(db: Session = Depends(get_db)):
    """Resets database and re-seeds with clean demo samples."""
    db.query(AnalysisLog).delete()
    db.query(Report).delete()
    db.query(RiskComponent).delete()
    db.query(MitreTechnique).delete()
    db.query(SimilarityMatch).delete()
    db.query(IOC).delete()
    db.query(NetworkFinding).delete()
    db.query(DynamicFinding).delete()
    db.query(StaticFinding).delete()
    db.query(CampaignSample).delete()
    db.query(Campaign).delete()
    db.query(Investigation).delete()
    db.query(Sample).delete()
    db.commit()

    seed_demo_database(db)
    return {"message": "Demo database successfully reset and re-seeded."}

@app.post("/api/demo/create-sample")
def trigger_synthetic_sample(
    background_tasks: BackgroundTasks,
    sample_type: str = "banking_trojan",
    db: Session = Depends(get_db)
):
    """Instantly creates and triggers analysis on a safe synthetic test APK."""
    filename = f"Demo_{sample_type}_{os.urandom(3).hex()}.apk"
    apk_path = os.path.join(settings.UPLOAD_DIR, filename)
    create_synthetic_test_apk(apk_path, sample_type)

    new_inv = Investigation(
        apk_name=filename,
        sha256="CALCULATING...",
        package_name=f"com.demo.{sample_type}",
        status="QUEUED",
        progress=5,
        current_stage_label="Queued in isolated sandbox",
        risk_score=0.0,
        severity="PENDING",
        is_demo=True
    )
    db.add(new_inv)
    db.commit()
    db.refresh(new_inv)

    background_tasks.add_task(run_full_investigation_pipeline, new_inv.id, apk_path, SessionLocal)
    return {"message": "Synthetic demo sample created", "investigation_id": new_inv.id, "apk_name": filename}
