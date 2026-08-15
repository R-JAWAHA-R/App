import asyncio

from sqlalchemy.orm import Session

from backend.app.analyzers.campaign_attribution import CampaignAttributionEngine
from backend.app.analyzers.dynamic_analyzer import DynamicAnalyzer
from backend.app.analyzers.genai_assistant import GenAIAssistant
from backend.app.analyzers.interaction_engine import AutomatedInteractionEngine
from backend.app.analyzers.mitre_mapper import MitreAttackMapper
from backend.app.analyzers.network_analyzer import NetworkAnalyzer
from backend.app.analyzers.risk_engine import ExplainableRiskEngine
from backend.app.analyzers.similarity_engine import HybridSimilarityEngine
from backend.app.analyzers.static_analyzer import StaticAnalyzer
from backend.app.analyzers.threat_intel import ThreatIntelProvider
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
    SimilarityMatch,
    StaticFinding,
)


def log_stage(db: Session, inv_id: int, stage: str, message: str, level: str = "INFO"):
    log_entry = AnalysisLog(investigation_id=inv_id, stage=stage, level=level, message=message)
    db.add(log_entry)
    db.commit()

async def run_full_investigation_pipeline(investigation_id: int, apk_path: str, db_factory):
    """
    Asynchronously executes the end-to-end multi-stage APK malware analysis pipeline.
    """
    db = db_factory()
    try:
        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            return

        # Stage 1: Extraction & Static Analysis
        inv.status = "STATIC_ANALYSIS"
        inv.progress = 15
        inv.current_stage_label = "Running Static Decompilation & YARA Signatures"
        db.commit()
        log_stage(db, investigation_id, "STATIC_ANALYSIS", f"Starting static inspection on {inv.apk_name}...")

        static_engine = StaticAnalyzer(apk_path)
        static_data = static_engine.analyze()

        # Update sample hashes & metadata
        inv.sha256 = static_data["hashes"]["sha256"]
        inv.package_name = static_data["manifest"].get("package_name", inv.package_name)
        inv.file_size = static_data["hashes"]["file_size"]

        # Persist static findings
        for f in static_data["permission_findings"]:
            db.add(StaticFinding(
                investigation_id=inv.id,
                category=f.get("category", "PERMISSION"),
                title=f.get("permission", ""),
                description=f.get("description", ""),
                severity=f.get("severity", "LOW"),
                evidence=f"Permission declared in AndroidManifest.xml: {f.get('permission')}"
            ))

        for o in static_data["obfuscation_indicators"]:
            db.add(StaticFinding(
                investigation_id=inv.id,
                category="OBFUSCATION",
                title=o.get("type", "OBFUSCATION_DETECTED"),
                description=o.get("description", ""),
                severity=o.get("severity", "MEDIUM"),
                evidence=o.get("evidence", "")
            ))

        for y in static_data["yara_matches"]:
            db.add(StaticFinding(
                investigation_id=inv.id,
                category="YARA_MATCH",
                title=y.get("rule_name", "YARA_HIT"),
                description=y.get("description", ""),
                severity=y.get("severity", "HIGH"),
                evidence=f"Matched patterns: {', '.join(y.get('matched_patterns', []))}"
            ))

        for fr in static_data["fraud_heuristics"]:
            db.add(StaticFinding(
                investigation_id=inv.id,
                category="FRAUD_HEURISTIC",
                title=fr.get("title", "FRAUD_INDICATOR"),
                description=fr.get("description", ""),
                severity=fr.get("severity", "HIGH"),
                evidence=fr.get("pattern", "")
            ))

        db.commit()
        await asyncio.sleep(0.5)

        # Stage 2: Dynamic Analysis in Isolated Sandbox
        inv.status = "DYNAMIC_ANALYSIS"
        inv.progress = 35
        inv.current_stage_label = "Tracing Runtime API Calls in Isolated Sandbox"
        db.commit()
        log_stage(db, investigation_id, "DYNAMIC_ANALYSIS", "Spawning dynamic emulator tracing & Frida hooks...")

        dynamic_engine = DynamicAnalyzer(apk_path, inv.package_name, static_data)
        dynamic_data = dynamic_engine.analyze()

        for trace in dynamic_data.get("api_traces", []):
            db.add(DynamicFinding(
                investigation_id=inv.id,
                api_class=trace.get("api_class", ""),
                method=trace.get("method", ""),
                parameters=trace.get("parameters", ""),
                return_value=trace.get("return_value", ""),
                timestamp_offset=trace.get("timestamp_offset", 0.0),
                is_sensitive=trace.get("is_sensitive", False),
                severity=trace.get("severity", "LOW"),
                description=trace.get("description", "")
            ))
        db.commit()
        await asyncio.sleep(0.5)

        # Stage 3: Automated Interaction Monkey
        inv.status = "INTERACTION_EXPLORATION"
        inv.progress = 50
        inv.current_stage_label = "Automated Monkey Exploration & Screen Coverage"
        db.commit()
        interaction_engine = AutomatedInteractionEngine(inv.package_name, dynamic_data)
        interaction_results = interaction_engine.run_exploration()
        log_stage(db, investigation_id, "INTERACTION", f"Completed UI exploration with {interaction_results['interaction_coverage_percent']}% screen coverage.")

        # Stage 4: Network & C2 Traffic Analysis
        inv.status = "NETWORK_ANALYSIS"
        inv.progress = 65
        inv.current_stage_label = "Analyzing Network Traffic & C2 Infrastructure"
        db.commit()
        log_stage(db, investigation_id, "NETWORK_ANALYSIS", "Inspecting DNS requests, TLS handshakes, and exfiltration channels...")

        network_engine = NetworkAnalyzer(static_data.get("extracted_urls", []), static_data.get("extracted_ips", []), dynamic_data)
        network_data = network_engine.analyze()

        for ep in network_data.get("endpoints", []):
            db.add(NetworkFinding(
                investigation_id=inv.id,
                domain=ep.get("domain", ""),
                ip=ep.get("ip", ""),
                port=ep.get("port", 80),
                protocol=ep.get("protocol", "HTTP"),
                url=ep.get("url", ""),
                is_c2=ep.get("is_c2", False),
                is_phishing=ep.get("is_phishing", False),
                reputation_score=ep.get("reputation_score", 0.0),
                exfiltration_type=ep.get("exfiltration_type", "NONE"),
                evidence=ep.get("evidence", "")
            ))

            # Store IOCs
            if ep.get("is_c2") or ep.get("is_phishing") or ep.get("reputation_score", 0) > 50:
                db.add(IOC(
                    investigation_id=inv.id,
                    ioc_type="DOMAIN",
                    value=ep.get("domain", ""),
                    description="Malicious Command & Control / Phishing Endpoint",
                    severity="CRITICAL" if ep.get("is_c2") else "HIGH",
                    source="NETWORK_CAPTURE",
                    recommended_action="BLOCK_AT_FIREWALL_AND_DNS"
                ))
                if ep.get("ip"):
                    db.add(IOC(
                        investigation_id=inv.id,
                        ioc_type="IP",
                        value=ep.get("ip", ""),
                        description="C2 Server Hosting IP",
                        severity="HIGH",
                        source="DNS_RESOLUTION",
                        recommended_action="BLOCK_IP_RANGE"
                    ))

        # Add Hash IOC
        db.add(IOC(
            investigation_id=inv.id,
            ioc_type="SHA256",
            value=inv.sha256,
            description="Malicious Sample Binary Hash",
            severity="CRITICAL",
            source="STATIC_EXTRACTOR",
            recommended_action="SUBMIT_TO_EDR_BLOCKLIST"
        ))
        db.commit()
        await asyncio.sleep(0.5)

        # Stage 5: Threat Intelligence Enrichment
        inv.status = "THREAT_INTEL"
        inv.progress = 75
        inv.current_stage_label = "Querying Threat Intelligence Feeds (VirusTotal & AbuseIPDB)"
        db.commit()
        threat_engine = ThreatIntelProvider(inv.sha256, [e.get("domain") for e in network_data.get("endpoints", [])], [e.get("ip") for e in network_data.get("endpoints", [])])
        threat_data = threat_engine.query_all()
        log_stage(db, investigation_id, "THREAT_INTEL", f"Threat intelligence enrichment completed. Reputation: {threat_data['overall_reputation']}.")

        # Stage 6: Similarity Matching & MITRE Auto-Mapping
        inv.status = "SIMILARITY_AND_MITRE"
        inv.progress = 85
        inv.current_stage_label = "Computing Hybrid Malware-Family Vectors & MITRE Matrix"
        db.commit()

        # Build feature set for similarity
        feature_set = []
        feature_set.extend(static_data.get("permissions", []))
        feature_set.extend(static_data.get("extracted_urls", []))
        for t in dynamic_data.get("api_traces", []):
            feature_set.append(f"{t.get('api_class')}.{t.get('method')}")
        for f in static_data.get("fraud_heuristics", []):
            feature_set.append(f.get("pattern", ""))

        similarity_engine = HybridSimilarityEngine(feature_set)
        similarity_results = similarity_engine.calculate_similarity()

        for s in similarity_results:
            db.add(SimilarityMatch(
                investigation_id=inv.id,
                family_name=s.get("family_name", ""),
                similarity_score=s.get("similarity_score", 0.0),
                matched_features=s.get("matched_features", []),
                vector_distance=s.get("vector_distance", 0.0),
                explanation=s.get("explanation", "")
            ))

        # MITRE ATT&CK Mapping
        mitre_engine = MitreAttackMapper(static_data, dynamic_data, network_data)
        mitre_results = mitre_engine.map_techniques()

        for m in mitre_results:
            db.add(MitreTechnique(
                investigation_id=inv.id,
                technique_id=m.get("technique_id", ""),
                technique_name=m.get("technique_name", ""),
                tactic=m.get("tactic", ""),
                evidence=m.get("evidence", ""),
                source_module=m.get("source_module", "HYBRID")
            ))

        db.commit()

        # Stage 7: Campaign Attribution
        campaign_engine = CampaignAttributionEngine(inv.id, [{"type": "DOMAIN", "value": e.get("domain", "")} for e in network_data.get("endpoints", [])], inv.package_name)
        campaign_data = campaign_engine.correlate()
        if campaign_data.get("has_campaign_attribution"):
            for camp in campaign_data.get("attributed_campaigns", []):
                db_camp = db.query(Campaign).filter(Campaign.id == camp["campaign_id"]).first()
                if not db_camp:
                    db_camp = Campaign(
                        id=camp["campaign_id"],
                        name=camp["campaign_name"],
                        threat_actor=camp["threat_actor"],
                        target_sector=camp["target_sector"],
                        description=camp["description"],
                        severity=camp["severity"]
                    )
                    db.add(db_camp)
                    db.commit()
                db.add(CampaignSample(campaign_id=db_camp.id, investigation_id=inv.id, correlation_reason=camp["reasoning"]))
                db.commit()

        # Stage 8: Evidence-Based Explainable Risk Scoring
        inv.status = "SCORING"
        inv.progress = 92
        inv.current_stage_label = "Calculating Evidence-Based Risk Score (0-100)"
        db.commit()

        risk_engine = ExplainableRiskEngine(static_data, dynamic_data, network_data, threat_data, similarity_results, mitre_results)
        risk_output = risk_engine.evaluate()

        inv.risk_score = risk_output["total_score"]
        inv.severity = risk_output["severity"]
        inv.confidence = risk_output["confidence"]
        inv.limitations = risk_output["limitations"]
        inv.top_reasons = risk_output["top_reasons"]

        for comp in risk_output["components"]:
            db.add(RiskComponent(
                investigation_id=inv.id,
                category=comp["category_label"],
                weight=comp["weight"],
                raw_score=comp["raw_score"],
                weighted_contribution=comp["weighted_contribution"],
                reasoning=comp["reasoning"],
                evidence_count=comp["evidence_count"],
                evidence_items=comp["evidence_items"]
            ))
        db.commit()

        # Stage 9: GenAI Threat Summary
        inv.status = "GENERATING_REPORT"
        inv.progress = 98
        inv.current_stage_label = "Generating Generative AI Investigation Report"
        db.commit()

        genai_engine = GenAIAssistant({
            "apk_name": inv.apk_name,
            "package_name": inv.package_name,
            "risk_score": inv.risk_score,
            "severity": inv.severity,
            "top_reasons": inv.top_reasons
        })
        ai_brief = genai_engine.generate_threat_summary()

        inv.summary = ai_brief.get("executive_summary", "")
        inv.ai_verdict = ai_brief.get("executive_summary", "")

        # Save Report
        db.add(Report(
            investigation_id=inv.id,
            report_type="ANALYST_EXECUTIVE",
            executive_summary=ai_brief.get("executive_summary", ""),
            prioritized_recommendations=ai_brief.get("prioritized_recommendations", [])
        ))

        # Finalize
        inv.status = "COMPLETED"
        inv.progress = 100
        inv.current_stage_label = "Analysis Successfully Completed"
        db.commit()
        log_stage(db, investigation_id, "COMPLETED", f"Investigation concluded with verdict: {inv.severity} ({inv.risk_score}/100).", level="SUCCESS")

    except Exception as e:
        if inv:
            inv.status = "FAILED"
            inv.current_stage_label = f"Analysis Error: {e!s}"
            db.commit()
            log_stage(db, investigation_id, "ERROR", f"Pipeline encountered fatal error: {e!s}", level="ERROR")
    finally:
        db.close()
