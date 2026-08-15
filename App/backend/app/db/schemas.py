from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


# Base & Shared Schemas
class StaticFindingSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    category: str
    title: str
    description: str
    severity: str
    evidence: str | None = ""
    context: str | None = ""

class DynamicFindingSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    api_class: str
    method: str
    parameters: str | None = ""
    return_value: str | None = ""
    timestamp_offset: float | None = 0.0
    is_sensitive: bool = False
    severity: str
    description: str | None = ""

class NetworkFindingSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    domain: str | None = ""
    ip: str | None = ""
    port: int | None = 80
    protocol: str | None = "HTTP"
    url: str | None = ""
    is_c2: bool = False
    is_phishing: bool = False
    reputation_score: float | None = 0.0
    exfiltration_type: str | None = ""
    evidence: str | None = ""

class IOCSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    ioc_type: str
    value: str
    description: str | None = ""
    severity: str
    source: str | None = "STATIC_EXTRACTOR"
    recommended_action: str | None = "BLOCK_AT_FIREWALL"

class SimilarityMatchSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    family_name: str
    similarity_score: float
    matched_features: list[str] = []
    vector_distance: float | None = 0.0
    explanation: str | None = ""

class MitreTechniqueSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    technique_id: str
    technique_name: str
    tactic: str
    evidence: str | None = ""
    source_module: str | None = "STATIC"

class RiskComponentSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    category: str
    weight: float
    raw_score: float
    weighted_contribution: float
    reasoning: str | None = ""
    evidence_count: int | None = 0
    evidence_items: list[str] = []

class AnalysisLogSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    stage: str
    level: str
    message: str
    timestamp: datetime

class InvestigationSummarySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    sha256: str
    apk_name: str
    package_name: str
    version_name: str
    status: str
    progress: int
    current_stage_label: str
    risk_score: float
    severity: str
    confidence: float
    is_demo: bool
    created_at: datetime
    updated_at: datetime | None = None

class InvestigationDetailSchema(InvestigationSummarySchema):
    file_size: int
    min_sdk: int
    target_sdk: int
    limitations: str | None = ""
    top_reasons: list[str] = []
    summary: str | None = ""
    ai_verdict: str | None = ""

    static_findings: list[StaticFindingSchema] = []
    dynamic_findings: list[DynamicFindingSchema] = []
    network_findings: list[NetworkFindingSchema] = []
    iocs: list[IOCSchema] = []
    similarity_matches: list[SimilarityMatchSchema] = []
    mitre_techniques: list[MitreTechniqueSchema] = []
    risk_components: list[RiskComponentSchema] = []
    analysis_logs: list[AnalysisLogSchema] = []

class URLSubmissionRequest(BaseModel):
    apk_url: str
    apk_name: str | None = None
    simulate_live: bool | None = False

class AssistantQueryRequest(BaseModel):
    investigation_id: int
    query: str
    chat_history: list[dict[str, str]] | None = []

class AssistantQueryResponse(BaseModel):
    answer: str
    grounded_evidence: list[str] = []
    suggested_followups: list[str] = []

class CampaignSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    threat_actor: str
    target_sector: str
    target_region: str
    description: str
    first_seen: datetime
    last_seen: datetime
    severity: str
    tactics: list[str] = []
    shared_iocs: list[dict[str, Any]] = []
    sample_count: int | None = 0
