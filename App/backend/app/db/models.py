import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Sample(Base):
    __tablename__ = "samples"

    id = Column(Integer, primary_key=True, index=True)
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    md5 = Column(String(32), index=True, nullable=True)
    original_filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100), default="application/vnd.android.package-archive")
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    investigations = relationship("Investigation", back_populates="sample", cascade="all, delete-orphan")

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=True)
    sha256 = Column(String(64), index=True, nullable=False)
    apk_name = Column(String(255), nullable=False)
    package_name = Column(String(255), default="unknown.package")
    version_name = Column(String(100), default="1.0.0")
    version_code = Column(String(50), default="1")
    min_sdk = Column(Integer, default=21)
    target_sdk = Column(Integer, default=34)
    file_size = Column(Integer, default=0)

    status = Column(String(50), default="PENDING")  # PENDING, EXTRACTING, STATIC_ANALYSIS, DYNAMIC_ANALYSIS, NETWORK_ANALYSIS, THREAT_INTEL, SIMILARITY_MATCHING, SCORING, COMPLETED, FAILED
    progress = Column(Integer, default=0)  # 0 to 100%
    current_stage_label = Column(String(255), default="Initialized")

    risk_score = Column(Float, default=0.0)  # 0 - 100
    severity = Column(String(20), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=0.95)
    limitations = Column(Text, default="")
    top_reasons = Column(JSON, default=list)
    summary = Column(Text, default="")
    ai_verdict = Column(Text, default="")

    is_demo = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))

    # Relationships
    sample = relationship("Sample", back_populates="investigations")
    static_findings = relationship("StaticFinding", back_populates="investigation", cascade="all, delete-orphan")
    dynamic_findings = relationship("DynamicFinding", back_populates="investigation", cascade="all, delete-orphan")
    network_findings = relationship("NetworkFinding", back_populates="investigation", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="investigation", cascade="all, delete-orphan")
    similarity_matches = relationship("SimilarityMatch", back_populates="investigation", cascade="all, delete-orphan")
    mitre_techniques = relationship("MitreTechnique", back_populates="investigation", cascade="all, delete-orphan")
    risk_components = relationship("RiskComponent", back_populates="investigation", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="investigation", cascade="all, delete-orphan")
    analysis_logs = relationship("AnalysisLog", back_populates="investigation", cascade="all, delete-orphan")
    campaign_links = relationship("CampaignSample", back_populates="investigation", cascade="all, delete-orphan")

class StaticFinding(Base):
    __tablename__ = "static_findings"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    category = Column(String(100), nullable=False)  # PERMISSION, API, STRING, OBFUSCATION, MANIFEST, YARA, FRAUD_RULE
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="INFO")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    evidence = Column(Text, default="")
    context = Column(Text, default="")

    investigation = relationship("Investigation", back_populates="static_findings")

class DynamicFinding(Base):
    __tablename__ = "dynamic_findings"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    api_class = Column(String(255), nullable=False)
    method = Column(String(255), nullable=False)
    parameters = Column(Text, default="")
    return_value = Column(Text, default="")
    timestamp_offset = Column(Float, default=0.0)
    is_sensitive = Column(Boolean, default=False)
    severity = Column(String(20), default="LOW")
    description = Column(Text, default="")

    investigation = relationship("Investigation", back_populates="dynamic_findings")

class NetworkFinding(Base):
    __tablename__ = "network_findings"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    domain = Column(String(255), default="")
    ip = Column(String(100), default="")
    port = Column(Integer, default=80)
    protocol = Column(String(20), default="HTTP")
    url = Column(Text, default="")
    is_c2 = Column(Boolean, default=False)
    is_phishing = Column(Boolean, default=False)
    reputation_score = Column(Float, default=0.0)
    exfiltration_type = Column(String(100), default="")  # SMS, OTP, CONTACTS, CREDENTIALS, NONE
    evidence = Column(Text, default="")

    investigation = relationship("Investigation", back_populates="network_findings")

class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    ioc_type = Column(String(50), nullable=False)  # DOMAIN, IP, SHA256, URL, PACKAGE, CERT_FINGERPRINT, WALLET, PHONE
    value = Column(String(512), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(20), default="MEDIUM")
    source = Column(String(100), default="STATIC_EXTRACTOR")
    recommended_action = Column(String(255), default="BLOCK_AT_FIREWALL")

    investigation = relationship("Investigation", back_populates="iocs")

class SimilarityMatch(Base):
    __tablename__ = "similarity_matches"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    family_name = Column(String(100), nullable=False)
    similarity_score = Column(Float, nullable=False)  # 0.0 to 1.0 (or percentage)
    matched_features = Column(JSON, default=list)
    vector_distance = Column(Float, default=0.0)
    explanation = Column(Text, default="")

    investigation = relationship("Investigation", back_populates="similarity_matches")

class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    threat_actor = Column(String(255), default="Unknown Adversary")
    target_sector = Column(String(255), default="Financial / Banking")
    target_region = Column(String(100), default="India & Global")
    description = Column(Text, default="")
    first_seen = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    severity = Column(String(20), default="HIGH")
    tactics = Column(JSON, default=list)
    shared_iocs = Column(JSON, default=list)

    samples = relationship("CampaignSample", back_populates="campaign", cascade="all, delete-orphan")

class CampaignSample(Base):
    __tablename__ = "campaign_samples"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    correlation_reason = Column(Text, default="")

    campaign = relationship("Campaign", back_populates="samples")
    investigation = relationship("Investigation", back_populates="campaign_links")

class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    technique_id = Column(String(50), nullable=False)  # e.g., T1400, T1582, T1417
    technique_name = Column(String(255), nullable=False)
    tactic = Column(String(100), nullable=False)  # Credential Access, Collection, Defense Evasion, etc.
    evidence = Column(Text, default="")
    source_module = Column(String(100), default="STATIC")

    investigation = relationship("Investigation", back_populates="mitre_techniques")

class RiskComponent(Base):
    __tablename__ = "risk_components"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    category = Column(String(100), nullable=False)
    weight = Column(Float, nullable=False)
    raw_score = Column(Float, nullable=False)  # 0 to 100
    weighted_contribution = Column(Float, nullable=False)
    reasoning = Column(Text, default="")
    evidence_count = Column(Integer, default=0)
    evidence_items = Column(JSON, default=list)

    investigation = relationship("Investigation", back_populates="risk_components")

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    report_type = Column(String(50), default="ANALYST")  # ANALYST, EXECUTIVE
    executive_summary = Column(Text, default="")
    prioritized_recommendations = Column(JSON, default=list)
    html_content = Column(Text, default="")
    pdf_path = Column(String(512), default="")
    generated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    investigation = relationship("Investigation", back_populates="reports")

class AnalysisLog(Base):
    __tablename__ = "analysis_logs"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    stage = Column(String(100), nullable=False)
    level = Column(String(20), default="INFO")  # INFO, WARNING, ERROR, SUCCESS
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    investigation = relationship("Investigation", back_populates="analysis_logs")
