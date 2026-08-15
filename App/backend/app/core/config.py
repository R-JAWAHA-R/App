import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="allow")

    APP_NAME: str = "Fraudulent APK AI Analysis Platform"
    APP_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    DEBUG: bool = True

    # Storage & Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    UPLOAD_DIR: str = os.path.join(BASE_DIR, "uploads")
    REPORTS_DIR: str = os.path.join(BASE_DIR, "generated_reports")
    DATABASE_URL: str = f"sqlite:///{os.path.join(BASE_DIR, 'fraud_apk_analysis.db')}"

    # External API Keys (Demo fallback will automatically be used if missing)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

    # Sandbox & Analysis Settings
    DEMO_MODE: bool = True
    ISOLATED_EMULATOR_ENABLED: bool = False
    EMULATOR_DEVICE_NAME: str = "emulator-5554"
    FRIDA_HOST: str = "127.0.0.1:27042"
    ADB_PATH: str = os.getenv("ADB_PATH", "adb")
    JADX_PATH: str = os.getenv("JADX_PATH", "jadx")
    APKTOOL_PATH: str = os.getenv("APKTOOL_PATH", "apktool")

    # Configurable Risk Scoring Weights
    DEFAULT_RISK_WEIGHTS: dict[str, float] = {
        "suspicious_permissions": 0.20,
        "dangerous_api_usage": 0.18,
        "obfuscation_indicators": 0.12,
        "malicious_urls_c2": 0.18,
        "dynamic_behavior": 0.12,
        "threat_intelligence": 0.10,
        "malware_similarity": 0.05,
        "mitre_techniques": 0.05
    }

settings = Settings()

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
