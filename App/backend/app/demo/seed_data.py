import datetime
import os

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.models import (
    IOC,
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
from backend.app.demo.synthetic_apk import create_synthetic_test_apk


def seed_demo_database(db: Session):
    """Populates the database with rich, realistic cybersecurity investigations."""
    # Check if data already exists
    if db.query(Investigation).count() > 0:
        return

    print("[*] Seeding database with realistic demonstration samples and threat campaigns...")

    # Create synthetic APK files
    apk1_path = os.path.join(settings.UPLOAD_DIR, "SafeCalculator_v1.2.apk")
    apk2_path = os.path.join(settings.UPLOAD_DIR, "SBI_YONO_Rewards_Update.apk")
    apk3_path = os.path.join(settings.UPLOAD_DIR, "SharkBot_UPI_Stealer_2024.apk")
    apk4_path = os.path.join(settings.UPLOAD_DIR, "FastCash_Loan_Extortion.apk")

    create_synthetic_test_apk(apk1_path, "clean")
    create_synthetic_test_apk(apk2_path, "banking_trojan")
    create_synthetic_test_apk(apk3_path, "banking_trojan")
    create_synthetic_test_apk(apk4_path, "loan_spyware")

    # 1. Campaigns
    camp1 = Campaign(
        id=1,
        name="Operation FakeYONO Phish (India Banking Syndicate)",
        threat_actor="UNC-3882 (South Asia Phishing Nexus)",
        target_sector="State Bank of India / Retail Banking Customers",
        target_region="India (Maharashtra, Delhi-NCR, Karnataka)",
        description="Mass SMS and WhatsApp lure campaigns distributing malicious APKs impersonating SBI YONO rewards, KYC verification, and PAN update utilities.",
        first_seen=datetime.datetime(2024, 1, 10, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 8, 14, tzinfo=datetime.timezone.utc),
        severity="CRITICAL",
        tactics=["Phishing Lures", "Overlay Injection", "SMS Interception", "Telegram C2"],
        shared_iocs=[
            {"type": "DOMAIN", "value": "sbi-rewards-bonus.top"},
            {"type": "DOMAIN", "value": "update-yono-kyc.xyz"},
            {"type": "IP", "value": "185.220.101.5"}
        ]
    )
    camp2 = Campaign(
        id=2,
        name="Predatory Loan Extortion Network (ShadowLender)",
        threat_actor="GhostLoan Group",
        target_sector="Instant Micro-loan Borrowers",
        target_region="India, Southeast Asia",
        description="Deceptive fast-loan APKs that exfiltrate entire contact lists, photo galleries, and location history to blackmail victims.",
        first_seen=datetime.datetime(2023, 11, 5, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 8, 12, tzinfo=datetime.timezone.utc),
        severity="HIGH",
        tactics=["Social Engineering", "Contact Harvesting", "Camera Access", "Ransom & Harassment"],
        shared_iocs=[
            {"type": "DOMAIN", "value": "fastloan-api-in.live"},
            {"type": "IP", "value": "194.26.29.110"}
        ]
    )
    db.add_all([camp1, camp2])
    db.commit()

    # 2. Critical Risk: SharkBot UPI Stealer 2024
    inv_crit = Investigation(
        id=1,
        sha256="7a8b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b",
        apk_name="SharkBot_UPI_Stealer_2024.apk",
        package_name="com.sbi.rewards.yono.update",
        version_name="2.4.1",
        version_code="241",
        min_sdk=23,
        target_sdk=34,
        file_size=1258291,
        status="COMPLETED",
        progress=100,
        current_stage_label="Analysis Completed",
        risk_score=94.5,
        severity="CRITICAL",
        confidence=0.98,
        is_demo=True,
        limitations="Isolated emulator trace captured 18 sensitive runtime events.",
        top_reasons=[
            "Privileged Permissions: BIND_ACCESSIBILITY_SERVICE & SYSTEM_ALERT_WINDOW combined.",
            "C2 Network Traffic: Live beaconing to bulletproof server 'sbi-rewards-bonus.top' (185.220.101.5).",
            "Credential Theft: Active overlay injection targeting SBI YONO and Google Pay foreground activities.",
            "SMS/OTP Interception: Hooked android.provider.Telephony.SMS_RECEIVED receiver."
        ],
        summary="Critical banking trojan variant impersonating SBI YONO. Employs Accessibility Service hijacking to intercept SMS 2FA codes, logs keystrokes, and displays overlay phishing screens.",
        ai_verdict="Weaponized Banking Trojan (SharkBot/FakeSBI). High urgency threat requiring immediate network perimeter blocking and MTD containment."
    )
    db.add(inv_crit)
    db.commit()

    # Link to Campaign
    db.add(CampaignSample(campaign_id=1, investigation_id=1, correlation_reason="Matches primary C2 domain 'sbi-rewards-bonus.top' and certificate signature."))

    # Findings for Critical Sample
    db.add_all([
        StaticFinding(investigation_id=1, category="SUSPICIOUS_PERMISSION", title="android.permission.BIND_ACCESSIBILITY_SERVICE", description="Grants malware full control over UI hierarchy and keystroke events.", severity="CRITICAL", evidence="Declared in AndroidManifest.xml"),
        StaticFinding(investigation_id=1, category="SUSPICIOUS_PERMISSION", title="android.permission.SYSTEM_ALERT_WINDOW", description="Allows malware to draw floating overlays over banking login interfaces.", severity="HIGH", evidence="Declared in AndroidManifest.xml"),
        StaticFinding(investigation_id=1, category="SUSPICIOUS_PERMISSION", title="android.permission.RECEIVE_SMS", description="Allows intercepting 2FA banking SMS authentication codes.", severity="CRITICAL", evidence="Declared in AndroidManifest.xml"),
        StaticFinding(investigation_id=1, category="YARA_MATCH", title="Android_Banking_Trojan_Overlay_Injector", description="Matches SharkBot/TeaBot ATS signatures.", severity="CRITICAL", evidence="Matched patterns: SYSTEM_ALERT_WINDOW, AccessibilityService, WindowManager.addView"),
        StaticFinding(investigation_id=1, category="OBFUSCATION", title="DYNAMIC_CODE_LOADING", description="App unpacks secondary DEX payload from encrypted assets.", severity="HIGH", evidence="DexClassLoader detected in dex strings"),

        DynamicFinding(investigation_id=1, api_class="android.accessibilityservice.AccessibilityService", method="onAccessibilityEvent", parameters="TYPE_VIEW_TEXT_CHANGED, target: com.sbi.lotus.integra", return_value="void", timestamp_offset=1.24, is_sensitive=True, severity="CRITICAL", description="Intercepted user keystrokes from active SBI YONO banking screen."),
        DynamicFinding(investigation_id=1, api_class="android.view.WindowManager", method="addView", parameters="PhishingOverlayView, TYPE_APPLICATION_OVERLAY", return_value="void", timestamp_offset=2.15, is_sensitive=True, severity="CRITICAL", description="Injected phishing overlay window over payment screen."),
        DynamicFinding(investigation_id=1, api_class="android.telephony.SmsManager", method="sendTextMessage", parameters="dest: +919876543210, text: OTP_TOKEN_INTERCEPTED", return_value="void", timestamp_offset=3.42, is_sensitive=True, severity="HIGH", description="Exfiltrated intercepted OTP code via SMS."),

        NetworkFinding(investigation_id=1, domain="sbi-rewards-bonus.top", ip="185.220.101.5", port=443, protocol="HTTPS", url="https://sbi-rewards-bonus.top/api/v2/gate", is_c2=True, is_phishing=True, reputation_score=98.0, exfiltration_type="OTP_CREDENTIALS", evidence="Active beaconing observed every 10 seconds"),
        NetworkFinding(investigation_id=1, domain="api.telegram.org", ip="149.154.167.220", port=443, protocol="HTTPS", url="https://api.telegram.org/bot7182938102:AAF9x_FakeTokenSBI_exfil/sendMessage", is_c2=True, is_phishing=False, reputation_score=92.0, exfiltration_type="SMS_EXFIL", evidence="Direct bot API payload upload"),

        IOC(investigation_id=1, ioc_type="DOMAIN", value="sbi-rewards-bonus.top", description="Primary C2 Server Domain", severity="CRITICAL", source="NETWORK_CAPTURE", recommended_action="BLOCK_AT_FIREWALL_AND_DNS"),
        IOC(investigation_id=1, ioc_type="IP", value="185.220.101.5", description="Bulletproof C2 Server IP", severity="CRITICAL", source="DNS_RESOLUTION", recommended_action="BLOCK_IP_RANGE"),
        IOC(investigation_id=1, ioc_type="SHA256", value="7a8b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b", description="Sample Binary SHA-256 Hash", severity="CRITICAL", source="STATIC_EXTRACTOR", recommended_action="SUBMIT_TO_EDR_BLOCKLIST"),
        IOC(investigation_id=1, ioc_type="PACKAGE", value="com.sbi.rewards.yono.update", description="Malicious Sideload Package Name", severity="HIGH", source="MANIFEST_PARSER", recommended_action="ADD_TO_MDM_BLACKLIST"),

        SimilarityMatch(investigation_id=1, family_name="Fake SBI Banking Trojan (Operation FakeYONO)", similarity_score=92.4, matched_features=["android.permission.RECEIVE_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE", "sbi-rewards-bonus.top", "WindowManager.addView"], vector_distance=0.08, explanation="92.4% match to Fake SBI Trojan based on 8 matching API signatures and shared C2 domain patterns."),
        SimilarityMatch(investigation_id=1, family_name="SharkBot / TeaBot Banking Trojan", similarity_score=87.6, matched_features=["android.permission.BIND_ACCESSIBILITY_SERVICE", "DexClassLoader", "WindowManager.addView"], vector_distance=0.12, explanation="87.6% match to SharkBot core overlay logic."),

        MitreTechnique(investigation_id=1, technique_id="T1400", technique_name="Accessibility Abuse", tactic="Credential Access & Execution", evidence="Abuses AccessibilityService to capture keystrokes and inject clicks.", source_module="DYNAMIC_HOOK"),
        MitreTechnique(investigation_id=1, technique_id="T1417", technique_name="Input Capture / Keylogging", tactic="Credential Access", evidence="Monitored onAccessibilityEvent with TYPE_VIEW_TEXT_CHANGED.", source_module="DYNAMIC_HOOK"),
        MitreTechnique(investigation_id=1, technique_id="T1582", technique_name="SMS Interception & Forwarding", tactic="Credential Access & Collection", evidence="Registered broadcast receiver on SMS_RECEIVED and forwards messages to C2.", source_module="STATIC_MANIFEST"),
        MitreTechnique(investigation_id=1, technique_id="T1437", technique_name="Application Layer Protocol C2", tactic="Command and Control", evidence="Dispatched exfiltrated credentials over HTTPS to sbi-rewards-bonus.top.", source_module="NETWORK_ANALYZER"),

        RiskComponent(investigation_id=1, category="Suspicious & Privileged Permissions", weight=0.20, raw_score=95.0, weighted_contribution=19.0, reasoning="Dangerous permissions (Accessibility, SMS, Overlay) granted.", evidence_count=3, evidence_items=["Critical: BIND_ACCESSIBILITY_SERVICE", "Critical: RECEIVE_SMS", "High: SYSTEM_ALERT_WINDOW"]),
        RiskComponent(investigation_id=1, category="C2 & Malicious Network Traffic", weight=0.18, raw_score=95.0, weighted_contribution=17.1, reasoning="Active communication with phishing domain and Telegram bot C2.", evidence_count=2, evidence_items=["C2 Domain: sbi-rewards-bonus.top", "Exfiltration: OTP_CREDENTIALS"]),
        RiskComponent(investigation_id=1, category="Runtime Suspicious Behaviors", weight=0.12, raw_score=90.0, weighted_contribution=10.8, reasoning="Overlay injection and SMS theft hooks confirmed.", evidence_count=3, evidence_items=["Overlay injection via WindowManager", "Keystroke interception in SBI YONO"]),
        RiskComponent(investigation_id=1, category="Threat Intelligence Reputation", weight=0.10, raw_score=96.0, weighted_contribution=9.6, reasoning="VirusTotal: 58/72 vendors flagged malicious; AbuseIPDB: 98% confidence score.", evidence_count=2, evidence_items=["VirusTotal: 58 positive engines", "AbuseIPDB: 98% abuse score on 185.220.101.5"]),
        RiskComponent(investigation_id=1, category="Malware Family Signature Match", weight=0.05, raw_score=92.0, weighted_contribution=4.6, reasoning="92.4% vector similarity to Fake SBI Banking Trojan.", evidence_count=1, evidence_items=["92.4% match to Fake SBI Trojan"]),
        RiskComponent(investigation_id=1, category="MITRE ATT&CK Mobile Tactics", weight=0.05, raw_score=90.0, weighted_contribution=4.5, reasoning="4 Mobile ATT&CK techniques mapped across Credential Access and C2.", evidence_count=4, evidence_items=["T1400 Accessibility Abuse", "T1417 Input Capture", "T1582 SMS Interception", "T1437 Application Layer Protocol C2"]),
        RiskComponent(investigation_id=1, category="Dangerous System API Usage", weight=0.18, raw_score=90.0, weighted_contribution=16.2, reasoning="Detected overlay injection and SMS listening routines.", evidence_count=2, evidence_items=["Fraud Rule: ACCESSIBILITY_OVERLAY_HIJACKING", "Target: Financial Impersonation"]),
        RiskComponent(investigation_id=1, category="Obfuscation & Evasion Indicators", weight=0.12, raw_score=85.0, weighted_contribution=10.2, reasoning="DexClassLoader and encrypted asset payload routines found.", evidence_count=2, evidence_items=["Dynamic code loading detected", "Base64 + Cipher decryption routines"]),

        Report(investigation_id=1, report_type="ANALYST_EXECUTIVE", executive_summary="High-severity forensic dossier documenting weaponized SBI YONO phishing trojan with overlay capabilities and automated SMS OTP harvesting.", prioritized_recommendations=["Block sbi-rewards-bonus.top and 185.220.101.5 at firewall and DNS.", "Push SHA-256 hash block to enterprise EDR.", "Notify cert-in and registrar for domain takedown."])
    ])
    db.commit()

    # 3. Clean Sample: SafeCalculator Pro
    inv_clean = Investigation(
        id=2,
        sha256="4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
        apk_name="SafeCalculator_v1.2.apk",
        package_name="com.clean.tools.calculator",
        version_name="1.2.0",
        version_code="12",
        min_sdk=21,
        target_sdk=34,
        file_size=428000,
        status="COMPLETED",
        progress=100,
        current_stage_label="Analysis Completed",
        risk_score=8.5,
        severity="LOW",
        confidence=0.99,
        is_demo=True,
        limitations="Clean utility app.",
        top_reasons=["No suspicious or dangerous Android permissions requested.", "Zero C2 endpoints or malicious URLs observed.", "Normal UI activity lifecycle behavior."],
        summary="Safe utility application without malicious intent or abnormal permission requests.",
        ai_verdict="Benign Application. Standard deployment approved."
    )
    db.add(inv_clean)
    db.commit()

    db.add_all([
        StaticFinding(investigation_id=2, category="PERMISSION", title="android.permission.INTERNET", description="Standard internet access for optional anonymous usage analytics.", severity="INFO", evidence="Declared in AndroidManifest.xml"),
        DynamicFinding(investigation_id=2, api_class="android.app.Activity", method="onCreate", parameters="savedInstanceState=null", return_value="void", timestamp_offset=0.32, is_sensitive=False, severity="INFO", description="Standard calculator UI initialization."),
        NetworkFinding(investigation_id=2, domain="analytics.safecalculator.com", ip="104.21.48.1", port=443, protocol="HTTPS", url="https://analytics.safecalculator.com/ping", is_c2=False, is_phishing=False, reputation_score=0.0, exfiltration_type="NONE", evidence="Standard telemetry ping"),
        SimilarityMatch(investigation_id=2, family_name="Clean Android Utility / Tool", similarity_score=95.0, matched_features=["android.permission.INTERNET", "Activity.onCreate"], vector_distance=0.05, explanation="95.0% match to verified benign Android utility profile."),
        RiskComponent(investigation_id=2, category="Suspicious & Privileged Permissions", weight=0.20, raw_score=5.0, weighted_contribution=1.0, reasoning="Only standard non-privileged internet permission.", evidence_count=1, evidence_items=["Normal permission: INTERNET"]),
        RiskComponent(investigation_id=2, category="C2 & Malicious Network Traffic", weight=0.18, raw_score=0.0, weighted_contribution=0.0, reasoning="No suspicious endpoints.", evidence_count=0, evidence_items=[]),
        RiskComponent(investigation_id=2, category="Runtime Suspicious Behaviors", weight=0.12, raw_score=0.0, weighted_contribution=0.0, reasoning="Standard activity initialization.", evidence_count=0, evidence_items=[]),
        RiskComponent(investigation_id=2, category="Dangerous System API Usage", weight=0.18, raw_score=0.0, weighted_contribution=0.0, reasoning="Zero dangerous API calls.", evidence_count=0, evidence_items=[]),
        RiskComponent(investigation_id=2, category="Obfuscation & Evasion Indicators", weight=0.12, raw_score=0.0, weighted_contribution=0.0, reasoning="No packing or dynamic classloading.", evidence_count=0, evidence_items=[]),
        RiskComponent(investigation_id=2, category="Threat Intelligence Reputation", weight=0.10, raw_score=0.0, weighted_contribution=0.0, reasoning="0 detections on VirusTotal.", evidence_count=0, evidence_items=[]),
        RiskComponent(investigation_id=2, category="Malware Family Signature Match", weight=0.05, raw_score=0.0, weighted_contribution=0.0, reasoning="Matches clean utility profile.", evidence_count=0, evidence_items=[]),
        RiskComponent(investigation_id=2, category="MITRE ATT&CK Mobile Tactics", weight=0.05, raw_score=0.0, weighted_contribution=0.0, reasoning="No adversary techniques mapped.", evidence_count=0, evidence_items=[])
    ])
    db.commit()

    # 4. Loan Spyware Sample: FastCash Instant Loan
    inv_loan = Investigation(
        id=3,
        sha256="8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a",
        apk_name="FastCash_Loan_Extortion.apk",
        package_name="com.fastcash.loan.instant",
        version_name="1.0.0",
        version_code="10",
        min_sdk=21,
        target_sdk=33,
        file_size=890000,
        status="COMPLETED",
        progress=100,
        current_stage_label="Analysis Completed",
        risk_score=88.0,
        severity="CRITICAL",
        confidence=0.96,
        is_demo=True,
        limitations="Predatory loan spyware application.",
        top_reasons=[
            "Exfiltration of device contact book (380+ contacts dumped).",
            "Covert background camera access and photo gallery harvesting.",
            "Data synchronization to extortion server 'fastloan-api-in.live' (194.26.29.110)."
        ],
        summary="Predatory loan app harvesting victim contacts, call history, and camera permissions for blackmail and harassment extortion campaigns.",
        ai_verdict="Predatory Loan Shark Spyware (SpyLoan Syndicate). Immediate removal and report to cyber crime portal."
    )
    db.add(inv_loan)
    db.commit()

    db.add(CampaignSample(campaign_id=2, investigation_id=3, correlation_reason="Connected to ShadowLender extortion C2 infrastructure."))
    db.add_all([
        StaticFinding(investigation_id=3, category="SUSPICIOUS_PERMISSION", title="android.permission.READ_CONTACTS", description="Harvests phone address book contacts for extortion.", severity="HIGH", evidence="Declared in AndroidManifest.xml"),
        StaticFinding(investigation_id=3, category="SUSPICIOUS_PERMISSION", title="android.permission.CAMERA", description="Allows covert background camera snapshots.", severity="HIGH", evidence="Declared in AndroidManifest.xml"),
        StaticFinding(investigation_id=3, category="FRAUD_HEURISTIC", title="Loan Shark Extortion Pattern", description="Aggressive permissions paired with contact exfiltration endpoint.", severity="HIGH", evidence="Matched syncDeviceData & uploadContacts"),
        DynamicFinding(investigation_id=3, api_class="android.content.ContentResolver", method="query", parameters="content://com.android.contacts/contacts", return_value="Cursor[384 entries]", timestamp_offset=1.05, is_sensitive=True, severity="CRITICAL", description="Extracted all 384 contacts from device address book."),
        NetworkFinding(investigation_id=3, domain="fastloan-api-in.live", ip="194.26.29.110", port=443, protocol="HTTPS", url="https://fastloan-api-in.live/uploadContacts", is_c2=True, is_phishing=False, reputation_score=94.0, exfiltration_type="CONTACTS", evidence="POST request with 384 contacts payload"),
        IOC(investigation_id=3, ioc_type="DOMAIN", value="fastloan-api-in.live", description="Loan Extortion Exfiltration Endpoint", severity="CRITICAL", source="NETWORK_CAPTURE", recommended_action="BLOCK_AT_FIREWALL"),
        IOC(investigation_id=3, ioc_type="IP", value="194.26.29.110", description="Extortion C2 Server IP", severity="HIGH", source="DNS_RESOLUTION", recommended_action="BLOCK_IP"),
        SimilarityMatch(investigation_id=3, family_name="SpyLoan / Loan Shark Extortion Spyware", similarity_score=91.5, matched_features=["android.permission.READ_CONTACTS", "android.permission.CAMERA", "uploadContacts"], vector_distance=0.09, explanation="91.5% match to SpyLoan extortion syndicate profile."),
        MitreTechnique(investigation_id=3, technique_id="T1430", technique_name="Location Tracking", tactic="Collection", evidence="Harvests fine GPS coordinates.", source_module="STATIC_MANIFEST"),
        RiskComponent(investigation_id=3, category="Suspicious & Privileged Permissions", weight=0.20, raw_score=90.0, weighted_contribution=18.0, reasoning="READ_CONTACTS, CAMERA, ACCESS_FINE_LOCATION requested.", evidence_count=3, evidence_items=["READ_CONTACTS", "CAMERA", "ACCESS_FINE_LOCATION"]),
        RiskComponent(investigation_id=3, category="C2 & Malicious Network Traffic", weight=0.18, raw_score=90.0, weighted_contribution=16.2, reasoning="Active contact exfiltration to fastloan-api-in.live.", evidence_count=1, evidence_items=["fastloan-api-in.live"]),
        RiskComponent(investigation_id=3, category="Runtime Suspicious Behaviors", weight=0.12, raw_score=85.0, weighted_contribution=10.2, reasoning="Harvested entire contact book via ContentResolver query.", evidence_count=1, evidence_items=["ContentResolver.query(contacts)"]),
        RiskComponent(investigation_id=3, category="Dangerous System API Usage", weight=0.18, raw_score=85.0, weighted_contribution=15.3, reasoning="CameraManager and ContactResolver abuse.", evidence_count=2, evidence_items=["CameraManager.openCamera", "ContentResolver.query"]),
        RiskComponent(investigation_id=3, category="Obfuscation & Evasion Indicators", weight=0.12, raw_score=40.0, weighted_contribution=4.8, reasoning="Basic string obfuscation.", evidence_count=1, evidence_items=["Base64 decoding"]),
        RiskComponent(investigation_id=3, category="Threat Intelligence Reputation", weight=0.10, raw_score=90.0, weighted_contribution=9.0, reasoning="VirusTotal: 42 detections.", evidence_count=1, evidence_items=["VirusTotal: 42 detections"]),
        RiskComponent(investigation_id=3, category="Malware Family Signature Match", weight=0.05, raw_score=91.0, weighted_contribution=4.55, reasoning="91.5% match to SpyLoan.", evidence_count=1, evidence_items=["91.5% match to SpyLoan"]),
        RiskComponent(investigation_id=3, category="MITRE ATT&CK Mobile Tactics", weight=0.05, raw_score=75.0, weighted_contribution=3.75, reasoning="Mapped T1430 Location Tracking and Collection.", evidence_count=1, evidence_items=["T1430 Location Tracking"])
    ])
    db.commit()

    print("[+] Demo database initialized with 3 investigations and 2 threat campaigns.")
