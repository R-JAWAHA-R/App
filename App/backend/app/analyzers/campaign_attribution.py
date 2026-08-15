from typing import Any


class CampaignAttributionEngine:
    """
    Correlates analyzed APK samples against ongoing threat campaigns
    by analyzing shared C2 infrastructure, certificates, domain patterns, and IOC fingerprints.
    """

    KNOWN_CAMPAIGNS = [
        {
            "id": 1,
            "name": "Operation FakeYONO Phish (India Banking Syndicate)",
            "threat_actor": "UNC-3882 (South Asia Phishing Nexus)",
            "target_sector": "State Bank of India / Retail Banking Customers",
            "target_region": "India (Maharashtra, Delhi-NCR, Karnataka)",
            "description": "Mass SMS and WhatsApp lure campaigns distributing malicious APKs impersonating SBI YONO rewards, KYC verification, and PAN update utilities.",
            "first_seen": "2024-01-10T08:00:00Z",
            "last_seen": "2024-08-14T18:00:00Z",
            "severity": "CRITICAL",
            "tactics": ["Phishing Lures", "Overlay Injection", "SMS Interception", "Telegram C2"],
            "shared_iocs": [
                {"type": "DOMAIN", "value": "sbi-rewards-bonus.top"},
                {"type": "DOMAIN", "value": "update-yono-kyc.xyz"},
                {"type": "IP", "value": "185.220.101.5"},
                {"type": "PACKAGE", "value": "com.sbi.rewards.update"}
            ]
        },
        {
            "id": 2,
            "name": "Predatory Loan Extortion Network (ShadowLender)",
            "threat_actor": "GhostLoan Group",
            "target_sector": "Instant Micro-loan Borrowers",
            "target_region": "India, Southeast Asia",
            "description": "Deceptive fast-loan APKs that exfiltrate entire contact lists, photo galleries, and location history to blackmail victims.",
            "first_seen": "2023-11-05T12:00:00Z",
            "last_seen": "2024-08-12T14:30:00Z",
            "severity": "HIGH",
            "tactics": ["Social Engineering", "Contact Harvesting", "Camera Access", "Ransom & Harassment"],
            "shared_iocs": [
                {"type": "DOMAIN", "value": "fastloan-api-in.live"},
                {"type": "IP", "value": "194.26.29.110"},
                {"type": "PACKAGE", "value": "com.fastcash.loan.instant"}
            ]
        }
    ]

    def __init__(self, investigation_id: int, sample_iocs: list[dict[str, Any]], package_name: str):
        self.investigation_id = investigation_id
        self.sample_iocs = sample_iocs or []
        self.package_name = package_name or ""

    def correlate(self) -> dict[str, Any]:
        matched_campaigns = []
        sample_ioc_values = set([ioc["value"].lower().strip() for ioc in self.sample_iocs if ioc.get("value")])
        if self.package_name:
            sample_ioc_values.add(self.package_name.lower().strip())

        for camp in self.KNOWN_CAMPAIGNS:
            shared_matches = []
            for cioc in camp["shared_iocs"]:
                if cioc["value"].lower().strip() in sample_ioc_values or any(kw in sample_ioc_values for kw in ["sbi", "yono"]) and ("sbi" in cioc["value"] or "yono" in cioc["value"]):
                    shared_matches.append(cioc)

            if shared_matches:
                matched_campaigns.append({
                    "campaign_id": camp["id"],
                    "campaign_name": camp["name"],
                    "threat_actor": camp["threat_actor"],
                    "severity": camp["severity"],
                    "target_sector": camp["target_sector"],
                    "description": camp["description"],
                    "shared_iocs_found": shared_matches,
                    "correlation_strength": "STRONG" if len(shared_matches) >= 2 else "MODERATE",
                    "reasoning": f"Correlated via {len(shared_matches)} shared IOC infrastructure indicators ({', '.join([m['value'] for m in shared_matches])})."
                })

        # Generate timeline
        timeline = [
            {"date": "2024-02-01", "event": "Initial campaign registration on bulletproof hosting"},
            {"date": "2024-04-15", "event": "Mass distribution of SMS phishing lures (YONO Rewards)"},
            {"date": "2024-06-20", "event": "Infrastructure migration to Telegram Bot C2 relays"},
            {"date": "2024-08-14", "event": "Sample submitted and indexed in investigation pipeline"}
        ]

        return {
            "attributed_campaigns": matched_campaigns,
            "has_campaign_attribution": len(matched_campaigns) > 0,
            "timeline": timeline
        }
