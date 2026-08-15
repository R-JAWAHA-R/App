import math
from typing import Any


class HybridSimilarityEngine:
    """
    Combines static API sequences, permissions, strings, IOCs, and dynamic behaviors
    into multi-dimensional feature vectors to compute hybrid similarity against
    known Android malware families.
    """

    KNOWN_MALWARE_INDEX = [
        {
            "family_name": "Fake SBI Banking Trojan (Operation FakeYONO)",
            "category": "BANKING_PHISHING",
            "core_features": [
                "android.permission.RECEIVE_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "sbi", "yono", "kyc", "mpin",
                "AccessibilityService.onAccessibilityEvent",
                "WindowManager.addView",
                "sbi-rewards-bonus.top",
                "TELEGRAM_C2_EXFILTRATION"
            ],
            "description": "Indian banking trojan targeting State Bank of India YONO users via phishing overlays and OTP interception."
        },
        {
            "family_name": "SharkBot / TeaBot Banking Trojan",
            "category": "ADVANCED_BANKING_TROJAN",
            "core_features": [
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "DexClassLoader", "Class.forName",
                "FLAG_NOT_TOUCHABLE",
                "AccessibilityNodeInfo",
                "AccessibilityService.onAccessibilityEvent",
                "WindowManager.addView"
            ],
            "description": "Modular ATS (Automated Transfer System) banking trojan executing automated money transfers and overlay attacks."
        },
        {
            "family_name": "SpyLoan / Loan Shark Extortion Spyware",
            "category": "SPYWARE_EXTORTION",
            "core_features": [
                "android.permission.READ_CONTACTS",
                "android.permission.READ_PHONE_STATE",
                "android.permission.CAMERA",
                "ContentResolver.query(contacts)",
                "fastloan-api-in.live",
                "syncDeviceData", "uploadContacts"
            ],
            "description": "Predatory loan app harvesting victim contacts and photo libraries for harassment and extortion."
        },
        {
            "family_name": "WhatsApp OTP Stealer / SmsThief",
            "category": "CREDENTIAL_HARVESTER",
            "core_features": [
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "SMS_RECEIVED", "SmsManager.sendTextMessage",
                "api.telegram.org/bot"
            ],
            "description": "Stealth SMS forwarder hijacking WhatsApp, Telegram, and banking OTP codes."
        },
        {
            "family_name": "Clean Android Utility / Tool",
            "category": "BENIGN",
            "core_features": [
                "android.permission.INTERNET",
                "Activity.onCreate",
                "SharedPreferences.getString"
            ],
            "description": "Standard non-malicious utility application without privileged surveillance or interception features."
        }
    ]

    def __init__(self, sample_features: list[str]):
        self.sample_features = set([f.lower().strip() for f in sample_features if f])

    def calculate_similarity(self) -> list[dict[str, Any]]:
        results = []

        for family in self.KNOWN_MALWARE_INDEX:
            family_features = set([f.lower().strip() for f in family["core_features"]])

            # Intersection
            intersection = set()
            for sf in self.sample_features:
                for ff in family_features:
                    if sf == ff or sf in ff or ff in sf:
                        intersection.add(ff)

            overlap_ratio = len(intersection) / max(1, len(family_features))
            # Ratio relative to query size
            query_ratio = len(intersection) / max(1, len(self.sample_features))

            # Weighted hybrid similarity
            score_raw = (0.8 * overlap_ratio + 0.2 * query_ratio) * 100
            hybrid_score = min(100.0, max(0.0, round(score_raw, 1)))

            # If it's benign but has dangerous permissions, dampen benign score
            if family["category"] == "BENIGN" and any(p in self.sample_features for p in ["android.permission.bind_accessibility_service", "android.permission.receive_sms"]):
                hybrid_score = min(hybrid_score, 10.0)

            results.append({
                "family_name": family["family_name"],
                "category": family["category"],
                "similarity_score": hybrid_score,
                "vector_distance": round(math.sqrt(max(0.0, 1.0 - (hybrid_score / 100.0))), 3),
                "matched_features": sorted(list(intersection)),
                "total_family_features": len(family_features),
                "explanation": f"{hybrid_score}% similar to {family['family_name']} based on {len(intersection)} matched signature traits."
            })

        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        return results
