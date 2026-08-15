from typing import Any


class MitreAttackMapper:
    """
    Automatically correlates static indicators, dynamic API hooks, and network behaviors
    to the standard MITRE ATT&CK for Mobile Matrix framework.
    """

    MAPPINGS_DATABASE = [
        {
            "technique_id": "T1400",
            "technique_name": "Accessibility Abuse",
            "tactic": "Credential Access & Execution",
            "trigger_keywords": ["accessibility", "bind_accessibility_service", "onaccessibilityevent", "accessibilityservice"],
            "description": "Adversaries abuse Android Accessibility services to capture credentials, automate clicks, and intercept screen contents without user interaction."
        },
        {
            "technique_id": "T1417",
            "technique_name": "Input Capture / Keylogging",
            "tactic": "Credential Access",
            "trigger_keywords": ["type_view_text_changed", "accessibilityevent", "keylog", "windowmanager.addview", "overlay"],
            "description": "Adversaries log user input or inject overlay windows to steal banking PINs, credentials, and authentication codes."
        },
        {
            "technique_id": "T1582",
            "technique_name": "SMS Interception & Forwarding",
            "tactic": "Credential Access & Collection",
            "trigger_keywords": ["receive_sms", "sms_received", "read_sms", "sendtextmessage"],
            "description": "Adversaries intercept incoming SMS messages containing OTP (One-Time Password) verification tokens to bypass 2FA authentication."
        },
        {
            "technique_id": "T1437",
            "technique_name": "Application Layer Protocol C2",
            "tactic": "Command and Control",
            "trigger_keywords": ["api.telegram.org", "c2", "telegram_c2", "http", "https", "socket"],
            "description": "Adversaries communicate with command and control infrastructure using standard HTTP/HTTPS or Telegram bot webhooks to evade perimeter defenses."
        },
        {
            "technique_id": "T1624",
            "technique_name": "Event Triggered Execution",
            "tactic": "Persistence",
            "trigger_keywords": ["boot_completed", "receive_boot_completed", "action_power_connected"],
            "description": "Malware registers broadcast receivers to automatically execute background services upon device power on or power state change."
        },
        {
            "technique_id": "T1407",
            "technique_name": "Dynamic Code Loading",
            "tactic": "Defense Evasion",
            "trigger_keywords": ["dexclassloader", "inmemorydexclassloader", "class.forname"],
            "description": "Adversaries download or decrypt payload code at runtime to evade static antivirus and store inspection signatures."
        },
        {
            "technique_id": "T1430",
            "technique_name": "Location Tracking",
            "tactic": "Collection",
            "trigger_keywords": ["access_fine_location", "access_coarse_location", "gps"],
            "description": "Adversaries track victim geographic positioning for surveillance and profiling."
        },
        {
            "technique_id": "T1418",
            "technique_name": "Application Discovery",
            "tactic": "Discovery",
            "trigger_keywords": ["query_all_packages", "getinstalledpackages", "packagemanager"],
            "description": "Adversaries enumerate installed banking, crypto, and payment applications to trigger targeted overlay injection."
        }
    ]

    def __init__(self, static_findings: dict[str, Any], dynamic_findings: dict[str, Any], network_findings: dict[str, Any]):
        self.static = static_findings or {}
        self.dynamic = dynamic_findings or {}
        self.network = network_findings or {}

    def map_techniques(self) -> list[dict[str, Any]]:
        observed_techniques = []

        # Build searchable string corpus from all analysis results
        corpus = []
        corpus.extend(self.static.get("permissions", []))
        for item in self.static.get("extracted_strings_sample", []):
            corpus.append(str(item))
        for obf in self.static.get("obfuscation_indicators", []):
            corpus.append(str(obf.get("evidence", "")))
            corpus.append(str(obf.get("type", "")))
        for fraud in self.static.get("fraud_heuristics", []):
            corpus.append(str(fraud.get("pattern", "")))
            corpus.append(str(fraud.get("description", "")))
        for dyn in self.dynamic.get("api_traces", []):
            corpus.append(f"{dyn.get('api_class')}.{dyn.get('method')}")
            corpus.append(str(dyn.get("description", "")))
        for net in self.network.get("endpoints", []):
            corpus.append(str(net.get("url", "")))
            corpus.append(str(net.get("exfiltration_type", "")))
            if net.get("is_c2"):
                corpus.append("c2")

        unified_corpus_text = " \n ".join([s.lower() for s in corpus if s])

        for tech in self.MAPPINGS_DATABASE:
            matched_triggers = []
            for kw in tech["trigger_keywords"]:
                if kw in unified_corpus_text:
                    matched_triggers.append(kw)

            if matched_triggers:
                observed_techniques.append({
                    "technique_id": tech["technique_id"],
                    "technique_name": tech["technique_name"],
                    "tactic": tech["tactic"],
                    "evidence": f"Matched indicators: {', '.join(matched_triggers[:3])}. {tech['description']}",
                    "source_module": "HYBRID_ENGINE"
                })

        return observed_techniques
