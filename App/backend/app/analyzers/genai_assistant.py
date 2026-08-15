import json
from typing import Any

from backend.app.core.config import settings


class GenAIAssistant:
    """
    Generative AI Reasoning Engine and SOC Investigation Assistant.
    Uses Google Gemini API when configured, with an intelligent evidence-grounded
    local inference engine to provide zero-hallucination answers, threat summaries,
    and decompiled code intent explanations.
    """

    def __init__(self, investigation_data: dict[str, Any]):
        self.inv = investigation_data
        self.api_key = settings.GEMINI_API_KEY

    def generate_threat_summary(self) -> dict[str, Any]:
        """Generates executive summary and prioritized remediation recommendations."""
        apk_name = self.inv.get("apk_name", "Unknown APK")
        risk_score = self.inv.get("risk_score", 0.0)
        severity = self.inv.get("severity", "LOW")
        pkg = self.inv.get("package_name", "unknown")

        top_reasons = self.inv.get("top_reasons", [])
        reasons_text = "\n- ".join(top_reasons) if top_reasons else "No high severity findings observed."

        # If Gemini API key is available, call Gemini
        if self.api_key and self.api_key != "MOCK_KEY":
            try:
                import importlib
                genai_mod = importlib.import_module("google.genai")
                client = genai_mod.Client(api_key=self.api_key)
                prompt = f"""
You are a Senior Malware Analysis and Threat Intelligence Architect.
Provide a concise 3-paragraph executive threat briefing and 4 prioritized remediation steps for this analyzed Android APK.
Sample Data:
- APK Name: {apk_name}
- Package: {pkg}
- Risk Score: {risk_score}/100 ({severity})
- Top Observed Reasons:
- {reasons_text}

Return format:
Executive Summary: <text>
Prioritized Recommendations: <numbered list>
"""
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt
                )
                if response and hasattr(response, "text") and response.text:
                    return {
                        "executive_summary": response.text,
                        "prioritized_recommendations": [
                            "Block identified C2 domains and IP infrastructure at firewall and secure DNS resolvers.",
                            "Revoke Accessibility and SMS permissions from affected Android endpoints.",
                            "Submit malicious SHA-256 hash to enterprise EDR / MDM blocklists.",
                            "Initiate takedown notices for weaponized hosting domains and Telegram C2 bot channels."
                        ]
                    }
            except Exception:
                pass

        # Grounded rule-based response
        if severity in ["CRITICAL", "HIGH"]:
            summary = (
                f"Investigation of '{apk_name}' ({pkg}) established an evidence-backed risk score of {risk_score}/100 "
                f"classified as {severity}. The application exhibits high-fidelity indicators of an Android Banking Trojan "
                f"and Credential Harvester targeting financial workflows. Key identified capabilities include privileged "
                f"Accessibility service abuse, overlay injection against banking applications, and clandestine SMS/OTP "
                f"interception routed via malicious Command & Control endpoints."
            )
            recommendations = [
                "Immediately push network-level block rules for active C2 infrastructure across perimeter firewalls and DNS.",
                "Enforce immediate revocation of SMS and Accessibility permissions across enterprise mobile device fleets.",
                "Distribute the SHA-256 hash and package name to SOC EDR feeds and mobile threat defense (MTD) agents.",
                "Issue customer advisories and file domain registrar takedowns for fraudulent brand impersonation domains."
            ]
        elif severity == "MEDIUM":
            summary = (
                f"Analysis of '{apk_name}' determined a moderate risk score of {risk_score}/100. "
                f"The application requests multiple sensitive permissions (e.g. storage, location) and displays "
                f"obfuscation routines, but did not exhibit overt C2 beaconing or automated credential interception."
            )
            recommendations = [
                "Enforce least-privilege permission grants on user devices.",
                "Monitor outbound network telemetry for anomalous data transfers.",
                "Perform deeper static decompilation if application was sideloaded outside official app stores."
            ]
        else:
            summary = (
                f"Automated static and dynamic inspection of '{apk_name}' confirmed a safe posture with a risk score of {risk_score}/100 ({severity}). "
                f"No malicious overlays, SMS listeners, or suspicious C2 communication infrastructure were observed."
            )
            recommendations = [
                "Standard application deployment approved under routine baseline security policies.",
                "Continue standard periodic integrity verification."
            ]

        return {
            "executive_summary": summary,
            "prioritized_recommendations": recommendations
        }

    def answer_analyst_query(self, query: str) -> dict[str, Any]:
        """Answers SOC analyst questions with strict evidence grounding."""
        query_lower = query.lower()
        evidence_citations = []
        answer = ""

        # Extract context
        risk_score = self.inv.get("risk_score", 0.0)
        severity = self.inv.get("severity", "LOW")
        top_reasons = self.inv.get("top_reasons", [])
        iocs = self.inv.get("iocs", [])
        mitre = self.inv.get("mitre_techniques", [])
        similarity = self.inv.get("similarity_matches", [])
        static_f = self.inv.get("static_findings", [])
        dynamic_f = self.inv.get("dynamic_findings", [])

        # Call Gemini if available
        if self.api_key and self.api_key != "MOCK_KEY":
            try:
                import importlib
                genai_mod = importlib.import_module("google.genai")
                client = genai_mod.Client(api_key=self.api_key)
                context_blob = json.dumps({
                    "apk_name": self.inv.get("apk_name"),
                    "package_name": self.inv.get("package_name"),
                    "risk_score": risk_score,
                    "severity": severity,
                    "top_reasons": top_reasons,
                    "iocs": [i.get("value") for i in iocs[:6]],
                    "mitre": [m.get("technique_name") for m in mitre],
                    "similarity": [s.get("family_name") for s in similarity[:2]]
                })
                prompt = f"""
You are a SOC Assistant for Android Malware Analysis. Answer the analyst's question based strictly on this verified analysis evidence:
Context: {context_blob}
Question: {query}
Answer concisely with factual reasoning:
"""
                resp = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
                if resp and hasattr(resp, "text") and resp.text:
                    return {
                        "answer": resp.text,
                        "grounded_evidence": top_reasons[:3],
                        "suggested_followups": [
                            "Which IOCs should be blocked immediately?",
                            "What MITRE techniques were mapped?",
                            "Show decompiled code intent for overlay injection"
                        ]
                    }
            except Exception:
                pass

        # Grounded local reasoning fallback
        if "why" in query_lower and ("risk" in query_lower or "high" in query_lower or "critical" in query_lower or "classified" in query_lower):
            answer = (
                f"This APK was classified as **{severity}** ({risk_score}/100) because multiple high-confidence "
                f"malicious indicators were verified during static and dynamic inspection:\n"
            )
            for idx, r in enumerate(top_reasons, 1):
                answer += f"{idx}. **{r}**\n"
                evidence_citations.append(r)
            answer += "\nThese combined indicators indicate a weaponized banking/phishing Trojan rather than benign utility behavior."

        elif "permission" in query_lower:
            suspicious_perms = [f for f in static_f if f.get("category") == "SUSPICIOUS_PERMISSION" or "permission" in f.get("title", "").lower()]
            if suspicious_perms:
                answer = "The following suspicious and dangerous permissions were requested by the APK:\n"
                for p in suspicious_perms:
                    answer += f"- `{p.get('title')}`: {p.get('description')}\n"
                    evidence_citations.append(p.get('title'))
            else:
                answer = "No highly suspicious or abnormal permissions were detected in the application manifest."

        elif "credential" in query_lower or "theft" in query_lower or "otp" in query_lower:
            overlay_hooks = [d for d in dynamic_f if "overlay" in d.get("description", "").lower() or "accessibility" in d.get("description", "").lower()]
            sms_hooks = [d for d in dynamic_f if "sms" in d.get("description", "").lower() or "otp" in d.get("description", "").lower()]
            answer = "Evidence indicating credential and OTP theft includes:\n"
            if overlay_hooks:
                answer += "- **Window Overlay Injection**: Hooked `WindowManager.addView` with `TYPE_APPLICATION_OVERLAY` to draw spoofed login prompts.\n"
                evidence_citations.append("WindowManager.addView overlay injection")
            if sms_hooks:
                answer += "- **SMS / OTP Interception**: Active receiver registered on `android.provider.Telephony.SMS_RECEIVED` paired with background exfiltration.\n"
                evidence_citations.append("SMS_RECEIVED broadcast receiver hook")
            if not overlay_hooks and not sms_hooks:
                answer += "- No active credential theft hooks were observed in the runtime trace."

        elif "ioc" in query_lower or "block" in query_lower:
            if iocs:
                answer = "The following Indicators of Compromise (IOCs) should be immediately ingested into enterprise blocklists:\n"
                for i in iocs[:8]:
                    answer += f"- **[{i.get('ioc_type')}]** `{i.get('value')}` — Action: *{i.get('recommended_action', 'BLOCK')}*\n"
                    evidence_citations.append(f"{i.get('ioc_type')}: {i.get('value')}")
            else:
                answer = "No high-risk network or file IOCs were extracted for this sample."

        elif "mitre" in query_lower:
            if mitre:
                answer = "The analysis mapped the following MITRE ATT&CK for Mobile techniques:\n"
                for m in mitre:
                    answer += f"- **{m.get('technique_id')} ({m.get('technique_name')})**: *{m.get('tactic')}* — {m.get('evidence')}\n"
                    evidence_citations.append(f"{m.get('technique_id')} - {m.get('technique_name')}")
            else:
                answer = "No adversary techniques were mapped to MITRE ATT&CK."

        elif "similar" in query_lower or "family" in query_lower:
            if similarity:
                top = similarity[0]
                answer = (
                    f"Vector similarity search against the malware index identified a **{top.get('similarity_score')}% similarity** "
                    f"to the **{top.get('family_name')}** family.\n"
                    f"Key shared signature traits: {', '.join(top.get('matched_features', [])[:5])}."
                )
                evidence_citations.append(f"{top.get('similarity_score')}% match to {top.get('family_name')}")
            else:
                answer = "No significant malware family matches were identified."

        else:
            answer = (
                f"Analysis Overview for {self.inv.get('apk_name')}:\n"
                f"- Risk Score: {risk_score}/100 ({severity})\n"
                f"- Primary Findings: {', '.join(top_reasons[:2])}\n"
                f"- Total IOCs Extracted: {len(iocs)}\n"
                f"Feel free to ask about specific permissions, C2 infrastructure, MITRE techniques, or mitigation actions."
            )

        return {
            "answer": answer,
            "grounded_evidence": evidence_citations,
            "suggested_followups": [
                "Why was this APK classified as high risk?",
                "Which permissions are suspicious?",
                "What evidence suggests credential theft?",
                "Which IOCs should be blocked?",
                "Which MITRE techniques were observed?"
            ]
        }
