from typing import Any

from backend.app.core.config import settings


class ExplainableRiskEngine:
    """
    Computes an explainable, evidence-grounded risk score (0-100)
    with rigorous breakdown of category weights, raw points, and explicit audit trails.
    """

    def __init__(self, static_data: dict[str, Any], dynamic_data: dict[str, Any], network_data: dict[str, Any],
                 threat_intel_data: dict[str, Any], similarity_data: list[dict[str, Any]], mitre_data: list[dict[str, Any]],
                 custom_weights: dict[str, float] | None = None):
        self.static_data = static_data or {}
        self.dynamic_data = dynamic_data or {}
        self.network_data = network_data or {}
        self.threat_intel_data = threat_intel_data or {}
        self.similarity_data = similarity_data or []
        self.mitre_data = mitre_data or []
        self.weights = custom_weights or settings.DEFAULT_RISK_WEIGHTS

    def evaluate(self) -> dict[str, Any]:
        components: list[dict[str, Any]] = []

        # 1. Suspicious Permissions Score (0 - 100)
        perm_score, perm_evidence = self._calc_permissions_score()
        components.append(self._build_component("suspicious_permissions", perm_score, "Suspicious & Privileged Permissions", perm_evidence))

        # 2. Dangerous API Usage Score
        api_score, api_evidence = self._calc_api_score()
        components.append(self._build_component("dangerous_api_usage", api_score, "Dangerous System API Usage", api_evidence))

        # 3. Obfuscation & Dynamic Loading
        obf_score, obf_evidence = self._calc_obfuscation_score()
        components.append(self._build_component("obfuscation_indicators", obf_score, "Obfuscation & Evasion Indicators", obf_evidence))

        # 4. Malicious URLs & C2 Network Activity
        net_score, net_evidence = self._calc_network_score()
        components.append(self._build_component("malicious_urls_c2", net_score, "C2 & Malicious Network Traffic", net_evidence))

        # 5. Dynamic Runtime Behavior
        dyn_score, dyn_evidence = self._calc_dynamic_score()
        components.append(self._build_component("dynamic_behavior", dyn_score, "Runtime Suspicious Behaviors", dyn_evidence))

        # 6. External Threat Intelligence
        intel_score, intel_evidence = self._calc_intel_score()
        components.append(self._build_component("threat_intelligence", intel_score, "Threat Intelligence Reputation", intel_evidence))

        # 7. Malware Family Similarity
        sim_score, sim_evidence = self._calc_similarity_score()
        components.append(self._build_component("malware_similarity", sim_score, "Malware Family Signature Match", sim_evidence))

        # 8. MITRE ATT&CK Mapping Severity
        mitre_score, mitre_evidence = self._calc_mitre_score()
        components.append(self._build_component("mitre_techniques", mitre_score, "MITRE ATT&CK Mobile Tactics", mitre_evidence))

        # Calculate Total Weighted Score
        total_score = sum(c["weighted_contribution"] for c in components)
        total_score = min(100.0, max(0.0, round(total_score, 1)))

        # Severity Classification
        if total_score >= 75.0:
            severity = "CRITICAL"
        elif total_score >= 50.0:
            severity = "HIGH"
        elif total_score >= 25.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Formulate Top Reasons
        top_reasons = []
        sorted_comps = sorted(components, key=lambda x: x["weighted_contribution"], reverse=True)
        for comp in sorted_comps:
            if comp["raw_score"] > 20 and comp["evidence_items"]:
                top_reasons.append(f"{comp['category_label']}: {comp['evidence_items'][0]}")

        if not top_reasons:
            top_reasons = ["No significant malicious behavioral indicators or abnormal permissions detected."]

        confidence = 0.95 if not settings.DEMO_MODE else 0.90
        limitations = "Analysis was performed in an isolated sandbox with static heuristic extraction. Dynamic instrumentation utilized simulated replay adapter."

        return {
            "total_score": total_score,
            "severity": severity,
            "confidence": confidence,
            "limitations": limitations,
            "top_reasons": top_reasons[:4],
            "components": components
        }

    def _build_component(self, key: str, raw_score: float, label: str, evidence: list[str]) -> dict[str, Any]:
        weight = self.weights.get(key, 0.10)
        contribution = round((raw_score * weight), 2)
        return {
            "category": key,
            "category_label": label,
            "weight": weight,
            "raw_score": raw_score,
            "weighted_contribution": contribution,
            "reasoning": f"Derived from {len(evidence)} verified findings.",
            "evidence_count": len(evidence),
            "evidence_items": evidence
        }

    def _calc_permissions_score(self) -> tuple[float, list[str]]:
        findings = self.static_data.get("permission_findings", [])
        evidence = []
        score = 0
        for f in findings:
            if f.get("severity") == "CRITICAL":
                score += 35
                evidence.append(f"Critical Permission: {f.get('permission')} ({f.get('description')})")
            elif f.get("severity") == "HIGH":
                score += 20
                evidence.append(f"High-Risk Permission: {f.get('permission')} ({f.get('description')})")
            elif f.get("severity") == "MEDIUM":
                score += 10
        return min(100.0, score), evidence

    def _calc_api_score(self) -> tuple[float, list[str]]:
        fraud_rules = self.static_data.get("fraud_heuristics", [])
        evidence = []
        score = 0
        for r in fraud_rules:
            if r.get("severity") == "CRITICAL":
                score += 45
                evidence.append(f"Fraud Rule Hit: {r.get('title')}")
            elif r.get("severity") == "HIGH":
                score += 30
                evidence.append(f"Fraud Rule Hit: {r.get('title')}")
        return min(100.0, score), evidence

    def _calc_obfuscation_score(self) -> tuple[float, list[str]]:
        obfs = self.static_data.get("obfuscation_indicators", [])
        evidence = []
        score = 0
        for o in obfs:
            if o.get("severity") == "HIGH":
                score += 40
                evidence.append(f"Obfuscation: {o.get('evidence')} ({o.get('type')})")
            elif o.get("severity") == "MEDIUM":
                score += 25
                evidence.append(f"Obfuscation: {o.get('evidence')}")
        return min(100.0, score), evidence

    def _calc_network_score(self) -> tuple[float, list[str]]:
        net = self.network_data
        evidence = []
        score = 0
        if net.get("c2_detected"):
            score += 50
            evidence.append("Command & Control (C2) server communication infrastructure detected.")
        if net.get("phishing_detected"):
            score += 35
            evidence.append("Phishing domain / Financial brand impersonation endpoint verified.")
        if net.get("exfiltration_indicators"):
            score += 30
            evidence.append(f"Exfiltration channels observed: {', '.join(set(net['exfiltration_indicators']))}")
        return min(100.0, score), evidence

    def _calc_dynamic_score(self) -> tuple[float, list[str]]:
        dyn = self.dynamic_data
        evidence = []
        score = 0
        sensitive_calls = dyn.get("sensitive_api_calls", [])
        for call in sensitive_calls:
            if call.get("severity") == "CRITICAL":
                score += 30
                evidence.append(f"Runtime Hook: {call.get('api_class')}.{call.get('method')} - {call.get('description')}")
            elif call.get("severity") == "HIGH":
                score += 20
                evidence.append(f"Runtime Hook: {call.get('api_class')}.{call.get('method')}")
        return min(100.0, score), evidence

    def _calc_intel_score(self) -> tuple[float, list[str]]:
        intel = self.threat_intel_data
        vt = intel.get("virustotal", {})
        abuse = intel.get("abuseipdb", {})
        evidence = []
        score = 0

        positives = vt.get("positives", 0)
        if positives > 10:
            score += 70
            evidence.append(f"VirusTotal: {positives} security vendors flagged this APK as malicious.")
        elif positives > 0:
            score += 30
            evidence.append(f"VirusTotal: {positives} vendors flagged APK.")

        abuse_score = abuse.get("abuse_confidence_score", 0)
        if abuse_score > 50:
            score += 30
            evidence.append(f"AbuseIPDB: C2 IP {abuse.get('ip')} has {abuse_score}% abuse confidence rating.")

        return min(100.0, score), evidence

    def _calc_similarity_score(self) -> tuple[float, list[str]]:
        evidence = []
        if not self.similarity_data:
            return 0.0, evidence

        top_match = self.similarity_data[0]
        score = 0
        if top_match.get("category") != "BENIGN":
            sim = top_match.get("similarity_score", 0)
            score = sim
            evidence.append(f"{sim}% match to known malware family '{top_match.get('family_name')}'.")
        return min(100.0, score), evidence

    def _calc_mitre_score(self) -> tuple[float, list[str]]:
        evidence = []
        score = 0
        for tech in self.mitre_data:
            score += 15
            evidence.append(f"MITRE {tech.get('technique_id')}: {tech.get('technique_name')} ({tech.get('tactic')})")
        return min(100.0, score), evidence[:5]
