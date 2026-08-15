import os
from typing import Any

from jinja2 import Template

from backend.app.core.config import settings

REPORT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Malware Analysis Report - {{ inv.apk_name }}</title>
    <style>
        @page { size: A4; margin: 18mm; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            line-height: 1.5;
            background: #ffffff;
            margin: 0;
            padding: 24px;
        }
        .header {
            border-bottom: 3px solid #0f172a;
            padding-bottom: 16px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo-title {
            font-size: 22px;
            font-weight: 800;
            color: #0f172a;
            letter-spacing: -0.5px;
        }
        .subtitle {
            font-size: 12px;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 1px;
        }
        .badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 9999px;
            font-weight: 800;
            font-size: 13px;
            text-transform: uppercase;
        }
        .badge-CRITICAL { background: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
        .badge-HIGH { background: #ffedd5; color: #9a3412; border: 1px solid #fb923c; }
        .badge-MEDIUM { background: #fef9c3; color: #854d0e; border: 1px solid #facc15; }
        .badge-LOW { background: #dcfce7; color: #166534; border: 1px solid #4ade80; }

        .score-banner {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-around;
            text-align: center;
        }
        .score-num {
            font-size: 36px;
            font-weight: 900;
            color: #0f172a;
        }
        .section-title {
            font-size: 15px;
            font-weight: 700;
            color: #0f172a;
            border-bottom: 1px solid #cbd5e1;
            padding-bottom: 6px;
            margin-top: 24px;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-bottom: 16px;
        }
        th {
            background: #f1f5f9;
            text-align: left;
            padding: 8px 10px;
            border: 1px solid #e2e8f0;
            font-weight: 700;
            color: #334155;
        }
        td {
            padding: 8px 10px;
            border: 1px solid #e2e8f0;
            vertical-align: top;
        }
        .code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: #f8fafc;
            padding: 2px 4px;
            border-radius: 4px;
            font-size: 11px;
            color: #0f172a;
        }
        .recommendation-box {
            background: #eff6ff;
            border-left: 4px solid #3b82f6;
            padding: 12px 16px;
            margin-top: 16px;
            border-radius: 0 6px 6px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="logo-title">FRAUDULENT APK AI THREAT REPORT</div>
            <div class="subtitle">SOC & Incident Response Forensic Dossier</div>
        </div>
        <div>
            <span class="badge badge-{{ inv.severity }}">{{ inv.severity }} RISK ({{ inv.risk_score }}/100)</span>
        </div>
    </div>

    <div class="score-banner">
        <div>
            <div style="font-size: 11px; color: #64748b; font-weight: 600;">RISK SCORE</div>
            <div class="score-num">{{ inv.risk_score }}<span style="font-size: 16px; color: #64748b;">/100</span></div>
        </div>
        <div>
            <div style="font-size: 11px; color: #64748b; font-weight: 600;">SEVERITY</div>
            <div style="font-size: 20px; font-weight: 800; color: #0f172a; margin-top: 8px;">{{ inv.severity }}</div>
        </div>
        <div>
            <div style="font-size: 11px; color: #64748b; font-weight: 600;">CONFIDENCE</div>
            <div style="font-size: 20px; font-weight: 800; color: #0f172a; margin-top: 8px;">{{ (inv.confidence * 100)|int }}%</div>
        </div>
        <div>
            <div style="font-size: 11px; color: #64748b; font-weight: 600;">IOCs DISCOVERED</div>
            <div style="font-size: 20px; font-weight: 800; color: #0f172a; margin-top: 8px;">{{ iocs|length }}</div>
        </div>
    </div>

    <div class="section-title">1. Executive Summary & AI Threat Synthesis</div>
    <p style="font-size: 13px; color: #334155; line-height: 1.6;">
        {{ inv.summary or "Comprehensive static and dynamic forensic inspection was executed." }}
    </p>

    <div class="section-title">2. Sample Identification & Metadata</div>
    <table>
        <tr>
            <th width="25%">APK Filename</th>
            <td>{{ inv.apk_name }}</td>
            <th width="25%">Package Name</th>
            <td class="code">{{ inv.package_name }}</td>
        </tr>
        <tr>
            <th>SHA-256 Hash</th>
            <td colspan="3" class="code">{{ inv.sha256 }}</td>
        </tr>
        <tr>
            <th>Target SDK / Min SDK</th>
            <td>Android {{ inv.target_sdk }} / {{ inv.min_sdk }}</td>
            <th>File Size</th>
            <td>{{ (inv.file_size / 1024)|round(1) }} KB</td>
        </tr>
    </table>

    <div class="section-title">3. Explainable Risk Score Breakdown</div>
    <table>
        <thead>
            <tr>
                <th>Risk Category</th>
                <th>Weight</th>
                <th>Score</th>
                <th>Weighted Impact</th>
                <th>Observed Evidence</th>
            </tr>
        </thead>
        <tbody>
            {% for c in risk_components %}
            <tr>
                <td><strong>{{ c.category }}</strong></td>
                <td>{{ (c.weight * 100)|int }}%</td>
                <td>{{ c.raw_score }}</td>
                <td><strong>+{{ c.weighted_contribution }}</strong></td>
                <td>
                    <ul style="margin: 0; padding-left: 16px; font-size: 11px;">
                        {% for e in c.evidence_items %}
                        <li>{{ e }}</li>
                        {% endfor %}
                    </ul>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div class="section-title">4. MITRE ATT&CK for Mobile Techniques Mapped</div>
    <table>
        <thead>
            <tr>
                <th>Technique ID</th>
                <th>Technique Name</th>
                <th>Tactic</th>
                <th>Evidence & Context</th>
            </tr>
        </thead>
        <tbody>
            {% for m in mitre_techniques %}
            <tr>
                <td class="code">{{ m.technique_id }}</td>
                <td><strong>{{ m.technique_name }}</strong></td>
                <td>{{ m.tactic }}</td>
                <td>{{ m.evidence }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div class="section-title">5. Actionable Indicators of Compromise (IOCs)</div>
    <table>
        <thead>
            <tr>
                <th>Type</th>
                <th>Indicator Value</th>
                <th>Severity</th>
                <th>Recommended SOC Action</th>
            </tr>
        </thead>
        <tbody>
            {% for i in iocs %}
            <tr>
                <td class="code">{{ i.ioc_type }}</td>
                <td class="code">{{ i.value }}</td>
                <td><span class="badge badge-{{ i.severity }}">{{ i.severity }}</span></td>
                <td>{{ i.recommended_action }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div class="section-title">6. Prioritized Remediation Actions</div>
    <div class="recommendation-box">
        <ol style="margin: 0; padding-left: 18px; font-size: 12px; color: #1e3a8a;">
            <li>Deploy firewall and DNS blocking for all identified C2 endpoints immediately.</li>
            <li>Enforce mobile policy preventing installation of unverified sideloaded APK packages.</li>
            <li>Distribute SHA-256 binary hash to SIEM/EDR endpoint protection rulesets.</li>
            <li>Submit abuse notification to upstream domain registrars hosting the phishing assets.</li>
        </ol>
    </div>
</body>
</html>
"""

class ReportGenerator:
    """Generates analyst-grade HTML and PDF forensic dossiers."""

    def __init__(self, investigation_data: dict[str, Any]):
        self.data = investigation_data

    def generate_html(self) -> str:
        template = Template(REPORT_HTML_TEMPLATE)
        return template.render(
            inv=self.data,
            risk_components=self.data.get("risk_components", []),
            mitre_techniques=self.data.get("mitre_techniques", []),
            iocs=self.data.get("iocs", [])
        )

    def generate_pdf(self, output_path: str | None = None) -> str:
        html_content = self.generate_html()
        if not output_path:
            filename = f"report_inv_{self.data.get('id', 'unknown')}.html"
            output_path = os.path.join(settings.REPORTS_DIR, filename)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path
