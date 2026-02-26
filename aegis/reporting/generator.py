import json
from datetime import datetime
from typing import List
from aegis.core.models import ScanResult, Finding
from aegis.reporting.ai_cvss import AICVSSScorer

class ReportGenerator:
    """Consumes ScanResults to generate security reports in various formats."""
    
    # ─── JSON ────────────────────────────────────────────────────────────────

    @staticmethod
    def generate_json(result: ScanResult) -> str:
        """Serialize result to a standard JSON format."""
        def dt_converter(o):
            if isinstance(o, datetime):
                return o.isoformat()

        data = {
            "scan_id": result.scan_id,
            "target": result.target.name,
            "overall_risk_score": result.overall_risk_score,
            "findings": [f.model_dump(mode='json') for f in result.findings]
        }
        return json.dumps(data, default=dt_converter, indent=2)

    # ─── Markdown ────────────────────────────────────────────────────────────

    @staticmethod
    def generate_markdown(result: ScanResult) -> str:
        """Format result as a human-readable Markdown Report."""
        md = [
            f"# Aegis Security Report: {result.target.name}",
            f"**Scan ID:** `{result.scan_id}`",
            f"**Overall Risk Score:** {result.overall_risk_score}/10.0",
            f"**Tests Executed:** {result.tests_run} ({result.tests_passed} Passed / {result.tests_failed} Failed)",
            "\n## Executive Summary",
            f"{result.executive_summary}",
            "\n## Findings"
        ]

        if not result.findings:
            md.append("\nNo vulnerabilities discovered.")
        else:
            for i, finding in enumerate(result.findings):
                cvss = AICVSSScorer.calculate_score(finding)
                md.append(f"\n### {i+1}. [{finding.severity.value}] {finding.title}")
                md.append(f"- **Finding ID:** `{finding.finding_id}`")
                md.append(f"- **AI-CVSS Score:** {cvss['score']} ({cvss['severity']})")
                md.append(f"- **Vector:** `{cvss['vector_string']}`")
                md.append(f"- **OWASP LLM:** {finding.owasp_llm.value if finding.owasp_llm else 'N/A'}")
                md.append(f"- **OWASP Agentic:** {finding.owasp_agentic.value if finding.owasp_agentic else 'N/A'}")
                md.append(f"- **Maestro Layer:** {finding.maestro_layer.value}")
                md.append(f"\n**Description:**\n{finding.description}")
                md.append(f"\n**Remediation:**\n{finding.remediation}")
                if finding.remediation_code_snippet:
                    md.append(f"\n```\n{finding.remediation_code_snippet}\n```")
                md.append("---")

        # OWASP coverage summary
        owasp_categories = set()
        for f in result.findings:
            if f.owasp_llm:     owasp_categories.add(f.owasp_llm.value)
            if f.owasp_agentic: owasp_categories.add(f.owasp_agentic.value)
        if owasp_categories:
            md.append("\n## OWASP Coverage")
            for cat in sorted(owasp_categories):
                md.append(f"- {cat}")

        return "\n".join(md)

    # ─── SARIF ───────────────────────────────────────────────────────────────

    @staticmethod
    def generate_sarif(result: ScanResult) -> str:
        """
        Generate SARIF 2.1.0 output for CI/CD integration.
        Compatible with GitHub Code Scanning / upload-sarif action.
        """
        rules = ReportGenerator._sarif_rules(result.findings)
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Aegis AI Security Scanner",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/your-org/aegis",
                            "rules": rules
                        }
                    },
                    "results": [
                        ReportGenerator._finding_to_sarif(f) for f in result.findings
                    ]
                }
            ]
        }
        return json.dumps(sarif, indent=2)

    @staticmethod
    def _sarif_rules(findings: List[Finding]) -> list:
        """Build the SARIF rules list from unique finding categories."""
        seen = set()
        rules = []
        for f in findings:
            rule_id = (f.owasp_agentic or f.owasp_llm)
            if rule_id is None:
                continue
            rid = rule_id.value
            if rid not in seen:
                seen.add(rid)
                rules.append({
                    "id": rid,
                    "shortDescription": {"text": rid},
                    "helpUri": f"https://owasp.org/llm/{rid}"
                })
        return rules

    @staticmethod
    def _finding_to_sarif(finding: Finding) -> dict:
        """Convert a Finding to a SARIF result object."""
        severity_map = {
            "CRITICAL": "error", "HIGH": "error",
            "MEDIUM": "warning", "LOW": "note", "INFO": "none"
        }
        rule_id = (finding.owasp_agentic or finding.owasp_llm)
        cvss = AICVSSScorer.calculate_score(finding)
        return {
            "ruleId": rule_id.value if rule_id else "AEGIS-GENERIC",
            "level": severity_map.get(finding.severity.value, "warning"),
            "message": {"text": finding.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.target_system}
                    }
                }
            ],
            "properties": {
                "owasp":         rule_id.value if rule_id else None,
                "maestro_layer": finding.maestro_layer.value,
                "ai_cvss_score": cvss["score"],
                "vector_string":  cvss["vector_string"],
                "remediation":   finding.remediation,
            }
        }

