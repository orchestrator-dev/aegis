import json
from datetime import datetime
from aegis.core.models import ScanResult
from aegis.reporting.ai_cvss import AICVSSScorer

class ReportGenerator:
    """Consumes ScanResults to generate security reports in various formats"""
    
    @staticmethod
    def generate_json(result: ScanResult) -> str:
        """Serialize result to a standard JSON format"""
        # Ensure datetimes are serialized correctly
        def dt_converter(o):
            if isinstance(o, datetime):
                return o.isoformat()
            
        # Manually construct dict instead of model_dump to handle serialization more smoothly in Phase 5
        data = {
            "scan_id": result.scan_id,
            "target": result.target.name,
            "overall_risk_score": result.overall_risk_score,
            "findings": [f.model_dump(mode='json') for f in result.findings]
        }
        return json.dumps(data, default=dt_converter, indent=2)
        
    @staticmethod
    def generate_markdown(result: ScanResult) -> str:
        """Format result as a human-readable Markdown Report"""
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
                ai_cvss = AICVSSScorer.calculate_score(finding)
                
                md.append(f"\n### {i+1}. [{finding.severity.value}] {finding.title}")
                md.append(f"- **Finding ID:** `{finding.finding_id}`")
                md.append(f"- **AI-CVSS Score:** {ai_cvss}")
                md.append(f"- **OWASP LLM:** {finding.owasp_llm.value if finding.owasp_llm else 'N/A'}")
                md.append(f"- **Maestro Layer:** {finding.maestro_layer.value}")
                md.append(f"\n**Description:**\n{finding.description}")
                md.append(f"\n**Remediation:**\n{finding.remediation}")
                md.append("---")
                
        return "\n".join(md)
