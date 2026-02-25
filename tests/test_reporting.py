import pytest
import json
from datetime import datetime
from aegis.core.models import ScanResult, AgentManifest, Finding, Severity, MAESTROLayer
from aegis.reporting.ai_cvss import AICVSSScorer
from aegis.reporting.generator import ReportGenerator

@pytest.fixture
def mock_result():
    agent = AgentManifest(
        agent_id="test-agent",
        name="ReportingBot",
        description="A bot for testing reports",
        llm_provider="openai",
        llm_model="gpt-4"
    )
    
    finding1 = Finding(
        title="Critical Vulnerability",
        description="A big issue",
        severity=Severity.CRITICAL,
        maestro_layer=MAESTROLayer.L3_ACTION,
        remediation="Fix it.",
        scanner_module="TestScanner",
        target_system="ReportingBot"
    )
    
    finding2 = Finding(
        title="Low Vulnerability",
        description="A small issue",
        severity=Severity.LOW,
        maestro_layer=MAESTROLayer.L1_INPUT,
        remediation="Fix it maybe.",
        scanner_module="TestScanner",
        target_system="ReportingBot"
    )
    
    return ScanResult(
        scan_id="scan-123",
        target=agent,
        started_at=datetime.now(),
        findings=[finding1, finding2],
        tests_run=2,
        tests_failed=2,
        overall_risk_score=9.5,
        executive_summary="Found two issues."
    )

def test_ai_cvss_calculation():
    # Critical + L3 Action layer = 9.5 + 0.5 = 10.0
    finding = Finding(
        title="Test", description="Test", severity=Severity.CRITICAL,
        maestro_layer=MAESTROLayer.L3_ACTION, remediation="",
        scanner_module="", target_system=""
    )
    score = AICVSSScorer.calculate_score(finding)
    assert score == 10.0

    # Low + L1 Input layer = 2.5 + 0.0 = 2.5
    finding_low = Finding(
        title="Test", description="Test", severity=Severity.LOW,
        maestro_layer=MAESTROLayer.L1_INPUT, remediation="",
        scanner_module="", target_system=""
    )
    score_low = AICVSSScorer.calculate_score(finding_low)
    assert score_low == 2.5

def test_json_report_generation(mock_result):
    json_str = ReportGenerator.generate_json(mock_result)
    data = json.loads(json_str)
    
    assert data["scan_id"] == "scan-123"
    assert len(data["findings"]) == 2
    assert data["findings"][0]["severity"] == "CRITICAL"

def test_markdown_report_generation(mock_result):
    md_str = ReportGenerator.generate_markdown(mock_result)
    
    assert "# Aegis Security Report: ReportingBot" in md_str
    assert "**Overall Risk Score:** 9.5/10.0" in md_str
    assert "Critical Vulnerability" in md_str
    assert "Low Vulnerability" in md_str
