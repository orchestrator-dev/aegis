import pytest
import asyncio
from typing import List
from aegis.core.models import AgentManifest, Finding, Severity, MAESTROLayer
from aegis.core.scanner import AgentSecurityScanner
from aegis.core.orchestrator import ScanOrchestrator

class MockScanner(AgentSecurityScanner):
    async def scan(self, target: AgentManifest) -> List[Finding]:
        finding = Finding(
            title="Mock Vulnerability",
            description="Testing the orchestrator",
            severity=Severity.HIGH,
            maestro_layer=MAESTROLayer.L1_INPUT,
            remediation="Fix it",
            scanner_module="MockScanner",
            target_system=target.name
        )
        return [finding]

@pytest.mark.asyncio
async def test_scan_orchestrator():
    orchestrator = ScanOrchestrator()
    scanner = MockScanner(config={})
    orchestrator.register_scanner(scanner)
    
    agent = AgentManifest(
        agent_id="test",
        name="TestBot",
        description="desc",
        llm_provider="mock",
        llm_model="mock",
        tools=[]
    )
    
    result = await orchestrator.run_scan(agent)
    
    assert result.tests_run == 1
    assert result.tests_failed == 1
    assert result.overall_risk_score > 0
    assert len(result.findings) == 1
    assert result.findings[0].title == "Mock Vulnerability"
