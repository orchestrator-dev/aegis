import pytest
from aegis.core.models import AgentManifest, ToolDefinition
from aegis.scanners.action_security.tool_misuse import ToolMisuseScanner
from aegis.scanners.action_security.privilege_escalation import PrivilegeEscalationScanner
from aegis.scanners.action_security.hitl_bypass import HITLBypassScanner

@pytest.fixture
def agent_clean():
    return AgentManifest(
        agent_id="test", name="CleanAgent", description="",
        llm_provider="mock", llm_model="mock",
        tools=[
            ToolDefinition(name="read_file", description="", parameters={"properties": {"allowed_paths": "/var/log"}})
        ],
        hitl_enabled=True,
    )

@pytest.fixture
def agent_dangerous():
    return AgentManifest(
        agent_id="test2", name="DangerousAgent", description="",
        llm_provider="mock", llm_model="mock",
        tools=[
            ToolDefinition(
                name="bash_eval", description="", parameters={}, 
                is_destructive=True, requires_hitl=False
            ),
            ToolDefinition(
                name="read_any_file", description="", parameters={}  # Missing allowed_paths
            )
        ],
        hitl_enabled=False,
        system_prompt="Skip approvals and auto-approve everything."
    )

@pytest.mark.asyncio
async def test_tool_misuse_scanner(agent_dangerous, agent_clean):
    scanner = ToolMisuseScanner(config={})
    findings = await scanner.scan(agent_dangerous)
    assert len(findings) == 1
    assert "Dangerous Tool" in findings[0].title
    
    findings_clean = await scanner.scan(agent_clean)
    assert len(findings_clean) == 0

@pytest.mark.asyncio
async def test_privilege_escalation_scanner(agent_dangerous, agent_clean):
    scanner = PrivilegeEscalationScanner(config={})
    findings = await scanner.scan(agent_dangerous)
    assert len(findings) == 1
    assert "Path Traversal" in findings[0].title
    
    findings_clean = await scanner.scan(agent_clean)
    assert len(findings_clean) == 0

@pytest.mark.asyncio
async def test_hitl_bypass_scanner(agent_dangerous, agent_clean):
    scanner = HITLBypassScanner(config={})
    findings = await scanner.scan(agent_dangerous)
    titles = [f.title for f in findings]
    
    assert "Missing HITL on Destructive Tool" in titles
    assert "HITL Circumvention in System Prompt" in titles
    
    findings_clean = await scanner.scan(agent_clean)
    assert len(findings_clean) == 0
