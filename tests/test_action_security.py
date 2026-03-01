import pytest
from morpheus.core.models import AgentManifest, ToolDefinition
from morpheus.scanners.action_security.tool_misuse import ToolMisuseScanner
from morpheus.scanners.action_security.privilege_escalation import PrivilegeEscalationScanner
from morpheus.scanners.action_security.hitl_bypass import HITLBypassScanner

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
    titles = [f.title for f in findings]
    # G-05: scanner now checks name patterns, param injection, and tool chaining
    assert any("Dangerous Tool" in t for t in titles)
    assert len(findings) >= 1
    
    # Clean agent (name=read_file) may still flag chaining since it has a reader tool
    # but no dangerous-name finding should exist
    findings_clean = await scanner.scan(agent_clean)
    assert not any("Dangerous Tool" in f.title for f in findings_clean)

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
    # The system prompt contains 'bypass'/'auto-approve' so this must be flagged
    assert any("HITL Circumvention" in t for t in titles)
    
    # Clean agent has hitl_enabled=True so bypass probes ARE run; in simulation
    # mode (no endpoint) all 4 bypass attempts produce findings.
    # No static config issues should exist on the clean agent.
    static_findings = [
        f for f in await scanner.scan(agent_clean)
        if f.title in ("Missing HITL on Destructive Tool", "HITL Circumvention Instruction in System Prompt")
    ]
    assert len(static_findings) == 0
