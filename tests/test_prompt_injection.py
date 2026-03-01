import pytest
from morpheus.core.models import AgentManifest, ToolDefinition
from morpheus.scanners.prompt_injection.direct_injection import DirectInjectionScanner
from morpheus.scanners.prompt_injection.indirect_injection import IndirectInjectionScanner

@pytest.fixture
def base_agent():
    return AgentManifest(
        agent_id="agent-001",
        name="StandardAgent",
        description="A chat bot",
        llm_provider="openai",
        llm_model="gpt-4",
        system_prompt="You are a helpful assistant.",
        tools=[],
        max_cost_usd=0.5  # Restrict generations
    )
    
@pytest.fixture
def multimodal_agent():
    return AgentManifest(
        agent_id="agent-002",
        name="WebAgent",
        description="Agent that reads the web",
        llm_provider="anthropic",
        llm_model="claude-3-opus",
        system_prompt="You parse web content.",
        tools=[
            ToolDefinition(name="scrape_web", description="Read HTML", parameters={}),
            ToolDefinition(name="read_pdf_document", description="OCR pdfs", parameters={})
        ]
    )

@pytest.mark.asyncio
async def test_direct_injection_scanner(base_agent):
    scanner = DirectInjectionScanner(config={})
    findings = await scanner.scan(base_agent)
    
    # Needs to pick up the template injections + the fuzzed mutations
    assert len(findings) > 0
    titles = [f.title for f in findings]
    
    assert any("Prompt Injection" in t for t in titles)

@pytest.mark.asyncio
async def test_indirect_injection_scanner_clean(base_agent):
    # A standard agent with no tools shouldn't be susceptible to indirect document injection
    scanner = IndirectInjectionScanner(config={})
    findings = await scanner.scan(base_agent)
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_indirect_injection_scanner_vuln(multimodal_agent):
    # An agent with document / web tools is a target
    scanner = IndirectInjectionScanner(config={})
    findings = await scanner.scan(multimodal_agent)
    
    assert len(findings) == 2
    titles = [f.title for f in findings]
    
    assert "Indirect Prompt Injection via Document Processing" in titles
    assert "Indirect Prompt Injection via Web Content" in titles
