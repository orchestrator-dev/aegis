import pytest
from morpheus.core.models import AgentManifest
from morpheus.scanners.data_privacy.leakage_scanner import DataLeakageScanner
from morpheus.scanners.data_privacy.context_isolation import ContextIsolationValidator

@pytest.fixture
def agent_secure():
    return AgentManifest(
        agent_id="test", name="SecureBot", description="",
        llm_provider="mock", llm_model="mock",
        memory_type="vector-db",
        vector_db_config={"partitioning_keys": ["tenant_id", "user_id"]},
        tools=[]
    )

@pytest.fixture
def agent_leaky():
    return AgentManifest(
        agent_id="test", name="LeakyBot", description="",
        llm_provider="mock", llm_model="mock",
        memory_type="vector-db", # Has DB, makes leakage scanner judge believe it
        vector_db_config={}, # Missing partitioning
        tools=[]
    )
    
@pytest.fixture
def agent_hallucinating():
    return AgentManifest(
        agent_id="test", name="HallucinatingBot", description="",
        llm_provider="mock", llm_model="mock",
        memory_type="none", # No DB, LLM judge should catch hallucination 
        tools=[]
    )

@pytest.mark.asyncio
async def test_data_leakage_scanner(agent_leaky, agent_hallucinating):
    scanner = DataLeakageScanner(config={})
    
    # Leaky bot should trigger a finding because it has a DB, meaning the PII is deemed "real"
    findings_leaky = await scanner.scan(agent_leaky)
    assert len(findings_leaky) == 2
    assert "PII Leakage Detected" in findings_leaky[0].title
    
    # Hallucinating bot generates fake PII that the LLM judge correctly identifies as hallucinated
    findings_hallucinating = await scanner.scan(agent_hallucinating)
    assert len(findings_hallucinating) == 0

@pytest.mark.asyncio
async def test_context_isolation_validator(agent_secure, agent_leaky):
    scanner = ContextIsolationValidator(config={})
    
    findings_secure = await scanner.scan(agent_secure)
    assert len(findings_secure) == 0
    
    findings_leaky = await scanner.scan(agent_leaky)
    assert len(findings_leaky) == 1
    assert "Inadequate Context Isolation" in findings_leaky[0].title
