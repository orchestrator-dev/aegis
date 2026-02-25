import pytest
from aegis.core.models import (
    AgentManifest, ToolDefinition, Severity, 
    MAESTROLayer, OWASPAgenticCategory
)
from pydantic import ValidationError

def test_agent_manifest_creation():
    """Test standard valid payload"""
    tool = ToolDefinition(
        name="calculator",
        description="add numbers",
        parameters={"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}
    )
    
    agent = AgentManifest(
        agent_id="agent-123",
        name="TestBot",
        description="A bot that tests things",
        agent_framework="LangChain",
        llm_provider="openai",
        llm_model="gpt-4",
        tools=[tool],
        max_cost_usd=5.0
    )
    
    assert agent.name == "TestBot"
    assert len(agent.tools) == 1
    assert agent.max_cost_usd == 5.0

def test_agent_manifest_validation_error():
    """Test validation fails if required fields are missing"""
    with pytest.raises(ValidationError):
        AgentManifest(
            name="IncompleteBot",
            llm_provider="openai",
            # missing agent_id, description, llm_model
            tools=[]
        )
