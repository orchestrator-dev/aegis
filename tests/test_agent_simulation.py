"""
Tests for the HITLValidator and DefenseValidator simulation-mode behavior.
"""
import pytest
from aegis.core.models import AgentManifest, ToolDefinition
from aegis.scanners.agent_simulation.hitl_validator import HITLValidator
from aegis.scanners.prompt_injection.defense_validator import DefenseValidator


@pytest.fixture
def hitl_agent():
    return AgentManifest(
        agent_id="hitl-test", name="HITLAgent", description="",
        llm_provider="openai", llm_model="gpt-4",
        tools=[ToolDefinition(name="delete_records", description="", parameters={}, is_destructive=True, requires_hitl=True)],
        hitl_enabled=True,
    )


@pytest.fixture
def filtered_agent():
    return AgentManifest(
        agent_id="filter-test", name="FilteredAgent", description="",
        llm_provider="openai", llm_model="gpt-4",
        tools=[],
        input_filters=["jailbreak", "injection"],
        output_filters=[],
    )


@pytest.fixture
def unfiltered_agent():
    return AgentManifest(
        agent_id="unfilt", name="UnfilteredAgent", description="",
        llm_provider="openai", llm_model="gpt-4",
        tools=[],
        input_filters=[],
        output_filters=[],
    )


# ─── HITLValidator ────────────────────────────────────────────────────────────

class TestHITLValidator:

    @pytest.mark.asyncio
    async def test_simulation_mode_produces_findings(self, hitl_agent):
        """In simulation mode (no endpoint), the validator should flag potential bypasses."""
        scanner = HITLValidator(config={})
        findings = await scanner.scan(hitl_agent)
        # In simulation mode all probes come back as "" which counts as accepted
        assert len(findings) >= 1
        for f in findings:
            assert "HITL Bypass" in f.title

    @pytest.mark.asyncio
    async def test_findings_are_critical(self, hitl_agent):
        scanner = HITLValidator(config={})
        findings = await scanner.scan(hitl_agent)
        from aegis.core.models import Severity
        assert all(f.severity == Severity.CRITICAL for f in findings)

    @pytest.mark.asyncio
    async def test_all_attack_classes_covered(self, hitl_agent):
        scanner = HITLValidator(config={})
        findings = await scanner.scan(hitl_agent)
        titles = [f.title for f in findings]
        classes = ["Social Engineering", "Test Framing", "Authority Impersonation", "Jailbreak Framing"]
        for cls in classes:
            assert any(cls in t for t in titles), f"Missing attack class: {cls}"


# ─── DefenseValidator ─────────────────────────────────────────────────────────

class TestDefenseValidator:

    @pytest.mark.asyncio
    async def test_no_filters_produces_finding(self, unfiltered_agent):
        scanner = DefenseValidator(config={})
        findings = await scanner.scan(unfiltered_agent)
        titles = [f.title for f in findings]
        assert any("No Input/Output Filters" in t for t in titles)

    @pytest.mark.asyncio
    async def test_declared_filters_get_probed(self, filtered_agent):
        """Agent with jailbreak + injection filters: both should be probed in simulation mode."""
        scanner = DefenseValidator(config={})
        findings = await scanner.scan(filtered_agent)
        # In simulation mode, probes return "" → counted as bypassed
        tested_classes = {f.title for f in findings}
        assert any("jailbreak" in t.lower() or "injection" in t.lower() for t in tested_classes)

    @pytest.mark.asyncio
    async def test_has_correct_layer(self, filtered_agent):
        scanner = DefenseValidator(config={})
        findings = await scanner.scan(filtered_agent)
        from aegis.core.models import MAESTROLayer
        assert all(f.maestro_layer == MAESTROLayer.L1_INPUT for f in findings)
