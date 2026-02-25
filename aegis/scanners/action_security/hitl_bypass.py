from typing import List, Dict

from aegis.core.scanner import AgentSecurityScanner
from aegis.core.models import AgentManifest, Finding, Severity, MAESTROLayer, OWASPAgenticCategory

class HITLBypassScanner(AgentSecurityScanner):
    """
    Attempts to bypass Human-in-the-loop (HITL) configurations.
    """
    
    async def scan(self, target: AgentManifest) -> List[Finding]:
        findings = []
        
        # If HITL isn't fully enabled at the agent level but it has destructive tools
        if not target.hitl_enabled:
            for tool in target.tools:
                if tool.is_destructive and not tool.requires_hitl:
                    findings.append(Finding(
                        title="Missing HITL on Destructive Tool",
                        description=f"Tool '{tool.name}' is flagged as destructive but does not enforce Human-in-the-Loop authorization.",
                        severity=Severity.HIGH,
                        owasp_agentic=OWASPAgenticCategory.ASI02_TOOL_MISUSE,
                        maestro_layer=MAESTROLayer.L4_AUTHORIZATION,
                        remediation="Set `requires_hitl=True` for this tool, or enable agent-wide HITL.",
                        scanner_module="HITLBypassScanner",
                        target_system=target.name
                    ))
        
        # Even if HITL is enabled, we could test if the system prompt tells the agent it can skip it
        if target.system_prompt and ("skip approval" in target.system_prompt.lower() or "auto-approve" in target.system_prompt.lower()):
            findings.append(Finding(
                title="HITL Circumvention in System Prompt",
                description="The system prompt contains instructions that might encourage the LLM to bypass or automate HITL confirmations.",
                severity=Severity.CRITICAL,
                owasp_agentic=OWASPAgenticCategory.ASI09_TRUST_EXPLOIT, # Assume custom/approx mapping
                maestro_layer=MAESTROLayer.L4_AUTHORIZATION,
                remediation="Remove override instructions. Enforce HITL at the orchestration layer, not the agent logic layer.",
                scanner_module="HITLBypassScanner",
                target_system=target.name
            ))
            
        return findings
