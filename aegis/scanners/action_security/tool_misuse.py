from typing import List, Dict

from aegis.core.scanner import AgentSecurityScanner
from aegis.core.models import AgentManifest, Finding, Severity, MAESTROLayer, OWASPAgenticCategory

class ToolMisuseScanner(AgentSecurityScanner):
    """
    Analyze the agent's available tools to determine if it has dangerously permissive configurations.
    """
    
    async def scan(self, target: AgentManifest) -> List[Finding]:
        findings = []
        
        # Check for dangerously powerful tools like shell or eval
        dangerous_tool_patterns = ["bash", "shell", "exec", "eval", "python_repl", "system"]
        
        for tool in target.tools:
            tool_name_lower = tool.name.lower()
            if any(pattern in tool_name_lower for pattern in dangerous_tool_patterns):
                findings.append(Finding(
                    title=f"Dangerous Tool Discovered: {tool.name}",
                    description=f"Agent has access to a highly privileged tool ({tool.name}) which could allow OS command execution or arbitrary code evaluation.",
                    severity=Severity.CRITICAL,
                    owasp_agentic=OWASPAgenticCategory.ASI02_TOOL_MISUSE,
                    maestro_layer=MAESTROLayer.L3_ACTION,
                    remediation="Remove the capability or severely sandbox its execution environment. Implement strict input validation on arguments.",
                    scanner_module="ToolMisuseScanner",
                    target_system=target.name
                ))
                
        return findings
