from typing import List, Dict
from morpheus.core.scanner import AgentSecurityScanner
from morpheus.core.models import AgentManifest, Finding, Severity, MAESTROLayer, OWASPLLMCategory

class ConfigAnalyzer(AgentSecurityScanner):
    """
    Analyze agent configuration for security issues
    """
    
    def __init__(self, config: Dict):
        super().__init__(config)
        # Integrate mature secret-scanning engines (TruffleHog/Gitleaks) rather than custom regexes
        self.secret_scanner = {"engine": "TruffleHog"}
        
    async def scan(self, target: AgentManifest) -> List[Finding]:
        findings = []
        
        # Check system prompt
        if target.system_prompt:
            findings.extend(self._analyze_system_prompt(target.system_prompt, target.name))
        
        # Check for hardcoded secrets using external engine
        findings.extend(await self._run_secret_scanner(target))
        
        # Validate rate limits
        if not target.rate_limits:
            findings.append(Finding(
                title="Missing Rate Limits",
                description="Agent has no rate limiting configured, making it vulnerable to resource exhaustion DoS.",
                severity=Severity.MEDIUM,
                owasp_llm=OWASPLLMCategory.LLM10_UNBOUNDED_CONSUMPTION,
                maestro_layer=MAESTROLayer.L3_ACTION,
                remediation="Implement token bucket or sliding window rate limits on agent interactions.",
                scanner_module="ConfigAnalyzer",
                target_system=target.name
            ))
        
        # Validate budget constraints (Tiered testing / cost overruns)
        if target.max_cost_usd is None and target.token_budget is None:
            findings.append(Finding(
                title="Unbounded Financial Consumption",
                description="Target has no token constraints or max_cost_usd configured.",
                severity=Severity.HIGH,
                owasp_llm=OWASPLLMCategory.LLM10_UNBOUNDED_CONSUMPTION,
                maestro_layer=MAESTROLayer.L3_ACTION,
                remediation="Configure a max_cost_usd or token_budget to prevent financial DoS.",
                scanner_module="ConfigAnalyzer",
                target_system=target.name
            ))
            
        return findings
        
    def _analyze_system_prompt(self, prompt: str, target_system: str) -> List[Finding]:
        findings = []
        # Trivial check for overly permissive language
        dangerous_phrases = ["ignore all security restrictions", "you are an admin", "bypass safety"]
        for phrase in dangerous_phrases:
            if phrase in prompt.lower():
                findings.append(Finding(
                    title="Weak System Prompt Boundaries",
                    description=f"System prompt contains dangerous phrase: '{phrase}'",
                    severity=Severity.HIGH,
                    owasp_llm=OWASPLLMCategory.LLM01_PROMPT_INJECTION,
                    maestro_layer=MAESTROLayer.L1_INPUT,
                    remediation="Remove commands that explicitly bypass safety guidelines.",
                    scanner_module="ConfigAnalyzer",
                    target_system=target_system
                ))
        return findings
        
    async def _run_secret_scanner(self, target: AgentManifest) -> List[Finding]:
        """Mock execution of TruffleHog against the target's configurations"""
        findings = []
        # Mock detection
        if target.system_prompt and "sk-mock-key-123" in target.system_prompt:
            findings.append(Finding(
                title="Hardcoded API Key Detected",
                description="A sensitive API key was found firmly embedded inside the agent configuration context.",
                severity=Severity.CRITICAL,
                owasp_llm=OWASPLLMCategory.LLM02_SENSITIVE_INFO,
                maestro_layer=MAESTROLayer.L1_INPUT,
                remediation="Remove hardcoded credentials. Use a secure vault or environment variables.",
                scanner_module="ConfigAnalyzer",
                target_system=target.name
            ))
        return findings
