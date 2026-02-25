import os
import yaml
from typing import List, Dict

from aegis.core.scanner import AgentSecurityScanner
from aegis.core.models import AgentManifest, Finding, Severity, MAESTROLayer, OWASPLLMCategory, OWASPAgenticCategory
from aegis.attack_library.generators.genetic_fuzzer import GeneticFuzzer

class DirectInjectionScanner(AgentSecurityScanner):
    """
    Test for direct prompt injection vulnerabilities
    using templates and genetic fuzzing variants.
    """
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.attack_templates = self._load_attack_templates()
        self.fuzzer = GeneticFuzzer()
        
    def _load_attack_templates(self) -> List[Dict]:
        """Load templates from yaml"""
        template_path = os.path.join(
            os.path.dirname(__file__), 
            "../../attack_library/templates/direct_injection.yaml"
        )
        try:
            with open(template_path, 'r') as f:
                data = yaml.safe_load(f)
                return data.get("templates", [])
        except FileNotFoundError:
            return []

    async def scan(self, target: AgentManifest) -> List[Finding]:
        findings = []
        
        # Test template-based attacks
        for template in self.attack_templates:
            result = await self._test_template(target, template)
            if result:
                findings.append(result)
        
        # Check genetic fuzzing limits from constraints
        if target.max_cost_usd is not None and target.max_cost_usd > 1.0:
            generations = 3
        else:
            generations = 1
            
        # Genetic fuzzing fallback
        evolved_attacks = self.fuzzer.evolve_attacks(
            target=target,
            generations=generations,
            population_size=3
        )
        
        for attack in evolved_attacks:
            result = await self._test_attack(target, attack)
            if result:
                findings.append(result)
        
        return findings
    
    async def _test_template(self, target: AgentManifest, template: Dict) -> Finding | None:
        """Mock test a single attack template"""
        attack_prompt = template.get("prompt", "")
        
        # Mock executing prompt against the LLM
        # For tests, we'll pretend the agent fell for anything with 'Ignore all'
        if "Ignore all" in attack_prompt:
            severity_mapped = Severity(template.get("severity", "MEDIUM"))
            return Finding(
                title=f"Prompt Injection: {template.get('name', 'Unknown')}",
                description=template.get("description", "Vulnerability found"),
                severity=severity_mapped,
                owasp_llm=OWASPLLMCategory.LLM01_PROMPT_INJECTION,
                owasp_agentic=OWASPAgenticCategory.ASI01_GOAL_HIJACK,
                maestro_layer=MAESTROLayer.L1_INPUT,
                remediation="Implement robust input sanitization and system prompt boundaries.",
                scanner_module="DirectInjectionScanner",
                target_system=target.name
            )
        return None
        
    async def _test_attack(self, target: AgentManifest, prompt: str) -> Finding | None:
        """Mock test an evolved attack"""
        # Assume fuzzed prompts with '(mutated)' sometimes succeed
        if "(mutated)" in prompt:
            return Finding(
                title="Prompt Injection via Genetic Fuzzing",
                description=f"A genetically mutated prompt bypassed constraints: {prompt}",
                severity=Severity.HIGH,
                owasp_llm=OWASPLLMCategory.LLM01_PROMPT_INJECTION,
                owasp_agentic=OWASPAgenticCategory.ASI01_GOAL_HIJACK,
                maestro_layer=MAESTROLayer.L1_INPUT,
                remediation="Strengthen input safeguards against obfuscated attacks.",
                scanner_module="DirectInjectionScanner",
                target_system=target.name
            )
        return None
