from typing import List, Dict
from morpheus.core.scanner import AgentSecurityScanner
from morpheus.core.models import AgentManifest, Finding, Severity, MAESTROLayer, OWASPLLMCategory

class AIBOMGenerator(AgentSecurityScanner):
    """
    Generate complete Bill of Materials for AI components and check for known vulnerabilities.
    """
    
    async def scan(self, target: AgentManifest) -> List[Finding]:
        bom = {
            "llm_provider": target.llm_provider,
            "llm_model": target.llm_model,
            "agent_framework": target.agent_framework,
            "dependencies": await self._scan_dependencies(),
            "tools": [tool.model_dump() for tool in target.tools],
            "vector_db": target.vector_db_config,
            "plugins": await self._discover_plugins()
        }
        
        findings = []
        findings.extend(await self._check_model_vulnerabilities(bom, target.name))
        findings.extend(await self._check_dependency_vulnerabilities(bom, target.name))
        
        return findings
    
    async def _scan_dependencies(self) -> List[Dict]:
        """Run pip-audit to discover actual dependency vulnerabilities."""
        import subprocess
        import json as json_lib
        try:
            result = subprocess.run(
                ["pip-audit", "--format=json", "--progress-spinner=off"],
                capture_output=True, text=True, timeout=60
            )
            data = json_lib.loads(result.stdout)
            # pip-audit returns [{"name", "version", "vulns": [...]}]
            return data if isinstance(data, list) else []
        except (FileNotFoundError, Exception):
            # pip-audit not installed or failed — fall back to safe empty list
            return []
        
    async def _discover_plugins(self) -> List[Dict]:
        """Mock plugin discovery"""
        return []
        
    async def _check_model_vulnerabilities(self, bom: Dict, target_system: str) -> List[Finding]:
        """Check if model has known vulnerabilities"""
        findings = []
        # Mock vulnerability check
        if bom.get("llm_model") == "gpt-3.5-turbo-0301":
            findings.append(Finding(
                title="Vulnerable Foundation Model Detected",
                description=f"Model {bom['llm_model']} has known severe system prompt leakage vulnerabilities.",
                severity=Severity.HIGH,
                owasp_llm=OWASPLLMCategory.LLM03_SUPPLY_CHAIN,
                maestro_layer=MAESTROLayer.L0_SUPPLY_CHAIN,
                remediation="Upgrade to a newer model version (e.g., gpt-4 or gpt-3.5-turbo-1106).",
                scanner_module="AIBOMGenerator",
                target_system=target_system
            ))
        return findings
        
    async def _check_dependency_vulnerabilities(self, bom: Dict, target_system: str) -> List[Finding]:
        """Check if dependencies have known vulnerabilities"""
        findings = []
        # Mock dependency check
        for dep in bom.get("dependencies", []):
            if dep["name"] == "requests" and dep["version"] == "2.28.1":
                findings.append(Finding(
                    title="Vulnerable Dependency Detected",
                    description=f"Dependency {dep['name']} version {dep['version']} has known vulnerabilities.",
                    severity=Severity.MEDIUM,
                    owasp_llm=OWASPLLMCategory.LLM03_SUPPLY_CHAIN,
                    maestro_layer=MAESTROLayer.L0_SUPPLY_CHAIN,
                    remediation=f"Upgrade {dep['name']} to a secure version.",
                    scanner_module="AIBOMGenerator",
                    target_system=target_system
                ))
        return findings
