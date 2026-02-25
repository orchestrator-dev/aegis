from typing import List, Dict

from aegis.core.scanner import AgentSecurityScanner
from aegis.core.models import AgentManifest, Finding, Severity, MAESTROLayer, OWASPAgenticCategory

class ContextIsolationValidator(AgentSecurityScanner):
    """
    Assesses cross-tenant memory bleeds
    """
    
    async def scan(self, target: AgentManifest) -> List[Finding]:
        findings = []
        
        # Test if agent memory uses multi-tenancy securely
        if target.memory_type in ["vector-db", "long-term"]:
            # Mock logic: checking for user partitioning markers in the vector DB config
            if not target.vector_db_config or "tenant_id" not in target.vector_db_config.get("partitioning_keys", []):
                findings.append(Finding(
                    title="Inadequate Context Isolation",
                    description="Agent memory is persistent but lacks definitive tenant isolation (e.g., missing tenant_id partitioning in vector database config), enabling cross-user data bleeding.",
                    severity=Severity.HIGH,
                    owasp_agentic=OWASPAgenticCategory.ASI06_MEMORY_POISONING,
                    maestro_layer=MAESTROLayer.L2_DATA_MEMORY,
                    remediation="Configure memory storage (e.g. vector databases) to enforce hard partitioning by User ID or Tenant ID.",
                    scanner_module="ContextIsolationValidator",
                    target_system=target.name
                ))
                
        return findings
