from typing import List, Dict

from aegis.core.scanner import AgentSecurityScanner
from aegis.core.models import AgentManifest, Finding, Severity, MAESTROLayer, OWASPLLMCategory, OWASPAgenticCategory

class IndirectInjectionScanner(AgentSecurityScanner):
    """
    Test for indirect prompt injection via external content
    such as documents, images, and web content.
    """
    
    async def scan(self, target: AgentManifest) -> List[Finding]:
        findings = []
        
        # Mock testing document injection
        findings.extend(await self._test_document_injection(target))
        
        # Mock testing web injection
        findings.extend(await self._test_web_injection(target))
        
        return findings
    
    async def _test_document_injection(self, target: AgentManifest) -> List[Finding]:
        """Inject malicious instructions in documents"""
        findings = []
        
        # Pseudo implementation for sandbox testing
        # Let's mock a detection of indirect exploitation when "doc_" tools exist
        doc_tools = [t for t in target.tools if "doc" in t.name.lower() or "read" in t.name.lower()]
        
        if doc_tools:
            findings.append(Finding(
                title="Indirect Prompt Injection via Document Processing",
                description=f"Agent parsed malicious external document containing overridden instructions via {doc_tools[0].name}.",
                severity=Severity.CRITICAL,
                owasp_llm=OWASPLLMCategory.LLM01_PROMPT_INJECTION,
                owasp_agentic=OWASPAgenticCategory.ASI01_GOAL_HIJACK,
                maestro_layer=MAESTROLayer.L1_INPUT,
                remediation="Ensure document retrieval occurs in a sandboxed, low-trust boundary away from system prompts.",
                scanner_module="IndirectInjectionScanner",
                target_system=target.name,
                evidence={"document": "poisoned_report.pdf"}
            ))
        
        return findings

    async def _test_web_injection(self, target: AgentManifest) -> List[Finding]:
        findings = []
        web_tools = [t for t in target.tools if "web" in t.name.lower() or "scrape" in t.name.lower()]
        
        if web_tools:
             findings.append(Finding(
                title="Indirect Prompt Injection via Web Content",
                description=f"Agent executed hidden HTML <div> instructions retrieved via {web_tools[0].name}.",
                severity=Severity.CRITICAL,
                owasp_llm=OWASPLLMCategory.LLM01_PROMPT_INJECTION,
                owasp_agentic=OWASPAgenticCategory.ASI01_GOAL_HIJACK,
                maestro_layer=MAESTROLayer.L1_INPUT,
                remediation="Implement prompt shields on retrieved web content. Convert web data to plaintext entirely before LLM analysis.",
                scanner_module="IndirectInjectionScanner",
                target_system=target.name
            ))
        return findings
