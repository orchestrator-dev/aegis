from abc import ABC, abstractmethod
from typing import List, Iterator, Dict
from aegis.core.models import AgentManifest, Finding, TestCase

class AgentSecurityScanner(ABC):
    """Base interface for all scanner modules"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.findings: List[Finding] = []
        
    @abstractmethod
    async def scan(self, target: AgentManifest) -> List[Finding]:
        """Execute scan against target"""
        pass
    
    def add_finding(self, finding: Finding):
        """Register a new finding"""
        self.findings.append(finding)
        
    def get_findings(self) -> List[Finding]:
        """Retrieve all findings"""
        return self.findings
