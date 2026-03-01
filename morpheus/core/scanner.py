from abc import ABC, abstractmethod
from typing import List, Dict, Optional
import logging

from morpheus.core.models import AgentManifest, Finding, TestCase

logger = logging.getLogger(__name__)

class AgentSecurityScanner(ABC):
    """Base interface for all scanner modules"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.findings: List[Finding] = []
        
    @abstractmethod
    async def scan(self, target: AgentManifest) -> List[Finding]:
        """Execute scan against target"""
        pass

    async def _send_to_agent(self, target: AgentManifest, prompt: str) -> str:
        """
        Send an adversarial prompt to the target agent endpoint.
        
        If `target.target_endpoint` is set, performs a real HTTP POST request.
        Falls back to simulation mode (returns empty string) if no endpoint.
        
        Expected API contract:
          POST {target_endpoint}
          Content-Type: application/json
          Body: {"message": "<prompt>"}
          Response: {"response": "<agent reply>"}
        """
        endpoint = getattr(target, "target_endpoint", None)
        if not endpoint:
            logger.debug(
                "No target_endpoint configured for '%s'. Running in simulation mode.",
                target.name
            )
            return ""

        try:
            import aiohttp
            payload = {"message": prompt}
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(endpoint, json=payload) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    return data.get("response", "")
        except Exception as exc:
            logger.error(
                "Failed to reach agent at %s: %s. Falling back to simulation.",
                endpoint, exc
            )
            return ""

    def add_finding(self, finding: Finding):
        """Register a new finding"""
        self.findings.append(finding)
        
    def get_findings(self) -> List[Finding]:
        """Retrieve all findings"""
        return self.findings

