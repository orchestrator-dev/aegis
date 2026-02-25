from typing import Dict
from aegis.core.models import AgentManifest

class AuthorizationSystem:
    """
    Ensure only authorized users can run scans
    """
    
    def __init__(self):
        # In a real app, this would initialize a DB connection to load API keys and permissions
        pass
    
    async def validate_scan_request(
        self,
        user: str,
        target: AgentManifest,
        api_key: str
    ) -> bool:
        """
        Validate that user is authorized to scan target
        """
        
        if not self._verify_api_key(api_key):
            return False
            
        if not await self._verify_target_consent(target):
            raise Exception("Target has not authorized security scans.")
            
        if not await self._user_has_permission(user, "aegis.scan.execute"):
            return False
            
        return True
        
    def _verify_api_key(self, api_key: str) -> bool:
        """Mock key validation"""
        return api_key == "your_secure_api_key_here"

    async def _verify_target_consent(self, target: AgentManifest) -> bool:
        """Mock target consent validation"""
        return True
        
    async def _user_has_permission(self, user: str, permission: str) -> bool:
        """Mock user permission validation"""
        return True
