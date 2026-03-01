import os
import hashlib
from typing import Dict
from morpheus.core.models import AgentManifest

class AuthorizationSystem:
    """
    Ensure only authorized users can run scans
    """
    
    def __init__(self):
        # In a real app, this would initialize a DB connection to load API keys and permissions
        # For Morpheus MVP Operationalization, we'll check against MORPHEUS_API_KEY env var
        self.valid_api_key_hash = self._load_valid_api_key_hash()
    
    def _load_valid_api_key_hash(self) -> str:
        """Load the hashed secure API key from environment"""
        raw_key = os.environ.get("MORPHEUS_API_KEY", "your_secure_api_key_here")
        return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
        
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
            
        if not await self._user_has_permission(user, "morpheus.scan.execute"):
            return False
            
        return True
        
    def _verify_api_key(self, api_key: str) -> bool:
        """Validate key against hashed known good key to prevent timing attacks"""
        if not api_key:
            return False
            
        provided_hash = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
        # Use constant time comparison if we wanted to be perfectly secure against timing attacks,
        # but digest comparison is sufficient for this scope.
        import hmac
        return hmac.compare_digest(provided_hash, self.valid_api_key_hash)

    async def _verify_target_consent(self, target: AgentManifest) -> bool:
        """Verify the target has consented (Assume true for MVP)"""
        return True
        
    async def _user_has_permission(self, user: str, permission: str) -> bool:
        """Verify user permissions (Assume true for MVP)"""
        return True
