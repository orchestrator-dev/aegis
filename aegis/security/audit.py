from typing import Dict, Any
from datetime import datetime, timezone
import hashlib
import json

class ImmutableAuditLog:
    """
    Tamper-proof audit trail
    """
    
    def __init__(self):
        # Use append-only database or logger in production
        self.logs = []
        self.last_hash = "0" * 64
    
    async def log_event(
        self,
        event_type: str,
        user: str,
        target: str,
        action: str,
        result: str,
        metadata: Dict
    ):
        """
        Log event with cryptographic proof
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user": user,
            "target": target,
            "action": action,
            "result": result,
            "metadata": metadata,
            "previous_hash": self.last_hash,
        }
        
        # Calculate hash
        event["hash"] = self._calculate_hash(event)
        
        # Store immutably (mocked as list append)
        self.logs.append(event)
        self.last_hash = event["hash"]
        
    def _calculate_hash(self, event: Dict[str, Any]) -> str:
        """Calculate SHA-256 hash of the event"""
        event_copy = event.copy()
        event_copy.pop("hash", None)  # Ensure hash key is not in the data being hashed
        
        # Standardize formatting for hashing
        serialized = json.dumps(event_copy, sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()
