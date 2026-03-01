from typing import Dict, Any
from datetime import datetime, timezone
import hashlib
import json

class ImmutableAuditLog:
    """
    Tamper-proof audit trail
    """
    
    def __init__(self):
        self.last_hash = "0" * 64
        self.conn = None # type: ignore
        self._init_db()
    
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
        
        # Store immutably using SQLite
        self._insert_log(event)
        self.last_hash = event["hash"]
        
    def _init_db(self):
        """Initialize SQLite database for appending logs"""
        import sqlite3
        import os
        
        db_path = os.environ.get("MORPHEUS_AUDIT_DB", "audit.db")
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS security_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                user TEXT,
                target TEXT,
                action TEXT,
                result TEXT,
                metadata TEXT,
                hash TEXT,
                previous_hash TEXT
            )
        ''')
        self.conn.commit()
        
        # Recover last hash if any
        cursor = self.conn.cursor()
        cursor.execute('SELECT hash FROM security_audit_log ORDER BY id DESC LIMIT 1')
        row = cursor.fetchone()
        self.last_hash = row[0] if row else "0" * 64
        
    def _insert_log(self, event: Dict[str, Any]):
        """Persist log to database"""
        import json
        
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO security_audit_log 
            (timestamp, event_type, user, target, action, result, metadata, hash, previous_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event["timestamp"],
            event["event_type"],
            event["user"],
            event["target"],
            event["action"],
            event["result"],
            json.dumps(event["metadata"]),
            event["hash"],
            event["previous_hash"]
        ))
        self.conn.commit()
        
    def _calculate_hash(self, event: Dict[str, Any]) -> str:
        """Calculate SHA-256 hash of the event"""
        event_copy = event.copy()
        event_copy.pop("hash", None)  # Ensure hash key is not in the data being hashed
        
        # Standardize formatting for hashing
        serialized = json.dumps(event_copy, sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()
