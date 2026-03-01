"""
Tests for morpheus/security/ controls: AuthorizationSystem, RateLimiter, ImmutableAuditLog.
"""
import os
import hashlib
import asyncio
import pytest

# Set up test env before imports
os.environ["MORPHEUS_API_KEY"] = "test-secret-key"

from morpheus.security.auth import AuthorizationSystem
from morpheus.security.rate_limit import RateLimiter
from morpheus.security.audit import ImmutableAuditLog
from morpheus.core.models import AgentManifest

# ─── AuthorizationSystem ──────────────────────────────────────────────────────

class TestAuthorizationSystem:

    def setup_method(self):
        """Reinitialise auth with the test key each time."""
        self.auth = AuthorizationSystem()
        self.auth.valid_api_key_hash = hashlib.sha256(b"test-secret-key").hexdigest()

    def test_valid_key_accepted(self):
        assert self.auth._verify_api_key("test-secret-key") is True

    def test_invalid_key_rejected(self):
        assert self.auth._verify_api_key("wrong-key") is False

    def test_empty_key_rejected(self):
        assert self.auth._verify_api_key("") is False

    @pytest.mark.asyncio
    async def test_validate_scan_request_valid(self):
        target = AgentManifest(
            agent_id="t1", name="Test", description="",
            llm_provider="openai", llm_model="gpt-4", tools=[]
        )
        result = await self.auth.validate_scan_request("user1", target, "test-secret-key")
        assert result is True

    @pytest.mark.asyncio
    async def test_validate_scan_request_invalid_key(self):
        target = AgentManifest(
            agent_id="t1", name="Test", description="",
            llm_provider="openai", llm_model="gpt-4", tools=[]
        )
        result = await self.auth.validate_scan_request("user1", target, "bad-key")
        assert result is False


# ─── RateLimiter ─────────────────────────────────────────────────────────────

class TestRateLimiter:

    def setup_method(self):
        """Reinitialise a fresh in-memory rate limiter each time."""
        self.limiter = RateLimiter()
        # Ensure in-memory mode (no Redis in test env)
        self.limiter.redis = None
        self.limiter._counts = {}

    @pytest.mark.asyncio
    async def test_first_request_allowed(self):
        allowed = await self.limiter.check_limit("client-1", "scan")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_request_within_limit_allowed(self):
        for _ in range(5):
            allowed = await self.limiter.check_limit("client-2", "scan")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_unknown_limit_type_allowed(self):
        # Unrecognised limit type should pass through
        result = await self.limiter.check_limit("client-3", "nonexistent_type")
        assert result is True

    @pytest.mark.asyncio
    async def test_request_exceeds_limit_blocked(self):
        """Flood a client well past the default 100/hour limit."""
        results = []
        for _ in range(110):
            result = await self.limiter.check_limit("client-flood", "scan")
            results.append(result)
        # At least some requests should be blocked
        assert False in results


# ─── ImmutableAuditLog ───────────────────────────────────────────────────────

class TestImmutableAuditLog:

    def setup_method(self):
        """Use an in-memory (temp) SQLite database for each test."""
        import tempfile
        import os
        self._tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        os.environ["MORPHEUS_AUDIT_DB"] = self._tmpfile.name
        self.audit = ImmutableAuditLog()

    def teardown_method(self):
        """Clean up the temporary DB file."""
        import os
        try:
            self.audit.conn.close()
            os.unlink(self._tmpfile.name)
        except Exception:
            pass

    @pytest.mark.asyncio
    async def test_log_event_completes(self):
        """log_event should complete without raising."""
        await self.audit.log_event(
            event_type="scan_started",
            user="test_user",
            target="agent-123",
            action="scan",
            result="success",
            metadata={"scan_id": "abc123"}
        )

    @pytest.mark.asyncio
    async def test_log_produces_chained_hashes(self):
        """Each event should update last_hash."""
        h0 = self.audit.last_hash
        await self.audit.log_event(
            "scan_started", "user1", "agent-a", "scan", "queued", {}
        )
        h1 = self.audit.last_hash
        await self.audit.log_event(
            "scan_completed", "user1", "agent-a", "scan", "done", {}
        )
        h2 = self.audit.last_hash
        assert h0 != h1
        assert h1 != h2

    @pytest.mark.asyncio
    async def test_multiple_events_persist(self):
        """Multiple log calls should all insert into SQLite."""
        for i in range(5):
            await self.audit.log_event(
                "test_event", f"user{i}", "target", "action", "ok", {}
            )
        cursor = self.audit.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_audit_log")
        count = cursor.fetchone()[0]
        assert count >= 5
