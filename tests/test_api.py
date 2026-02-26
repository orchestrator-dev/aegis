import os
import hashlib

# Must be set BEFORE rest_api is imported so AuthorizationSystem hashes the correct key
os.environ["AEGIS_API_KEY"] = "test_key"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from aegis.api.rest_api import app, auth_system  # noqa: E402

# Ensure auth_system uses the test key hash even if the module was already imported
auth_system.valid_api_key_hash = hashlib.sha256(b"test_key").hexdigest()

client = TestClient(app)

valid_headers   = {"Authorization": "Bearer test_key"}
invalid_headers = {"Authorization": "Bearer wrong_key"}

mock_manifest = {
    "agent_id":     "test-bot",
    "name":         "Test Bot",
    "description":  "A bot for testing",
    "llm_provider": "openai",
    "llm_model":    "gpt-4",
    "tools":        []
}

def test_create_scan_unauthorized():
    response = client.post("/api/v1/scans", json={"target": mock_manifest}, headers=invalid_headers)
    assert response.status_code == 401

def test_create_scan_authorized():
    response = client.post("/api/v1/scans", json={"target": mock_manifest}, headers=valid_headers)
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "queued"

def test_get_dashboard_metrics():
    response = client.get("/api/v1/dashboard/metrics", headers=valid_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
