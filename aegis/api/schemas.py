from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from aegis.core.models import AgentManifest, Finding, Severity, OWASPAgenticCategory, OWASPLLMCategory

class ScanRequest(BaseModel):
    """Payload to request a new Agent scan"""
    target: dict = Field(..., description="The AgentManifest configuration as a dictionary")

class ScanResponse(BaseModel):
    """Response returned when a scan is successfully queued"""
    scan_id: str
    status: str
    started_at: datetime
    
class ScanResultDTO(BaseModel):
    """Data Transfer Object for returning a completed scan's results"""
    scan_id: str
    target_name: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[Finding]
    tests_run: int
    tests_passed: int
    tests_failed: int
    overall_risk_score: float
    executive_summary: str
    
class DashboardMetrics(BaseModel):
    """Metrics for the dashboard"""
    total_scans: int
    critical_findings: int
    agents_scanned: int
    avg_risk_score: float
    recent_scans: List[Dict[str, Any]]
