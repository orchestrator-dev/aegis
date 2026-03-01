from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
import uuid
import datetime
import asyncio

from morpheus.core.models import AgentManifest, Finding, Severity
from morpheus.core.orchestrator import ScanOrchestrator
from morpheus.api.schemas import ScanRequest, ScanResponse, ScanResultDTO, DashboardMetrics
from morpheus.security.auth import AuthorizationSystem

app = FastAPI(title="Morpheus AI Security Scanner API", version="1.0.0")

# Setup CORS for the dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()
auth_system = AuthorizationSystem()

# In-memory store (production: replace with aiosqlite/SQLAlchemy)
_scan_results = {}
_dashboard_stats = {
    "total_scans": 0,
    "critical_findings": 0,
    "agents_scanned": set(),
    "risk_scores": []
}

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency: verify Bearer token against the configured MORPHEUS_API_KEY."""
    is_valid = auth_system._verify_api_key(credentials.credentials)  # sync method
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return credentials.credentials

@app.get("/api/v1/scans", tags=["Scans"])
async def list_scans(api_key: str = Depends(verify_api_key)):
    """List all scans and their current status."""
    return [
        {"scan_id": sid, "status": "completed", "target_name": r.target.name}
        for sid, r in _scan_results.items()
    ]

@app.post("/api/v1/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    scan_request: ScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """Create and queue a new security scan."""
    scan_id = str(uuid.uuid4())
    
    try:
        # Pydantic will validate the dict conforms to AgentManifest via **unpacking
        target = AgentManifest(**scan_request.target)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload format for AgentManifest: {e}")
    
    # In a real deployed app, this would use Celery or a background task queue.
    # We will use BackgroundTasks or just execute async natively since we test fast.
    # For MVP operationalization, we run inline to populate the mock DB, but wrap in a task.
    
    async def run_scan_bg():
        try:
            orchestrator = ScanOrchestrator()
            # Morpheus' orchestrator needs plugins loaded. Let's do a basic instantiation
            # In production, plugins would be discovery loaded.
            result = await orchestrator.run_scan(target)
            _scan_results[scan_id] = result
            
            # Update metrics
            _dashboard_stats["total_scans"] += 1
            _dashboard_stats["agents_scanned"].add(target.name)
            _dashboard_stats["risk_scores"].append(result.overall_risk_score)
            _dashboard_stats["critical_findings"] += len([f for f in result.findings if f.severity == Severity.CRITICAL])
            
        except Exception as e:
            import logging
            logging.error(f"Scan {scan_id} failed: {e}")

    # Kickoff the scan non-blocking
    asyncio.create_task(run_scan_bg())

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        started_at=datetime.datetime.now(datetime.timezone.utc)
    )

@app.get("/api/v1/scans/{scan_id}", response_model=ScanResultDTO, tags=["Scans"])
async def get_scan_results(scan_id: str, api_key: str = Depends(verify_api_key)):
    """Retrieve details of a completed scan."""
    if scan_id not in _scan_results:
        raise HTTPException(status_code=404, detail="Scan not found or still processing.")
        
    res = _scan_results[scan_id]
    return ScanResultDTO(
        scan_id=res.scan_id,
        target_name=res.target.name,
        started_at=res.started_at,
        completed_at=res.completed_at,
        findings=res.findings,
        tests_run=res.tests_run,
        tests_passed=res.tests_passed,
        tests_failed=res.tests_failed,
        overall_risk_score=res.overall_risk_score,
        executive_summary=res.executive_summary
    )

@app.get("/api/v1/scans/{scan_id}/findings", response_model=List[Finding], tags=["Scans"])
async def get_findings(
    scan_id: str,
    severity: Optional[Severity] = None,
    api_key: str = Depends(verify_api_key)
):
    """Get filtered findings for a scan."""
    if scan_id not in _scan_results:
        raise HTTPException(status_code=404, detail="Scan not found.")
        
    findings = _scan_results[scan_id].findings
    
    if severity:
        findings = [f for f in findings if f.severity == severity.value]
        
    return findings

@app.get("/api/v1/dashboard/metrics", response_model=DashboardMetrics, tags=["Dashboard"])
async def get_dashboard_metrics(api_key: str = Depends(verify_api_key)):
    """Get metrics for dashboard."""
    avg_score = 0.0
    if _dashboard_stats["risk_scores"]:
        avg_score = sum(_dashboard_stats["risk_scores"]) / len(_dashboard_stats["risk_scores"])
        
    return DashboardMetrics(
        total_scans=_dashboard_stats["total_scans"],
        critical_findings=_dashboard_stats["critical_findings"],
        agents_scanned=len(_dashboard_stats["agents_scanned"]),
        avg_risk_score=round(avg_score, 2),
        recent_scans=[] # We'd return recent scan IDs here in prod
    )
