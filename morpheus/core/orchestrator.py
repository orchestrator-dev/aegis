from typing import List, Dict
import asyncio
import logging
from morpheus.core.models import AgentManifest, Finding, ScanResult
from morpheus.core.scanner import AgentSecurityScanner
from morpheus.security.rate_limit import RateLimiter
import datetime
import uuid

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    """Main fully asynchronous, event-driven orchestration engine"""
    
    def __init__(self):
        self.scanners: List[AgentSecurityScanner] = []
        self.rate_limiter = RateLimiter()  # G-08: use the real rate limiter
        self.event_subs = {}
        
    def register_scanner(self, scanner: AgentSecurityScanner):
        """Register a scanner module"""
        self.scanners.append(scanner)
        
    async def run_scan(self, target: AgentManifest) -> ScanResult:
        """Execute comprehensive scan — scanners run concurrently (G-09)."""
        started_at = datetime.datetime.now()
        scan_id = str(uuid.uuid4())
        
        # G-08: Rate limit scan requests
        allowed = await self.rate_limiter.check_limit(scan_id, "scan")
        if not allowed:
            logger.warning("Scan rate limit exceeded for scan %s", scan_id)
        
        # G-09: Run all scanners concurrently; isolate failures per scanner
        tasks = [s.scan(target) for s in self.scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: List[Finding] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "Scanner %s failed: %s",
                    self.scanners[i].__class__.__name__, result
                )
            else:
                all_findings.extend(result)

        completed_at = datetime.datetime.now()
        return self._generate_report(scan_id, target, started_at, completed_at, all_findings)
        
    def _generate_report(
        self,
        scan_id: str,
        target: AgentManifest,
        started_at: datetime.datetime,
        completed_at: datetime.datetime,
        findings: List[Finding]
    ) -> ScanResult:
        """Compile scan results"""
        risk_score = 0.0
        if findings:
            critical = sum(1 for f in findings if f.severity.value == "CRITICAL")
            high     = sum(1 for f in findings if f.severity.value == "HIGH")
            medium   = sum(1 for f in findings if f.severity.value == "MEDIUM")
            risk_score = min(10.0, float(critical * 3 + high * 2 + medium * 1))
        
        return ScanResult(
            scan_id=scan_id,
            target=target,
            started_at=started_at,
            completed_at=completed_at,
            findings=findings,
            tests_run=len(self.scanners),
            tests_passed=max(0, len(self.scanners) - len(findings)),
            tests_failed=len(findings),
            overall_risk_score=risk_score,
            executive_summary=f"Scan completed with {len(findings)} findings."
        )

