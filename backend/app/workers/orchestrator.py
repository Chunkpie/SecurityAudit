"""
Scan Orchestrator - coordinates all scanning tools and normalizes findings.
"""
import asyncio
import logging
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from app.workers.scanners.tls_scanner import TLSScanner
from app.workers.scanners.header_scanner import HeaderScanner
from app.workers.scanners.exposure_scanner import ExposureScanner
from app.workers.scanners.nuclei_scanner import NucleiScanner
from app.workers.scanners.nmap_scanner import NmapScanner
from app.workers.scanners.ssl_scanner import SSLScanner
from app.workers.scanners.injection_scanner import InjectionScanner
from app.workers.scanners.directory_scanner import DirectoryScanner

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self, target_url: str, scan_type: str = "full", scan_config: dict = None):
        self.target_url = target_url
        self.scan_type = scan_type
        self.scan_config = scan_config or {}
        parsed = urlparse(target_url)
        self.domain = parsed.netloc.split(":")[0]
        self.scheme = parsed.scheme
        self.findings = []
        self.metadata = {}
        self.start_time = None

    async def run(self) -> dict:
        self.start_time = time.time()
        logger.info(f"Starting scan: {self.target_url} ({self.scan_type})")

        scanners = self._get_scanners()
        tasks = [self._run_scanner(scanner) for scanner in scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Scanner error: {result}")
            elif isinstance(result, list):
                self.findings.extend(result)

        score = self._calculate_score()
        verdict = self._determine_verdict(score)

        duration = time.time() - self.start_time
        self.metadata["scan_duration_seconds"] = round(duration, 2)
        self.metadata["total_findings"] = len(self.findings)
        self.metadata["scan_type"] = self.scan_type

        return {
            "findings": self.findings,
            "security_score": score,
            "verdict": verdict,
            "metadata": self.metadata,
        }

    def _get_scanners(self) -> list:
        if self.scan_type == "quick":
            return [
                HeaderScanner(self.target_url),
                TLSScanner(self.target_url),
                ExposureScanner(self.target_url),
            ]
        elif self.scan_type == "tls":
            return [TLSScanner(self.target_url), SSLScanner(self.target_url)]
        elif self.scan_type == "headers":
            return [HeaderScanner(self.target_url)]
        else:  # full
            scanners = [
                HeaderScanner(self.target_url),
                TLSScanner(self.target_url),
                ExposureScanner(self.target_url),
                NmapScanner(self.domain),
                DirectoryScanner(self.target_url),
            ]
            if self.scan_config.get("enable_nuclei", True):
                scanners.append(NucleiScanner(self.target_url))
            if self.scan_config.get("enable_injection", True):
                scanners.append(InjectionScanner(self.target_url))
            return scanners

    async def _run_scanner(self, scanner) -> list:
        try:
            logger.info(f"Running {scanner.__class__.__name__}")
            return await scanner.scan()
        except Exception as e:
            logger.error(f"{scanner.__class__.__name__} failed: {e}")
            return []

    def _calculate_score(self) -> float:
        """
        Score = 100 - deductions based on findings.
        Critical: -20 each (max -60)
        High: -10 each (max -30)
        Medium: -5 each (max -15)
        Low: -2 each (max -5)
        """
        score = 100.0
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1

        deduction = min(counts["critical"] * 20, 60)
        deduction += min(counts["high"] * 10, 30)
        deduction += min(counts["medium"] * 5, 15)
        deduction += min(counts["low"] * 2, 5)

        score = max(0.0, score - deduction)
        return round(score, 1)

    def _determine_verdict(self, score: float) -> str:
        critical = sum(1 for f in self.findings if f.get("severity") == "critical")
        high = sum(1 for f in self.findings if f.get("severity") == "high")

        if critical > 0 or score < 50:
            return "NO_GO"
        elif high > 3 or score < 70:
            return "GO_WITH_CONDITIONS"
        else:
            return "GO"
