"""
Base scanner with common utilities for all scanners.
"""
import asyncio
import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


def make_finding(
    title: str,
    severity: str,
    category: str,
    description: str,
    impact: str,
    remediation: str,
    evidence: dict = None,
    affected_url: str = None,
    tool_name: str = None,
    reproduction_steps: str = None,
    verification_steps: str = None,
    cve_ids: list = None,
    cvss_score: float = None,
) -> dict:
    """Normalize a finding into the standard schema."""
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "evidence": evidence or {},
        "affected_url": affected_url,
        "tool_name": tool_name or "internal",
        "reproduction_steps": reproduction_steps,
        "verification_steps": verification_steps,
        "cve_ids": cve_ids or [],
        "cvss_score": cvss_score,
    }


async def run_command(cmd: list, timeout: int = 300) -> tuple[str, str, int]:
    """Run an external command asynchronously."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
    except asyncio.TimeoutError:
        logger.warning(f"Command timed out: {' '.join(cmd)}")
        return "", "Timeout", -1
    except FileNotFoundError:
        logger.warning(f"Tool not found: {cmd[0]}")
        return "", f"Tool not installed: {cmd[0]}", -2
    except Exception as e:
        logger.error(f"Command error: {e}")
        return "", str(e), -3


class BaseScanner:
    def __init__(self, target: str):
        self.target = target

    async def scan(self) -> list:
        raise NotImplementedError
