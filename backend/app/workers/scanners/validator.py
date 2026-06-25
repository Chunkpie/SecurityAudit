"""
Sandboxed Scanner Validation — re-runs critical findings with more aggressive flags to confirm.
"""
import logging
from typing import Optional

from app.workers.scanners import run_command

logger = logging.getLogger(__name__)

VALIDATION_CONFIGS = {
    "nmap": {
        "cmd": lambda target: [
            "nmap", "-sV", "-sC", "--script", "vuln",
            "-T4", "--max-retries", "2",
            target,
        ],
        "timeout": 180,
    },
    "nuclei": {
        "cmd": lambda target: [
            "nuclei", "-u", target,
            "-j", "-silent",
            "-severity", "critical,high",
            "-rl", "100",
            "-timeout", "10",
            "-retries", "2",
        ],
        "timeout": 240,
    },
}


async def validate_finding(finding: dict) -> Optional[dict]:
    severity = finding.get("severity", "")
    if severity not in ("critical", "high"):
        return finding

    tool = finding.get("tool_name", "").split("+")[0]
    config = VALIDATION_CONFIGS.get(tool)
    if not config:
        return finding

    target = finding.get("affected_url") or finding.get("evidence", {}).get("url", "")
    if not target:
        return finding

    logger.info(f"Validating {tool} finding: {finding.get('title')}")

    cmd = config["cmd"](target)
    stdout, stderr, rc = await run_command(cmd, timeout=config["timeout"])

    if rc == -2:
        logger.warning(f"Validation tool {tool} not installed")
        return finding

    if not stdout or len(stdout.strip()) < 50:
        finding["severity"] = "medium"
        finding["validation_status"] = "downgraded"
        finding["confidence"] = min(finding.get("confidence", 0.5), 0.5)
        logger.info(f"Finding downgraded after validation: {finding.get('title')}")
    else:
        finding["validation_status"] = "confirmed"
        likelihood = "critical" in stdout.lower() or "critical" in stderr.lower()
        if likelihood:
            finding["confidence"] = max(finding.get("confidence", 0.5), 0.85)
        logger.info(f"Finding confirmed by validation: {finding.get('title')}")

    return finding
