"""
WhatWeb — website technology stack fingerprinting.
Identifies CMS, web frameworks, analytics, JavaScript libraries, and server software.
"""
import logging
import re

from app.workers.scanners import BaseScanner, make_finding, run_command

logger = logging.getLogger(__name__)

TECHNOLOGY_RISK_MAP = {
    "jquery": {"severity": "info", "category": "Technology Stack"},
    "bootstrap": {"severity": "info", "category": "Technology Stack"},
    "react": {"severity": "info", "category": "Technology Stack"},
    "vue.js": {"severity": "info", "category": "Technology Stack"},
    "angularjs": {"severity": "info", "category": "Technology Stack"},
    "php": {"severity": "low", "category": "Technology Stack"},
    "apache": {"severity": "low", "category": "Server Hardening"},
    "nginx": {"severity": "low", "category": "Server Hardening"},
    "iis": {"severity": "medium", "category": "Server Hardening"},
    "wordpress": {"severity": "low", "category": "cms_security"},
    "drupal": {"severity": "low", "category": "cms_security"},
    "joomla": {"severity": "low", "category": "cms_security"},
    "outdated": {"severity": "medium", "category": "Server Hardening"},
}


class WhatWebScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        stdout, stderr, rc = await run_command([
            "whatweb",
            "--color=never",
            "--no-errors",
            f"-u={self.target}",
        ], timeout=60)

        if rc == -2:
            logger.warning("whatweb not installed, skipping")
            return []

        if stdout:
            findings.extend(self._parse_output(stdout.strip()))

        return findings

    def _parse_output(self, output: str) -> list:
        findings = []
        for tech_name, config in TECHNOLOGY_RISK_MAP.items():
            if tech_name in output.lower():
                findings.append(make_finding(
                    title=f"Technology Detected: {tech_name.title()}",
                    severity=config["severity"],
                    category=config["category"],
                    description=f"The website uses {tech_name.title()}.",
                    impact=f"Knowledge of the technology stack helps attackers target known vulnerabilities.",
                    remediation="Keep all technologies updated to latest stable versions.",
                    evidence={"technology": tech_name, "raw_output": output[:500]},
                    affected_url=self.target,
                    tool_name="whatweb",
                ))

        # Check for version disclosure
        version_matches = re.findall(r'\[([\w.\-]+)\]', output)
        for match in version_matches:
            if any(c.isdigit() for c in match) and len(match) < 20:
                findings.append(make_finding(
                    title=f"Version Disclosed: {match}",
                    severity="low",
                    category="Server Hardening",
                    description=f"WhatWeb detected version string '{match}' in HTTP response.",
                    impact="Version information enables targeted attacks using known CVEs.",
                    remediation="Configure server to suppress version banners.",
                    evidence={"version": match, "raw_output": output[:500]},
                    affected_url=self.target,
                    tool_name="whatweb",
                ))
                break

        return findings
