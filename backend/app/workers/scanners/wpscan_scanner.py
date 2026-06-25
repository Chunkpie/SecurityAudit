"""
WPScan CMS Scanner — detects vulnerable WordPress versions, plugins, themes, and misconfigurations.
"""
import json
import logging

from app.workers.scanners import BaseScanner, make_finding, run_command

logger = logging.getLogger(__name__)


class WPScanScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        stdout, stderr, rc = await run_command([
            "wpscan",
            "--url", self.target,
            "--format", "json",
            "--no-update",
            "--random-user-agent",
            "--api-token", "",
            "--batch",
        ], timeout=300)

        if rc == -2:
            logger.warning("wpscan not installed, skipping")
            return []

        if stdout:
            try:
                data = json.loads(stdout)
                findings.extend(self._parse_version(data))
                findings.extend(self._parse_vulnerabilities(data))
                findings.extend(self._parse_plugins(data))
                findings.extend(self._parse_themes(data))
            except json.JSONDecodeError:
                pass

        return findings

    def _parse_version(self, data: dict) -> list:
        findings = []
        version_info = data.get("version", {})
        if not version_info.get("number"):
            findings.append(make_finding(
                title="WordPress Version Not Detected",
                severity="low",
                category="cms_security",
                description="WPScan could not determine the WordPress version.",
                impact="Without version detection, vulnerability assessment is incomplete.",
                remediation="Ensure WordPress is not hiding its version via security plugins.",
                evidence={"wpscan_output": version_info},
                affected_url=self.target,
                tool_name="wpscan",
            ))
        return findings

    def _parse_vulnerabilities(self, data: dict) -> list:
        findings = []
        version_info = data.get("version", {})
        vulns = version_info.get("vulnerabilities", [])
        for vuln in vulns:
            findings.append(make_finding(
                title=f"[WPScan] {vuln.get('title', 'WordPress Vulnerability')}",
                severity="high",
                category="cms_security",
                description=vuln.get("description", "Vulnerability detected in WordPress core."),
                impact="May allow unauthorized access, data disclosure, or RCE.",
                remediation=vuln.get("fixed_in", "Update WordPress to the latest version."),
                evidence={"vulnerability": vuln},
                affected_url=self.target,
                tool_name="wpscan",
                cve_ids=vuln.get("cve", []),
                cvss_score=vuln.get("cvss", {}).get("score"),
            ))
        return findings

    def _parse_plugins(self, data: dict) -> list:
        findings = []
        for slug, info in data.get("plugins", {}).items():
            vulns = info.get("vulnerabilities", [])
            if vulns:
                for vuln in vulns:
                    findings.append(make_finding(
                        title=f"[WPScan] Plugin Vulnerability: {slug}",
                        severity=vuln.get("severity", "high"),
                        category="cms_security",
                        description=f"Plugin '{slug}' has known vulnerabilities: {vuln.get('title', '')}",
                        impact="Compromised plugin can lead to site takeover.",
                        remediation=f"Update or remove the '{slug}' plugin.",
                        evidence={"plugin": slug, "vulnerability": vuln},
                        affected_url=self.target,
                        tool_name="wpscan",
                        cve_ids=vuln.get("cve", []),
                    ))
        return findings

    def _parse_themes(self, data: dict) -> list:
        findings = []
        for slug, info in data.get("themes", {}).items():
            vulns = info.get("vulnerabilities", [])
            if vulns:
                for vuln in vulns:
                    findings.append(make_finding(
                        title=f"[WPScan] Theme Vulnerability: {slug}",
                        severity=vuln.get("severity", "high"),
                        category="cms_security",
                        description=f"Theme '{slug}' has known vulnerabilities: {vuln.get('title', '')}",
                        impact="Compromised theme can lead to site takeover.",
                        remediation=f"Update or replace the '{slug}' theme.",
                        evidence={"theme": slug, "vulnerability": vuln},
                        affected_url=self.target,
                        tool_name="wpscan",
                        cve_ids=vuln.get("cve", []),
                    ))
        return findings
