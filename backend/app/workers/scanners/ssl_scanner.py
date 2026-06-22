"""
SSL/TLS Deep Analysis using testssl.sh and SSLyze
"""
import json
import logging
from urllib.parse import urlparse

from app.workers.scanners import BaseScanner, make_finding, run_command

logger = logging.getLogger(__name__)


class SSLScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        parsed = urlparse(self.target if self.target.startswith("http") else f"https://{self.target}")
        domain = parsed.netloc.split(":")[0]

        # Try SSLyze first
        sslyze_findings = await self._run_sslyze(domain)
        if sslyze_findings is not None:
            findings.extend(sslyze_findings)
        else:
            # Fallback to testssl.sh
            findings.extend(await self._run_testssl(domain))

        return findings

    async def _run_sslyze(self, domain: str) -> list | None:
        stdout, stderr, rc = await run_command([
            "python3", "-m", "sslyze",
            "--json_out", "-",
            "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
            "--heartbleed", "--openssl_ccs",
            "--robot", "--reneg",
            domain,
        ], timeout=120)

        if rc == -2 or rc != 0:
            return None

        try:
            data = json.loads(stdout)
            return self._parse_sslyze(data, domain)
        except Exception as e:
            logger.error(f"SSLyze parse error: {e}")
            return None

    def _parse_sslyze(self, data: dict, domain: str) -> list:
        findings = []
        for server_scan in data.get("server_scan_results", []):
            scan_result = server_scan.get("scan_result", {})

            # Check TLS 1.0
            tls1_result = scan_result.get("tls_1_0_cipher_suites", {})
            if tls1_result.get("result", {}).get("accepted_cipher_suites"):
                findings.append(make_finding(
                    title="TLS 1.0 Supported (Deprecated Protocol)",
                    severity="high",
                    category="TLS & HTTPS",
                    description=f"The server {domain} supports TLS 1.0, which has known vulnerabilities (BEAST, POODLE).",
                    impact="TLS 1.0 is deprecated and vulnerable to protocol downgrade attacks.",
                    remediation="Disable TLS 1.0 and TLS 1.1. Support only TLS 1.2 and TLS 1.3.",
                    evidence={"protocol": "TLS 1.0", "domain": domain},
                    affected_url=f"https://{domain}",
                    tool_name="sslyze",
                    cvss_score=7.4,
                ))

            # Check TLS 1.1
            tls11_result = scan_result.get("tls_1_1_cipher_suites", {})
            if tls11_result.get("result", {}).get("accepted_cipher_suites"):
                findings.append(make_finding(
                    title="TLS 1.1 Supported (Deprecated Protocol)",
                    severity="medium",
                    category="TLS & HTTPS",
                    description=f"The server {domain} supports TLS 1.1, which is deprecated.",
                    impact="TLS 1.1 lacks modern security features and is deprecated by RFC 8996.",
                    remediation="Disable TLS 1.1. Use only TLS 1.2 and TLS 1.3.",
                    evidence={"protocol": "TLS 1.1", "domain": domain},
                    affected_url=f"https://{domain}",
                    tool_name="sslyze",
                    cvss_score=5.9,
                ))

            # Check Heartbleed
            heartbleed = scan_result.get("heartbleed", {}).get("result", {})
            if heartbleed.get("is_vulnerable_to_heartbleed"):
                findings.append(make_finding(
                    title="Heartbleed Vulnerability (CVE-2014-0160)",
                    severity="critical",
                    category="TLS & HTTPS",
                    description="The server is vulnerable to the Heartbleed OpenSSL bug.",
                    impact="Attackers can read 64KB of server memory per request, potentially exposing private keys, session tokens, and user data.",
                    remediation="Update OpenSSL to version 1.0.1g or later immediately. Regenerate all certificates and revoke old ones.",
                    evidence={"cve": "CVE-2014-0160", "domain": domain},
                    affected_url=f"https://{domain}",
                    tool_name="sslyze",
                    cve_ids=["CVE-2014-0160"],
                    cvss_score=7.5,
                ))

        return findings

    async def _run_testssl(self, domain: str) -> list:
        stdout, stderr, rc = await run_command([
            "testssl.sh", "--quiet", "--jsonfile", "/dev/stdout",
            "--protocols", "--headers", "--vulnerabilities",
            f"{domain}:443",
        ], timeout=180)

        if rc == -2:
            logger.warning("testssl.sh not found, skipping deep SSL analysis")
            return []

        try:
            data = json.loads(stdout)
            return self._parse_testssl(data, domain)
        except Exception as e:
            logger.debug(f"testssl.sh parse error: {e}")
            return []

    def _parse_testssl(self, data: dict, domain: str) -> list:
        findings = []
        for item in data if isinstance(data, list) else []:
            severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
            severity = severity_map.get(item.get("severity", "INFO").upper(), "info")
            finding_id = item.get("id", "")
            finding_value = item.get("finding", "")

            if severity in ["critical", "high", "medium"] and finding_value and "not vulnerable" not in finding_value.lower():
                findings.append(make_finding(
                    title=f"SSL/TLS Issue: {finding_id}",
                    severity=severity,
                    category="TLS & HTTPS",
                    description=f"testssl.sh found: {finding_value}",
                    impact="SSL/TLS misconfiguration can allow downgrade attacks, protocol vulnerabilities, or cipher weaknesses.",
                    remediation="Review and fix the SSL/TLS configuration based on current best practices (Mozilla SSL Config Generator).",
                    evidence={"testssl_id": finding_id, "finding": finding_value, "domain": domain},
                    affected_url=f"https://{domain}",
                    tool_name="testssl",
                ))
        return findings
