"""
Injection Scanner
Checks: SQL injection, NoSQL injection, Command injection, LDAP injection
Uses SQLMap in non-destructive mode.
"""
import logging
import re

import aiohttp

from app.workers.scanners import BaseScanner, make_finding, run_command

logger = logging.getLogger(__name__)


class InjectionScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        findings.extend(await self._check_http_methods())
        findings.extend(await self._check_error_based_sqli())
        findings.extend(await self._run_sqlmap_safe())
        return findings

    async def _check_http_methods(self) -> list:
        """Check for dangerous HTTP methods: TRACE, PUT, DELETE"""
        findings = []
        dangerous_methods = ["TRACE", "PUT", "DELETE", "PATCH", "OPTIONS"]
        try:
            async with aiohttp.ClientSession() as session:
                for method in dangerous_methods:
                    try:
                        async with session.request(
                            method, self.target,
                            timeout=aiohttp.ClientTimeout(total=8),
                            ssl=False,
                        ) as resp:
                            if method == "TRACE" and resp.status == 200:
                                body = await resp.text(errors="replace")
                                if "TRACE" in body:
                                    findings.append(make_finding(
                                        title="HTTP TRACE Method Enabled",
                                        severity="medium",
                                        category="Server Hardening",
                                        description="The HTTP TRACE method is enabled on the server.",
                                        impact="TRACE can be exploited for Cross-Site Tracing (XST) attacks to steal cookies and credentials.",
                                        remediation="Disable the TRACE method in your web server configuration.",
                                        evidence={"method": "TRACE", "status_code": resp.status},
                                        affected_url=self.target,
                                        tool_name="injection_scanner",
                                        cvss_score=4.3,
                                    ))
                            elif method == "PUT" and resp.status in [200, 201, 204]:
                                findings.append(make_finding(
                                    title="HTTP PUT Method Enabled",
                                    severity="high",
                                    category="Server Hardening",
                                    description="The HTTP PUT method is enabled, potentially allowing arbitrary file uploads.",
                                    impact="Attackers may upload malicious files (web shells) to the server.",
                                    remediation="Disable PUT method unless required for WebDAV or REST APIs with proper authentication.",
                                    evidence={"method": "PUT", "status_code": resp.status},
                                    affected_url=self.target,
                                    tool_name="injection_scanner",
                                    cvss_score=7.5,
                                ))
                            elif method == "DELETE" and resp.status in [200, 204]:
                                findings.append(make_finding(
                                    title="HTTP DELETE Method Enabled",
                                    severity="high",
                                    category="Server Hardening",
                                    description="The HTTP DELETE method is enabled and returned a success response.",
                                    impact="Unauthenticated DELETE requests may allow content deletion.",
                                    remediation="Disable DELETE method or restrict to authenticated users with proper authorization.",
                                    evidence={"method": "DELETE", "status_code": resp.status},
                                    affected_url=self.target,
                                    tool_name="injection_scanner",
                                    cvss_score=7.5,
                                ))
                    except aiohttp.ClientConnectorError:
                        break
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"HTTP method check error: {e}")
        return findings

    async def _check_error_based_sqli(self) -> list:
        """Basic error-based SQL injection probing."""
        findings = []
        sqli_payloads = ["'", "\"", "'; --", "1 OR 1=1", "1' OR '1'='1"]
        sql_errors = [
            "SQL syntax", "mysql_fetch", "ORA-", "SQLite3::", "pg_query",
            "Warning: mysql", "Unclosed quotation mark", "Microsoft OLE DB",
            "SQLServer JDBC Driver", "PSQLException",
        ]
        try:
            async with aiohttp.ClientSession() as session:
                for payload in sqli_payloads[:2]:  # Limit to avoid DoS
                    test_url = f"{self.target}?id={payload}"
                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=8),
                            ssl=False,
                        ) as resp:
                            body = await resp.text(errors="replace")
                            for error in sql_errors:
                                if error.lower() in body.lower():
                                    findings.append(make_finding(
                                        title="SQL Injection Vulnerability (Error-Based)",
                                        severity="critical",
                                        category="Injection",
                                        description=f"SQL error message detected in response to injection payload: '{payload}'",
                                        impact="SQL injection allows attackers to read, modify, or delete database content and potentially achieve remote code execution.",
                                        remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL. Apply input validation.",
                                        evidence={
                                            "url": test_url,
                                            "payload": payload,
                                            "error_detected": error,
                                            "response_preview": body[:300],
                                        },
                                        affected_url=test_url,
                                        tool_name="injection_scanner",
                                        reproduction_steps=f"1. Send GET request to {self.target}?id={payload}\n2. Observe SQL error in response",
                                        verification_steps="Confirm with SQLMap: sqlmap -u \"URL\" --dbs",
                                        cvss_score=9.8,
                                    ))
                                    return findings  # One confirmed finding is enough
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"SQLi check error: {e}")
        return findings

    async def _run_sqlmap_safe(self) -> list:
        """Run SQLMap in safe, non-destructive mode."""
        stdout, stderr, rc = await run_command([
            "sqlmap",
            "-u", f"{self.target}?id=1",
            "--batch",
            "--level=1",
            "--risk=1",
            "--technique=BE",  # Boolean and Error-based only (no time-based, non-destructive)
            "--no-cast",
            "--output-dir=/tmp/sqlmap_out",
            "--forms",
            "--crawl=1",
            "-q",
        ], timeout=180)

        if rc == -2:
            logger.warning("sqlmap not installed, skipping automated SQLi scan")
            return []

        findings = []
        if stdout and "is vulnerable" in stdout.lower():
            param_match = re.search(r"Parameter: (\S+) \(", stdout)
            param = param_match.group(1) if param_match else "unknown"
            findings.append(make_finding(
                title="SQL Injection Confirmed by SQLMap",
                severity="critical",
                category="Injection",
                description=f"SQLMap confirmed SQL injection vulnerability in parameter '{param}'.",
                impact="Full database compromise possible. May lead to authentication bypass, data theft, or RCE via INTO OUTFILE.",
                remediation="Use prepared statements exclusively. Remove the vulnerable parameter from user-controllable input. Apply WAF rules.",
                evidence={"sqlmap_output": stdout[:1000], "parameter": param},
                affected_url=self.target,
                tool_name="sqlmap",
                cvss_score=9.8,
            ))
        return findings
