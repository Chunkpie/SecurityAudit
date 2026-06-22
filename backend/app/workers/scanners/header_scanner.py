"""
HTTP Security Headers Scanner
Checks: CSP, X-Frame-Options, X-Content-Type-Options, CORS, Cookie flags, etc.
"""
import logging

import aiohttp

from app.workers.scanners import BaseScanner, make_finding

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "description": "Content Security Policy (CSP) is not set.",
        "impact": "Without CSP, the browser allows inline scripts and external resources from any origin, greatly increasing XSS risk.",
        "remediation": "Implement a strict Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'",
        "cvss": 6.1,
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options header is missing.",
        "impact": "The page can be embedded in iframes on other sites, enabling clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing by same origin is needed).",
        "cvss": 4.3,
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "X-Content-Type-Options header is not set.",
        "impact": "Browsers may MIME-sniff responses away from the declared content-type, enabling content injection attacks.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "cvss": 4.3,
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header is not set.",
        "impact": "Full URL may be sent in the Referer header to third parties, leaking sensitive path/query data.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cvss": 3.1,
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy header is not configured.",
        "impact": "Browser features like geolocation, camera, and microphone are not explicitly restricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "cvss": 3.1,
    },
}


class HeaderScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target,
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    headers = resp.headers
                    findings.extend(self._check_security_headers(headers))
                    findings.extend(self._check_server_version(headers))
                    findings.extend(self._check_cors(headers))
                    findings.extend(self._check_csp_issues(headers))
        except aiohttp.ClientConnectorError as e:
            logger.warning(f"Cannot connect to {self.target}: {e}")
        except Exception as e:
            logger.error(f"Header scan error: {e}")
        return findings

    def _check_security_headers(self, headers) -> list:
        findings = []
        for header, config in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(make_finding(
                    title=f"Missing Security Header: {header}",
                    severity=config["severity"],
                    category="Security Headers",
                    description=config["description"],
                    impact=config["impact"],
                    remediation=config["remediation"],
                    evidence={"missing_header": header, "url": self.target},
                    affected_url=self.target,
                    tool_name="header_scanner",
                    cvss_score=config["cvss"],
                ))
        return findings

    def _check_server_version(self, headers) -> list:
        findings = []
        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")

        if server and any(c.isdigit() for c in server):
            findings.append(make_finding(
                title="Server Version Disclosure",
                severity="low",
                category="Server Hardening",
                description=f"Server header reveals software version: '{server}'",
                impact="Version information enables targeted exploitation using known CVEs for that specific version.",
                remediation="Configure the web server to suppress version information from the Server header.",
                evidence={"server_header": server},
                affected_url=self.target,
                tool_name="header_scanner",
                cvss_score=3.1,
            ))

        if x_powered:
            findings.append(make_finding(
                title="Technology Disclosure via X-Powered-By",
                severity="low",
                category="Server Hardening",
                description=f"X-Powered-By header reveals backend technology: '{x_powered}'",
                impact="Discloses backend technology stack to attackers for targeted attacks.",
                remediation="Remove the X-Powered-By header. In PHP: expose_php = Off. In Express: app.disable('x-powered-by')",
                evidence={"x_powered_by": x_powered},
                affected_url=self.target,
                tool_name="header_scanner",
                cvss_score=3.1,
            ))
        return findings

    def _check_cors(self, headers) -> list:
        findings = []
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            findings.append(make_finding(
                title="Wildcard CORS Policy",
                severity="medium",
                category="Access Control",
                description="Access-Control-Allow-Origin is set to '*', allowing any origin to make cross-origin requests.",
                impact="Sensitive API endpoints may be accessed from malicious third-party sites via CORS requests.",
                remediation="Restrict CORS to specific trusted origins. Use an allowlist instead of wildcard.",
                evidence={"acao_header": acao},
                affected_url=self.target,
                tool_name="header_scanner",
                cvss_score=5.4,
            ))
        return findings

    def _check_csp_issues(self, headers) -> list:
        findings = []
        csp = headers.get("Content-Security-Policy", "")
        if csp:
            if "unsafe-inline" in csp and "nonce-" not in csp:
                findings.append(make_finding(
                    title="CSP Allows Unsafe Inline Scripts",
                    severity="medium",
                    category="Security Headers",
                    description="Content-Security-Policy includes 'unsafe-inline' without nonce-based exceptions.",
                    impact="Inline scripts are permitted, partially defeating XSS protection from CSP.",
                    remediation="Remove 'unsafe-inline' and use nonces or hashes to allow specific inline scripts.",
                    evidence={"csp": csp},
                    affected_url=self.target,
                    tool_name="header_scanner",
                    cvss_score=5.4,
                ))
            if "unsafe-eval" in csp:
                findings.append(make_finding(
                    title="CSP Allows unsafe-eval",
                    severity="medium",
                    category="Security Headers",
                    description="CSP includes 'unsafe-eval', allowing JavaScript eval() and similar functions.",
                    impact="Allows execution of strings as code, increasing XSS risk.",
                    remediation="Remove 'unsafe-eval' from CSP and refactor code to avoid eval().",
                    evidence={"csp": csp},
                    affected_url=self.target,
                    tool_name="header_scanner",
                    cvss_score=4.7,
                ))
        return findings
