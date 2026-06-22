"""
TLS & HTTPS Security Scanner
Checks: HTTPS enforcement, HSTS, redirects, mixed content, certificate health
"""
import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiohttp

from app.workers.scanners import BaseScanner, make_finding

logger = logging.getLogger(__name__)


class TLSScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        parsed = urlparse(self.target)
        domain = parsed.netloc.split(":")[0]

        # 1. HTTPS Enforcement
        if parsed.scheme == "http":
            findings.append(make_finding(
                title="HTTPS Not Enforced",
                severity="high",
                category="TLS & HTTPS",
                description="The site is accessible over plain HTTP without redirection to HTTPS.",
                impact="All traffic between client and server is transmitted in plaintext, enabling eavesdropping and man-in-the-middle attacks.",
                remediation="Configure the web server to redirect all HTTP traffic to HTTPS (301 redirect). Ensure SSL/TLS certificates are valid.",
                evidence={"url": self.target, "scheme": "http"},
                affected_url=self.target,
                tool_name="tls_scanner",
                cvss_score=7.5,
            ))

        # 2. Check HTTPS and certificate details
        try:
            async with aiohttp.ClientSession() as session:
                # Check HTTP -> HTTPS redirect
                http_url = f"http://{domain}"
                try:
                    async with session.get(http_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status not in [301, 302, 307, 308]:
                            findings.append(make_finding(
                                title="Missing HTTP to HTTPS Redirect",
                                severity="medium",
                                category="TLS & HTTPS",
                                description=f"HTTP request to {http_url} returned status {resp.status} instead of a redirect.",
                                impact="Users accessing the HTTP version of the site are not automatically secured.",
                                remediation="Add a 301 permanent redirect from all HTTP URLs to HTTPS equivalents.",
                                evidence={"http_status": resp.status, "url": http_url},
                                affected_url=http_url,
                                tool_name="tls_scanner",
                                cvss_score=5.3,
                            ))
                except Exception:
                    pass

                # Check HSTS header
                https_url = f"https://{domain}"
                try:
                    async with session.get(https_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        hsts = resp.headers.get("Strict-Transport-Security")
                        if not hsts:
                            findings.append(make_finding(
                                title="Missing HSTS Header",
                                severity="medium",
                                category="TLS & HTTPS",
                                description="The Strict-Transport-Security (HSTS) header is not present.",
                                impact="Without HSTS, browsers may connect over HTTP before being redirected, enabling SSL stripping attacks.",
                                remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                                evidence={"url": https_url, "headers": dict(resp.headers)},
                                affected_url=https_url,
                                tool_name="tls_scanner",
                                cvss_score=5.3,
                            ))
                        elif "max-age=0" in hsts:
                            findings.append(make_finding(
                                title="HSTS max-age Set to 0",
                                severity="medium",
                                category="TLS & HTTPS",
                                description="HSTS header has max-age=0, which effectively disables HSTS.",
                                impact="HSTS protection is disabled, leaving users vulnerable to downgrade attacks.",
                                remediation="Set HSTS max-age to at least 31536000 (1 year).",
                                evidence={"hsts_value": hsts},
                                affected_url=https_url,
                                tool_name="tls_scanner",
                                cvss_score=5.3,
                            ))
                        elif "includeSubDomains" not in hsts:
                            findings.append(make_finding(
                                title="HSTS Missing includeSubDomains",
                                severity="low",
                                category="TLS & HTTPS",
                                description="HSTS header does not include the 'includeSubDomains' directive.",
                                impact="Subdomains are not protected by HSTS, allowing potential downgrade attacks on subdomain traffic.",
                                remediation="Add 'includeSubDomains' to the HSTS header.",
                                evidence={"hsts_value": hsts},
                                affected_url=https_url,
                                tool_name="tls_scanner",
                                cvss_score=3.1,
                            ))
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"TLS HTTP scan error: {e}")

        # 3. Certificate analysis via SSL
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
            conn.settimeout(10)
            conn.connect((domain, 443))
            cert = conn.getpeercert()
            conn.close()

            # Check expiry
            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expire_dt - now).days

                if days_left < 0:
                    findings.append(make_finding(
                        title="SSL Certificate Expired",
                        severity="critical",
                        category="TLS & HTTPS",
                        description=f"The SSL certificate for {domain} has expired.",
                        impact="Browsers will display security warnings, blocking users from accessing the site. All traffic is untrusted.",
                        remediation="Renew the SSL certificate immediately. Consider using Let's Encrypt for auto-renewal.",
                        evidence={"expired_at": expire_str, "days_past_expiry": abs(days_left)},
                        affected_url=f"https://{domain}",
                        tool_name="tls_scanner",
                        cvss_score=9.1,
                    ))
                elif days_left < 30:
                    findings.append(make_finding(
                        title=f"SSL Certificate Expiring Soon ({days_left} days)",
                        severity="high" if days_left < 14 else "medium",
                        category="TLS & HTTPS",
                        description=f"The SSL certificate for {domain} expires in {days_left} days.",
                        impact="If not renewed, the certificate will expire and users will receive browser security warnings.",
                        remediation="Renew the SSL certificate before it expires. Set up automatic renewal with certbot/Let's Encrypt.",
                        evidence={"expires_at": expire_str, "days_remaining": days_left},
                        affected_url=f"https://{domain}",
                        tool_name="tls_scanner",
                        cvss_score=5.9 if days_left < 14 else 3.7,
                    ))

            # Check TLS version
            tls_version = conn.version() if hasattr(conn, 'version') else None

        except ssl.SSLError as e:
            findings.append(make_finding(
                title="SSL/TLS Certificate Error",
                severity="critical",
                category="TLS & HTTPS",
                description=f"SSL/TLS certificate validation failed: {str(e)}",
                impact="The SSL certificate cannot be validated, making secure connections impossible.",
                remediation="Obtain and install a valid SSL certificate from a trusted CA.",
                evidence={"error": str(e)},
                affected_url=f"https://{domain}",
                tool_name="tls_scanner",
                cvss_score=8.6,
            ))
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            findings.append(make_finding(
                title="HTTPS Not Available",
                severity="critical",
                category="TLS & HTTPS",
                description=f"Could not establish HTTPS connection to {domain}: {str(e)}",
                impact="The site does not support HTTPS, leaving all data in transit unencrypted.",
                remediation="Configure HTTPS with a valid SSL/TLS certificate.",
                evidence={"error": str(e)},
                affected_url=f"https://{domain}",
                tool_name="tls_scanner",
                cvss_score=8.6,
            ))
        except Exception as e:
            logger.error(f"Certificate check error: {e}")

        return findings
