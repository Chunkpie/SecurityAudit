"""
Subfinder — passive subdomain enumeration using open-source intelligence sources.
"""
import json
import logging
from urllib.parse import urlparse

from app.workers.scanners import BaseScanner, make_finding, run_command

logger = logging.getLogger(__name__)


class SubfinderScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        parsed = urlparse(self.target)
        domain = parsed.netloc.split(":")[0]

        stdout, stderr, rc = await run_command([
            "subfinder",
            "-d", domain,
            "-silent",
            "-nW",
            "-oJ",
            "-timeout", "30",
        ], timeout=60)

        if rc == -2:
            logger.warning("subfinder not installed, skipping")
            return []

        subdomains = []
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    subdomains.append(data.get("host", line))
                except json.JSONDecodeError:
                    subdomains.append(line)

        if subdomains:
            findings.append(make_finding(
                title=f"Subdomains Discovered ({len(subdomains)})",
                severity="info",
                category="subdomain_enum",
                description=f"Subfinder discovered {len(subdomains)} subdomains for {domain}.",
                impact="Subdomains expand the attack surface and may host forgotten or vulnerable applications.",
                remediation="Audit all discovered subdomains. Remove or secure forgotten subdomains.",
                evidence={
                    "domain": domain,
                    "subdomains_found": len(subdomains),
                    "subdomain_list": subdomains[:50],
                    "tool": "subfinder",
                },
                affected_url=self.target,
                tool_name="subfinder",
            ))

        if not subdomains and not stderr:
            findings.append(make_finding(
                title="No Subdomains Discovered",
                severity="info",
                category="subdomain_enum",
                description=f"Subfinder found no additional subdomains for {domain}.",
                impact="No impact. This is informational.",
                remediation="None required.",
                evidence={"domain": domain},
                affected_url=self.target,
                tool_name="subfinder",
            ))

        return findings
