"""
Nuclei Template-Based Vulnerability Scanner
Runs community-maintained templates against target.
"""
import json
import logging

from app.workers.scanners import BaseScanner, make_finding, run_command

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class NucleiScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        stdout, stderr, rc = await run_command([
            "nuclei",
            "-u", self.target,
            "-j",  # JSON output
            "-silent",
            "-severity", "critical,high,medium,low",
            "-t", "cves/,exposures/,misconfiguration/,takeovers/,technologies/",
            "-rl", "50",  # rate limit
            "-timeout", "5",
            "-retries", "1",
        ], timeout=300)

        if rc == -2:
            logger.warning("nuclei not installed, skipping template scan")
            return []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
                finding = self._parse_nuclei_result(result)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                continue

        return findings

    def _parse_nuclei_result(self, result: dict) -> dict | None:
        try:
            info = result.get("info", {})
            severity = SEVERITY_MAP.get(result.get("severity", "info").lower(), "info")
            name = info.get("name", "Unknown Vulnerability")
            template_id = result.get("template-id", "")
            matched_url = result.get("matched-at", self.target)
            description = info.get("description", "Vulnerability detected by Nuclei template.")
            remediation = info.get("remediation", "Review the finding and apply the recommended fix.")
            cve_ids = info.get("classification", {}).get("cve-id", [])
            cvss_score = info.get("classification", {}).get("cvss-score")

            evidence = {
                "template_id": template_id,
                "matcher_name": result.get("matcher-name", ""),
                "extracted_results": result.get("extracted-results", []),
                "request": result.get("request", ""),
                "response": (result.get("response", "") or "")[:1000],
            }

            tags = info.get("tags", [])
            category = self._determine_category(tags, template_id)

            return make_finding(
                title=f"[Nuclei] {name}",
                severity=severity,
                category=category,
                description=description,
                impact=info.get("impact", f"The vulnerability '{name}' was detected and may be exploitable."),
                remediation=remediation,
                evidence=evidence,
                affected_url=matched_url,
                tool_name="nuclei",
                cve_ids=cve_ids if isinstance(cve_ids, list) else [cve_ids] if cve_ids else [],
                cvss_score=float(cvss_score) if cvss_score else None,
            )
        except Exception as e:
            logger.error(f"Error parsing nuclei result: {e}")
            return None

    def _determine_category(self, tags: list, template_id: str) -> str:
        tag_str = " ".join(tags).lower()
        template_id = template_id.lower()
        if any(t in tag_str for t in ["xss", "cross-site"]):
            return "XSS"
        elif any(t in tag_str for t in ["sqli", "sql-injection"]):
            return "Injection"
        elif any(t in tag_str for t in ["exposure", "disclosure"]):
            return "Sensitive Data Exposure"
        elif any(t in tag_str for t in ["cve"]):
            return "CVE"
        elif any(t in tag_str for t in ["misconfig", "misconfiguration"]):
            return "Misconfiguration"
        elif any(t in tag_str for t in ["takeover"]):
            return "Subdomain Takeover"
        else:
            return "Vulnerability"
