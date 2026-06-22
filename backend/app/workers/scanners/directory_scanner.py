"""
Directory Discovery Scanner using FFUF or Gobuster
"""
import json
import logging

from app.workers.scanners import BaseScanner, make_finding, run_command

logger = logging.getLogger(__name__)

WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
FALLBACK_WORDLIST = "/app/wordlists/common.txt"

INTERESTING_PATHS = {
    "/admin": ("high", "Admin panel discovered"),
    "/administrator": ("high", "Admin panel discovered"),
    "/backup": ("high", "Backup directory discovered"),
    "/uploads": ("medium", "Uploads directory discovered"),
    "/api": ("info", "API endpoint discovered"),
    "/swagger": ("medium", "API documentation discovered"),
    "/actuator": ("critical", "Spring Boot Actuator exposed"),
    "/metrics": ("medium", "Metrics endpoint discovered"),
    "/health": ("info", "Health check endpoint"),
    "/phpmyadmin": ("critical", "phpMyAdmin exposed"),
    "/.well-known": ("info", "Well-known directory"),
    "/debug": ("high", "Debug endpoint exposed"),
    "/console": ("critical", "Console endpoint exposed"),
    "/graphql": ("info", "GraphQL endpoint discovered"),
    "/graphiql": ("medium", "GraphiQL interface exposed"),
}


class DirectoryScanner(BaseScanner):
    async def scan(self) -> list:
        findings = await self._run_ffuf()
        if not findings:
            findings = await self._run_gobuster()
        return findings

    async def _run_ffuf(self) -> list:
        import os
        wordlist = WORDLIST if os.path.exists(WORDLIST) else FALLBACK_WORDLIST
        if not os.path.exists(wordlist):
            return await self._check_common_paths()

        stdout, stderr, rc = await run_command([
            "ffuf",
            "-u", f"{self.target}/FUZZ",
            "-w", wordlist,
            "-mc", "200,201,204,301,302,403",
            "-t", "20",
            "-rate", "50",
            "-timeout", "5",
            "-o", "/tmp/ffuf_out.json",
            "-of", "json",
            "-s",
        ], timeout=180)

        if rc == -2:
            return []

        try:
            import os
            if os.path.exists("/tmp/ffuf_out.json"):
                with open("/tmp/ffuf_out.json") as f:
                    data = json.load(f)
                return self._parse_ffuf(data)
        except Exception as e:
            logger.error(f"FFUF parse error: {e}")
        return []

    def _parse_ffuf(self, data: dict) -> list:
        findings = []
        for result in data.get("results", []):
            url = result.get("url", "")
            status = result.get("status", 0)
            path = "/" + url.split("/")[-1] if "/" in url else url

            for interesting_path, (severity, title) in INTERESTING_PATHS.items():
                if interesting_path.lower() in path.lower():
                    findings.append(make_finding(
                        title=f"Sensitive Path Discovered: {path}",
                        severity=severity,
                        category="Access Control",
                        description=f"{title}. Path '{path}' returned HTTP {status}.",
                        impact="Exposed administrative or sensitive paths increase the attack surface.",
                        remediation=f"Restrict access to {path} via authentication or IP allowlisting. Disable if not needed.",
                        evidence={"url": url, "status_code": status, "path": path},
                        affected_url=url,
                        tool_name="ffuf",
                    ))
                    break
        return findings

    async def _run_gobuster(self) -> list:
        import os
        wordlist = WORDLIST if os.path.exists(WORDLIST) else FALLBACK_WORDLIST
        if not os.path.exists(wordlist):
            return await self._check_common_paths()

        stdout, stderr, rc = await run_command([
            "gobuster", "dir",
            "-u", self.target,
            "-w", wordlist,
            "-t", "20",
            "--timeout", "5s",
            "-q",
            "-o", "/tmp/gobuster_out.txt",
        ], timeout=180)

        if rc == -2:
            return await self._check_common_paths()
        return []

    async def _check_common_paths(self) -> list:
        """Fallback: manually check common interesting paths."""
        import aiohttp
        import asyncio
        findings = []

        async def check(session, path):
            url = self.target.rstrip("/") + path
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False, allow_redirects=False) as resp:
                    if resp.status in [200, 403]:
                        severity, title = INTERESTING_PATHS.get(path, ("info", f"Path {path} accessible"))
                        return make_finding(
                            title=f"Sensitive Path Accessible: {path}",
                            severity=severity,
                            category="Access Control",
                            description=f"{title}. Returned HTTP {resp.status}.",
                            impact="Exposed paths may provide attackers with admin access, debugging information, or data.",
                            remediation=f"Restrict or remove {path}. Require authentication for sensitive endpoints.",
                            evidence={"url": url, "status_code": resp.status},
                            affected_url=url,
                            tool_name="directory_scanner",
                        )
            except Exception:
                pass
            return None

        async with aiohttp.ClientSession() as session:
            tasks = [check(session, path) for path in INTERESTING_PATHS.keys()]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r and not isinstance(r, Exception):
                    findings.append(r)

        return findings
