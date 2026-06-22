"""
Sensitive Data Exposure Scanner
Checks: .env, .git, backup files, debug endpoints, source maps, API keys in responses
"""
import logging
import re
from urllib.parse import urljoin

import aiohttp

from app.workers.scanners import BaseScanner, make_finding

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = [
    # Environment and config files
    ("/.env", "Environment File Exposed", "critical", "Contains API keys, DB credentials, and secrets."),
    ("/.env.local", "Local Environment File Exposed", "critical", "Contains local development secrets."),
    ("/.env.production", "Production Environment File Exposed", "critical", "Contains production secrets."),
    ("/.env.backup", "Backup Environment File Exposed", "critical", "Contains backed-up secrets."),
    # Git
    ("/.git/config", "Git Repository Exposed", "critical", "Git config reveals repository structure and remotes."),
    ("/.git/HEAD", "Git HEAD File Exposed", "high", "Git repository is publicly accessible."),
    ("/.gitignore", "Gitignore File Exposed", "info", "Reveals file structure and potentially ignored sensitive files."),
    # Backup files
    ("/backup.sql", "SQL Backup Exposed", "critical", "Database backup file is publicly accessible."),
    ("/backup.zip", "Backup Archive Exposed", "critical", "Backup archive is publicly accessible."),
    ("/db.sql", "Database Dump Exposed", "critical", "Database dump file is publicly accessible."),
    ("/database.sql", "Database File Exposed", "critical", "Database file is publicly accessible."),
    ("/dump.sql", "Database Dump Exposed", "critical", "SQL dump file is publicly accessible."),
    # Config files
    ("/config.php", "PHP Config Exposed", "high", "PHP configuration file may contain credentials."),
    ("/wp-config.php.bak", "WordPress Config Backup Exposed", "critical", "WordPress config backup with credentials."),
    ("/config.yml", "YAML Config Exposed", "high", "YAML configuration file may contain secrets."),
    ("/config.json", "JSON Config Exposed", "medium", "JSON configuration file is publicly accessible."),
    ("/settings.py", "Django Settings Exposed", "high", "Django settings file may contain SECRET_KEY and DB credentials."),
    # Debug endpoints
    ("/phpinfo.php", "PHP Info Page Exposed", "high", "phpinfo() reveals server configuration and PHP settings."),
    ("/info.php", "PHP Info Page Exposed", "high", "PHP info page reveals server details."),
    ("/test.php", "Test PHP File Exposed", "medium", "Test PHP file is publicly accessible."),
    ("/_profiler", "Symfony Profiler Exposed", "high", "Symfony profiler reveals internal application data."),
    ("/debug", "Debug Endpoint Exposed", "high", "Debug endpoint is publicly accessible."),
    ("/console", "Debug Console Exposed", "critical", "Debug console may allow code execution."),
    # Logs
    ("/error.log", "Error Log Exposed", "high", "Error log file reveals internal errors and stack traces."),
    ("/access.log", "Access Log Exposed", "medium", "Access log reveals internal URL patterns and user data."),
    ("/logs/error.log", "Error Log Exposed", "high", "Error log in /logs/ directory is accessible."),
    # Common admin paths
    ("/admin", "Admin Panel Exposed", "medium", "Administrative interface is publicly accessible."),
    ("/wp-admin/", "WordPress Admin Exposed", "medium", "WordPress admin panel is accessible."),
    ("/administrator", "Joomla Admin Exposed", "medium", "Joomla administrator panel is accessible."),
    # Package files
    ("/package.json", "Package.json Exposed", "low", "Node.js package file reveals dependencies and scripts."),
    ("/composer.json", "Composer.json Exposed", "low", "PHP Composer file reveals dependencies."),
    ("/Gemfile", "Gemfile Exposed", "low", "Ruby Gemfile reveals dependencies."),
    ("/requirements.txt", "Requirements.txt Exposed", "low", "Python requirements file reveals dependencies."),
]

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "API Key"),
    (r"(?i)(secret[_-]?key|secretkey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Secret Key"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([a-zA-Z0-9_@#!]{8,})", "Password"),
    (r"(?i)(aws_access_key_id)\s*[=:]\s*([A-Z0-9]{20})", "AWS Access Key"),
    (r"(?i)(aws_secret_access_key)\s*[=:]\s*([a-zA-Z0-9/+]{40})", "AWS Secret Key"),
    (r"(?i)(private[_-]?key)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Private Key"),
    (r"(?i)(database[_-]?url|db[_-]?url)\s*[=:]\s*['\"]?(postgresql|mysql|mongodb)[^\"'\s]+", "Database URL"),
]


class ExposureScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        async with aiohttp.ClientSession() as session:
            tasks = [self._check_path(session, base, path_info) for path_info in SENSITIVE_PATHS]
            import asyncio
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)

            # Check source maps
            findings.extend(await self._check_source_maps(session, base))

        return findings

    async def _check_path(self, session, base: str, path_info: tuple) -> list:
        path, title, severity, description = path_info
        url = urljoin(base, path)
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=8),
                ssl=False,
                allow_redirects=False,
            ) as resp:
                if resp.status == 200:
                    content = await resp.text(errors="replace")
                    # Avoid false positives: check content looks relevant
                    if len(content) > 10 and not self._is_error_page(content):
                        secret_findings = self._check_secrets_in_content(content, url)
                        finding = make_finding(
                            title=title,
                            severity=severity,
                            category="Sensitive Data Exposure",
                            description=description,
                            impact=f"Sensitive file {path} is publicly accessible and may leak credentials, configuration, or data.",
                            remediation=f"Deny access to {path} in your web server configuration. Remove the file from the webroot if not needed.",
                            evidence={
                                "url": url,
                                "status_code": 200,
                                "content_preview": content[:500],
                            },
                            affected_url=url,
                            tool_name="exposure_scanner",
                            verification_steps=f"1. Open {url} in a browser\n2. Verify content is returned\n3. Check if sensitive data is present",
                        )
                        return [finding] + secret_findings
        except (aiohttp.ClientConnectorError, aiohttp.ServerTimeoutError):
            pass
        except Exception as e:
            logger.debug(f"Error checking {url}: {e}")
        return []

    def _is_error_page(self, content: str) -> bool:
        error_indicators = ["404", "not found", "error", "forbidden", "403"]
        content_lower = content.lower()[:200]
        return any(ind in content_lower for ind in error_indicators)

    def _check_secrets_in_content(self, content: str, url: str) -> list:
        findings = []
        for pattern, secret_type in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                findings.append(make_finding(
                    title=f"{secret_type} Exposed in Response",
                    severity="critical",
                    category="Sensitive Data Exposure",
                    description=f"Potential {secret_type} found in publicly accessible file.",
                    impact="Exposed credentials can be used for unauthorized access to systems, databases, or cloud infrastructure.",
                    remediation="Immediately rotate the exposed credential. Remove sensitive values from public files. Use environment variables.",
                    evidence={"url": url, "secret_type": secret_type, "pattern_match": True},
                    affected_url=url,
                    tool_name="exposure_scanner",
                    cvss_score=9.8,
                ))
        return findings

    async def _check_source_maps(self, session, base: str) -> list:
        findings = []
        map_paths = ["/static/js/main.chunk.js.map", "/assets/index.js.map", "/js/app.js.map"]
        for path in map_paths:
            url = urljoin(base, path)
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False, allow_redirects=False) as resp:
                    if resp.status == 200:
                        findings.append(make_finding(
                            title="JavaScript Source Map Exposed",
                            severity="medium",
                            category="Sensitive Data Exposure",
                            description=f"Source map file found at {url}. Source maps expose the original, minified source code.",
                            impact="Attackers can recover the original source code, revealing application logic, API endpoints, and comments.",
                            remediation="Disable source map serving in production. Remove .map files or restrict access.",
                            evidence={"url": url, "status_code": 200},
                            affected_url=url,
                            tool_name="exposure_scanner",
                            cvss_score=5.3,
                        ))
            except Exception:
                pass
        return findings
