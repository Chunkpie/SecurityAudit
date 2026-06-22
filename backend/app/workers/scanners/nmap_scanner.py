"""
Nmap Network Scanner
Checks: open ports, dangerous services, default banners, service versions
"""
import json
import logging
import xml.etree.ElementTree as ET

from app.workers.scanners import BaseScanner, make_finding, run_command

logger = logging.getLogger(__name__)

DANGEROUS_PORTS = {
    21: ("FTP Service Open", "high", "FTP transmits data and credentials in plaintext."),
    23: ("Telnet Service Open", "critical", "Telnet transmits all data including credentials in plaintext."),
    25: ("SMTP Service Exposed", "medium", "SMTP server exposed; may be used for spam or relay attacks."),
    3306: ("MySQL Database Port Exposed", "critical", "MySQL database is directly accessible from the internet."),
    5432: ("PostgreSQL Port Exposed", "critical", "PostgreSQL database is directly accessible from the internet."),
    27017: ("MongoDB Port Exposed", "critical", "MongoDB is directly accessible from the internet."),
    6379: ("Redis Port Exposed", "critical", "Redis is directly accessible from the internet without authentication."),
    9200: ("Elasticsearch Port Exposed", "critical", "Elasticsearch is directly accessible from the internet."),
    2181: ("Zookeeper Port Exposed", "high", "Zookeeper coordination service is exposed."),
    4444: ("Metasploit Handler Port Open", "critical", "Port 4444 commonly used by Metasploit is open."),
    8080: ("HTTP Alternative Port Open", "low", "HTTP running on non-standard port."),
    8443: ("HTTPS Alternative Port Open", "info", "HTTPS running on non-standard port."),
    5900: ("VNC Service Exposed", "critical", "VNC remote desktop is accessible from the internet."),
    3389: ("RDP Service Exposed", "critical", "Remote Desktop Protocol is exposed to the internet."),
    22: None,  # SSH - handled specially
    80: None,  # HTTP - expected
    443: None,  # HTTPS - expected
}


class NmapScanner(BaseScanner):
    async def scan(self) -> list:
        findings = []
        stdout, stderr, rc = await run_command([
            "nmap", "-sV", "-sC", "--open",
            "-p", "21,22,23,25,80,443,3306,5432,6379,8080,8443,9200,27017,3389,5900,4444,2181",
            "-T4", "--max-retries", "1",
            "-oX", "-",
            self.target,
        ], timeout=120)

        if rc == -2:
            logger.warning("nmap not installed, skipping network scan")
            return []

        if stdout:
            findings.extend(self._parse_nmap_xml(stdout))

        return findings

    def _parse_nmap_xml(self, xml_output: str) -> list:
        findings = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                for port_elem in host.findall(".//port"):
                    portid = int(port_elem.get("portid", 0))
                    state = port_elem.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    service = port_elem.find("service")
                    service_name = service.get("name", "unknown") if service is not None else "unknown"
                    service_version = service.get("version", "") if service is not None else ""
                    service_product = service.get("product", "") if service is not None else ""

                    if portid == 22:
                        findings.append(make_finding(
                            title="SSH Service Exposed to Internet",
                            severity="medium",
                            category="Server Hardening",
                            description=f"SSH service is accessible on port 22. Version: {service_product} {service_version}".strip(),
                            impact="Brute force and credential stuffing attacks against SSH are common. Exposed SSH increases attack surface.",
                            remediation="Restrict SSH access to known IP ranges via firewall. Use key-based auth only. Disable password authentication.",
                            evidence={"port": 22, "service": service_name, "version": service_version},
                            affected_url=f"ssh://{self.target}:22",
                            tool_name="nmap",
                            cvss_score=5.3,
                        ))
                        continue

                    config = DANGEROUS_PORTS.get(portid)
                    if config is not None:
                        title, severity, description = config
                        findings.append(make_finding(
                            title=title,
                            severity=severity,
                            category="Server Hardening",
                            description=f"{description} Service info: {service_product} {service_version}".strip(),
                            impact=f"Port {portid} exposed to internet increases attack surface and may allow unauthorized access.",
                            remediation=f"Close port {portid} to public internet access via firewall. If needed, restrict to specific IP ranges.",
                            evidence={"port": portid, "service": service_name, "version": service_version, "product": service_product},
                            affected_url=f"{service_name}://{self.target}:{portid}",
                            tool_name="nmap",
                        ))

                    # Check for version disclosure
                    if service_version and portid not in [80, 443]:
                        findings.append(make_finding(
                            title=f"Service Version Disclosed on Port {portid}",
                            severity="info",
                            category="Server Hardening",
                            description=f"Port {portid} ({service_name}) reports version: {service_product} {service_version}",
                            impact="Version information helps attackers identify known vulnerabilities for this specific version.",
                            remediation="Configure services to suppress version banners where possible.",
                            evidence={"port": portid, "product": service_product, "version": service_version},
                            tool_name="nmap",
                        ))
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
        return findings
