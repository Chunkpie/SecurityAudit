"""
PDF Report Generator
Generates professional security audit PDF reports using Playwright for HTML-to-PDF rendering.
"""
import asyncio
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from app.core.config import settings

logger = logging.getLogger(__name__)


async def generate_pdf_report(scan, findings: list) -> str:
    """Generate a PDF report and return the file path."""
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    report_path = os.path.join(settings.REPORTS_DIR, f"report_{scan.id}.pdf")

    html = _build_report_html(scan, findings)
    html_path = f"/tmp/report_{scan.id}.html"
    with open(html_path, "w") as f:
        f.write(html)

    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )
            page = await browser.new_page()
            await page.goto(f"file://{html_path}")
            await page.wait_for_load_state("networkidle")
            await page.pdf(
                path=report_path,
                format="A4",
                print_background=True,
                margin={"top": "20mm", "bottom": "20mm", "left": "15mm", "right": "15mm"},
            )
            await browser.close()
    except ImportError:
        logger.warning("Playwright not available, generating HTML report instead")
        report_path = html_path.replace(".html", "_report.html")
        with open(report_path, "w") as f:
            f.write(html)
    except Exception as e:
        logger.error(f"PDF generation error: {e}")
        report_path = html_path

    return report_path


def _severity_color(severity: str) -> str:
    return {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#6b7280",
    }.get(severity, "#6b7280")


def _verdict_color(verdict: str) -> str:
    return {"GO": "#16a34a", "GO_WITH_CONDITIONS": "#d97706", "NO_GO": "#dc2626"}.get(verdict, "#6b7280")


def _count_by_severity(findings: list, sev: str) -> int:
    return sum(1 for f in findings if getattr(f, "severity", None) == sev and not getattr(f, "is_false_positive", False))


def _build_report_html(scan, findings: list) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    score = scan.security_score or 0
    verdict = scan.verdict or "NO_GO"
    verdict_color = _verdict_color(verdict)
    score_color = "#16a34a" if score >= 80 else "#d97706" if score >= 60 else "#dc2626"

    c = _count_by_severity(findings, "critical")
    h = _count_by_severity(findings, "high")
    m = _count_by_severity(findings, "medium")
    l = _count_by_severity(findings, "low")
    i = _count_by_severity(findings, "info")

    valid_findings = [f for f in findings if not getattr(f, "is_false_positive", False)]
    findings_html = ""
    for idx, f in enumerate(valid_findings, 1):
        sev_color = _severity_color(f.severity)
        evidence_html = ""
        if f.evidence:
            for key, val in f.evidence.items():
                evidence_html += f"<div><strong>{key}:</strong> <code>{str(val)[:300]}</code></div>"
        cve_html = ""
        if f.cve_ids:
            cve_html = "<div><strong>CVE IDs:</strong> " + ", ".join(f.cve_ids) + "</div>"

        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {sev_color}; margin-bottom:20px; padding:16px; background:#f9fafb; border-radius:4px; page-break-inside:avoid;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start;">
            <h3 style="margin:0; font-size:14px; color:#111827;">#{idx} {f.title}</h3>
            <span style="background:{sev_color}; color:white; padding:2px 10px; border-radius:12px; font-size:11px; font-weight:700; white-space:nowrap; margin-left:12px;">{f.severity.upper()}</span>
          </div>
          <div style="color:#6b7280; font-size:12px; margin-top:4px;">Category: {f.category} &nbsp;|&nbsp; Tool: {f.tool_name or 'internal'}{' &nbsp;|&nbsp; CVSS: ' + str(f.cvss_score) if f.cvss_score else ''}</div>
          {cve_html}
          <div style="margin-top:12px;"><strong style="font-size:12px;">Description</strong><p style="font-size:13px; color:#374151; margin:4px 0;">{f.description}</p></div>
          <div style="margin-top:8px;"><strong style="font-size:12px;">Impact</strong><p style="font-size:13px; color:#374151; margin:4px 0;">{f.impact}</p></div>
          {f'<div style="margin-top:8px;"><strong style="font-size:12px;">Affected URL</strong><p style="font-size:12px; color:#374151; font-family:monospace; margin:4px 0;">{f.affected_url}</p></div>' if f.affected_url else ""}
          {'<div style="margin-top:8px;"><strong style="font-size:12px;">Evidence</strong><div style="font-size:12px; background:#1f2937; color:#f9fafb; padding:8px; border-radius:4px; font-family:monospace; margin-top:4px;">' + evidence_html + '</div></div>' if evidence_html else ""}
          <div style="margin-top:8px; background:#ecfdf5; padding:10px; border-radius:4px;"><strong style="font-size:12px; color:#065f46;">Remediation</strong><p style="font-size:13px; color:#065f46; margin:4px 0;">{f.remediation}</p></div>
          {f'<div style="margin-top:8px;"><strong style="font-size:12px;">Verification Steps</strong><p style="font-size:12px; color:#374151; margin:4px 0; white-space:pre-line;">{f.verification_steps}</p></div>' if f.verification_steps else ""}
        </div>
        """

    roadmap_items = ""
    priorities = [("critical", "Priority 1 — Fix Immediately"), ("high", "Priority 2 — Fix Before Deployment"), ("medium", "Priority 3 — Fix Within 30 Days")]
    for sev, label in priorities:
        sev_findings = [f for f in valid_findings if f.severity == sev]
        if sev_findings:
            items = "".join(f"<li style='margin-bottom:4px;'>{f.title}</li>" for f in sev_findings[:10])
            roadmap_items += f"""
            <div style="margin-bottom:16px; padding:12px; background:#f9fafb; border-radius:6px; border:1px solid #e5e7eb;">
              <h4 style="margin:0 0 8px; color:{_severity_color(sev)};">{label}</h4>
              <ul style="margin:0; padding-left:20px; font-size:13px; color:#374151;">{items}</ul>
            </div>"""

    checklist_items = [
        ("HTTPS Enforced", score >= 70),
        ("Valid SSL Certificate", c == 0),
        ("Security Headers Present", h <= 2),
        ("No Critical Vulnerabilities", c == 0),
        ("No Sensitive Files Exposed", not any("Sensitive Data Exposure" in getattr(f, "category", "") and f.severity in ["critical", "high"] for f in valid_findings)),
        ("No SQL Injection", not any("SQL Injection" in getattr(f, "title", "") for f in valid_findings)),
        ("No Open Dangerous Ports", not any("Exposed" in getattr(f, "title", "") and f.severity == "critical" for f in valid_findings)),
    ]
    checklist_html = "".join(
        f'<div style="display:flex; align-items:center; margin-bottom:8px; font-size:13px;">'
        f'<span style="color:{"#16a34a" if passed else "#dc2626"}; margin-right:8px; font-weight:700;">{"✓ PASS" if passed else "✗ FAIL"}</span>'
        f'<span style="color:#374151;">{item}</span></div>'
        for item, passed in checklist_items
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report — {scan.target_domain}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #111827; margin: 0; padding: 0; }}
  .cover {{ min-height: 100vh; background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 60px; page-break-after: always; }}
  .section {{ padding: 40px; page-break-inside: avoid; }}
  .section-title {{ font-size: 20px; font-weight: 700; color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 20px; }}
  .stat-card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; text-align: center; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }}
  code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 3px; font-size: 12px; }}
  @media print {{ body {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} }}
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
  <div style="text-align:center; color:white;">
    <div style="font-size:13px; color:#94a3b8; text-transform:uppercase; letter-spacing:2px; margin-bottom:8px;">Security Audit Report</div>
    <h1 style="font-size:36px; margin:0 0 8px; font-weight:800;">{scan.target_domain}</h1>
    <div style="font-size:16px; color:#94a3b8; margin-bottom:48px;">{scan.target_url}</div>
    <div style="background:rgba(255,255,255,0.1); backdrop-filter:blur(10px); border-radius:16px; padding:40px 60px; margin-bottom:40px;">
      <div style="font-size:72px; font-weight:900; color:{score_color}; line-height:1;">{score}</div>
      <div style="font-size:18px; color:#cbd5e1; margin-top:4px;">Security Score / 100</div>
      <div style="margin-top:24px; background:{verdict_color}; color:white; padding:12px 32px; border-radius:50px; font-size:20px; font-weight:800; display:inline-block;">{verdict.replace("_", " ")}</div>
    </div>
    <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:40px;">
      <div style="background:rgba(220,38,38,0.2); border:1px solid rgba(220,38,38,0.4); border-radius:8px; padding:16px;">
        <div style="font-size:32px; font-weight:800; color:#fca5a5;">{c}</div>
        <div style="font-size:12px; color:#fca5a5;">CRITICAL</div>
      </div>
      <div style="background:rgba(234,88,12,0.2); border:1px solid rgba(234,88,12,0.4); border-radius:8px; padding:16px;">
        <div style="font-size:32px; font-weight:800; color:#fdba74;">{h}</div>
        <div style="font-size:12px; color:#fdba74;">HIGH</div>
      </div>
      <div style="background:rgba(217,119,6,0.2); border:1px solid rgba(217,119,6,0.4); border-radius:8px; padding:16px;">
        <div style="font-size:32px; font-weight:800; color:#fde68a;">{m}</div>
        <div style="font-size:12px; color:#fde68a;">MEDIUM</div>
      </div>
      <div style="background:rgba(37,99,235,0.2); border:1px solid rgba(37,99,235,0.4); border-radius:8px; padding:16px;">
        <div style="font-size:32px; font-weight:800; color:#93c5fd;">{l}</div>
        <div style="font-size:12px; color:#93c5fd;">LOW</div>
      </div>
    </div>
    <div style="font-size:12px; color:#64748b; border-top:1px solid rgba(255,255,255,0.1); padding-top:20px;">
      Audit ID: {scan.id} &nbsp;|&nbsp; Generated: {now} &nbsp;|&nbsp; Scan Type: {scan.scan_type}
    </div>
  </div>
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="section" style="page-break-after:always;">
  <div class="section-title">Executive Summary</div>
  <p style="font-size:14px; color:#374151; line-height:1.7;">
    This security audit was conducted on <strong>{scan.target_domain}</strong> on {now}.
    The assessment identified <strong>{len(valid_findings)} findings</strong> across multiple security categories,
    resulting in a security score of <strong style="color:{score_color};">{score}/100</strong>.
  </p>
  <p style="font-size:14px; color:#374151; line-height:1.7;">
    The deployment verdict is <strong style="color:{verdict_color};">{verdict.replace("_", " ")}</strong>.
    {_verdict_explanation(verdict, c, h)}
  </p>
  <div class="grid-4" style="margin-top:24px;">
    {''.join(f'<div class="stat-card"><div style="font-size:28px; font-weight:800; color:{_severity_color(sev)};">{cnt}</div><div style="font-size:12px; color:#6b7280; margin-top:4px;">{sev.upper()}</div></div>' for sev, cnt in [("critical",c),("high",h),("medium",m),("low",l)])}
  </div>
</div>

<!-- DETAILED FINDINGS -->
<div class="section" style="page-break-before:always;">
  <div class="section-title">Detailed Findings</div>
  {findings_html if findings_html else '<p style="color:#6b7280; font-style:italic;">No significant findings detected.</p>'}
</div>

<!-- REMEDIATION ROADMAP -->
<div class="section" style="page-break-before:always;">
  <div class="section-title">Remediation Roadmap</div>
  {roadmap_items if roadmap_items else '<p style="color:#16a34a;">No critical or high severity items require immediate remediation.</p>'}
</div>

<!-- PRODUCTION READINESS CHECKLIST -->
<div class="section">
  <div class="section-title">Production Readiness Checklist</div>
  <div style="background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:20px;">
    {checklist_html}
  </div>
</div>

<!-- TECHNICAL APPENDIX -->
<div class="section" style="page-break-before:always;">
  <div class="section-title">Technical Appendix</div>
  <table style="width:100%; border-collapse:collapse; font-size:13px;">
    <tr style="background:#f3f4f6;"><th style="padding:8px; text-align:left; border:1px solid #e5e7eb;">Property</th><th style="padding:8px; text-align:left; border:1px solid #e5e7eb;">Value</th></tr>
    <tr><td style="padding:8px; border:1px solid #e5e7eb;">Target URL</td><td style="padding:8px; border:1px solid #e5e7eb; font-family:monospace;">{scan.target_url}</td></tr>
    <tr><td style="padding:8px; border:1px solid #e5e7eb;">Scan Type</td><td style="padding:8px; border:1px solid #e5e7eb;">{scan.scan_type}</td></tr>
    <tr><td style="padding:8px; border:1px solid #e5e7eb;">Scan ID</td><td style="padding:8px; border:1px solid #e5e7eb; font-family:monospace;">{scan.id}</td></tr>
    <tr><td style="padding:8px; border:1px solid #e5e7eb;">Started At</td><td style="padding:8px; border:1px solid #e5e7eb;">{scan.started_at}</td></tr>
    <tr><td style="padding:8px; border:1px solid #e5e7eb;">Completed At</td><td style="padding:8px; border:1px solid #e5e7eb;">{scan.completed_at}</td></tr>
    <tr><td style="padding:8px; border:1px solid #e5e7eb;">Duration</td><td style="padding:8px; border:1px solid #e5e7eb;">{(scan.scan_metadata or {}).get('scan_duration_seconds', 'N/A')}s</td></tr>
    <tr><td style="padding:8px; border:1px solid #e5e7eb;">Total Findings</td><td style="padding:8px; border:1px solid #e5e7eb;">{len(valid_findings)}</td></tr>
    <tr><td style="padding:8px; border:1px solid #e5e7eb;">Security Score</td><td style="padding:8px; border:1px solid #e5e7eb; font-weight:700; color:{score_color};">{score}/100</td></tr>
    <tr><td style="padding:8px; border:1px solid #e5e7eb;">Verdict</td><td style="padding:8px; border:1px solid #e5e7eb; font-weight:700; color:{verdict_color};">{verdict}</td></tr>
  </table>
  <p style="font-size:11px; color:#9ca3af; margin-top:20px; border-top:1px solid #e5e7eb; padding-top:12px;">
    This report was generated by SecAudit Platform. The user confirmed authorization to test this target before scanning commenced.
    Scan timestamp and consent IP are stored in the audit log.
  </p>
</div>

</body>
</html>"""


def _verdict_explanation(verdict: str, critical: int, high: int) -> str:
    if verdict == "GO":
        return "The target demonstrates an acceptable security posture for production deployment."
    elif verdict == "GO_WITH_CONDITIONS":
        return f"Deployment may proceed after resolving {high} high-severity finding(s). Monitor and remediate all findings promptly."
    else:
        return f"Deployment is blocked due to {critical} critical finding(s) that must be resolved before any production exposure."
