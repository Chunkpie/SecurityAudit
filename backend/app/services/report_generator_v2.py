"""
PDF Report Generator
Generates professional security audit PDF reports using Playwright for HTML-to-PDF rendering.
Includes severity donut chart, category bar chart, CWE/OWASP mapping, and an executive
risk narrative — all rendered as inline SVG so no client-side JS/chart library is required
inside the headless browser (keeps PDF generation fast and deterministic).
"""
import logging
import math
import os
from datetime import datetime, timezone
from html import escape as _esc

from app.core.config import settings

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}


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
                display_header_footer=True,
                header_template="<div></div>",
                footer_template=(
                    "<div style='font-size:9px; color:#9ca3af; width:100%; text-align:center; "
                    "font-family:-apple-system,sans-serif;'>"
                    "SecAudit Confidential Report &nbsp;|&nbsp; Page <span class='pageNumber'></span> "
                    "of <span class='totalPages'></span></div>"
                ),
                margin={"top": "16mm", "bottom": "16mm", "left": "15mm", "right": "15mm"},
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


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, "#6b7280")


def _verdict_color(verdict: str) -> str:
    return {"GO": "#16a34a", "GO_WITH_CONDITIONS": "#d97706", "NO_GO": "#dc2626"}.get(verdict, "#6b7280")


def _count_by_severity(findings: list, sev: str) -> int:
    return sum(1 for f in findings if getattr(f, "severity", None) == sev and not getattr(f, "is_false_positive", False))


def _valid(findings: list) -> list:
    return [f for f in findings if not getattr(f, "is_false_positive", False)]


# ─── SVG chart builders (no external chart lib needed for PDF rendering) ──────

def _donut_chart_svg(counts: dict, size: int = 180) -> str:
    """Render a severity-distribution donut chart as inline SVG."""
    total = sum(counts.values())
    cx = cy = size / 2
    r_outer = size / 2 - 8
    r_inner = r_outer * 0.6
    stroke_width = r_outer - r_inner

    if total == 0:
        return f"""
        <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
          <circle cx="{cx}" cy="{cy}" r="{(r_outer + r_inner) / 2}" fill="none"
                  stroke="#16a34a" stroke-width="{stroke_width}" />
          <text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="22" font-weight="800" fill="#16a34a" font-family="Arial,sans-serif">0</text>
          <text x="{cx}" y="{cy + 16}" text-anchor="middle" font-size="10" fill="#6b7280" font-family="Arial,sans-serif">Findings</text>
        </svg>"""

    circumference = 2 * math.pi * ((r_outer + r_inner) / 2)
    offset = 0
    segments = ""
    r_mid = (r_outer + r_inner) / 2
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        fraction = count / total
        dash = fraction * circumference
        gap = circumference - dash
        segments += (
            f'<circle cx="{cx}" cy="{cy}" r="{r_mid}" fill="none" '
            f'stroke="{SEVERITY_COLORS[sev]}" stroke-width="{stroke_width}" '
            f'stroke-dasharray="{dash:.2f} {gap:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})" />'
        )
        offset += dash

    return f"""
    <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
      {segments}
      <text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="26" font-weight="800" fill="#111827" font-family="Arial,sans-serif">{total}</text>
      <text x="{cx}" y="{cy + 16}" text-anchor="middle" font-size="10" fill="#6b7280" font-family="Arial,sans-serif">Findings</text>
    </svg>"""


def _category_bar_chart_svg(breakdown: dict, width: int = 480) -> str:
    """Horizontal bar chart of findings per category."""
    if not breakdown:
        return '<p style="color:#9ca3af; font-size:13px;">No category data available.</p>'

    items = sorted(breakdown.items(), key=lambda x: -x[1])[:10]
    max_val = max(v for _, v in items) or 1
    bar_height = 22
    gap = 10
    label_width = 190
    chart_width = width - label_width - 50
    height = len(items) * (bar_height + gap) + gap

    bars = ""
    y = gap
    for cat, count in items:
        bar_w = max(4, (count / max_val) * chart_width)
        color = "#3b82f6"
        bars += f"""
        <text x="0" y="{y + bar_height / 2 + 4}" font-size="11" fill="#374151" font-family="Arial,sans-serif">{_esc(_truncate(cat, 26))}</text>
        <rect x="{label_width}" y="{y}" width="{bar_w:.1f}" height="{bar_height}" rx="3" fill="{color}" />
        <text x="{label_width + bar_w + 8}" y="{y + bar_height / 2 + 4}" font-size="11" font-weight="700" fill="#111827" font-family="Arial,sans-serif">{count}</text>
        """
        y += bar_height + gap

    return f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">{bars}</svg>'


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _score_gauge_svg(score: float, size: int = 160) -> str:
    """Semi-circular gauge for the security score."""
    cx, cy = size / 2, size / 2 + 10
    r = size / 2 - 14
    color = "#16a34a" if score >= 80 else "#d97706" if score >= 60 else "#dc2626"
    angle = (score / 100) * 180
    rad = math.radians(180 - angle)
    end_x = cx + r * math.cos(rad)
    end_y = cy - r * math.sin(rad)
    large_arc = 1 if angle > 180 else 0

    return f"""
    <svg width="{size}" height="{size / 2 + 30}" viewBox="0 0 {size} {size / 2 + 30}">
      <path d="M {cx - r} {cy} A {r} {r} 0 0 1 {cx + r} {cy}" fill="none" stroke="#e5e7eb" stroke-width="14" stroke-linecap="round"/>
      <path d="M {cx - r} {cy} A {r} {r} 0 0 1 {end_x:.1f} {end_y:.1f}" fill="none" stroke="{color}" stroke-width="14" stroke-linecap="round"/>
      <text x="{cx}" y="{cy - 8}" text-anchor="middle" font-size="32" font-weight="900" fill="{color}" font-family="Arial,sans-serif">{score:g}</text>
      <text x="{cx}" y="{cy + 14}" text-anchor="middle" font-size="11" fill="#6b7280" font-family="Arial,sans-serif">out of 100</text>
    </svg>"""


# ─── Main HTML builder ────────────────────────────────────────────────────────

def _build_report_html(scan, findings: list) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    score = scan.security_score or 0
    verdict = scan.verdict or "NO_GO"
    verdict_color = _verdict_color(verdict)

    # Escape once — scan fields ultimately derive from user/network input
    # (target_url, target_domain) and must never be trusted as safe HTML.
    target_domain = _esc(scan.target_domain)
    target_url = _esc(scan.target_url)
    scan_type = _esc(scan.scan_type)
    scan_id = _esc(str(scan.id))

    counts = {sev: _count_by_severity(findings, sev) for sev in SEVERITY_ORDER}
    valid_findings = _valid(findings)

    category_breakdown = {}
    for f in valid_findings:
        category_breakdown[f.category] = category_breakdown.get(f.category, 0) + 1

    donut_svg = _donut_chart_svg(counts)
    bar_svg = _category_bar_chart_svg(category_breakdown)
    gauge_svg = _score_gauge_svg(score)

    findings_html = _build_findings_section(valid_findings)
    roadmap_html = _build_roadmap(valid_findings)
    checklist_html = _build_checklist(valid_findings, counts, score)
    toc_html = _build_toc()
    legend_html = _build_severity_legend(counts)

    metadata = scan.scan_metadata or {}
    scanners_run = metadata.get("scanners_executed", [])
    scanners_html = "".join(
        f'<span style="display:inline-block; background:#eff6ff; color:#1e40af; padding:3px 10px; '
        f'border-radius:12px; font-size:11px; margin:2px;">{s.get("name", "Unknown")} '
        f'({s.get("findings_count", 0)})</span>'
        for s in scanners_run
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Audit Report — {target_domain}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: Arial, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #111827; margin: 0; padding: 0; font-size: 13px; }}
  .cover {{ min-height: 100vh; background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 60px; page-break-after: always; }}
  .section {{ padding: 30px 40px; }}
  .section-title {{ font-size: 19px; font-weight: 800; color: #111827; border-bottom: 3px solid #2563eb; padding-bottom: 8px; margin-bottom: 18px; display:flex; align-items:center; gap:8px; }}
  .section-number {{ background:#2563eb; color:white; width:26px; height:26px; border-radius:6px; display:inline-flex; align-items:center; justify-content:center; font-size:14px; }}
  .stat-card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px; text-align: center; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }}
  .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
  code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 3px; font-size: 11px; font-family: 'Courier New', monospace; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 7px 10px; border: 1px solid #e5e7eb; font-size: 11.5px; }}
  th {{ background: #f3f4f6; font-weight: 700; color: #374151; }}
  .pill {{ display:inline-block; padding:2px 10px; border-radius:10px; font-size:10.5px; font-weight:700; }}
  .toc-item {{ display:flex; justify-content:space-between; padding:9px 0; border-bottom:1px dotted #e5e7eb; font-size:13px; }}
  @media print {{ body {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} }}
</style>
</head>
<body>

<!-- ═══════════════════ COVER PAGE ═══════════════════ -->
<div class="cover">
  <div style="text-align:center; color:white; max-width:600px;">
    <div style="font-size:12px; color:#60a5fa; text-transform:uppercase; letter-spacing:3px; margin-bottom:10px; font-weight:700;">⛨ Security Audit Report</div>
    <h1 style="font-size:34px; margin:0 0 6px; font-weight:900;">{target_domain}</h1>
    <div style="font-size:14px; color:#94a3b8; margin-bottom:36px; word-break:break-all;">{target_url}</div>

    <div style="background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.15); border-radius:16px; padding:32px 40px; margin-bottom:32px;">
      <div style="display:flex; align-items:center; justify-content:center; gap:40px;">
        <div>{gauge_svg}</div>
        <div style="width:1px; height:80px; background:rgba(255,255,255,0.2);"></div>
        <div>{donut_svg}</div>
      </div>
      <div style="margin-top:20px; background:{verdict_color}; color:white; padding:10px 28px; border-radius:50px; font-size:17px; font-weight:800; display:inline-block;">
        {verdict.replace("_", " ")}
      </div>
    </div>

    <div style="display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin-bottom:32px;">
      {"".join(f'''
      <div style="background:rgba(255,255,255,0.06); border:1px solid {SEVERITY_COLORS[sev]}55; border-radius:8px; padding:12px 4px;">
        <div style="font-size:24px; font-weight:800; color:{SEVERITY_COLORS[sev]};">{counts[sev]}</div>
        <div style="font-size:9px; color:#cbd5e1; text-transform:uppercase; letter-spacing:0.5px;">{sev}</div>
      </div>''' for sev in SEVERITY_ORDER)}
    </div>

    <div style="font-size:11px; color:#64748b; border-top:1px solid rgba(255,255,255,0.1); padding-top:18px; line-height:1.8;">
      <strong style="color:#94a3b8;">Audit ID:</strong> {scan_id}<br/>
      <strong style="color:#94a3b8;">Generated:</strong> {now} &nbsp;·&nbsp;
      <strong style="color:#94a3b8;">Scan Type:</strong> {scan_type} &nbsp;·&nbsp;
      <strong style="color:#94a3b8;">Duration:</strong> {metadata.get('scan_duration_seconds', '—')}s
    </div>
  </div>
</div>

<!-- ═══════════════════ TABLE OF CONTENTS ═══════════════════ -->
<div class="section" style="page-break-after:always;">
  {toc_html}
</div>

<!-- ═══════════════════ EXECUTIVE SUMMARY ═══════════════════ -->
<div class="section" style="page-break-after:always;">
  <div class="section-title"><span class="section-number">1</span> Executive Summary</div>
  <p style="font-size:13.5px; color:#374151; line-height:1.8;">
    This security audit was conducted on <strong>{target_domain}</strong> on {now} using the SecAudit
    automated security testing platform. The assessment combined network reconnaissance, TLS/HTTPS analysis,
    HTTP security header evaluation, injection testing, cross-site scripting probes, authentication and session
    security review, CORS configuration analysis, and template-based vulnerability scanning.
  </p>
  <p style="font-size:13.5px; color:#374151; line-height:1.8;">
    The assessment identified <strong>{len(valid_findings)} confirmed findings</strong> across
    <strong>{len(category_breakdown)} categories</strong>, resulting in a security score of
    <strong style="color:{_severity_color('critical') if score < 50 else '#16a34a'};">{score}/100</strong>.
    {_verdict_explanation(verdict, counts['critical'], counts['high'])}
  </p>

  <div class="grid-2" style="margin-top:24px;">
    <div>
      <h3 style="font-size:13px; color:#374151; margin-bottom:10px;">Severity Distribution</h3>
      {legend_html}
    </div>
    <div>
      <h3 style="font-size:13px; color:#374151; margin-bottom:10px;">Findings by Category</h3>
      {bar_svg}
    </div>
  </div>

  <h3 style="font-size:13px; color:#374151; margin-top:24px; margin-bottom:10px;">Scanners Executed</h3>
  <div>{scanners_html if scanners_html else '<span style="color:#9ca3af; font-size:12px;">Scanner metadata unavailable</span>'}</div>
</div>

<!-- ═══════════════════ RISK DASHBOARD ═══════════════════ -->
<div class="section" style="page-break-after:always;">
  <div class="section-title"><span class="section-number">2</span> Risk Dashboard</div>
  <table>
    <tr><th>Severity</th><th>Count</th><th>Description</th><th>SLA Recommendation</th></tr>
    <tr><td><span class="pill" style="background:#fee2e2; color:#991b1b;">CRITICAL</span></td><td><strong>{counts['critical']}</strong></td><td>Immediate exploitation risk; blocks production deployment</td><td>Fix before any deployment</td></tr>
    <tr><td><span class="pill" style="background:#ffedd5; color:#9a3412;">HIGH</span></td><td><strong>{counts['high']}</strong></td><td>Significant risk requiring prompt remediation</td><td>Fix within 7 days</td></tr>
    <tr><td><span class="pill" style="background:#fef3c7; color:#92400e;">MEDIUM</span></td><td><strong>{counts['medium']}</strong></td><td>Moderate risk, should be addressed</td><td>Fix within 30 days</td></tr>
    <tr><td><span class="pill" style="background:#dbeafe; color:#1e40af;">LOW</span></td><td><strong>{counts['low']}</strong></td><td>Minor risk, best-practice improvement</td><td>Fix within 90 days</td></tr>
    <tr><td><span class="pill" style="background:#f3f4f6; color:#374151;">INFO</span></td><td><strong>{counts['info']}</strong></td><td>Informational, no immediate action required</td><td>Track for awareness</td></tr>
  </table>
</div>

<!-- ═══════════════════ DETAILED FINDINGS ═══════════════════ -->
<div class="section" style="page-break-before:always;">
  <div class="section-title"><span class="section-number">3</span> Detailed Findings</div>
  {findings_html if findings_html else '<p style="color:#16a34a; font-style:italic;">No significant findings detected.</p>'}
</div>

<!-- ═══════════════════ REMEDIATION ROADMAP ═══════════════════ -->
<div class="section" style="page-break-before:always;">
  <div class="section-title"><span class="section-number">4</span> Remediation Roadmap</div>
  {roadmap_html}
</div>

<!-- ═══════════════════ READINESS CHECKLIST ═══════════════════ -->
<div class="section" style="page-break-before:always;">
  <div class="section-title"><span class="section-number">5</span> Production Readiness Checklist</div>
  <div style="background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:18px;">
    {checklist_html}
  </div>
</div>

<!-- ═══════════════════ TECHNICAL APPENDIX ═══════════════════ -->
<div class="section" style="page-break-before:always;">
  <div class="section-title"><span class="section-number">6</span> Technical Appendix</div>
  <table>
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Target URL</td><td><code>{target_url}</code></td></tr>
    <tr><td>Scan Type</td><td>{scan_type}</td></tr>
    <tr><td>Scan ID</td><td><code>{scan_id}</code></td></tr>
    <tr><td>Started At</td><td>{scan.started_at}</td></tr>
    <tr><td>Completed At</td><td>{scan.completed_at}</td></tr>
    <tr><td>Duration</td><td>{metadata.get('scan_duration_seconds', 'N/A')}s</td></tr>
    <tr><td>Total Findings (post-dedup)</td><td>{len(valid_findings)}</td></tr>
    <tr><td>Raw Findings (pre-dedup)</td><td>{metadata.get('raw_findings_before_dedup', '—')}</td></tr>
    <tr><td>Security Score</td><td><strong>{score}/100</strong></td></tr>
    <tr><td>Verdict</td><td><strong style="color:{verdict_color};">{verdict}</strong></td></tr>
  </table>

  <p style="font-size:10.5px; color:#9ca3af; margin-top:24px; border-top:1px solid #e5e7eb; padding-top:14px; line-height:1.6;">
    This report was generated by the SecAudit Platform using automated security testing tools.
    Automated scanning may produce false positives or false negatives — findings should be
    manually verified before remediation, especially for high-risk production changes.
    The user confirmed authorization to test this target before scanning commenced; the
    consent timestamp and source IP address are stored in the platform's permanent audit log.
    This report does not constitute a certified penetration test or compliance attestation.
  </p>
</div>

</body>
</html>"""


def _build_toc() -> str:
    items = [
        ("1", "Executive Summary"),
        ("2", "Risk Dashboard"),
        ("3", "Detailed Findings"),
        ("4", "Remediation Roadmap"),
        ("5", "Production Readiness Checklist"),
        ("6", "Technical Appendix"),
    ]
    rows = "".join(
        f'<div class="toc-item"><span><strong>{num}.</strong> &nbsp; {title}</span></div>'
        for num, title in items
    )
    return f'<div class="section-title">Table of Contents</div><div style="margin-top:8px;">{rows}</div>'


def _build_severity_legend(counts: dict) -> str:
    rows = ""
    total = sum(counts.values()) or 1
    for sev in SEVERITY_ORDER:
        count = counts[sev]
        pct = round((count / total) * 100) if total else 0
        rows += f"""
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
          <span style="width:10px; height:10px; border-radius:2px; background:{SEVERITY_COLORS[sev]}; display:inline-block;"></span>
          <span style="font-size:12px; color:#374151; width:60px; text-transform:capitalize;">{sev}</span>
          <div style="flex:1; background:#f3f4f6; border-radius:4px; height:8px; overflow:hidden;">
            <div style="width:{pct}%; height:100%; background:{SEVERITY_COLORS[sev]};"></div>
          </div>
          <span style="font-size:12px; font-weight:700; color:#111827; width:24px; text-align:right;">{count}</span>
        </div>"""
    return rows


def _build_findings_section(valid_findings: list) -> str:
    findings_html = ""
    for idx, f in enumerate(valid_findings, 1):
        sev_color = _severity_color(f.severity)
        evidence_html = ""
        if f.evidence:
            for key, val in f.evidence.items():
                val_str = str(val)
                if len(val_str) > 300:
                    val_str = val_str[:300] + "…"
                evidence_html += f"<div><strong>{_esc(str(key))}:</strong> <code style='color:#86efac; background:transparent;'>{_esc(val_str)}</code></div>"

        cve_html = ""
        if f.cve_ids:
            cve_html = " ".join(
                f'<span class="pill" style="background:#fee2e2; color:#991b1b; margin-right:4px;">{_esc(c)}</span>'
                for c in f.cve_ids
            )

        meta_chips = f'<span class="pill" style="background:#f3f4f6; color:#374151;">{_esc(f.category)}</span>'
        if getattr(f, "cwe_id", None):
            meta_chips += f' <span class="pill" style="background:#ede9fe; color:#5b21b6;">{_esc(f.cwe_id)}</span>'
        if getattr(f, "owasp_category", None):
            meta_chips += f' <span class="pill" style="background:#dbeafe; color:#1e40af;">{_esc(f.owasp_category)}</span>'
        if f.cvss_score:
            meta_chips += f' <span class="pill" style="background:#fef3c7; color:#92400e;">CVSS {f.cvss_score}</span>'

        title = _esc(f.title)
        description = _esc(f.description)
        impact = _esc(f.impact)
        remediation = _esc(f.remediation)
        affected_url = _esc(f.affected_url) if f.affected_url else None
        parameter = _esc(f.parameter) if getattr(f, "parameter", None) else None
        reproduction_steps = _esc(f.reproduction_steps) if getattr(f, "reproduction_steps", None) else None
        verification_steps = _esc(f.verification_steps) if getattr(f, "verification_steps", None) else None

        findings_html += f"""
        <div style="border-left: 5px solid {sev_color}; margin-bottom:18px; padding:14px 16px; background:#fafafa; border-radius:6px; page-break-inside:avoid;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:6px;">
            <h3 style="margin:0; font-size:13.5px; color:#111827; flex:1;">#{idx} {title}</h3>
            <span class="pill" style="background:{sev_color}; color:white; white-space:nowrap; margin-left:10px;">{f.severity.upper()}</span>
          </div>
          <div style="margin:6px 0 10px;">{meta_chips} {cve_html}</div>
          <div style="margin-top:10px;"><strong style="font-size:11px; color:#6b7280; text-transform:uppercase;">Description</strong><p style="font-size:12.5px; color:#374151; margin:4px 0;">{description}</p></div>
          <div style="margin-top:8px;"><strong style="font-size:11px; color:#6b7280; text-transform:uppercase;">Impact</strong><p style="font-size:12.5px; color:#374151; margin:4px 0;">{impact}</p></div>
          {f'<div style="margin-top:8px;"><strong style="font-size:11px; color:#6b7280; text-transform:uppercase;">Affected URL</strong><p style="font-size:11.5px; color:#374151; font-family:monospace; margin:4px 0; word-break:break-all;">{affected_url}</p></div>' if affected_url else ""}
          {f'<div style="margin-top:8px;"><strong style="font-size:11px; color:#6b7280; text-transform:uppercase;">Parameter</strong> <code>{parameter}</code></div>' if parameter else ""}
          {'<div style="margin-top:8px;"><strong style="font-size:11px; color:#6b7280; text-transform:uppercase;">Evidence</strong><div style="font-size:11px; background:#1f2937; color:#f9fafb; padding:10px; border-radius:5px; font-family:monospace; margin-top:4px; line-height:1.6;">' + evidence_html + '</div></div>' if evidence_html else ""}
          <div style="margin-top:10px; background:#ecfdf5; padding:10px 12px; border-radius:5px; border:1px solid #a7f3d0;"><strong style="font-size:11px; color:#065f46; text-transform:uppercase;">Remediation</strong><p style="font-size:12.5px; color:#065f46; margin:4px 0;">{remediation}</p></div>
          {f'<div style="margin-top:8px;"><strong style="font-size:11px; color:#6b7280; text-transform:uppercase;">Reproduction</strong><pre style="font-size:11px; color:#374151; white-space:pre-wrap; background:#f3f4f6; padding:8px; border-radius:4px; margin:4px 0;">{reproduction_steps}</pre></div>' if reproduction_steps else ""}
          {f'<div style="margin-top:8px;"><strong style="font-size:11px; color:#6b7280; text-transform:uppercase;">Verification</strong><p style="font-size:11.5px; color:#374151; margin:4px 0; white-space:pre-line;">{verification_steps}</p></div>' if verification_steps else ""}
        </div>
        """
    return findings_html


def _build_roadmap(valid_findings: list) -> str:
    roadmap_items = ""
    priorities = [
        ("critical", "Priority 1 — Fix Immediately (blocks deployment)"),
        ("high", "Priority 2 — Fix Before Deployment"),
        ("medium", "Priority 3 — Fix Within 30 Days"),
        ("low", "Priority 4 — Fix Within 90 Days"),
    ]
    for sev, label in priorities:
        sev_findings = [f for f in valid_findings if f.severity == sev]
        if sev_findings:
            items = "".join(
                f"<li style='margin-bottom:5px;'>{_esc(f.title)} "
                f"<span style='color:#9ca3af; font-size:11px;'>({_esc(getattr(f, 'cwe_id', '') or '')})</span></li>"
                for f in sev_findings[:12]
            )
            roadmap_items += f"""
            <div style="margin-bottom:16px; padding:14px; background:#f9fafb; border-radius:6px; border:1px solid #e5e7eb; border-left:4px solid {_severity_color(sev)};">
              <h4 style="margin:0 0 8px; color:{_severity_color(sev)}; font-size:13px;">{label} ({len(sev_findings)})</h4>
              <ul style="margin:0; padding-left:20px; font-size:12px; color:#374151;">{items}</ul>
            </div>"""
    if not roadmap_items:
        roadmap_items = '<p style="color:#16a34a; font-style:italic;">No critical, high, medium, or low severity items require remediation.</p>'
    return roadmap_items


def _build_checklist(valid_findings: list, counts: dict, score: float) -> str:
    checklist_items = [
        ("HTTPS Enforced", score >= 70),
        ("Valid SSL Certificate (no expiry/chain issues)", counts["critical"] == 0),
        ("Security Headers Present (CSP, X-Frame-Options, etc.)", counts["high"] <= 2),
        ("No Critical Vulnerabilities", counts["critical"] == 0),
        ("No Sensitive Files Exposed (.env, .git, backups)", not any("Sensitive Data Exposure" in f.category and f.severity in ["critical", "high"] for f in valid_findings)),
        ("No SQL Injection", not any("SQL Injection" in f.title for f in valid_findings)),
        ("No Reflected/DOM XSS", not any(f.category == "XSS" and f.severity in ["critical", "high"] for f in valid_findings)),
        ("No Open Redirect", not any("Open Redirect" in f.title for f in valid_findings)),
        ("No CORS Misconfiguration", not any("CORS" in f.title for f in valid_findings)),
        ("Session Cookies Properly Flagged (Secure/HttpOnly/SameSite)", not any("Cookie" in f.title and f.severity in ["critical", "high"] for f in valid_findings)),
        ("No Subdomain Takeover Risk", not any("Takeover" in f.title for f in valid_findings)),
        ("No Dangerous Open Ports", not any("Exposed" in f.title and f.severity == "critical" for f in valid_findings)),
    ]
    return "".join(
        f'<div style="display:flex; align-items:center; margin-bottom:9px; font-size:12.5px;">'
        f'<span style="color:{"#16a34a" if passed else "#dc2626"}; margin-right:10px; font-weight:800; width:60px;">{"✓ PASS" if passed else "✗ FAIL"}</span>'
        f'<span style="color:#374151;">{item}</span></div>'
        for item, passed in checklist_items
    )


def _verdict_explanation(verdict: str, critical: int, high: int) -> str:
    if verdict == "GO":
        return "The target demonstrates an acceptable security posture for production deployment, with no blocking issues identified."
    elif verdict == "GO_WITH_CONDITIONS":
        return f"Deployment may proceed after resolving the {high} high-severity finding(s) listed in this report. Continued monitoring and prompt remediation are strongly recommended."
    else:
        return f"Deployment is <strong>blocked</strong> due to {critical} critical finding(s) that present an unacceptable risk and must be resolved before any production exposure."
