import csv
import io
import json
import logging
import os
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import MultipleResultsFound

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.models import Scan, Finding, Report, User, ScanStatus
from app.services.report_generator_v2 import generate_pdf_report

logger = logging.getLogger(__name__)

router = APIRouter()

async def get_scan_with_findings(scan_id: UUID, db: AsyncSession):
    """Fetch scan and its findings. Safe: Scan.id is a unique primary key."""
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        logger.warning("Scan not found: scan_id=%s", scan_id)
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        logger.warning("Scan not completed: scan_id=%s status=%s", scan_id, scan.status)
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity)
    )
    findings = findings_result.scalars().all()
    return scan, findings


async def get_existing_report(db: AsyncSession, scan_id: UUID, report_type: str) -> Optional[Report]:
    """Fetch latest report for a scan. Safe: query deterministically with limit(1)."""
    try:
        report_result = await db.execute(
            select(Report)
            .where(Report.scan_id == scan_id, Report.report_type == report_type)
            .order_by(Report.generated_at.desc())
            .limit(1)
        )
        return report_result.scalars().first()
    except MultipleResultsFound as exc:
        logger.error(
            "Multiple reports found for scan_id=%s report_type=%s (should not happen with unique constraint)",
            scan_id,
            report_type,
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Database integrity error: multiple reports found") from exc


@router.get("/{scan_id}/pdf")
async def export_pdf(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export scan as PDF report. Returns cached report if available and valid."""
    try:
        scan, findings = await get_scan_with_findings(scan_id, db)
    except HTTPException:
        raise

    # Check if valid cached report exists
    existing_report = await get_existing_report(db, scan_id, "pdf")
    if existing_report and existing_report.file_path and os.path.exists(existing_report.file_path):
        file_size = os.path.getsize(existing_report.file_path)
        logger.info(
            "Returning cached PDF report: report_id=%s scan_id=%s file_size=%d",
            existing_report.id,
            scan_id,
            file_size,
        )
        return FileResponse(
            existing_report.file_path,
            media_type="application/pdf",
            filename=f"secaudit-report-{scan_id}.pdf",
        )

    # Generate new report
    logger.info("Generating new PDF report: scan_id=%s", scan_id)
    try:
        pdf_path = await generate_pdf_report(scan, findings)
    except Exception as exc:
        logger.error("PDF generation failed: scan_id=%s error=%s", scan_id, str(exc), exc_info=True)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(exc)}") from exc

    # Validate generated PDF
    if not os.path.exists(pdf_path) or os.path.getsize(pdf_path) == 0:
        logger.error("PDF generation produced invalid output: scan_id=%s path=%s", scan_id, pdf_path)
        raise HTTPException(status_code=500, detail="PDF generation failed: invalid output")

    file_size = os.path.getsize(pdf_path)
    logger.info("PDF generated successfully: scan_id=%s file_size=%d", scan_id, file_size)

    # Cache report in database
    try:
        report = Report(
            scan_id=scan_id,
            report_type="pdf",
            file_path=pdf_path,
            file_size=file_size,
        )
        db.add(report)
        await db.commit()
        logger.info("Report cached: report_id=%s scan_id=%s", report.id, scan_id)
    except Exception as exc:
        logger.error("Failed to cache report: scan_id=%s error=%s", scan_id, str(exc), exc_info=True)
        await db.rollback()

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"secaudit-report-{scan_id}.pdf",
    )


@router.get("/{scan_id}/json")
async def export_json(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export scan as JSON report."""
    try:
        scan, findings = await get_scan_with_findings(scan_id, db)
    except HTTPException:
        raise

    report_data = {
        "report_id": str(scan_id),
        "generated_at": datetime.utcnow().isoformat(),
        "scan": {
            "id": str(scan.id),
            "target_url": scan.target_url,
            "target_domain": scan.target_domain,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "security_score": scan.security_score,
            "verdict": scan.verdict,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "scan_metadata": scan.scan_metadata,
        },
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "impact": f.impact,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "affected_url": f.affected_url,
                "cve_ids": f.cve_ids,
                "cvss_score": f.cvss_score,
                "risk_score": f.risk_score,
            }
            for f in findings
            if not f.is_false_positive
        ],
        "summary": {
            "total": len([f for f in findings if not f.is_false_positive]),
            "critical": len([f for f in findings if f.severity == "critical" and not f.is_false_positive]),
            "high": len([f for f in findings if f.severity == "high" and not f.is_false_positive]),
            "medium": len([f for f in findings if f.severity == "medium" and not f.is_false_positive]),
            "low": len([f for f in findings if f.severity == "low" and not f.is_false_positive]),
            "info": len([f for f in findings if f.severity == "info" and not f.is_false_positive]),
        },
    }

    return StreamingResponse(
        io.BytesIO(json.dumps(report_data, indent=2).encode()),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=secaudit-report-{scan_id}.json"},
    )


@router.get("/{scan_id}/csv")
async def export_csv(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export findings as CSV report."""
    try:
        scan, findings = await get_scan_with_findings(scan_id, db)
    except HTTPException:
        raise

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "title", "severity", "category", "description",
        "impact", "remediation", "affected_url", "cvss_score", "tool_name"
    ])
    writer.writeheader()

    for f in findings:
        if not f.is_false_positive:
            writer.writerow({
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "impact": f.impact,
                "remediation": f.remediation,
                "affected_url": f.affected_url or "",
                "cvss_score": f.cvss_score or "",
                "tool_name": f.tool_name or "",
            })

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.read().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=secaudit-findings-{scan_id}.csv"},
    )
