import csv
import io
import json
import os
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.models import Scan, Finding, Report, User, ScanStatus
from app.services.report_generator import generate_pdf_report

router = APIRouter()


async def get_scan_with_findings(scan_id: UUID, db: AsyncSession):
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity)
    )
    findings = findings_result.scalars().all()
    return scan, findings


@router.get("/{scan_id}/pdf")
async def export_pdf(
    scan_id: UUID,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan, findings = await get_scan_with_findings(scan_id, db)

    # Check if report already exists
    report_result = await db.execute(
        select(Report).where(Report.scan_id == scan_id, Report.report_type == "pdf")
    )
    existing_report = report_result.scalar_one_or_none()

    if existing_report and existing_report.file_path and os.path.exists(existing_report.file_path):
        return FileResponse(
            existing_report.file_path,
            media_type="application/pdf",
            filename=f"secaudit-report-{scan_id}.pdf",
        )

    # Generate report
    pdf_path = await generate_pdf_report(scan, findings)

    report = Report(
        scan_id=scan_id,
        report_type="pdf",
        file_path=pdf_path,
        file_size=os.path.getsize(pdf_path) if os.path.exists(pdf_path) else None,
    )
    db.add(report)

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
    scan, findings = await get_scan_with_findings(scan_id, db)

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
    scan, findings = await get_scan_with_findings(scan_id, db)

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
