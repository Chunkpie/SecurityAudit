from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.models import Scan, Finding, ScanStatus, User
from app.schemas.schemas import CICDGateResult

router = APIRouter()


@router.get("/gate/{scan_id}", response_model=CICDGateResult)
async def get_gate_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not completed")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id, Finding.is_false_positive == False)
    )
    findings = findings_result.scalars().all()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    verdict = scan.verdict or "NO_GO"
    passed = verdict in ["GO", "GO_WITH_CONDITIONS"]

    return CICDGateResult(
        status=verdict,
        security_score=scan.security_score or 0.0,
        critical_findings=counts["critical"],
        high_findings=counts["high"],
        medium_findings=counts["medium"],
        low_findings=counts["low"],
        scan_id=str(scan_id),
        scan_url=f"/scans/{scan_id}",
        timestamp=datetime.utcnow().isoformat(),
        passed=passed,
    )
