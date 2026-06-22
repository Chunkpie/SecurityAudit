"""
Celery Tasks for async scan execution.
"""
import asyncio
import logging
from datetime import datetime, timezone

from celery import Celery
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.workers.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)

celery_app = Celery(
    "secaudit",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.workers.tasks.run_scan_task": {"queue": "scans"},
        "app.workers.tasks.generate_report_task": {"queue": "reports"},
    },
)


def get_sync_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(settings.SYNC_DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


@celery_app.task(bind=True, name="run_scan_task", max_retries=2, soft_time_limit=3600)
def run_scan_task(self, scan_id: str):
    """Execute a full security scan."""
    logger.info(f"Starting scan task: {scan_id}")
    db = get_sync_db()
    try:
        from app.models.models import Scan, ScanStatus, Finding, ScanJob
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        # Mark as running
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan_job = ScanJob(
            scan_id=scan_id,
            celery_task_id=self.request.id,
            job_type="full_scan",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan_job)
        db.commit()

        # Run the async orchestrator in a sync context
        orchestrator = ScanOrchestrator(
            target_url=scan.target_url,
            scan_type=scan.scan_type,
            scan_config=scan.scan_config or {},
        )
        result = asyncio.run(orchestrator.run())

        # Store findings
        for finding_data in result["findings"]:
            finding = Finding(
                scan_id=scan_id,
                title=finding_data["title"],
                severity=finding_data["severity"],
                category=finding_data["category"],
                description=finding_data["description"],
                impact=finding_data["impact"],
                remediation=finding_data["remediation"],
                evidence=finding_data.get("evidence", {}),
                affected_url=finding_data.get("affected_url"),
                tool_name=finding_data.get("tool_name"),
                reproduction_steps=finding_data.get("reproduction_steps"),
                verification_steps=finding_data.get("verification_steps"),
                cve_ids=finding_data.get("cve_ids", []),
                cvss_score=finding_data.get("cvss_score"),
            )
            db.add(finding)

        scan.status = ScanStatus.COMPLETED
        scan.security_score = result["security_score"]
        scan.verdict = result["verdict"]
        scan.scan_metadata = result["metadata"]
        scan.completed_at = datetime.now(timezone.utc)
        scan_job.status = "completed"
        scan_job.completed_at = datetime.now(timezone.utc)
        scan_job.result = {"score": result["security_score"], "verdict": result["verdict"]}
        db.commit()

        logger.info(f"Scan {scan_id} completed. Score: {result['security_score']}, Verdict: {result['verdict']}")
        return {"scan_id": scan_id, "status": "completed", "score": result["security_score"]}

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        from app.models.models import Scan, ScanStatus, ScanJob
        try:
            scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
        raise self.retry(exc=e, countdown=60)
    finally:
        db.close()


@celery_app.task(name="generate_report_task")
def generate_report_task(scan_id: str, report_type: str = "pdf"):
    """Generate a report for a completed scan."""
    logger.info(f"Generating {report_type} report for scan {scan_id}")
    db = get_sync_db()
    try:
        from app.models.models import Scan, Finding, Report
        scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
        if not scan:
            return
        findings = db.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
        if report_type == "pdf":
            pdf_path = asyncio.run(_generate_pdf(scan, findings))
            report = Report(scan_id=scan_id, report_type="pdf", file_path=pdf_path)
            db.add(report)
            db.commit()
    finally:
        db.close()


async def _generate_pdf(scan, findings):
    from app.services.report_generator import generate_pdf_report
    return await generate_pdf_report(scan, findings)
