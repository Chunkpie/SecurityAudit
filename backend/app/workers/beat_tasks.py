"""
Celery Beat tasks for background maintenance — baseline tuning, cleanup, etc.
"""
import logging
from datetime import datetime, timezone
from collections import defaultdict

from sqlalchemy import select

from app.workers.tasks import celery_app, get_sync_db
from app.models.models import Finding, Scan, ScanBaseline

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.beat_tasks.update_scan_baselines")
def update_scan_baselines():
    logger.info("Starting baseline update")
    db = get_sync_db()

    try:
        scans = db.execute(
            select(Scan).where(Scan.status == "completed")
        ).scalars().all()

        groups = defaultdict(list)
        for scan in scans:
            key = (str(scan.organization_id), scan.target_domain)
            groups[key].append(scan)

        for (org_id, domain), group in groups.items():
            if len(group) < 5:
                continue

            finding_counts = defaultdict(int)
            total_scans = len(group)

            for scan in group:
                findings = db.execute(
                    select(Finding.title).where(Finding.scan_id == scan.id)
                ).scalars().all()

                seen_titles = set(findings)
                for title in seen_titles:
                    finding_counts[title] += 1

            noise_findings = {
                title: count
                for title, count in finding_counts.items()
                if count / total_scans > 0.8
            }

            existing = db.execute(
                select(ScanBaseline).where(
                    ScanBaseline.organization_id == org_id,
                    ScanBaseline.target_domain == domain,
                )
            ).scalar_one_or_none()

            if existing:
                existing.total_scans = total_scans
                existing.noise_findings = noise_findings
                existing.last_updated = datetime.now(timezone.utc)
            else:
                baseline = ScanBaseline(
                    organization_id=org_id,
                    target_domain=domain,
                    total_scans=total_scans,
                    noise_findings=noise_findings,
                )
                db.add(baseline)

            logger.info(
                f"Baseline for {domain}: {total_scans} scans, "
                f"{len(noise_findings)} noise candidates"
            )

        db.commit()
        logger.info("Baseline update complete")

    except Exception as e:
        logger.error(f"Baseline update failed: {e}", exc_info=True)
        db.rollback()
    finally:
        db.close()
