"""Add unique constraint on reports table (scan_id, report_type)

Revision ID: 002_add_report_unique_constraint
Revises: 001_initial
Create Date: 2024-12-22 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "002_add_report_unique_constraint"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade():
    """Add unique constraint to ensure one report per scan per type."""
    # First, clean up any duplicate reports (keep the latest by generated_at)
    op.execute("""
        DELETE FROM reports r1
        WHERE r1.id NOT IN (
            SELECT id FROM (
                SELECT id, row_number() OVER (
                    PARTITION BY scan_id, report_type ORDER BY generated_at DESC
                ) as rn
                FROM reports
            ) t
            WHERE t.rn = 1
        )
    """)

    # Add the unique constraint
    op.create_unique_constraint(
        "uq_reports_scan_type",
        "reports",
        ["scan_id", "report_type"],
    )


def downgrade():
    """Remove unique constraint."""
    op.drop_constraint(
        "uq_reports_scan_type",
        "reports",
        type_="unique",
    )
