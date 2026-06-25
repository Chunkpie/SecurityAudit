"""Add confidence, suppression rules, baselines

Revision ID: 003
Revises: 002_add_report_unique_constraint
Create Date: 2026-06-25
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "003"
down_revision: Union[str, None] = "002_add_report_unique_constraint"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("confidence", sa.Float(), nullable=True))

    op.create_table(
        "suppression_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("rule_type", sa.String(50), nullable=False),
        sa.Column("pattern", sa.String(1000), nullable=False),
        sa.Column("finding_title_pattern", sa.String(500), nullable=True),
        sa.Column("severity", sa.String(20), server_default=""),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_suppression_org", "suppression_rules", ["organization_id"])

    op.create_table(
        "scan_baselines",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_domain", sa.String(255), nullable=False),
        sa.Column("total_scans", sa.Integer(), server_default="0"),
        sa.Column("noise_findings", JSONB(), nullable=True),
        sa.Column("accepted_findings", JSONB(), nullable=True),
        sa.Column("last_updated", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_unique_constraint("uq_baseline_org_domain", "scan_baselines", ["organization_id", "target_domain"])


def downgrade() -> None:
    op.drop_column("findings", "confidence")
    op.drop_table("scan_baselines")
    op.drop_table("suppression_rules")
