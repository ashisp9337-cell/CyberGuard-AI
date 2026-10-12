"""add iocs (indicators of compromise) and audit_logs tables

Revision ID: f7c3d1e9a4b6
Revises: e5a1c9d7f3b2
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f7c3d1e9a4b6'
down_revision: Union[str, None] = 'e5a1c9d7f3b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "iocs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("ioc_type", sa.String(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("times_seen", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_risk", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("modules", sa.JSON(), nullable=True),
        sa.Column("first_scan_id", sa.String(), nullable=True),
        sa.Column("last_scan_id", sa.String(), nullable=True),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "ioc_type", "value", name="uq_iocs_user_type_value"),
    )
    op.create_index("ix_iocs_user_id", "iocs", ["user_id"])
    op.create_index("ix_iocs_ioc_type", "iocs", ["ioc_type"])
    op.create_index("ix_iocs_last_seen", "iocs", ["last_seen"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("actor", sa.String(), nullable=False, server_default=""),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target", sa.Text(), nullable=False, server_default=""),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("ip", sa.String(), nullable=False, server_default=""),
        sa.Column("user_agent", sa.Text(), nullable=False, server_default=""),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_iocs_last_seen", table_name="iocs")
    op.drop_index("ix_iocs_ioc_type", table_name="iocs")
    op.drop_index("ix_iocs_user_id", table_name="iocs")
    op.drop_table("iocs")
