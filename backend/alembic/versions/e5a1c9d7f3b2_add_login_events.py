"""add login_events table (automatic sign-in monitoring)

Revision ID: e5a1c9d7f3b2
Revises: d4e8f2a1b9c3
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e5a1c9d7f3b2'
down_revision: Union[str, None] = 'd4e8f2a1b9c3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "login_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("ip", sa.String(), nullable=False, server_default=""),
        sa.Column("user_agent", sa.Text(), nullable=False, server_default=""),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("stage", sa.String(), nullable=False, server_default="password"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_login_events_email", "login_events", ["email"])
    op.create_index("ix_login_events_user_id", "login_events", ["user_id"])
    op.create_index("ix_login_events_ip", "login_events", ["ip"])
    op.create_index("ix_login_events_timestamp", "login_events", ["timestamp"])


def downgrade() -> None:
    op.drop_index("ix_login_events_timestamp", table_name="login_events")
    op.drop_index("ix_login_events_ip", table_name="login_events")
    op.drop_index("ix_login_events_user_id", table_name="login_events")
    op.drop_index("ix_login_events_email", table_name="login_events")
    op.drop_table("login_events")
