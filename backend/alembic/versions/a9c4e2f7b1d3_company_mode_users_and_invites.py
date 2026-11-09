"""company mode: account status and last activity on users; invites

Revision ID: a9c4e2f7b1d3
Revises: e8f1a2b3c4d5
Create Date: 2026-11-10 00:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a9c4e2f7b1d3'
down_revision: Union[str, None] = 'e8f1a2b3c4d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("users", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("last_ip", sa.String(), nullable=True))
    op.add_column("users", sa.Column("last_user_agent", sa.String(), nullable=True))
    op.create_table(
        "invites",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="user"),
        sa.Column("invited_by", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_invites_email", "invites", ["email"])


def downgrade() -> None:
    op.drop_index("ix_invites_email", table_name="invites")
    op.drop_table("invites")
    op.drop_column("users", "last_user_agent")
    op.drop_column("users", "last_ip")
    op.drop_column("users", "last_seen_at")
    op.drop_column("users", "is_active")
