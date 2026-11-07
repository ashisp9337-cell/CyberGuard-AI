"""add extension_tokens (connection keys of the CyberGuard browser extension; only hashes are stored)

Revision ID: e8f1a2b3c4d5
Revises: d1a7c3e9b5f2
Create Date: 2026-11-06 23:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e8f1a2b3c4d5'
down_revision: Union[str, None] = 'd1a7c3e9b5f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "extension_tokens",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False, server_default="Browser"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_extension_tokens_user_id", "extension_tokens", ["user_id"])
    op.create_index("ix_extension_tokens_token_hash", "extension_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_extension_tokens_token_hash", table_name="extension_tokens")
    op.drop_index("ix_extension_tokens_user_id", table_name="extension_tokens")
    op.drop_table("extension_tokens")
