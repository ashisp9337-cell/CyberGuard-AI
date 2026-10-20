"""align the PostgreSQL schema with the models (found by the 19 Oct audit)

* audit_logs.detail and iocs.modules are NOT NULL in the models but were created nullable
  (empty values are filled with {} / [] first, so no row is lost)
* the index on iocs.value that the model declares was never created ("seen before" lookups use it)

Revision ID: b3d5f7a9c1e2
Revises: a9b8c7d6e5f4
Create Date: 2026-10-19 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b3d5f7a9c1e2'
down_revision: Union[str, None] = 'a9b8c7d6e5f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("UPDATE audit_logs SET detail = '{}' WHERE detail IS NULL")
    op.execute("UPDATE iocs SET modules = '[]' WHERE modules IS NULL")
    op.alter_column("audit_logs", "detail", existing_type=sa.JSON(), nullable=False)
    op.alter_column("iocs", "modules", existing_type=sa.JSON(), nullable=False)
    op.create_index("ix_iocs_value", "iocs", ["value"], unique=False, if_not_exists=True)


def downgrade() -> None:
    op.drop_index("ix_iocs_value", table_name="iocs", if_exists=True)
    op.alter_column("iocs", "modules", existing_type=sa.JSON(), nullable=True)
    op.alter_column("audit_logs", "detail", existing_type=sa.JSON(), nullable=True)
