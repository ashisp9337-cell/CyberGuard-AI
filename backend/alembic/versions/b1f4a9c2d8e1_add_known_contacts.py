"""add known_contacts table

Revision ID: b1f4a9c2d8e1
Revises: a8e2691f3dc7
Create Date: 2026-09-27 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b1f4a9c2d8e1'
down_revision: Union[str, None] = 'a8e2691f3dc7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('known_contacts',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('display_name', sa.String(), nullable=False),
    sa.Column('role_label', sa.String(), nullable=False),
    sa.Column('authorized_email', sa.String(), nullable=False),
    sa.Column('authorized_domain', sa.String(), nullable=False),
    sa.Column('typical_hours_start', sa.Integer(), nullable=False),
    sa.Column('typical_hours_end', sa.Integer(), nullable=False),
    sa.Column('high_risk_requests_allowed', sa.Boolean(), nullable=False),
    sa.Column('notes', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_known_contacts_user_id'), 'known_contacts', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_known_contacts_user_id'), table_name='known_contacts')
    op.drop_table('known_contacts')