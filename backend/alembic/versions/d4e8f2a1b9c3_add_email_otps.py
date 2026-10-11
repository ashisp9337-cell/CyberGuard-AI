"""add email_otps table (signup + login OTP)

Revision ID: d4e8f2a1b9c3
Revises: c7d3e5f1a2b4
Create Date: 2026-10-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4e8f2a1b9c3'
down_revision: Union[str, None] = 'c7d3e5f1a2b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('email_otps',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('purpose', sa.String(), nullable=False),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=True),
    sa.Column('name', sa.String(), nullable=True),
    sa.Column('code_hash', sa.String(), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('resends', sa.Integer(), nullable=False),
    sa.Column('remember_me', sa.Boolean(), nullable=False),
    sa.Column('verified', sa.Boolean(), nullable=False),
    sa.Column('consumed', sa.Boolean(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('sent_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_otps_purpose'), 'email_otps', ['purpose'], unique=False)
    op.create_index(op.f('ix_email_otps_email'), 'email_otps', ['email'], unique=False)
    op.create_index(op.f('ix_email_otps_user_id'), 'email_otps', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_email_otps_user_id'), table_name='email_otps')
    op.drop_index(op.f('ix_email_otps_email'), table_name='email_otps')
    op.drop_index(op.f('ix_email_otps_purpose'), table_name='email_otps')
    op.drop_table('email_otps')
