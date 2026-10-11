"""add email pipeline tables (email_records, sender_history)

Revision ID: c7d3e5f1a2b4
Revises: b1f4a9c2d8e1
Create Date: 2026-10-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c7d3e5f1a2b4'
down_revision: Union[str, None] = 'b1f4a9c2d8e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('email_records',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('scan_id', sa.String(), nullable=True),
    sa.Column('message_id', sa.String(), nullable=False),
    sa.Column('source', sa.String(), nullable=False),
    sa.Column('from_address', sa.String(), nullable=False),
    sa.Column('from_domain', sa.String(), nullable=False),
    sa.Column('from_display_name', sa.String(), nullable=False),
    sa.Column('subject', sa.Text(), nullable=False),
    sa.Column('spf', sa.String(), nullable=False),
    sa.Column('dkim', sa.String(), nullable=False),
    sa.Column('dmarc', sa.String(), nullable=False),
    sa.Column('originating_ip', sa.String(), nullable=False),
    sa.Column('link_count', sa.Integer(), nullable=False),
    sa.Column('attachment_count', sa.Integer(), nullable=False),
    sa.Column('category', sa.String(), nullable=False),
    sa.Column('risk_score', sa.Integer(), nullable=False),
    sa.Column('classification', sa.String(), nullable=False),
    sa.Column('mitre', sa.JSON(), nullable=False),
    sa.Column('components', sa.JSON(), nullable=False),
    sa.Column('details', sa.JSON(), nullable=False),
    sa.Column('action_taken', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_records_user_id'), 'email_records', ['user_id'], unique=False)
    op.create_index(op.f('ix_email_records_scan_id'), 'email_records', ['scan_id'], unique=False)
    op.create_index(op.f('ix_email_records_message_id'), 'email_records', ['message_id'], unique=False)
    op.create_index(op.f('ix_email_records_from_address'), 'email_records', ['from_address'], unique=False)
    op.create_index(op.f('ix_email_records_from_domain'), 'email_records', ['from_domain'], unique=False)
    op.create_index(op.f('ix_email_records_created_at'), 'email_records', ['created_at'], unique=False)

    op.create_table('sender_history',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('sender_address', sa.String(), nullable=False),
    sa.Column('sender_domain', sa.String(), nullable=False),
    sa.Column('message_count', sa.Integer(), nullable=False),
    sa.Column('safe_count', sa.Integer(), nullable=False),
    sa.Column('malicious_count', sa.Integer(), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sender_history_user_id'), 'sender_history', ['user_id'], unique=False)
    op.create_index(op.f('ix_sender_history_sender_address'), 'sender_history', ['sender_address'], unique=False)
    op.create_index(op.f('ix_sender_history_sender_domain'), 'sender_history', ['sender_domain'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_sender_history_sender_domain'), table_name='sender_history')
    op.drop_index(op.f('ix_sender_history_sender_address'), table_name='sender_history')
    op.drop_index(op.f('ix_sender_history_user_id'), table_name='sender_history')
    op.drop_table('sender_history')
    op.drop_index(op.f('ix_email_records_created_at'), table_name='email_records')
    op.drop_index(op.f('ix_email_records_from_domain'), table_name='email_records')
    op.drop_index(op.f('ix_email_records_from_address'), table_name='email_records')
    op.drop_index(op.f('ix_email_records_message_id'), table_name='email_records')
    op.drop_index(op.f('ix_email_records_scan_id'), table_name='email_records')
    op.drop_index(op.f('ix_email_records_user_id'), table_name='email_records')
    op.drop_table('email_records')
