"""add log_events table

Revision ID: 2_add_log_events
Revises: 1_initial
Create Date: 2024-01-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2_add_log_events'
down_revision = '1_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'log_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('destination_ip', sa.String(length=45), nullable=True),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('raw_message', sa.Text(), nullable=True),
        sa.Column('incident_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_log_events_timestamp'), 'log_events', ['timestamp'], unique=False)
    op.create_index(op.f('ix_log_events_incident_id'), 'log_events', ['incident_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_log_events_incident_id'), table_name='log_events')
    op.drop_index(op.f('ix_log_events_timestamp'), table_name='log_events')
    op.drop_table('log_events')