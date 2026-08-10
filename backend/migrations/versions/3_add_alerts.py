"""add alerts table

Revision ID: 3_add_alerts
Revises: 2_add_log_events
Create Date: 2024-01-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '3_add_alerts'
down_revision = '2_add_log_events'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.Enum('low', 'medium', 'high', 'critical', name='alertseverity'), nullable=False, server_default='low'),
        sa.Column('status', sa.Enum('open', 'investigating', 'closed', name='alertstatus'), nullable=False, server_default='open'),
        sa.Column('source_event_id', sa.Integer(), nullable=True),
        sa.Column('incident_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['source_event_id'], ['log_events.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_incident_id'), 'alerts', ['incident_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_alerts_incident_id'), table_name='alerts')
    op.drop_table('alerts')
    # drop enums
    op.execute("DROP TYPE IF EXISTS alertseverity")
    op.execute("DROP TYPE IF EXISTS alertstatus")