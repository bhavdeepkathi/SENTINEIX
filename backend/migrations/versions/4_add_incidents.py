"""add incidents and incident_events tables

Revision ID: 4_add_incidents
Revises: 3_add_alerts
Create Date: 2024-01-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4_add_incidents'
down_revision = '3_add_alerts'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'incidents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('severity', sa.Enum('low', 'medium', 'high', 'critical', name='incidentseverity'), nullable=False, server_default='low'),
        sa.Column('status', sa.Enum('open', 'investigating', 'closed', name='incidentstatus'), nullable=False, server_default='open'),
        sa.Column('owner_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table(
        'incident_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('incident_id', sa.Integer(), nullable=False),
        sa.Column('log_event_id', sa.Integer(), nullable=False),
        sa.Column('sequence_no', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
        sa.ForeignKeyConstraint(['log_event_id'], ['log_events.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incident_events_incident_id'), 'incident_events', ['incident_id'], unique=False)
    op.create_index(op.f('ix_incident_events_log_event_id'), 'incident_events', ['log_event_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_incident_events_log_event_id'), table_name='incident_events')
    op.drop_index(op.f('ix_incident_events_incident_id'), table_name='incident_events')
    op.drop_table('incident_events')
    op.drop_table('incidents')
    op.execute("DROP TYPE IF EXISTS incidentseverity")
    op.execute("DROP TYPE IF EXISTS incidentstatus")