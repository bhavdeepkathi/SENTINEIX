"""add investigations and recommendations tables

Revision ID: 8_add_investigations
Revises: 7_add_mitre
Create Date: 2024-01-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '8_add_investigations'
down_revision = '7_add_mitre'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'investigations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('incident_id', sa.Integer(), nullable=False),
        sa.Column('analyst_id', sa.Integer(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('attack_type', sa.String(length=255), nullable=True),
        sa.Column('attack_sequence', sa.Text(), nullable=True),
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('affected_assets', sa.Text(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('mitre_techniques', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
        sa.ForeignKeyConstraint(['analyst_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('incident_id')
    )
    op.create_table(
        'recommendations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('priority', sa.String(length=20), nullable=True),
        sa.Column('is_ai_generated', sa.Integer(), nullable=False, server_default='1'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_recommendations_investigation_id'), 'recommendations', ['investigation_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_recommendations_investigation_id'), table_name='recommendations')
    op.drop_table('recommendations')
    op.drop_table('investigations')