"""add evidence table

Revision ID: 6_add_evidence
Revises: 5_add_alert_incident_fk
Create Date: 2024-01-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '6_add_evidence'
down_revision = '5_add_alert_incident_fk'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'evidence',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('incident_id', sa.Integer(), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('file_type', sa.String(length=100), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('uploaded_by', sa.Integer(), nullable=False),
        sa.Column('uploaded_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('sha256')
    )
    op.create_index(op.f('ix_evidence_incident_id'), 'evidence', ['incident_id'], unique=False)
    op.create_index(op.f('ix_evidence_sha256'), 'evidence', ['sha256'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_evidence_sha256'), table_name='evidence')
    op.drop_index(op.f('ix_evidence_incident_id'), table_name='evidence')
    op.drop_table('evidence')