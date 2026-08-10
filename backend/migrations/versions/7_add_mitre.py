"""add mitre_techniques and incident_mitre

Revision ID: 7_add_mitre
Revises: 6_add_evidence
Create Date: 2024-01-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '7_add_mitre'
down_revision = '6_add_evidence'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'mitre_techniques',
        sa.Column('technique_id', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('tactic', sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint('technique_id')
    )
    op.create_table(
        'incident_mitre',
        sa.Column('incident_id', sa.Integer(), nullable=False),
        sa.Column('technique_id', sa.String(length=20), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('evidence_ref', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
        sa.ForeignKeyConstraint(['technique_id'], ['mitre_techniques.technique_id'], ),
        sa.PrimaryKeyConstraint('incident_id', 'technique_id')
    )
    # seed a few common techniques
    op.bulk_insert(
        sa.table('mitre_techniques',
            sa.column('technique_id', sa.String),
            sa.column('name', sa.String),
            sa.column('tactic', sa.String)
        ),
        [
            {'technique_id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'},
            {'technique_id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Initial Access'},
            {'technique_id': 'T1068', 'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'},
            {'technique_id': 'T1059.001', 'name': 'PowerShell', 'tactic': 'Execution'},
            {'technique_id': 'T1041', 'name': 'Exfiltration Over C2 Channel', 'tactic': 'Exfiltration'},
            {'technique_id': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion'},
            {'technique_id': 'T1003.001', 'name': 'LSASS Memory', 'tactic': 'Credential Access'},
            {'technique_id': 'T1505.003', 'name': 'Web Shell', 'tactic': 'Persistence'},
        ]
    )


def downgrade() -> None:
    op.drop_table('incident_mitre')
    op.drop_table('mitre_techniques')