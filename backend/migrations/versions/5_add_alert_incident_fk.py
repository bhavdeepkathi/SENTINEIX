"""add foreign key from alerts.incident_id to incidents.id

Revision ID: 5_add_alert_incident_fk
Revises: 4_add_incidents
Create Date: 2024-01-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '5_add_alert_incident_fk'
down_revision = '4_add_incidents'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add foreign key constraint
    op.create_foreign_key(
        'fk_alerts_incident_id_incidents',
        'alerts', 'incidents',
        ['incident_id'], ['id']
    )


def downgrade() -> None:
    op.drop_constraint('fk_alerts_incident_id_incidents', 'alerts', type_='foreignkey')