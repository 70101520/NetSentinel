"""Persist SNMP vendor templates.

Revision ID: 0009_snmp_vendor_templates
Revises: 0008_snmp_devices
"""
from alembic import op
import sqlalchemy as sa

revision="0009_snmp_vendor_templates"
down_revision="0008_snmp_devices"
branch_labels=None
depends_on=None

def upgrade():
    op.add_column("snmp_devices",sa.Column("vendor",sa.String(30),nullable=False,server_default="generic"))

def downgrade():
    op.drop_column("snmp_devices","vendor")
