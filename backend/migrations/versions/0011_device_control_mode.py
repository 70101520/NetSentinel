"""Add endpoint web-control mode.

Revision ID: 0011_device_control_mode
Revises: 0010_asset_metric_history
"""
from alembic import op
import sqlalchemy as sa

revision="0011_device_control_mode"
down_revision="0010_asset_metric_history"
branch_labels=None
depends_on=None


def upgrade():
    op.add_column("devices",sa.Column("control_mode",sa.String(20),nullable=False,server_default="MONITOR_ONLY"))
    op.create_check_constraint("ck_devices_control_mode","devices","control_mode IN ('MONITOR_ONLY','WEB_CONTROLLED')")
    op.add_column("agent_pairing_requests",sa.Column("requested_control_mode",sa.String(20),nullable=False,server_default="MONITOR_ONLY"))
    op.create_check_constraint("ck_pairing_requested_control_mode","agent_pairing_requests","requested_control_mode IN ('MONITOR_ONLY','WEB_CONTROLLED')")


def downgrade():
    op.drop_constraint("ck_pairing_requested_control_mode","agent_pairing_requests",type_="check")
    op.drop_column("agent_pairing_requests","requested_control_mode")
    op.drop_constraint("ck_devices_control_mode","devices",type_="check")
    op.drop_column("devices","control_mode")