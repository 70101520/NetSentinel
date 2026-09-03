"""Indexes supporting bounded endpoint state evaluation and filtering."""
from alembic import op

revision = "0004_endpoint_stabilization"
down_revision = "0003_endpoint_enrollment"


def upgrade():
    op.drop_index("ix_devices_status_seen", table_name="devices")
    op.create_index("ix_devices_status_heartbeat", "devices", ["current_status", "last_heartbeat"])
    op.create_index("ix_devices_enrollment_state", "devices", ["enrollment_state"])


def downgrade():
    op.drop_index("ix_devices_enrollment_state", table_name="devices")
    op.drop_index("ix_devices_status_heartbeat", table_name="devices")
    op.create_index("ix_devices_status_seen", "devices", ["current_status", "last_seen"])
