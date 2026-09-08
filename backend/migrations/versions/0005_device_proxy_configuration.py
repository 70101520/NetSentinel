"""Add per-device proxy configuration and reported state."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005_device_proxy_configuration"
down_revision = "0004_endpoint_stabilization"

def upgrade():
    op.create_table(
        "device_proxy_configurations",
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("host", sa.String(253)), sa.Column("port", sa.Integer()),
        sa.Column("bypass", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("mode", sa.String(20), nullable=False, server_default="disabled"),
        sa.Column("version", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("applied_version", sa.BigInteger()),
        sa.Column("current_state", sa.String(30), nullable=False, server_default="unknown"),
        sa.Column("drift_detected", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_apply_result", sa.String(50)), sa.Column("last_error", sa.String(500)),
        sa.Column("effective_host", sa.String(253)), sa.Column("effective_port", sa.Integer()),
        sa.Column("bypass_summary", sa.String(500)), sa.Column("last_reported_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("version >= 1", name="ck_proxy_version_positive"),
        sa.CheckConstraint("port IS NULL OR (port >= 1 AND port <= 65535)", name="ck_proxy_port_range"),
        sa.CheckConstraint("mode IN ('disabled','configured')", name="ck_proxy_mode"),
    )

def downgrade():
    op.drop_table("device_proxy_configurations")
