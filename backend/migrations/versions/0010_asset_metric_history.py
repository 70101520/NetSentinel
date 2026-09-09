"""Store Agent and SNMP metric history.

Revision ID: 0010_asset_metric_history
Revises: 0009_snmp_vendor_templates
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision="0010_asset_metric_history"
down_revision="0009_snmp_vendor_templates"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table(
        "asset_metric_samples",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("source_type",sa.String(10),nullable=False),
        sa.Column("source_id",postgresql.UUID(as_uuid=True),nullable=False),
        sa.Column("sampled_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column("uptime_seconds",sa.BigInteger()),
        sa.Column("cpu_percent",sa.Float()),
        sa.Column("memory_percent",sa.Float()),
        sa.Column("disk_percent",sa.Float()),
        sa.Column("network_receive_bps",sa.Float()),
        sa.Column("network_send_bps",sa.Float()),
        sa.Column("interfaces",postgresql.JSONB(),nullable=False,server_default=sa.text("'[]'::jsonb")),
        sa.CheckConstraint("source_type IN ('agent','snmp')",name="ck_asset_metric_source_type"),
    )
    op.create_index(
        "ix_asset_metric_source_time",
        "asset_metric_samples",
        ["source_type","source_id","sampled_at"],
    )

def downgrade():
    op.drop_index("ix_asset_metric_source_time",table_name="asset_metric_samples")
    op.drop_table("asset_metric_samples")
