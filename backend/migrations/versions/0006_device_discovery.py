"""device discovery foundation"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision="0006_device_discovery";down_revision="0005_device_proxy_configuration";branch_labels=None;depends_on=None
def upgrade():
    op.create_table("discovery_networks",sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),sa.Column("name",sa.String(100),nullable=False,unique=True),sa.Column("cidr",sa.String(43),nullable=False,unique=True),sa.Column("vlan",sa.String(100)),sa.Column("enabled",sa.Boolean(),nullable=False,server_default=sa.true()),sa.Column("interval_seconds",sa.Integer(),nullable=False,server_default="900"),sa.Column("probe_ports",postgresql.JSONB(),nullable=False,server_default="[]"),sa.Column("last_started_at",sa.DateTime(timezone=True)),sa.Column("last_completed_at",sa.DateTime(timezone=True)),sa.Column("last_status",sa.String(20),nullable=False,server_default="NEVER"),sa.Column("last_error",sa.String(300)),sa.Column("last_host_count",sa.Integer(),nullable=False,server_default="0"))
    op.create_table("discovery_hosts",sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),sa.Column("network_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("discovery_networks.id",ondelete="CASCADE"),nullable=False),sa.Column("ip_address",postgresql.INET(),nullable=False),sa.Column("hostname",sa.String(255)),sa.Column("state",sa.String(10),nullable=False,server_default="ONLINE"),sa.Column("first_seen",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),sa.Column("last_seen",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),sa.Column("open_ports",postgresql.JSONB(),nullable=False,server_default="[]"),sa.Column("matched_device_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("devices.id",ondelete="SET NULL")),sa.UniqueConstraint("network_id","ip_address",name="uq_discovery_host_network_ip"))
    op.create_index("ix_discovery_hosts_state_seen","discovery_hosts",["network_id","state","last_seen"])
def downgrade():
    op.drop_table("discovery_hosts");op.drop_table("discovery_networks")
