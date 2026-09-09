"""portal-approved agent pairing"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision="0007_agent_pairing";down_revision="0006_device_discovery";branch_labels=None;depends_on=None
def upgrade():
    op.create_table("agent_pairing_requests",sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),sa.Column("installation_id",sa.String(200),nullable=False,unique=True),sa.Column("pairing_secret_hash",sa.String(64),nullable=False),sa.Column("pairing_code",sa.String(12),nullable=False,unique=True),sa.Column("hostname",sa.String(255),nullable=False),sa.Column("os_name",sa.String(100),nullable=False),sa.Column("os_version",sa.String(100)),sa.Column("architecture",sa.String(30)),sa.Column("agent_version",sa.String(50),nullable=False),sa.Column("requested_ip",postgresql.INET()),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),sa.Column("expires_at",sa.DateTime(timezone=True),nullable=False),sa.Column("approved_at",sa.DateTime(timezone=True)),sa.Column("rejected_at",sa.DateTime(timezone=True)),sa.Column("claimed_at",sa.DateTime(timezone=True)),sa.Column("approved_by",postgresql.UUID(as_uuid=True),sa.ForeignKey("users.id")),sa.Column("device_id",postgresql.UUID(as_uuid=True),sa.ForeignKey("devices.id",ondelete="SET NULL"),unique=True),sa.Column("group_name",sa.String(100)),sa.Column("department",sa.String(100)))
    op.create_index("ix_agent_pairing_status","agent_pairing_requests",["created_at","expires_at","approved_at","rejected_at"])
def downgrade():
    op.drop_table("agent_pairing_requests")
