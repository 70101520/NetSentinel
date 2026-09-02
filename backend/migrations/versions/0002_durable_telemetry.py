"""Durable telemetry credentials and global idempotency."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision="0002_durable_telemetry"
down_revision="0001_foundation"
def upgrade():
    op.create_table("service_credentials",sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),sa.Column("name",sa.String(150),nullable=False,unique=True),sa.Column("kind",sa.String(30),nullable=False),sa.Column("secret_hash",sa.String(64),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),sa.Column("expires_at",sa.DateTime(timezone=True)),sa.Column("revoked_at",sa.DateTime(timezone=True)),sa.Column("last_used_at",sa.DateTime(timezone=True)),sa.CheckConstraint("kind IN ('proxy','agent','service')"))
    op.create_table("event_ids",sa.Column("event_id",postgresql.UUID(as_uuid=True),primary_key=True),sa.Column("event_time",sa.DateTime(timezone=True),nullable=False),sa.Column("received_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),schema="telemetry")
    op.add_column("proxy_events",sa.Column("received_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),schema="telemetry")
    op.add_column("proxy_events",sa.Column("username",sa.String(255)),schema="telemetry")
def downgrade():
    op.drop_column("proxy_events","username",schema="telemetry")
    op.drop_column("proxy_events","received_at",schema="telemetry")
    op.drop_table("event_ids",schema="telemetry")
    op.drop_table("service_credentials")
