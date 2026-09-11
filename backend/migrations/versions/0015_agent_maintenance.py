"""secure agent maintenance commands"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision="0015_agent_maintenance"
down_revision="0014_web_policy_groups"
branch_labels=None
depends_on=None

def upgrade():
    uid=postgresql.UUID(as_uuid=True)
    op.add_column("devices",sa.Column("uninstall_password_verifier",sa.Text()))
    op.add_column("devices",sa.Column("recovery_code_verifier",sa.Text()))
    op.add_column("devices",sa.Column("maintenance_version",sa.Integer(),nullable=False,server_default="0"))
    op.create_table("agent_commands",
        sa.Column("id",uid,primary_key=True),sa.Column("device_id",uid,sa.ForeignKey("devices.id",ondelete="CASCADE"),nullable=False),
        sa.Column("command_type",sa.String(30),nullable=False),sa.Column("nonce",sa.String(64),nullable=False,unique=True),
        sa.Column("payload",postgresql.JSONB(),nullable=False,server_default=sa.text("'{}'::jsonb")),sa.Column("status",sa.String(20),nullable=False,server_default="PENDING"),
        sa.Column("issued_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),sa.Column("expires_at",sa.DateTime(timezone=True),nullable=False),
        sa.Column("requested_by",uid,sa.ForeignKey("users.id")),sa.Column("acknowledged_at",sa.DateTime(timezone=True)),sa.Column("result_message",sa.String(300)),
        sa.CheckConstraint("command_type IN ('UNINSTALL')",name="ck_agent_command_type"),
        sa.CheckConstraint("status IN ('PENDING','ACKNOWLEDGED','FAILED','EXPIRED')",name="ck_agent_command_status"))
    op.create_index("ix_agent_commands_device_id","agent_commands",["device_id"])
    op.create_index("ix_agent_commands_status","agent_commands",["status"])

def downgrade():
    op.drop_index("ix_agent_commands_status",table_name="agent_commands");op.drop_index("ix_agent_commands_device_id",table_name="agent_commands");op.drop_table("agent_commands")
    op.drop_column("devices","maintenance_version");op.drop_column("devices","recovery_code_verifier");op.drop_column("devices","uninstall_password_verifier")
