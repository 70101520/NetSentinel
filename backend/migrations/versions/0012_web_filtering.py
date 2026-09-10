"""Add managed web domain block rules.

Revision ID: 0012_web_filtering
Revises: 0011_device_control_mode
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision="0012_web_filtering"
down_revision="0011_device_control_mode"
branch_labels=None
depends_on=None


def upgrade():
    op.create_table(
        "web_block_rules",
        sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),
        sa.Column("domain",sa.String(253),nullable=False,unique=True),
        sa.Column("include_subdomains",sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.Column("enabled",sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.Column("created_by",postgresql.UUID(as_uuid=True),sa.ForeignKey("users.id"),nullable=True),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
    )


def downgrade():
    op.drop_table("web_block_rules")