"""Add categorized filtering, allowlist and trusted networks.

Revision ID: 0013_web_policy_management
Revises: 0012_web_filtering
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision="0013_web_policy_management"
down_revision="0012_web_filtering"
branch_labels=None
depends_on=None


def upgrade():
    op.create_table("web_categories",sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),sa.Column("name",sa.String(100),nullable=False,unique=True),sa.Column("description",sa.String(300)),sa.Column("created_by",postgresql.UUID(as_uuid=True),sa.ForeignKey("users.id")),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.add_column("web_block_rules",sa.Column("category_id",postgresql.UUID(as_uuid=True),nullable=True))
    op.create_foreign_key("fk_web_block_rules_category","web_block_rules","web_categories",["category_id"],["id"],ondelete="SET NULL")
    op.create_table("web_allow_rules",sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),sa.Column("domain",sa.String(253),nullable=False,unique=True),sa.Column("include_subdomains",sa.Boolean(),nullable=False,server_default=sa.true()),sa.Column("created_by",postgresql.UUID(as_uuid=True),sa.ForeignKey("users.id")),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_table("web_trusted_networks",sa.Column("id",postgresql.UUID(as_uuid=True),primary_key=True),sa.Column("name",sa.String(100),nullable=False),sa.Column("cidr",sa.String(50),nullable=False,unique=True),sa.Column("created_by",postgresql.UUID(as_uuid=True),sa.ForeignKey("users.id")),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))


def downgrade():
    op.drop_table("web_trusted_networks")
    op.drop_table("web_allow_rules")
    op.drop_constraint("fk_web_block_rules_category","web_block_rules",type_="foreignkey")
    op.drop_column("web_block_rules","category_id")
    op.drop_table("web_categories")