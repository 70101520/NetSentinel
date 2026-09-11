import uuid
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision="0014_web_policy_groups"
down_revision="0013_web_policy_management"
branch_labels=None
depends_on=None

def upgrade():
    uid=postgresql.UUID(as_uuid=True)
    op.create_table("web_direct_bypass_rules",
        sa.Column("id",uid,primary_key=True),sa.Column("domain",sa.String(253),nullable=False,unique=True),
        sa.Column("include_subdomains",sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.Column("description",sa.String(200)),sa.Column("created_by",uid,sa.ForeignKey("users.id")),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_table("web_policy_groups",
        sa.Column("id",uid,primary_key=True),
        sa.Column("name",sa.String(100),nullable=False,unique=True),
        sa.Column("description",sa.String(300)),
        sa.Column("default_action",sa.String(10),nullable=False,server_default="ALLOW"),
        sa.Column("enabled",sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.Column("created_by",uid,sa.ForeignKey("users.id")),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_table("web_policy_group_categories",
        sa.Column("id",uid,primary_key=True),
        sa.Column("group_id",uid,sa.ForeignKey("web_policy_groups.id",ondelete="CASCADE"),nullable=False),
        sa.Column("category_id",uid,sa.ForeignKey("web_categories.id",ondelete="CASCADE"),nullable=False),
        sa.Column("action",sa.String(10),nullable=False),
        sa.UniqueConstraint("group_id","category_id",name="uq_web_policy_group_category"))
    op.create_table("device_web_policy_groups",
        sa.Column("device_id",uid,sa.ForeignKey("devices.id",ondelete="CASCADE"),primary_key=True),
        sa.Column("group_id",uid,sa.ForeignKey("web_policy_groups.id",ondelete="CASCADE"),nullable=False),
        sa.Column("assigned_by",uid,sa.ForeignKey("users.id")),
        sa.Column("assigned_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()))
    op.create_index("ix_device_web_policy_groups_group_id","device_web_policy_groups",["group_id"])
    names=("Artificial Intelligence","Cryptocurrency","Web Hosting","Remote Access","URL Shortening","Social Media","Gambling","Adult / Mature Content","Malware","Phishing","VPN / Proxy Avoidance","Information Technology","Web-based Applications","Web Analytics","Online Meeting","Charitable Organizations","Armed Forces","Unrated")
    sql=sa.text("INSERT INTO web_categories (id,name,description) VALUES (:id,:name,:description) ON CONFLICT (name) DO NOTHING")
    for name in names:
        op.get_bind().execute(sql,{"id":uuid.uuid4(),"name":name,"description":"Built-in policy category"})

def downgrade():
    op.drop_index("ix_device_web_policy_groups_group_id",table_name="device_web_policy_groups")
    op.drop_table("device_web_policy_groups")
    op.drop_table("web_policy_group_categories")
    op.drop_table("web_policy_groups")
    op.drop_table("web_direct_bypass_rules")
