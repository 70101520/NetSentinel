import asyncio,getpass,sys,uuid
from sqlalchemy import func,select
from app.db import SessionLocal
from app.models import Permission,Role,RolePermission,User,UserRole
from app.security import hash_password
PERMISSIONS=["dashboard.view","devices.view","devices.manage","policies.view","policies.manage","audit.view","web_logs.view","agents.manage","firewall.manage","reports.export","settings.manage"]
async def create_admin(email:str):
    password=getpass.getpass("Password: ")
    if len(password)<14: raise SystemExit("Password must contain at least 14 characters")
    async with SessionLocal() as db:
        if await db.scalar(select(func.count()).select_from(User)): raise SystemExit("Bootstrap refused: a user already exists")
        user=User(id=uuid.uuid4(),email=email.lower(),password_hash=hash_password(password)); role=Role(id=uuid.uuid4(),name="Super Admin"); db.add_all([user,role]); await db.flush()
        for code in PERMISSIONS:
            permission=Permission(id=uuid.uuid4(),code=code); db.add(permission); await db.flush(); db.add(RolePermission(role_id=role.id,permission_id=permission.id))
        db.add(UserRole(user_id=user.id,role_id=role.id)); await db.commit()
if __name__=="__main__":
    if len(sys.argv)==3 and sys.argv[1]=="create-admin": asyncio.run(create_admin(sys.argv[2]))
    else: raise SystemExit("usage: python -m app.cli create-admin EMAIL")
