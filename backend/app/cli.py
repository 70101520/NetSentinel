import asyncio,getpass,ipaddress,secrets,sys,uuid
from sqlalchemy import func,select
from app.db import SessionLocal
from app.models import AuditEvent,Device,DiscoveryNetwork,Permission,Role,RolePermission,ServiceCredential,User,UserRole
from app.config import settings
from app.security import hash_password
from app.service_auth import derive_secret
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
async def reset_admin_password(email:str):
    async with SessionLocal() as db:
        user=await db.scalar(select(User).where(func.lower(User.email)==email.lower()))
        if not user: raise SystemExit("Administrator account not found")
        password=getpass.getpass("New password: ")
        confirmation=getpass.getpass("Confirm new password: ")
        if len(password)<14: raise SystemExit("Password must contain at least 14 characters")
        if not secrets.compare_digest(password,confirmation): raise SystemExit("Password confirmation does not match")
        previous={"failed_logins":user.failed_logins,"locked":user.locked_until is not None}
        user.password_hash=hash_password(password); user.failed_logins=0; user.locked_until=None
        db.add(AuditEvent(actor_id=user.id,action="admin.password.recovery",resource_type="user",resource_id=str(user.id),source_ip=None,previous_value=previous,new_value={"failed_logins":0,"locked":False},result="success",request_id=f"cli-{uuid.uuid4()}"))
        await db.commit()
    print("Administrator password reset completed.")
async def create_service(name:str,kind:str):
    if kind not in {"proxy","agent","service"}: raise SystemExit("kind must be proxy, agent, or service")
    secret=secrets.token_urlsafe(32); credential=ServiceCredential(id=uuid.uuid4(),name=name,kind=kind,secret_hash=derive_secret(secret))
    async with SessionLocal() as db: db.add(credential); await db.commit()
    print(f"{credential.id}.{secret}")
def primary_network(interface_cidr:str)->str:
    try:interface=ipaddress.ip_interface(interface_cidr)
    except ValueError:raise SystemExit("Primary interface CIDR is invalid")
    allowed=(ipaddress.ip_network("10.0.0.0/8"),ipaddress.ip_network("172.16.0.0/12"),ipaddress.ip_network("192.168.0.0/16"))
    network=interface.network
    if interface.version!=4 or not any(network.subnet_of(item) for item in allowed):raise SystemExit("Primary interface must use an RFC1918 IPv4 network")
    if sum(1 for _ in network.hosts())>settings.discovery_max_hosts_per_network:raise SystemExit("Primary network exceeds the configured discovery host limit")
    return str(network)
async def ensure_primary_discovery_network(interface_cidr:str):
    cidr=primary_network(interface_cidr)
    async with SessionLocal() as db:
        item=await db.scalar(select(DiscoveryNetwork).where(DiscoveryNetwork.cidr==cidr))
        if item:
            changed=not item.enabled;item.enabled=True
        else:
            item=await db.scalar(select(DiscoveryNetwork).where(DiscoveryNetwork.name=="Primary server network"))
            if item:
                changed=item.cidr!=cidr or not item.enabled;item.cidr=cidr;item.enabled=True
            else:
                changed=True;item=DiscoveryNetwork(name="Primary server network",cidr=cidr,vlan="Primary LAN",enabled=True,interval_seconds=900,probe_ports=[22,80,443,445,3128,3389,8080]);db.add(item)
        if changed:
            await db.flush();db.add(AuditEvent(actor_id=None,action="discovery.primary_network.configure",resource_type="discovery_network",resource_id=str(item.id),source_ip=None,previous_value=None,new_value={"cidr":cidr},result="success",request_id=f"cli-{uuid.uuid4()}"))
        await db.commit()
    print(f"Primary discovery network configured: {cidr} ({item.name})")

def synthetic_signature(device:Device)->bool:
    lifecycle={"ALPHA":"filter-000","BRAVO":"filter-001","CHARLIE":"filter-002"}
    if device.hostname in lifecycle:return device.device_identifier==lifecycle[device.hostname] and device.agent_version=="0.2" and str(device.ip_address)=="192.0.2.10"
    return device.hostname=="MERGE-SMOKE" and device.device_identifier.startswith("merge-smoke-") and device.agent_version=="smoke-0.1" and str(device.ip_address)=="192.0.2.50"

async def purge_synthetic_devices(raw_ids:list[str],confirm:bool=False):
    try:ids=[uuid.UUID(value) for value in raw_ids]
    except ValueError:raise SystemExit("Every device ID must be a UUID")
    if not ids:raise SystemExit("At least one explicit device ID is required")
    async with SessionLocal() as db:
        devices=(await db.scalars(select(Device).where(Device.id.in_(ids)).with_for_update())).all()
        if len(devices)!=len(set(ids)):raise SystemExit("One or more device IDs do not exist")
        unsafe=[str(device.id) for device in devices if not synthetic_signature(device)]
        if unsafe:raise SystemExit("Cleanup refused: one or more records do not match a known synthetic signature")
        for device in devices:print(f"candidate {device.id} {device.hostname}")
        if not confirm:
            print("Dry run only; repeat with --confirm to delete these synthetic records")
            return
        for device in devices:
            db.add(AuditEvent(actor_id=None,action="test_data.device.purge",resource_type="device",resource_id=str(device.id),source_ip=None,previous_value={"hostname":device.hostname,"installation_id":device.device_identifier},new_value=None,result="success",request_id=f"cli-{uuid.uuid4()}"))
            await db.delete(device)
        await db.commit()
    print(f"Purged {len(devices)} confirmed synthetic device records; audit evidence retained")
if __name__=="__main__":
    if len(sys.argv)==3 and sys.argv[1]=="create-admin": asyncio.run(create_admin(sys.argv[2]))
    elif len(sys.argv)==3 and sys.argv[1]=="reset-admin-password": asyncio.run(reset_admin_password(sys.argv[2]))
    elif len(sys.argv)==4 and sys.argv[1]=="create-service-token": asyncio.run(create_service(sys.argv[2],sys.argv[3]))
    elif len(sys.argv)>=3 and sys.argv[1]=="purge-synthetic-devices": asyncio.run(purge_synthetic_devices([value for value in sys.argv[2:] if value!="--confirm"],"--confirm" in sys.argv[2:]))
    elif len(sys.argv)==3 and sys.argv[1]=="ensure-primary-discovery-network": asyncio.run(ensure_primary_discovery_network(sys.argv[2]))
    else: raise SystemExit("usage: python -m app.cli create-admin EMAIL | reset-admin-password EMAIL | create-service-token NAME KIND | purge-synthetic-devices UUID... [--confirm] | ensure-primary-discovery-network INTERFACE_CIDR")
