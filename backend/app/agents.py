import secrets,uuid
from datetime import datetime,timedelta,timezone
from fastapi import APIRouter,Depends,Header,HTTPException,Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.audit import record
from app.config import settings
from app.db import get_db
from app.models import AgentEnrollment,Device,DeviceStateTransition,User
from app.schemas import EnrollRequest,Heartbeat
from app.security import require
from app.service_auth import derive_secret
router=APIRouter(prefix="/api/v1/agents",tags=["agents"])
@router.post("/enrollment-tokens")
async def create_enrollment(request:Request,expires_minutes:int=60,max_uses:int=1,group:str|None=None,department:str|None=None,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    if not 1<=max_uses<=10000 or not 1<=expires_minutes<=10080: raise HTTPException(422,"Invalid enrollment limits")
    raw=secrets.token_urlsafe(32); item=AgentEnrollment(token_hash=derive_secret(raw),expires_at=datetime.now(timezone.utc)+timedelta(minutes=expires_minutes),max_uses=max_uses,group_name=group,department=department,created_by=user.id); db.add(item); await db.flush(); await record(db,request,user,"agent.enrollment_token.create","agent_enrollment",str(item.id),"success",new={"expires_at":item.expires_at.isoformat(),"max_uses":max_uses}); await db.commit(); return {"id":item.id,"token":raw,"expires_at":item.expires_at,"max_uses":max_uses}
@router.post("/enroll",status_code=201)
async def enroll(body:EnrollRequest,db:AsyncSession=Depends(get_db)):
    now=datetime.now(timezone.utc); digest=derive_secret(body.enrollment_token)
    token=await db.scalar(select(AgentEnrollment).where(AgentEnrollment.token_hash==digest).with_for_update())
    if not token or token.revoked_at or token.expires_at<=now or token.use_count>=token.max_uses: raise HTTPException(401,"Invalid enrollment token")
    if await db.scalar(select(Device.id).where(Device.device_identifier==body.installation_id)): raise HTTPException(409,"Installation already enrolled")
    secret=secrets.token_urlsafe(32); device=Device(device_identifier=body.installation_id,agent_identity=uuid.uuid4(),credential_hash=derive_secret(secret),hostname=body.hostname,ip_address=str(body.initial_ip) if body.initial_ip else None,mac_address=body.mac_address,os_name=body.os_name,os_version=body.os_version,architecture=body.architecture,agent_version=body.agent_version,last_seen=now,current_status="ONLINE",group_name=token.group_name,department=token.department); db.add(device); token.use_count+=1; token.used_at=now; await db.flush(); db.add(DeviceStateTransition(device_id=device.id,previous_status="UNENROLLED",new_status="ONLINE")); await db.commit(); return {"device_id":device.id,"agent_identity":device.agent_identity,"credential":f"{device.id}.{secret}","server":{"heartbeat_interval_seconds":settings.agent_heartbeat_interval_seconds}}
async def agent(body:Heartbeat,x_agent_credential:str=Header(...),db:AsyncSession=Depends(get_db)):
    try: device_id,secret=x_agent_credential.split(".",1); device_id=uuid.UUID(device_id)
    except Exception: raise HTTPException(401,"Invalid agent credential")
    device=await db.scalar(select(Device).where(Device.id==device_id).with_for_update())
    if not device or device.id!=body.device_id or device.credential_revoked_at or not device.credential_hash or not secrets.compare_digest(derive_secret(secret),device.credential_hash): raise HTTPException(401,"Invalid agent credential")
    return device
@router.post("/heartbeat")
async def heartbeat(request:Request,body:Heartbeat,db:AsyncSession=Depends(get_db),device:Device=Depends(agent)):
    now=datetime.now(timezone.utc); previous=device.current_status
    stale=device.last_heartbeat and (now-device.last_heartbeat).total_seconds()>settings.agent_heartbeat_timeout_seconds
    if stale and previous=="ONLINE":
        db.add(DeviceStateTransition(device_id=device.id,occurred_at=device.last_heartbeat+timedelta(seconds=settings.agent_heartbeat_timeout_seconds),previous_status="ONLINE",new_status="OFFLINE")); previous="OFFLINE"
    device.hostname=body.hostname; device.username=body.username; device.agent_version=body.agent_version; device.os_name=body.os_name; device.os_version=body.os_version; device.ip_address=str(body.active_ips[0]) if body.active_ips else device.ip_address; device.last_heartbeat_ip=request.client.host if request.client else None; device.boot_time=body.boot_time; device.uptime_seconds=body.uptime_seconds; device.last_seen=now; device.last_heartbeat=now; device.current_status="ONLINE"; device.metadata_={"active_ips":[str(v) for v in body.active_ips],"mac_addresses":body.mac_addresses,"gateway":str(body.gateway) if body.gateway else None,"dns":[str(v) for v in body.dns]}
    if previous!="ONLINE": db.add(DeviceStateTransition(device_id=device.id,previous_status=previous,new_status="ONLINE"))
    await db.commit(); return {"status":"accepted","server_time":now,"next_heartbeat_seconds":settings.agent_heartbeat_interval_seconds}
