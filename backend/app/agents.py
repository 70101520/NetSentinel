import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import record
from app.config import settings
from app.db import get_db
from app.models import AgentEnrollment, AgentPairingRequest, AssetMetricSample, Device, DeviceProxyConfiguration, DeviceStateTransition, User
from app.schemas import DeviceAssignment, DeviceControlModeInput, EnrollRequest, Heartbeat, PairingApprovalInput, PairingClaimInput, PairingRequestInput, ProxyConfigurationInput
from app.security import require
from app.service_auth import derive_secret

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


async def enforce_enrollment_limit(request: Request, token_digest: str) -> None:
    source = request.client.host if request.client else "unknown"
    key = f"netsentinel:agent-enroll-rate:{source}:{token_digest[:16]}"
    redis = request.app.state.redis
    count = await redis.eval(
        "local n=redis.call('INCR',KEYS[1]); if n==1 then "
        "redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n",
        1,
        key,
        settings.agent_enrollment_rate_window_seconds,
    )
    if count > settings.agent_enrollment_rate_limit:
        raise HTTPException(429, "Enrollment rate limit exceeded")

def pairing_status(item:AgentPairingRequest,now:datetime):
    if item.rejected_at:return "rejected"
    if item.expires_at<=now:return "expired"
    if item.approved_at:return "approved"
    return "pending"

@router.post("/pairing-requests",status_code=201)
async def request_pairing(request:Request,body:PairingRequestInput,db:AsyncSession=Depends(get_db)):
    now=datetime.now(timezone.utc);digest=derive_secret(body.pairing_secret)
    await enforce_enrollment_limit(request,digest)
    if await db.scalar(select(Device.id).where(Device.device_identifier==body.installation_id)):raise HTTPException(409,"Installation is already enrolled")
    item=await db.scalar(select(AgentPairingRequest).where(AgentPairingRequest.installation_id==body.installation_id).with_for_update())
    if item and pairing_status(item,now) in {"pending","approved"}:
        if not secrets.compare_digest(item.pairing_secret_hash,digest):raise HTTPException(409,"A pairing request already exists for this installation")
    elif item:
        item.pairing_secret_hash=digest;item.pairing_code=secrets.token_hex(4).upper();item.created_at=now;item.expires_at=now+timedelta(hours=24);item.approved_at=None;item.rejected_at=None;item.claimed_at=None;item.approved_by=None;item.device_id=None;item.requested_control_mode=body.requested_control_mode
    else:
        item=AgentPairingRequest(installation_id=body.installation_id,pairing_secret_hash=digest,pairing_code=secrets.token_hex(4).upper(),expires_at=now+timedelta(hours=24),hostname=body.hostname,os_name=body.os_name,os_version=body.os_version,architecture=body.architecture,agent_version=body.agent_version,requested_ip=str(body.initial_ip) if body.initial_ip else None,requested_control_mode=body.requested_control_mode);db.add(item)
    item.hostname=body.hostname;item.os_name=body.os_name;item.os_version=body.os_version;item.architecture=body.architecture;item.agent_version=body.agent_version;item.requested_ip=str(body.initial_ip) if body.initial_ip else item.requested_ip;item.requested_control_mode=body.requested_control_mode
    await db.commit();await db.refresh(item)
    return {"id":item.id,"pairing_code":item.pairing_code,"status":pairing_status(item,now),"expires_at":item.expires_at}

@router.post("/pairing-requests/{pairing_id}/claim")
async def claim_pairing(pairing_id:uuid.UUID,body:PairingClaimInput,db:AsyncSession=Depends(get_db)):
    now=datetime.now(timezone.utc);item=await db.get(AgentPairingRequest,pairing_id,with_for_update=True)
    if not item or not secrets.compare_digest(item.pairing_secret_hash,derive_secret(body.pairing_secret)):raise HTTPException(401,"Invalid pairing request")
    status=pairing_status(item,now)
    if status=="pending":return {"status":"pending","pairing_code":item.pairing_code,"expires_at":item.expires_at}
    if status=="rejected":raise HTTPException(403,"Pairing request was rejected")
    if status=="expired":raise HTTPException(410,"Pairing request expired")
    device=await db.get(Device,item.device_id)
    if not device:raise HTTPException(409,"Approved pairing has no device identity")
    item.claimed_at=now;await db.commit()
    return {"status":"approved","device_id":device.id,"agent_identity":device.agent_identity,"credential":f"{device.id}.{body.pairing_secret}","server":{"heartbeat_interval_seconds":settings.agent_heartbeat_interval_seconds}}

@router.get("/pairing-requests")
async def list_pairings(db:AsyncSession=Depends(get_db),_:User=Depends(require("agents.manage"))):
    now=datetime.now(timezone.utc);rows=(await db.scalars(select(AgentPairingRequest).order_by(AgentPairingRequest.created_at.desc()).limit(200))).all()
    return [{"id":item.id,"pairing_code":item.pairing_code,"hostname":item.hostname,"os_name":item.os_name,"os_version":item.os_version,"architecture":item.architecture,"agent_version":item.agent_version,"requested_ip":str(item.requested_ip) if item.requested_ip else None,"created_at":item.created_at,"expires_at":item.expires_at,"status":pairing_status(item,now),"device_id":item.device_id,"group_name":item.group_name,"department":item.department,"requested_control_mode":item.requested_control_mode} for item in rows]

@router.post("/pairing-requests/{pairing_id}/approve")
async def approve_pairing(pairing_id:uuid.UUID,body:PairingApprovalInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    now=datetime.now(timezone.utc);item=await db.get(AgentPairingRequest,pairing_id,with_for_update=True)
    if not item:raise HTTPException(404,"Pairing request not found")
    if pairing_status(item,now)!="pending":raise HTTPException(409,"Only a pending pairing request can be approved")
    if await db.scalar(select(Device.id).where(Device.device_identifier==item.installation_id)):raise HTTPException(409,"Installation is already enrolled")
    device=Device(device_identifier=item.installation_id,agent_identity=uuid.uuid4(),credential_hash=item.pairing_secret_hash,hostname=item.hostname,ip_address=item.requested_ip,os_name=item.os_name,os_version=item.os_version,architecture=item.architecture,agent_version=item.agent_version,last_seen=now,current_status="OFFLINE",group_name=body.group_name,department=body.department,control_mode=body.control_mode);db.add(device);await db.flush()
    item.approved_at=now;item.approved_by=user.id;item.device_id=device.id;item.group_name=body.group_name;item.department=body.department
    db.add(DeviceStateTransition(device_id=device.id,previous_status="UNENROLLED",new_status="OFFLINE"));await record(db,request,user,"agent.pairing.approve","agent_pairing",str(item.id),"success",new={"device_id":str(device.id),"hostname":device.hostname,"control_mode":device.control_mode});await db.commit()
    return {"id":item.id,"status":"approved","device_id":device.id}

@router.post("/pairing-requests/{pairing_id}/reject")
async def reject_pairing(pairing_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    now=datetime.now(timezone.utc);item=await db.get(AgentPairingRequest,pairing_id,with_for_update=True)
    if not item:raise HTTPException(404,"Pairing request not found")
    if pairing_status(item,now)!="pending":raise HTTPException(409,"Only a pending pairing request can be rejected")
    item.rejected_at=now;await record(db,request,user,"agent.pairing.reject","agent_pairing",str(item.id),"success",new={"hostname":item.hostname});await db.commit()
    return {"id":item.id,"status":"rejected"}


@router.post("/enrollment-tokens")
async def create_enrollment(request: Request, expires_minutes: int = 60, max_uses: int = 1,
                            group: str | None = None, department: str | None = None,
                            db: AsyncSession = Depends(get_db),
                            user: User = Depends(require("agents.manage"))):
    if not 1 <= max_uses <= 10000 or not 1 <= expires_minutes <= 10080:
        raise HTTPException(422, "Invalid enrollment limits")
    raw = secrets.token_urlsafe(32)
    item = AgentEnrollment(token_hash=derive_secret(raw), expires_at=datetime.now(timezone.utc) + timedelta(minutes=expires_minutes), max_uses=max_uses, group_name=group, department=department, created_by=user.id)
    db.add(item)
    await db.flush()
    await record(db, request, user, "agent.enrollment_token.create", "agent_enrollment", str(item.id), "success", new={"expires_at": item.expires_at.isoformat(), "max_uses": max_uses, "group": group, "department": department})
    await db.commit()
    return {"id": item.id, "token": raw, "expires_at": item.expires_at, "max_uses": max_uses, "use_count": 0}


@router.get("/enrollment-tokens")
async def list_enrollments(db: AsyncSession = Depends(get_db), _: User = Depends(require("agents.manage"))):
    now = datetime.now(timezone.utc)
    rows = (await db.scalars(select(AgentEnrollment).order_by(AgentEnrollment.created_at.desc()))).all()
    return [{"id": row.id, "created_at": row.created_at, "expires_at": row.expires_at, "revoked_at": row.revoked_at, "max_uses": row.max_uses, "use_count": row.use_count, "group_name": row.group_name, "department": row.department, "status": "revoked" if row.revoked_at else "expired" if row.expires_at <= now else "exhausted" if row.use_count >= row.max_uses else "active"} for row in rows]


@router.post("/enrollment-tokens/{token_id}/revoke")
async def revoke_enrollment(token_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(require("agents.manage"))):
    item = await db.get(AgentEnrollment, token_id, with_for_update=True)
    if not item:
        raise HTTPException(404, "Enrollment token not found")
    if not item.revoked_at:
        item.revoked_at = datetime.now(timezone.utc)
        await record(db, request, user, "agent.enrollment_token.revoke", "agent_enrollment", str(item.id), "success")
        await db.commit()
    return {"id": item.id, "revoked_at": item.revoked_at}


@router.post("/enroll", status_code=201)
async def enroll(request: Request, body: EnrollRequest, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    digest = derive_secret(body.enrollment_token)
    await enforce_enrollment_limit(request, digest)
    token = await db.scalar(select(AgentEnrollment).where(AgentEnrollment.token_hash == digest).with_for_update())
    if not token or token.revoked_at or token.expires_at <= now or token.use_count >= token.max_uses:
        raise HTTPException(401, "Invalid enrollment token")
    if await db.scalar(select(Device.id).where(Device.device_identifier == body.installation_id)):
        raise HTTPException(409, "Installation already enrolled; explicit administrator action is required")
    raw = secrets.token_urlsafe(32)
    device = Device(device_identifier=body.installation_id, agent_identity=uuid.uuid4(), credential_hash=derive_secret(raw), hostname=body.hostname, ip_address=str(body.initial_ip) if body.initial_ip else None, mac_address=body.mac_address, os_name=body.os_name, os_version=body.os_version, architecture=body.architecture, agent_version=body.agent_version, last_seen=now, last_heartbeat=now, current_status="ONLINE", group_name=token.group_name, department=token.department)
    db.add(device)
    token.use_count += 1
    token.used_at = now
    await db.flush()
    db.add(DeviceStateTransition(device_id=device.id, previous_status="UNENROLLED", new_status="ONLINE"))
    await db.commit()
    return {"device_id": device.id, "agent_identity": device.agent_identity, "credential": f"{device.id}.{raw}", "server": {"heartbeat_interval_seconds": settings.agent_heartbeat_interval_seconds}}


async def authenticate_credential(x_agent_credential: str, db: AsyncSession, expected_device_id: uuid.UUID | None = None):
    try:
        device_id, raw = x_agent_credential.split(".", 1)
        device_id = uuid.UUID(device_id)
    except (ValueError, AttributeError):
        raise HTTPException(401, "Invalid agent credential")
    device = await db.scalar(select(Device).where(Device.id == device_id).with_for_update())
    if not device or (expected_device_id and device.id != expected_device_id) or device.credential_revoked_at or device.enrollment_state != "ENROLLED" or not device.credential_hash or not secrets.compare_digest(derive_secret(raw), device.credential_hash):
        raise HTTPException(401, "Invalid agent credential")
    return device

async def authenticated_agent(body: Heartbeat, x_agent_credential: str = Header(...), db: AsyncSession = Depends(get_db)):
    return await authenticate_credential(x_agent_credential, db, body.device_id)

async def authenticated_agent_header(x_agent_credential: str = Header(...), db: AsyncSession = Depends(get_db)):
    return await authenticate_credential(x_agent_credential, db)

def proxy_payload(item: DeviceProxyConfiguration | None,force_disabled:bool=False):
    return {"proxy": {"enabled": item.enabled if item and not force_disabled else False, "host": item.host if item and not force_disabled else None, "port": item.port if item and not force_disabled else None, "bypass": item.bypass if item and not force_disabled else [], "mode": item.mode if item and not force_disabled else "disabled", "version": item.version if item else 1}}

@router.get("/config")
async def agent_config(db: AsyncSession = Depends(get_db), device: Device = Depends(authenticated_agent_header)):
    return {"control_mode":device.control_mode,**proxy_payload(await db.get(DeviceProxyConfiguration,device.id),force_disabled=device.control_mode!="WEB_CONTROLLED")}

@router.put("/control-mode")
async def sync_agent_control_mode(body:DeviceControlModeInput,db:AsyncSession=Depends(get_db),device:Device=Depends(authenticated_agent_header)):
    if device.control_mode!=body.control_mode:
        device.control_mode=body.control_mode
        proxy=await db.get(DeviceProxyConfiguration,device.id,with_for_update=True)
        if proxy:proxy.version+=1
        else:db.add(DeviceProxyConfiguration(device_id=device.id,enabled=False,bypass=[],mode="disabled",version=1))
        await db.commit()
    return {"id":device.id,"control_mode":device.control_mode}

@router.get("/devices/{device_id}/proxy-config")
async def get_proxy_config(device_id: uuid.UUID, db: AsyncSession = Depends(get_db), _: User = Depends(require("agents.manage"))):
    if not await db.get(Device, device_id): raise HTTPException(404, "Device not found")
    device=await db.get(Device,device_id)
    item=await db.get(DeviceProxyConfiguration,device_id)
    return {"control_mode":device.control_mode,**proxy_payload(item),"reported":None if not item else {"applied_version":item.applied_version,"current_state":item.current_state,"drift_detected":item.drift_detected,"last_apply_result":item.last_apply_result,"last_error":item.last_error,"effective_host":item.effective_host,"effective_port":item.effective_port,"bypass_summary":item.bypass_summary,"last_reported_at":item.last_reported_at}}

@router.put("/devices/{device_id}/control-mode")
async def update_control_mode(device_id:uuid.UUID,body:DeviceControlModeInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    device=await db.get(Device,device_id,with_for_update=True)
    if not device:raise HTTPException(404,"Device not found")
    previous=device.control_mode
    if previous!=body.control_mode:
        device.control_mode=body.control_mode
        proxy=await db.get(DeviceProxyConfiguration,device_id,with_for_update=True)
        if proxy:proxy.version+=1
        else:db.add(DeviceProxyConfiguration(device_id=device_id,enabled=False,bypass=[],mode="disabled",version=1))
        await record(db,request,user,"agent.control_mode.update","device",str(device_id),"success",previous={"control_mode":previous},new={"control_mode":body.control_mode})
        await db.commit()
    return {"id":device.id,"control_mode":device.control_mode}

@router.put("/devices/{device_id}/proxy-config")
async def update_proxy_config(device_id: uuid.UUID, body: ProxyConfigurationInput, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(require("agents.manage"))):
    if not await db.get(Device,device_id):raise HTTPException(404,"Device not found")
    item=await db.get(DeviceProxyConfiguration,device_id,with_for_update=True)
    desired={"enabled":body.enabled,"host":body.host if body.enabled else None,"port":body.port if body.enabled else None,"bypass":body.bypass if body.enabled else [],"mode":body.mode}
    previous=None if not item else {"enabled":item.enabled,"host":item.host,"port":item.port,"bypass":item.bypass,"mode":item.mode,"version":item.version}
    if not item:
        item=DeviceProxyConfiguration(device_id=device_id,version=1,**desired);db.add(item)
    elif any(getattr(item,key)!=value for key,value in desired.items()):
        for key,value in desired.items():setattr(item,key,value)
        item.version+=1
    await db.flush()
    await record(db,request,user,"agent.proxy.configuration.update","device",str(device_id),"success",previous=previous,new={**desired,"version":item.version})
    await db.commit()
    return proxy_payload(item)


@router.post("/heartbeat")
async def heartbeat(request: Request, body: Heartbeat, db: AsyncSession = Depends(get_db), device: Device = Depends(authenticated_agent)):
    now = datetime.now(timezone.utc)
    previous = device.current_status
    device.hostname, device.username = body.hostname, body.username
    device.agent_version, device.os_name, device.os_version = body.agent_version, body.os_name, body.os_version
    device.ip_address = str(body.active_ips[0]) if body.active_ips else device.ip_address
    device.last_heartbeat_ip = request.client.host if request.client else None
    device.boot_time, device.uptime_seconds = body.boot_time, body.uptime_seconds
    device.last_seen = device.last_heartbeat = now
    device.current_status = "ONLINE"
    metadata={**(device.metadata_ or {}),"active_ips":[str(v) for v in body.active_ips],"mac_addresses":body.mac_addresses,"gateway":str(body.gateway) if body.gateway else None,"dns":[str(v) for v in body.dns]}
    if body.system_metrics:
        metrics=body.system_metrics.model_dump(mode="json")
        metadata["system_metrics"]=metrics
        last_sample_text=metadata.get("metric_history_sampled_at")
        last_sample=datetime.fromisoformat(last_sample_text) if last_sample_text else None
        if not last_sample or (now-last_sample).total_seconds()>=30:
            db.add(AssetMetricSample(source_type="agent",source_id=device.id,sampled_at=now,uptime_seconds=body.uptime_seconds,cpu_percent=body.system_metrics.cpu_percent,memory_percent=body.system_metrics.memory_percent,disk_percent=body.system_metrics.disk_percent,network_receive_bps=body.system_metrics.network_receive_bps,network_send_bps=body.system_metrics.network_send_bps,interfaces=[{"name":body.system_metrics.network_adapter or "Primary adapter","status":"up","receive_bps":body.system_metrics.network_receive_bps,"send_bps":body.system_metrics.network_send_bps}]))
            metadata["metric_history_sampled_at"]=now.isoformat()
    device.metadata_=metadata
    if body.proxy_status:
        proxy=await db.get(DeviceProxyConfiguration,device.id)
        if proxy:
            report=body.proxy_status
            proxy.applied_version=report.applied_version;proxy.current_state=report.current_state;proxy.drift_detected=report.drift_detected
            proxy.last_apply_result=report.last_apply_result;proxy.last_error=report.last_error;proxy.effective_host=report.effective_host;proxy.effective_port=report.effective_port
            proxy.bypass_summary=report.bypass_summary;proxy.last_reported_at=now
    if previous != "ONLINE":
        db.add(DeviceStateTransition(device_id=device.id, previous_status=previous, new_status="ONLINE"))
    await db.commit()
    return {"status": "accepted", "server_time": now, "next_heartbeat_seconds": settings.agent_heartbeat_interval_seconds}


@router.post("/offline")
async def agent_offline(request: Request, db: AsyncSession = Depends(get_db), device: Device = Depends(authenticated_agent_header)):
    if device.current_status != "OFFLINE":
        previous = device.current_status
        device.current_status = "OFFLINE"
        db.add(DeviceStateTransition(device_id=device.id, previous_status=previous, new_status="OFFLINE"))
        await db.commit()
    return {"status": "accepted"}


@router.post("/devices/{device_id}/revoke")
async def revoke_device(device_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(require("agents.manage"))):
    device = await db.get(Device, device_id, with_for_update=True)
    if not device:
        raise HTTPException(404, "Device not found")
    if device.enrollment_state != "REVOKED":
        previous = {"enrollment_state": device.enrollment_state}
        device.enrollment_state = "REVOKED"
        device.credential_revoked_at = datetime.now(timezone.utc)
        await record(db, request, user, "agent.endpoint.revoke", "device", str(device.id), "success", previous=previous, new={"enrollment_state": "REVOKED"})
        await db.commit()
    return {"id": device.id, "enrollment_state": device.enrollment_state}


@router.post("/devices/{device_id}/rotate-credential")
async def rotate_credential(device_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(require("agents.manage"))):
    device = await db.get(Device, device_id, with_for_update=True)
    if not device or device.enrollment_state != "ENROLLED":
        raise HTTPException(404, "Active device not found")
    raw = secrets.token_urlsafe(32)
    old_version = device.credential_version
    device.credential_hash = derive_secret(raw)
    device.credential_version += 1
    device.credential_revoked_at = None
    await record(db, request, user, "agent.endpoint.credential.rotate", "device", str(device.id), "success", previous={"credential_version": old_version}, new={"credential_version": device.credential_version})
    await db.commit()
    return {"device_id": device.id, "credential": f"{device.id}.{raw}", "credential_version": device.credential_version}


@router.patch("/devices/{device_id}/assignment")
async def assign_device(device_id: uuid.UUID, body: DeviceAssignment, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(require("agents.manage"))):
    device = await db.get(Device, device_id, with_for_update=True)
    if not device:
        raise HTTPException(404, "Device not found")
    previous = {"group_name": device.group_name, "department": device.department}
    device.group_name, device.department = body.group_name, body.department
    await record(db, request, user, "agent.endpoint.assignment.update", "device", str(device.id), "success", previous=previous, new=body.model_dump())
    await db.commit()
    return {"id": device.id, **body.model_dump()}
