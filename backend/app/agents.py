import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import record
from app.config import settings
from app.db import get_db
from app.models import AgentEnrollment, Device, DeviceStateTransition, User
from app.schemas import DeviceAssignment, EnrollRequest, Heartbeat
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


async def authenticated_agent(body: Heartbeat, x_agent_credential: str = Header(...), db: AsyncSession = Depends(get_db)):
    try:
        device_id, raw = x_agent_credential.split(".", 1)
        device_id = uuid.UUID(device_id)
    except (ValueError, AttributeError):
        raise HTTPException(401, "Invalid agent credential")
    device = await db.scalar(select(Device).where(Device.id == device_id).with_for_update())
    if not device or device.id != body.device_id or device.credential_revoked_at or device.enrollment_state != "ENROLLED" or not device.credential_hash or not secrets.compare_digest(derive_secret(raw), device.credential_hash):
        raise HTTPException(401, "Invalid agent credential")
    return device


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
    device.metadata_ = {"active_ips": [str(v) for v in body.active_ips], "mac_addresses": body.mac_addresses, "gateway": str(body.gateway) if body.gateway else None, "dns": [str(v) for v in body.dns]}
    if previous != "ONLINE":
        db.add(DeviceStateTransition(device_id=device.id, previous_status=previous, new_status="ONLINE"))
    await db.commit()
    return {"status": "accepted", "server_time": now, "next_heartbeat_seconds": settings.agent_heartbeat_interval_seconds}


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
