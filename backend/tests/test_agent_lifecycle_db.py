import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import delete, func, select, update

from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import AgentEnrollment, AuditEvent, Device, DeviceStateTransition, Permission, Role, RolePermission, User, UserRole
from app.offline import mark_stale_devices_offline
from app.security import issue_token
from app.service_auth import derive_secret


@pytest.fixture
async def client():
    async with SessionLocal() as db:
        await db.execute(delete(DeviceStateTransition)); await db.execute(delete(AuditEvent)); await db.execute(delete(Device)); await db.execute(delete(AgentEnrollment))
        user = await db.scalar(select(User).where(User.email == "agent-tests@example.invalid"))
        if not user:
            user = User(email="agent-tests@example.invalid", password_hash="unused")
            role = Role(name=f"agent-tests-{uuid.uuid4()}")
            permissions = [Permission(code=f"agent-test-{uuid.uuid4()}-{code}") for code in ("agents", "devices")]
            permissions[0].code, permissions[1].code = "agents.manage", "devices.view"
            for permission in permissions:
                existing = await db.scalar(select(Permission).where(Permission.code == permission.code))
                if existing: permission = existing
                else: db.add(permission); await db.flush()
                role.permissions.append(permission)
            user.roles.append(role); db.add(user)
        await db.commit(); await db.refresh(user)
        bearer = issue_token(user)
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    rate_keys = [key async for key in redis.scan_iter("netsentinel:agent-enroll-rate:*")]
    if rate_keys:
        await redis.delete(*rate_keys)
    app.state.redis = redis
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers={"Authorization": f"Bearer {bearer}"}) as value:
        yield value
    await redis.aclose()


def enrollment_body(token, installation="install-001", hostname="PC-001"):
    return {"enrollment_token": token, "installation_id": installation, "hostname": hostname, "os_name": "Windows", "os_version": "11", "architecture": "x64", "initial_ip": "192.0.2.10", "agent_version": "0.2"}


def heartbeat_body(device_id, hostname="PC-001"):
    return {"device_id": device_id, "timestamp": datetime.now(timezone.utc).isoformat(), "hostname": hostname, "username": "alice", "agent_version": "0.2", "os_name": "Windows", "os_version": "11", "active_ips": ["192.0.2.10"], "mac_addresses": ["02:00:00:00:00:01"], "uptime_seconds": 100}


@pytest.mark.asyncio
async def test_complete_endpoint_lifecycle_and_inventory(client):
    created = await client.post("/api/v1/agents/enrollment-tokens?expires_minutes=60&max_uses=2&group=HQ&department=IT")
    assert created.status_code == 200
    token = created.json()["token"]
    listed = (await client.get("/api/v1/agents/enrollment-tokens")).json()
    assert listed[0]["use_count"] == 0 and "token" not in listed[0]
    enrolled = await client.post("/api/v1/agents/enroll", json=enrollment_body(token))
    assert enrolled.status_code == 201
    identity = enrolled.json(); credential = identity["credential"]
    duplicate = await client.post("/api/v1/agents/enroll", json=enrollment_body(token))
    assert duplicate.status_code == 409
    heartbeat = await client.post("/api/v1/agents/heartbeat", json=heartbeat_body(identity["device_id"]), headers={"X-Agent-Credential": credential})
    assert heartbeat.status_code == 200
    assert (await client.post("/api/v1/agents/heartbeat", json=heartbeat_body(identity["device_id"]), headers={"X-Agent-Credential": credential + "bad"})).status_code == 401
    details = await client.get(f"/api/v1/devices/{identity['device_id']}")
    assert details.status_code == 200 and details.json()["group_name"] == "HQ" and details.json()["active_ips"] == ["192.0.2.10"]
    rotated = await client.post(f"/api/v1/agents/devices/{identity['device_id']}/rotate-credential")
    new_credential = rotated.json()["credential"]
    assert (await client.post("/api/v1/agents/heartbeat", json=heartbeat_body(identity["device_id"]), headers={"X-Agent-Credential": credential})).status_code == 401
    assert (await client.post("/api/v1/agents/heartbeat", json=heartbeat_body(identity["device_id"]), headers={"X-Agent-Credential": new_credential})).status_code == 200
    # A fresh client represents an API process restart; persisted credentials remain usable.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as restarted:
        assert (await restarted.post("/api/v1/agents/heartbeat", json=heartbeat_body(identity["device_id"]), headers={"X-Agent-Credential": new_credential})).status_code == 200
    revoked = await client.post(f"/api/v1/agents/devices/{identity['device_id']}/revoke")
    assert revoked.status_code == 200
    assert (await client.post("/api/v1/agents/heartbeat", json=heartbeat_body(identity["device_id"]), headers={"X-Agent-Credential": new_credential})).status_code == 401
    assert (await client.get(f"/api/v1/devices/{identity['device_id']}")).status_code == 200
    async with SessionLocal() as db:
        actions = set((await db.scalars(select(AuditEvent.action))).all())
        assert {"agent.enrollment_token.create", "agent.endpoint.credential.rotate", "agent.endpoint.revoke"} <= actions


@pytest.mark.asyncio
async def test_token_denials_rate_limit_and_atomic_usage(client):
    invalid = enrollment_body("x" * 32, "invalid-001")
    for _ in range(settings.agent_enrollment_rate_limit):
        assert (await client.post("/api/v1/agents/enroll", json=invalid)).status_code == 401
    assert (await client.post("/api/v1/agents/enroll", json=invalid)).status_code == 429
    async with SessionLocal() as db:
        expired = AgentEnrollment(token_hash=derive_secret("e" * 32), expires_at=datetime.now(timezone.utc) - timedelta(seconds=1), max_uses=1)
        revoked = AgentEnrollment(token_hash=derive_secret("r" * 32), expires_at=datetime.now(timezone.utc) + timedelta(hours=1), revoked_at=datetime.now(timezone.utc), max_uses=1)
        exhausted = AgentEnrollment(token_hash=derive_secret("u" * 32), expires_at=datetime.now(timezone.utc) + timedelta(hours=1), max_uses=1, use_count=1)
        db.add_all([expired, revoked, exhausted]); await db.commit()
    for index, raw in enumerate(("e" * 32, "r" * 32, "u" * 32)):
        assert (await client.post("/api/v1/agents/enroll", json=enrollment_body(raw, f"denied-{index:03d}"))).status_code == 401


@pytest.mark.asyncio
async def test_offline_reconnect_pagination_and_filters(client):
    created = (await client.post("/api/v1/agents/enrollment-tokens?max_uses=3&group=Remote&department=Ops")).json()
    identities = []
    for index, name in enumerate(("ALPHA", "BRAVO", "CHARLIE")):
        response = await client.post("/api/v1/agents/enroll", json=enrollment_body(created["token"], f"filter-{index:03d}", name))
        identities.append(response.json())
    first = identities[0]
    stale = datetime.now(timezone.utc) - timedelta(seconds=settings.agent_heartbeat_timeout_seconds + 5)
    async with SessionLocal() as db:
        await db.execute(update(Device).where(Device.id == uuid.UUID(first["device_id"])).values(last_heartbeat=stale)); await db.commit()
    assert await mark_stale_devices_offline() == 1
    async with SessionLocal() as db:
        device = await db.get(Device, uuid.UUID(first["device_id"])); assert device.current_status == "OFFLINE"
        count = await db.scalar(select(func.count()).select_from(DeviceStateTransition).where(DeviceStateTransition.device_id == device.id)); assert count == 2
    assert (await client.post("/api/v1/agents/heartbeat", json=heartbeat_body(first["device_id"], "ALPHA"), headers={"X-Agent-Credential": first["credential"]})).status_code == 200
    async with SessionLocal() as db:
        transitions = (await db.scalars(select(DeviceStateTransition).where(DeviceStateTransition.device_id == uuid.UUID(first["device_id"])).order_by(DeviceStateTransition.occurred_at))).all()
        assert [(item.previous_status, item.new_status) for item in transitions][-2:] == [("ONLINE", "OFFLINE"), ("OFFLINE", "ONLINE")]
    assert (await client.get("/api/v1/devices?page=1&page_size=2")).json()["meta"]["pages"] == 2
    assert (await client.get("/api/v1/devices?page_size=9999")).json()["meta"]["page_size"] == settings.max_page_size
    assert (await client.get("/api/v1/devices?hostname=BRAVO")).json()["meta"]["total"] == 1
    assert (await client.get("/api/v1/devices?ip=192.0.2.10")).json()["meta"]["total"] == 3
    assert (await client.get("/api/v1/devices?username=alice")).json()["meta"]["total"] == 1
    assert (await client.get("/api/v1/devices?group=Remote")).json()["meta"]["total"] == 3
    assert (await client.get("/api/v1/devices?department=Ops")).json()["meta"]["total"] == 3
    assert (await client.get("/api/v1/devices?status=online")).json()["meta"]["total"] == 3
    assert (await client.get("/api/v1/devices?status=offline")).json()["meta"]["total"] == 0
