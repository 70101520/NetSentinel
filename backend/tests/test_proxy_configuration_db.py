import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import delete, select

from app.config import settings
from app.db import SessionLocal, engine
from app.main import app
from app.models import AgentEnrollment, Device, DeviceProxyConfiguration, Permission, Role, User
from app.security import issue_token
from app.service_auth import derive_secret

@pytest.fixture
async def proxy_client():
    await engine.dispose()
    async with SessionLocal() as db:
        await db.execute(delete(DeviceProxyConfiguration));await db.execute(delete(Device));await db.execute(delete(AgentEnrollment))
        permission=await db.scalar(select(Permission).where(Permission.code=="agents.manage"))
        if not permission:permission=Permission(code="agents.manage");db.add(permission);await db.flush()
        user=User(email=f"proxy-{uuid.uuid4()}@example.invalid",password_hash="unused")
        role=Role(name=f"proxy-{uuid.uuid4()}");role.permissions.append(permission);user.roles.append(role);db.add(user)
        first=Device(device_identifier="proxy-device-1",hostname="PROXY-ONE",credential_hash=derive_secret("first-secret"),enrollment_state="ENROLLED")
        second=Device(device_identifier="proxy-device-2",hostname="PROXY-TWO",credential_hash=derive_secret("second-secret"),enrollment_state="ENROLLED")
        revoked=Device(device_identifier="proxy-device-3",hostname="PROXY-REVOKED",credential_hash=derive_secret("revoked-secret"),enrollment_state="REVOKED",credential_revoked_at=datetime.now(timezone.utc))
        db.add_all([first,second,revoked]);await db.commit();await db.refresh(user);await db.refresh(first);await db.refresh(second);await db.refresh(revoked)
        values=(issue_token(user),first,second,revoked)
    app.state.redis=Redis.from_url(settings.redis_url,decode_responses=True)
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test",headers={"Authorization":f"Bearer {values[0]}"}) as client:
        yield client,values[1],values[2],values[3]
    await app.state.redis.aclose();await engine.dispose()

@pytest.mark.asyncio
async def test_proxy_configuration_lifecycle_validation_and_isolation(proxy_client):
    client,first,second,revoked=proxy_client
    first_header={"X-Agent-Credential":f"{first.id}.first-secret"}
    second_header={"X-Agent-Credential":f"{second.id}.second-secret"}
    disabled=await client.get("/api/v1/agents/config",headers=first_header)
    assert disabled.status_code==200 and disabled.json()["proxy"]=={"enabled":False,"host":None,"port":None,"bypass":[],"mode":"disabled","version":1}
    body={"enabled":True,"host":"proxy.test.invalid","port":3128,"bypass":["localhost","127.0.0.1","*.internal.invalid"],"mode":"configured"}
    saved=await client.put(f"/api/v1/agents/devices/{first.id}/proxy-config",json=body)
    assert saved.status_code==200 and saved.json()["proxy"]["version"]==1
    assert (await client.get("/api/v1/agents/config",headers=first_header)).json()["proxy"]["host"]=="proxy.test.invalid"
    assert (await client.get("/api/v1/agents/config",headers=second_header)).json()["proxy"]["enabled"] is False
    unchanged=await client.put(f"/api/v1/agents/devices/{first.id}/proxy-config",json=body)
    assert unchanged.json()["proxy"]["version"]==1
    body["port"]=8080
    changed=await client.put(f"/api/v1/agents/devices/{first.id}/proxy-config",json=body)
    assert changed.json()["proxy"]["version"]==2
    for invalid in (
        {"enabled":True,"host":"bad host;cmd","port":3128,"bypass":[],"mode":"configured"},
        {"enabled":True,"host":"proxy.test","port":70000,"bypass":[],"mode":"configured"},
        {"enabled":True,"host":"proxy.test","port":3128,"bypass":["ok;bad"],"mode":"configured"},
        {"enabled":True,"host":"proxy.test","port":3128,"bypass":[],"mode":"enforced"},
    ):
        assert (await client.put(f"/api/v1/agents/devices/{first.id}/proxy-config",json=invalid)).status_code==422
    assert (await client.get("/api/v1/agents/config",headers={"X-Agent-Credential":"invalid"})).status_code==401
    assert (await client.get("/api/v1/agents/config",headers={"X-Agent-Credential":f"{revoked.id}.revoked-secret"})).status_code==401

@pytest.mark.asyncio
async def test_heartbeat_records_safe_proxy_status(proxy_client):
    client,first,_,_=proxy_client
    await client.put(f"/api/v1/agents/devices/{first.id}/proxy-config",json={"enabled":True,"host":"proxy.test","port":3128,"bypass":["localhost"],"mode":"configured"})
    heartbeat={"device_id":str(first.id),"timestamp":datetime.now(timezone.utc).isoformat(),"hostname":"PROXY-ONE","agent_version":"0.2","os_name":"Windows","active_ips":[],"mac_addresses":[],"dns":[],"uptime_seconds":1,"proxy_status":{"desired_version":1,"applied_version":1,"current_state":"configured","drift_detected":False,"last_apply_result":"applied","effective_host":"proxy.test","effective_port":3128,"bypass_summary":"1 entries"}}
    result=await client.post("/api/v1/agents/heartbeat",json=heartbeat,headers={"X-Agent-Credential":f"{first.id}.first-secret"})
    assert result.status_code==200
    reported=(await client.get(f"/api/v1/agents/devices/{first.id}/proxy-config")).json()["reported"]
    assert reported["applied_version"]==1 and reported["last_error"] is None and reported["bypass_summary"]=="1 entries"
