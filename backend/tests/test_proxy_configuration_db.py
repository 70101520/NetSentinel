import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import delete, select

from app.config import settings
from app.db import SessionLocal, engine
from app.main import app
from app.models import AgentEnrollment, Device, DeviceProxyConfiguration, Permission, Role, User, WebAllowRule, WebBlockRule, WebCategory, WebTrustedNetwork
from app.security import issue_token
from app.service_auth import derive_secret

@pytest.fixture
async def proxy_client():
    await engine.dispose()
    async with SessionLocal() as db:
        await db.execute(delete(WebBlockRule));await db.execute(delete(WebAllowRule));await db.execute(delete(WebCategory));await db.execute(delete(WebTrustedNetwork));await db.execute(delete(DeviceProxyConfiguration));await db.execute(delete(Device));await db.execute(delete(AgentEnrollment))
        permissions=[]
        for code in ("agents.manage","policies.view","policies.manage"):
            permission=await db.scalar(select(Permission).where(Permission.code==code))
            if not permission:permission=Permission(code=code);db.add(permission);await db.flush()
            permissions.append(permission)
        user=User(email=f"proxy-{uuid.uuid4()}@example.invalid",password_hash="unused")
        role=Role(name=f"proxy-{uuid.uuid4()}");role.permissions.extend(permissions);user.roles.append(role);db.add(user)
        first=Device(device_identifier="proxy-device-1",hostname="PROXY-ONE",credential_hash=derive_secret("first-secret"),enrollment_state="ENROLLED",control_mode="WEB_CONTROLLED")
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

@pytest.mark.asyncio
async def test_monitor_only_forces_proxy_off_until_admin_enables_web_control(proxy_client):
    client,_,second,_=proxy_client
    header={"X-Agent-Credential":f"{second.id}.second-secret"}
    desired={"enabled":True,"host":"gateway.test.invalid","port":3128,"bypass":["localhost"],"mode":"configured"}
    assert (await client.put(f"/api/v1/agents/devices/{second.id}/proxy-config",json=desired)).status_code==200
    monitor=(await client.get("/api/v1/agents/config",headers=header)).json()
    assert monitor["control_mode"]=="MONITOR_ONLY" and monitor["proxy"]["enabled"] is False
    enabled=await client.put("/api/v1/agents/control-mode",json={"control_mode":"WEB_CONTROLLED"},headers=header)
    assert enabled.status_code==200 and enabled.json()["control_mode"]=="WEB_CONTROLLED"
    controlled=(await client.get("/api/v1/agents/config",headers=header)).json()
    assert controlled["proxy"]["enabled"] is True and controlled["proxy"]["host"]=="gateway.test.invalid"
    disabled=await client.put(f"/api/v1/agents/devices/{second.id}/control-mode",json={"control_mode":"MONITOR_ONLY"})
    assert disabled.status_code==200
    restored=(await client.get("/api/v1/agents/config",headers=header)).json()
    assert restored["proxy"]["enabled"] is False and restored["proxy"]["version"]>controlled["proxy"]["version"]
    assert (await client.put(f"/api/v1/agents/devices/{second.id}/control-mode",json={"control_mode":"BYPASS"})).status_code==422
@pytest.mark.asyncio
async def test_category_allowlist_and_trusted_lan_management(proxy_client):
    client,_,second,_=proxy_client
    category=await client.post("/api/v1/web/categories",json={"name":"Social media","description":"Reviewed test category"})
    assert category.status_code==201
    category_id=category.json()["id"]
    blocked=await client.post("/api/v1/web/blocklist",json={"domain":"social.example","category_id":category_id,"include_subdomains":True})
    assert blocked.status_code==201
    listed=(await client.get("/api/v1/web/blocklist")).json()
    assert listed[0]["category_name"]=="Social media"
    allowed=await client.post("/api/v1/web/allowlist",json={"domain":"safe.social.example","include_subdomains":True})
    assert allowed.status_code==201
    trusted=await client.post("/api/v1/web/trusted-networks",json={"name":"Office LAN","cidr":"192.168.32.25/24"})
    assert trusted.status_code==201 and trusted.json()["cidr"]=="192.168.32.0/24"
    header={"X-Agent-Credential":f"{second.id}.second-secret"}
    assert (await client.put("/api/v1/agents/control-mode",json={"control_mode":"WEB_CONTROLLED"},headers=header)).status_code==200
    config=(await client.get("/api/v1/agents/config",headers=header)).json()
    assert "192.168.32.0/24" in config["proxy"]["bypass"]
    assert (await client.delete(f"/api/v1/web/blocklist/{blocked.json()['id']}")).status_code==204
    assert (await client.delete(f"/api/v1/web/allowlist/{allowed.json()['id']}")).status_code==204
    assert (await client.delete(f"/api/v1/web/trusted-networks/{trusted.json()['id']}")).status_code==204
    assert (await client.delete(f"/api/v1/web/categories/{category_id}")).status_code==204