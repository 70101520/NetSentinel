import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete,select

from app.db import SessionLocal, engine
from app.main import app
from app.models import AssetMetricSample, AuditEvent, Permission, Role, RolePermission, SnmpDevice, User, UserRole
from app.schemas import SnmpDeviceInput
from app.security import issue_token
from app.snmp_secrets import decrypt_snmp_secret,encrypt_snmp_secret


@pytest.fixture
async def snmp_client():
    await engine.dispose()
    suffix = uuid.uuid4().hex
    email = f"snmp-{suffix}@example.invalid"
    role = Role(name=f"SNMP tests {suffix}")
    async with SessionLocal() as db:
        user = User(email=email, password_hash="unused", roles=[role])
        for code in ("agents.manage", "devices.view"):
            permission = await db.scalar(select(Permission).where(Permission.code == code))
            if permission is None:
                permission = Permission(code=code)
                db.add(permission)
                await db.flush()
            role.permissions.append(permission)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        user_id, role_id = user.id, role.id
        bearer = issue_token(user)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {bearer}"},
    ) as client:
        yield client

    async with SessionLocal() as db:
        await db.execute(delete(AuditEvent).where(AuditEvent.actor_id == user_id))
        await db.execute(delete(UserRole).where(UserRole.user_id == user_id))
        await db.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
        await db.execute(delete(User).where(User.id == user_id))
        await db.execute(delete(Role).where(Role.id == role_id))
        await db.commit()
    await engine.dispose()

def payload():return {"name":"Core switch","ip_address":"192.168.32.254","port":161,"version":"3","username":"netsentinel","auth_password":"auth-secret-123","privacy_password":"privacy-secret-123","poll_interval_seconds":60}

def test_snmp_input_rejects_public_ip_and_legacy_version():
    with pytest.raises(ValueError):SnmpDeviceInput(**{**payload(),"ip_address":"8.8.8.8"})
    with pytest.raises(ValueError):SnmpDeviceInput(**{**payload(),"version":"2c"})
    with pytest.raises(ValueError):SnmpDeviceInput(**{**payload(),"vendor":"unknown"})
    with pytest.raises(ValueError):SnmpDeviceInput(**{**payload(),"auth_protocol":"MD5"})

def test_snmp_vendor_protocol_compatibility_is_bounded():
    legacy=SnmpDeviceInput(**{**payload(),"vendor":"sonicwall","auth_protocol":"SHA-1"})
    assert legacy.vendor=="sonicwall" and legacy.auth_protocol=="SHA-1"
    modern=SnmpDeviceInput(**{**payload(),"vendor":"juniper","auth_protocol":"SHA-256"})
    assert modern.auth_protocol=="SHA-256" and modern.privacy_protocol=="AES-128"

def test_snmp_secret_encryption_round_trip():
    encrypted=encrypt_snmp_secret("do-not-store-plaintext")
    assert encrypted!="do-not-store-plaintext"
    assert decrypt_snmp_secret(encrypted)=="do-not-store-plaintext"

async def test_snmp_device_create_test_list_and_delete(snmp_client,monkeypatch):
    async def successful_probe(*_):return "pfSense appliance","core-router"
    async def successful_metrics(*_):return {"uptime_seconds":300,"cpu_percent":10.0,"memory_percent":20.0,"disk_percent":30.0,"network_receive_bps":1000.0,"network_send_bps":500.0,"interfaces":[{"index":1,"name":"WAN","port_name":"igb0","status":"up"}]}
    monkeypatch.setattr("app.snmp.probe_v3",successful_probe)
    monkeypatch.setattr("app.snmp.probe_metrics_v3",successful_metrics)
    created=await snmp_client.post("/api/v1/snmp/devices",json=payload())
    assert created.status_code==201
    body=created.json();device_id=body["id"]
    assert body["status"]=="ONLINE" and body["system_name"]=="core-router"
    assert body["vendor"]=="generic" and body["auth_protocol"]=="SHA-256"
    assert "auth_password" not in body and "privacy_password" not in body
    async with SessionLocal() as db:
        stored=await db.get(SnmpDevice,uuid.UUID(device_id))
        assert stored.auth_secret_encrypted!=payload()["auth_password"]
        assert payload()["auth_password"] not in str((await db.scalars(select(AuditEvent).where(AuditEvent.resource_id==device_id))).all())
    listed=await snmp_client.get("/api/v1/snmp/devices")
    assert listed.status_code==200 and listed.json()[0]["id"]==device_id
    tested=await snmp_client.post(f"/api/v1/snmp/devices/{device_id}/test")
    assert tested.status_code==200 and tested.json()["status"]=="ONLINE"
    updated=await snmp_client.put(f"/api/v1/snmp/devices/{device_id}",json={**payload(),"name":"Edge firewall","poll_interval_seconds":120,"auth_password":None,"privacy_password":None})
    assert updated.status_code==200 and updated.json()["name"]=="Edge firewall"
    async with SessionLocal() as db:
        stored=await db.get(SnmpDevice,uuid.UUID(device_id))
        assert decrypt_snmp_secret(stored.auth_secret_encrypted)==payload()["auth_password"]
        assert decrypt_snmp_secret(stored.privacy_secret_encrypted)==payload()["privacy_password"]
    history=await snmp_client.get(f"/api/v1/graphs/snmp/{device_id}?hours=1")
    assert history.status_code==200 and history.json()["latest"]["interfaces"][0]["name"]=="WAN"
    removed=await snmp_client.delete(f"/api/v1/snmp/devices/{device_id}")
    assert removed.status_code==204
    async with SessionLocal() as db:
        assert not (await db.scalars(select(AssetMetricSample).where(AssetMetricSample.source_id==uuid.UUID(device_id)))).all()
        await db.execute(delete(AuditEvent).where(AuditEvent.resource_type=="snmp_device"));await db.commit()
