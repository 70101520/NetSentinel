import uuid
from sqlalchemy import delete,select
from app.db import SessionLocal
from app.models import AuditEvent,SnmpDevice
from app.schemas import SnmpDeviceInput
from app.snmp_secrets import decrypt_snmp_secret,encrypt_snmp_secret

def payload():return {"name":"Core switch","ip_address":"192.168.32.254","port":161,"version":"3","username":"netsentinel","auth_password":"auth-secret-123","privacy_password":"privacy-secret-123","poll_interval_seconds":60}

def test_snmp_input_rejects_public_ip_and_legacy_version():
    import pytest
    with pytest.raises(ValueError):SnmpDeviceInput(**{**payload(),"ip_address":"8.8.8.8"})
    with pytest.raises(ValueError):SnmpDeviceInput(**{**payload(),"version":"2c"})

def test_snmp_secret_encryption_round_trip():
    encrypted=encrypt_snmp_secret("do-not-store-plaintext")
    assert encrypted!="do-not-store-plaintext"
    assert decrypt_snmp_secret(encrypted)=="do-not-store-plaintext"

async def test_snmp_device_create_test_list_and_delete(client,monkeypatch):
    async def successful_probe(*_):return "pfSense appliance","core-router"
    monkeypatch.setattr("app.snmp.probe_v3",successful_probe)
    created=await client.post("/api/v1/snmp/devices",json=payload())
    assert created.status_code==201
    body=created.json();device_id=body["id"]
    assert body["status"]=="ONLINE" and body["system_name"]=="core-router"
    assert "auth_password" not in body and "privacy_password" not in body
    async with SessionLocal() as db:
        stored=await db.get(SnmpDevice,uuid.UUID(device_id))
        assert stored.auth_secret_encrypted!=payload()["auth_password"]
        assert payload()["auth_password"] not in str((await db.scalars(select(AuditEvent).where(AuditEvent.resource_id==device_id))).all())
    listed=await client.get("/api/v1/snmp/devices")
    assert listed.status_code==200 and listed.json()[0]["id"]==device_id
    tested=await client.post(f"/api/v1/snmp/devices/{device_id}/test")
    assert tested.status_code==200 and tested.json()["status"]=="ONLINE"
    removed=await client.delete(f"/api/v1/snmp/devices/{device_id}")
    assert removed.status_code==204
    async with SessionLocal() as db:
        await db.execute(delete(AuditEvent).where(AuditEvent.resource_type=="snmp_device"));await db.commit()
