import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.config import settings
from app.db import SessionLocal, engine
from app.main import app
from app.models import Device, Permission, Role, User
from app.security import issue_token

@pytest.mark.asyncio
async def test_dashboard_devices_authentication_and_expiry():
    await engine.dispose()
    async with SessionLocal() as db:
        await db.execute(delete(Device))
        user=User(email=f"portal-{uuid.uuid4()}@example.invalid",password_hash="unused")
        permissions=[]
        for code in ("dashboard.view","devices.view"):
            permission=await db.scalar(select(Permission).where(Permission.code==code))
            if not permission:permission=Permission(code=code);db.add(permission);await db.flush()
            permissions.append(permission)
        role=Role(name=f"portal-{uuid.uuid4()}",permissions=permissions);user.roles.append(role)
        device=Device(device_identifier=f"portal-device-{uuid.uuid4()}",hostname="REAL-ENDPOINT",last_heartbeat=datetime.now(timezone.utc),current_status="ONLINE")
        db.add_all([user,device]);await db.commit();await db.refresh(user)
        token=issue_token(user)
    async with AsyncClient(transport=ASGITransport(app=app),base_url="http://test") as client:
        assert (await client.get("/api/v1/devices")).status_code==401
        assert (await client.get("/api/v1/dashboard")).status_code==401
        headers={"Authorization":f"Bearer {token}"}
        devices=await client.get("/api/v1/devices",headers=headers);dashboard=await client.get("/api/v1/dashboard",headers=headers)
        assert devices.status_code==200 and devices.json()["items"][0]["hostname"]=="REAL-ENDPOINT"
        assert dashboard.status_code==200 and dashboard.json()["devices"]=={"total":1,"online":1,"offline":0,"historical":0}
        now=datetime.now(timezone.utc)
        expired=jwt.encode({"sub":str(user.id),"iss":settings.jwt_issuer,"aud":"netsentinel-api","iat":now-timedelta(hours=1),"exp":now-timedelta(minutes=1),"jti":str(uuid.uuid4())},settings.jwt_secret,algorithm="HS256")
        assert (await client.get("/api/v1/devices",headers={"Authorization":f"Bearer {expired}"})).status_code==401
    await engine.dispose()
