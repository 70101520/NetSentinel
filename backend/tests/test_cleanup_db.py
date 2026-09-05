import uuid

import pytest
from sqlalchemy import select

from app.cli import purge_synthetic_devices
from app.db import SessionLocal, engine
from app.models import AuditEvent, Device, DeviceStateTransition

@pytest.mark.asyncio
async def test_cleanup_is_dry_run_by_default_and_cascades_confirmed_fixture(capsys):
    await engine.dispose()
    async with SessionLocal() as db:
        synthetic=Device(device_identifier="filter-000",hostname="ALPHA",ip_address="192.0.2.10",agent_version="0.2")
        real=Device(device_identifier=f"real-{uuid.uuid4()}",hostname="REAL-ENDPOINT",ip_address="192.168.1.20",agent_version="0.1.0")
        db.add_all([synthetic,real]);await db.flush();db.add(DeviceStateTransition(device_id=synthetic.id,previous_status="UNENROLLED",new_status="ONLINE"));await db.commit();synthetic_id=synthetic.id;real_id=real.id
    await purge_synthetic_devices([str(synthetic_id)])
    async with SessionLocal() as db:assert await db.get(Device,synthetic_id) is not None
    await purge_synthetic_devices([str(synthetic_id)],True)
    async with SessionLocal() as db:
        assert await db.get(Device,synthetic_id) is None and await db.get(Device,real_id) is not None
        assert await db.scalar(select(AuditEvent).where(AuditEvent.resource_id==str(synthetic_id),AuditEvent.action=="test_data.device.purge")) is not None
    with pytest.raises(SystemExit,match="do not match"):
        await purge_synthetic_devices([str(real_id)],True)
    assert "Dry run only" in capsys.readouterr().out
    await engine.dispose()
