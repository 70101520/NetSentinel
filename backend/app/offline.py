import asyncio
from contextlib import suppress
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select, update

from app.config import settings
from app.db import SessionLocal
from app.models import Device, DeviceStateTransition

log = structlog.get_logger("agent_offline_evaluator")


async def mark_stale_devices_offline(now: datetime | None = None) -> int:
    """Claim and transition one bounded batch; the status/heartbeat index drives selection."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=settings.agent_heartbeat_timeout_seconds)
    async with SessionLocal() as db:
        async with db.begin():
            ids = (await db.scalars(
                select(Device.id)
                .where(Device.current_status == "ONLINE", Device.last_heartbeat < cutoff)
                .order_by(Device.last_heartbeat)
                .limit(settings.agent_offline_evaluator_batch_size)
                .with_for_update(skip_locked=True)
            )).all()
            if not ids:
                return 0
            await db.execute(update(Device).where(Device.id.in_(ids)).values(current_status="OFFLINE"))
            db.add_all([DeviceStateTransition(device_id=device_id, occurred_at=now, previous_status="ONLINE", new_status="OFFLINE") for device_id in ids])
        log.info("stale_devices_marked_offline", count=len(ids))
        return len(ids)


async def offline_evaluator(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await mark_stale_devices_offline()
        except Exception as exc:
            log.error("offline_evaluator_failure", error_type=type(exc).__name__)
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), settings.agent_offline_evaluator_interval_seconds)
