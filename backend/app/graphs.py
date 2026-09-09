import uuid
from datetime import datetime,timedelta,timezone

from fastapi import APIRouter,Depends,HTTPException,Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models import AssetMetricSample,Device,SnmpDevice,User
from app.security import require

router=APIRouter(prefix="/api/v1/graphs",tags=["graphs"])

@router.get("/{source_type}/{source_id}")
async def metric_history(source_type:str,source_id:uuid.UUID,hours:int=Query(24,ge=1,le=168),db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):
    if source_type=="agent":
        source=await db.get(Device,source_id)
        if not source:raise HTTPException(404,"Agent device not found")
        identity={"name":source.hostname,"ip_address":str(source.ip_address) if source.ip_address else None,"status":source.current_status.lower(),"source_type":"agent"}
    elif source_type=="snmp":
        source=await db.get(SnmpDevice,source_id)
        if not source:raise HTTPException(404,"SNMP device not found")
        identity={"name":source.name,"ip_address":str(source.ip_address),"status":source.status.lower(),"source_type":"snmp","system_name":source.system_name,"system_description":source.system_description}
    else:raise HTTPException(404,"Metric source not found")
    since=datetime.now(timezone.utc)-timedelta(hours=hours)
    rows=(await db.scalars(select(AssetMetricSample).where(AssetMetricSample.source_type==source_type,AssetMetricSample.source_id==source_id,AssetMetricSample.sampled_at>=since).order_by(AssetMetricSample.sampled_at).limit(2000))).all()
    samples=[{
        "sampled_at":row.sampled_at,
        "uptime_seconds":row.uptime_seconds,
        "cpu_percent":row.cpu_percent,
        "memory_percent":row.memory_percent,
        "disk_percent":row.disk_percent,
        "network_receive_bps":row.network_receive_bps,
        "network_send_bps":row.network_send_bps,
        "interfaces":row.interfaces or [],
    } for row in rows]
    return {
        "identity":identity,
        "hours":hours,
        "samples":samples,
        "latest":samples[-1] if samples else None,
        "message":None if samples else "Waiting for the first real metric sample.",
    }
