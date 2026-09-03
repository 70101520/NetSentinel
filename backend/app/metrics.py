from fastapi import APIRouter,Request
from fastapi.responses import PlainTextResponse
from app.config import settings
router=APIRouter()
@router.get("/internal/metrics",include_in_schema=False,response_class=PlainTextResponse)
async def metrics(request:Request):
    redis=request.app.state.redis
    names=["events_accepted","events_rejected","batches_accepted","events_persisted","duplicates_ignored","failed_db_batches","retries","dlq_count"]
    values=await redis.mget([f"netsentinel:metrics:{n}" for n in names])
    stream_length=await redis.xlen(settings.telemetry_stream); pending=0; lag=0
    try:
        pending=(await redis.xpending(settings.telemetry_stream,settings.telemetry_group))["pending"]
        groups=await redis.xinfo_groups(settings.telemetry_stream)
        group=next((g for g in groups if g["name"]==settings.telemetry_group),{})
        lag=int(group.get("lag") or 0)
    except Exception: pass
    state=await redis.hgetall("netsentinel:telemetry:worker-state")
    queue_state="critical" if stream_length>=settings.telemetry_queue_critical else "warning" if stream_length>=settings.telemetry_queue_warning else "normal"
    lines=[f"netsentinel_telemetry_{n} {int(v or 0)}" for n,v in zip(names,values)]
    lines += [f"netsentinel_telemetry_stream_length {stream_length}",f"netsentinel_telemetry_pending {pending}",f"netsentinel_telemetry_consumer_lag {lag}",f'netsentinel_telemetry_queue_state{{state="{queue_state}"}} 1',f'netsentinel_telemetry_worker_state{{state="{state.get("status","healthy")}"}} 1']
    return "\n".join(lines)+"\n"
