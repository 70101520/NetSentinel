from fastapi import APIRouter,Request
from fastapi.responses import PlainTextResponse
from app.config import settings
router=APIRouter()
@router.get("/internal/metrics",include_in_schema=False,response_class=PlainTextResponse)
async def metrics(request:Request):
    redis=request.app.state.redis
    names=["events_accepted","events_rejected","batches_accepted","events_persisted","duplicates_ignored","failed_db_batches","retries","dlq_count"]
    values=await redis.mget([f"netsentinel:metrics:{n}" for n in names])
    stream_length=await redis.xlen(settings.telemetry_stream); pending=0
    try: pending=(await redis.xpending(settings.telemetry_stream,settings.telemetry_group))["pending"]
    except Exception: pass
    lines=[f"netsentinel_telemetry_{n} {int(v or 0)}" for n,v in zip(names,values)]
    lines += [f"netsentinel_telemetry_stream_length {stream_length}",f"netsentinel_telemetry_pending {pending}"]
    return "\n".join(lines)+"\n"
