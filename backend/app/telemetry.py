import json,time
from fastapi import APIRouter,Depends,HTTPException,Request,status
from redis.asyncio import Redis
from app.config import settings
from app.models import ServiceCredential
from app.schemas import TelemetryAccepted,TelemetryBatch
from app.service_auth import service_identity
router=APIRouter(prefix="/api/v1/telemetry",tags=["telemetry"])
def redis_client(request:Request)->Redis: return request.app.state.redis
@router.post("/events",response_model=TelemetryAccepted,status_code=status.HTTP_202_ACCEPTED)
async def ingest(body:TelemetryBatch,identity:ServiceCredential=Depends(service_identity),redis:Redis=Depends(redis_client)):
    started=time.perf_counter(); count=len(body.events)
    if count>settings.telemetry_max_batch_size: raise HTTPException(413,f"Batch exceeds {settings.telemetry_max_batch_size} events")
    try:
        length=await redis.xlen(settings.telemetry_stream)
        if length>=settings.telemetry_queue_critical:
            await redis.incr("netsentinel:metrics:events_rejected",count)
            raise HTTPException(503,"Telemetry queue at critical capacity")
        rate_key=f"netsentinel:rate:telemetry:{identity.id}"
        async with redis.pipeline(transaction=True) as pipe:
            pipe.incrby(rate_key,count); pipe.expire(rate_key,settings.telemetry_rate_window_seconds,nx=True)
            used,_=await pipe.execute()
        if used>settings.telemetry_rate_limit_events:
            await redis.incr("netsentinel:metrics:events_rejected",count)
            raise HTTPException(429,"Telemetry rate limit exceeded")
        async with redis.pipeline(transaction=False) as pipe:
            for event in body.events:
                payload=event.model_dump(mode="json")
                pipe.xadd(settings.telemetry_stream,{"event":json.dumps(payload,separators=(",",":")),"producer":str(identity.id),"attempts":"0","first_failure":""})
            pipe.incrby("netsentinel:metrics:events_accepted",count); pipe.incr("netsentinel:metrics:batches_accepted")
            await pipe.execute()
        await redis.lpush("netsentinel:metrics:ingest_latency_ms",f"{(time.perf_counter()-started)*1000:.3f}")
        await redis.ltrim("netsentinel:metrics:ingest_latency_ms",0,9999)
    except HTTPException: raise
    except Exception as exc: raise HTTPException(503,"Telemetry queue unavailable") from exc
    return TelemetryAccepted(accepted=count)
