import asyncio,json,os,signal,socket,time,uuid
from datetime import datetime,timezone
import structlog
from redis.asyncio import Redis
from sqlalchemy.exc import DBAPIError,DataError,IntegrityError,InterfaceError,OperationalError,TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.dialects.postgresql import insert
from app.config import settings
from app.db import SessionLocal,engine
from app.models import ProxyEvent,TelemetryEventId
log=structlog.get_logger("telemetry_worker"); consumer=f"{socket.gethostname()}-{os.getpid()}"; stopping=asyncio.Event()
attempt_key="netsentinel:telemetry:attempts"; failure_key="netsentinel:telemetry:first-failure"
state_key="netsentinel:telemetry:worker-state"
TRANSIENT_DB_ERRORS=(OperationalError,InterfaceError,SQLAlchemyTimeoutError,DBAPIError,ConnectionError,TimeoutError)
def is_retryable(exc):
    return not isinstance(exc,(DataError,IntegrityError)) and isinstance(exc,TRANSIENT_DB_ERRORS)
async def ensure_group(redis):
    try: await redis.xgroup_create(settings.telemetry_stream,settings.telemetry_group,id="0",mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc): raise
def decode(fields):
    e=json.loads(fields["event"])
    parse_uuid=lambda value: uuid.UUID(value) if value else None
    return {"id":uuid.UUID(e["event_id"]),"occurred_at":datetime.fromisoformat(e["event_time"].replace("Z","+00:00")),"device_id":parse_uuid(e.get("device_id")),"username":e.get("username"),"hostname":e.get("hostname"),"source_ip":e.get("source_ip"),"destination_ip":e.get("destination_ip"),"domain":e["domain"],"url":e.get("url"),"protocol":e["protocol"],"port":e["port"],"action":e["action"],"policy_id":parse_uuid(e.get("policy_id")),"category":e.get("category"),"bytes_up":e.get("bytes_uploaded",0),"bytes_down":e.get("bytes_downloaded",0),"idempotency_key":e["event_id"]}
async def persist(events):
    registry=[{"event_id":e["id"],"event_time":e["occurred_at"]} for e in events]
    async with SessionLocal() as db:
        async with db.begin():
            result=await db.execute(insert(TelemetryEventId).values(registry).on_conflict_do_nothing(index_elements=["event_id"]).returning(TelemetryEventId.event_id))
            inserted={str(v) for v in result.scalars()}; fresh=[e for e in events if str(e["id"]) in inserted]
            if fresh: await db.execute(insert(ProxyEvent),fresh)
    return len(fresh),len(events)-len(fresh)
async def move_dlq(redis,message_id,fields,reason,attempts):
    now=datetime.now(timezone.utc).isoformat(); first=await redis.hget(failure_key,message_id) or now
    await redis.xadd(settings.telemetry_dlq_stream,{"original_event":fields.get("event",""),"failure_reason":reason[:500],"attempts":str(attempts),"first_failure_time":first,"last_failure_time":now,"consumer_identity":consumer})
    await redis.xack(settings.telemetry_stream,settings.telemetry_group,message_id); await redis.xdel(settings.telemetry_stream,message_id); await redis.hdel(attempt_key,message_id); await redis.hdel(failure_key,message_id); await redis.incr("netsentinel:metrics:dlq_count")
    log.error("telemetry_dlq",message_id=message_id,attempts=attempts,reason=reason[:200])
async def process(redis,messages):
    valid=[]; ids=[]; fields_by_id=dict(messages)
    for message_id,fields in messages:
        try: valid.append(decode(fields)); ids.append(message_id)
        except Exception as exc: await move_dlq(redis,message_id,fields,f"decode:{type(exc).__name__}",settings.telemetry_max_attempts)
    if not valid:return
    started=time.perf_counter()
    try:
        persisted,duplicates=await persist(valid); await redis.xack(settings.telemetry_stream,settings.telemetry_group,*ids); await redis.xdel(settings.telemetry_stream,*ids)
        async with redis.pipeline(transaction=False) as pipe:
            pipe.hdel(attempt_key,*ids); pipe.hdel(failure_key,*ids); pipe.delete(state_key); pipe.incrby("netsentinel:metrics:events_persisted",persisted); pipe.incrby("netsentinel:metrics:duplicates_ignored",duplicates); pipe.lpush("netsentinel:metrics:batch_write_latency_ms",f"{(time.perf_counter()-started)*1000:.3f}"); pipe.ltrim("netsentinel:metrics:batch_write_latency_ms",0,9999); await pipe.execute()
        log.info("telemetry_batch_persisted",received=len(valid),persisted=persisted,duplicates=duplicates)
    except Exception as exc:
        await redis.incr("netsentinel:metrics:failed_db_batches"); now=datetime.now(timezone.utc).isoformat(); retry=[]; transient=is_retryable(exc)
        for message_id in ids:
            attempts=await redis.hincrby(attempt_key,message_id,1); await redis.hsetnx(failure_key,message_id,now)
            if not transient and attempts>=settings.telemetry_max_attempts: await move_dlq(redis,message_id,fields_by_id[message_id],type(exc).__name__,attempts)
            else: retry.append(attempts)
        if retry: await redis.incrby("netsentinel:metrics:retries",len(retry))
        delay=min(settings.telemetry_db_retry_base_seconds*(2**min(max(retry,default=1)-1,10)),30)
        await redis.hset(state_key,mapping={"status":"blocked" if transient else "degraded","reason":type(exc).__name__,"since":now,"retry_seconds":str(delay)}); await redis.expire(state_key,300)
        log.error("telemetry_db_failure",count=len(valid),error_type=type(exc).__name__,retryable=transient,retry_seconds=delay); await asyncio.sleep(delay)
async def reclaim(redis):
    result=await redis.xautoclaim(settings.telemetry_stream,settings.telemetry_group,consumer,settings.telemetry_reclaim_idle_ms,"0-0",count=settings.telemetry_worker_batch_size)
    return result[1] if len(result)>1 else []
async def main():
    redis=Redis.from_url(settings.redis_url,decode_responses=True); await ensure_group(redis); log.info("telemetry_worker_started",consumer=consumer,group=settings.telemetry_group)
    try:
        while not stopping.is_set():
            recovered=await reclaim(redis)
            if recovered: await process(redis,recovered); continue
            response=await redis.xreadgroup(settings.telemetry_group,consumer,{settings.telemetry_stream:">"},count=settings.telemetry_worker_batch_size,block=settings.telemetry_block_ms)
            if response: await process(redis,response[0][1])
    finally: await redis.aclose(); await engine.dispose(); log.info("telemetry_worker_stopped",consumer=consumer)
if __name__=="__main__":
    loop=asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    for sig in (signal.SIGTERM,signal.SIGINT): loop.add_signal_handler(sig,stopping.set)
    loop.run_until_complete(main())
