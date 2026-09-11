import asyncio
import contextlib
import ipaddress
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

import structlog
from sqlalchemy import select
from redis.asyncio import Redis

from app.config import settings
from app.db import SessionLocal, engine
from app.models import Device, ProxyEvent
from app.web_filtering import compile_web_policy, evaluate_compiled_policy, normalize_domain

log=structlog.get_logger("web_gateway")
MAX_HEADER_BYTES=65_536
CONNECT_TIMEOUT_SECONDS=15
IDLE_TIMEOUT_SECONDS=120
DEVICE_CACHE_TTL_SECONDS=2
_device_snapshot={}
_device_snapshot_loaded_at=0.0
_device_lock=asyncio.Lock()
_policy_snapshot=None
_policy_version=None
_policy_checked_at=0.0
_policy_loaded_at=0.0
_policy_lock=asyncio.Lock()
_redis=None


def client_ip(peer)->str:
    value=str(peer[0]) if peer else ""
    value = value.removeprefix("::ffff:")
    return value


async def controlled_device(db,source_ip:str):
    global _device_snapshot,_device_snapshot_loaded_at
    try:address=str(ipaddress.ip_address(source_ip))
    except ValueError:return None
    now=time.monotonic()
    if now-_device_snapshot_loaded_at>=DEVICE_CACHE_TTL_SECONDS:
        async with _device_lock:
            now=time.monotonic()
            if now-_device_snapshot_loaded_at>=DEVICE_CACHE_TTL_SECONDS:
                cutoff=datetime.now(UTC)-timedelta(seconds=settings.agent_heartbeat_timeout_seconds)
                devices=(await db.scalars(select(Device).where(Device.enrollment_state=="ENROLLED",Device.control_mode=="WEB_CONTROLLED",Device.current_status=="ONLINE",Device.last_heartbeat>=cutoff).order_by(Device.last_heartbeat.desc()))).all()
                snapshot={}
                for device in devices:
                    observed={str(value) for value in (device.ip_address,device.last_heartbeat_ip) if value}
                    observed.update(str(value) for value in (device.metadata_ or {}).get("active_ips",[]) if value)
                    for value in observed:snapshot.setdefault(value,device)
                _device_snapshot=snapshot;_device_snapshot_loaded_at=now
    return _device_snapshot.get(address)

async def policy_decision(db,domain,device_id):
    global _policy_snapshot,_policy_version,_policy_checked_at,_policy_loaded_at
    now=time.monotonic()
    if _policy_snapshot is not None and now-_policy_checked_at<1:return evaluate_compiled_policy(_policy_snapshot,domain,device_id)
    async with _policy_lock:
        now=time.monotonic();version=None
        if _redis:
            with contextlib.suppress(Exception):version=await _redis.get("netsentinel:web-policy-version")
        _policy_checked_at=now
        if _policy_snapshot is None or version!=_policy_version or now-_policy_loaded_at>=30:
            _policy_snapshot=await compile_web_policy(db);_policy_version=version;_policy_loaded_at=now
    return evaluate_compiled_policy(_policy_snapshot,domain,device_id)


def parse_target(request_line:str):
    parts=request_line.split(" ")
    if len(parts)!=3:raise ValueError("Malformed request line")
    method,target,version=parts
    if method.upper()=="CONNECT":
        host,separator,raw_port=target.rpartition(":")
        if not separator:host=target;raw_port="443"
        port=int(raw_port)
        if port!=443:raise ValueError("CONNECT is restricted to HTTPS port 443")
        return method.upper(),normalize_domain(host.strip("[]")),port,None,version
    parsed=urlsplit(target)
    if parsed.scheme.lower() not in {"http","https"} or not parsed.hostname:raise ValueError("Explicit proxy URL required")
    port=parsed.port or (443 if parsed.scheme.lower()=="https" else 80)
    default_port=443 if parsed.scheme.lower()=="https" else 80
    authority=parsed.hostname if port==default_port else f"{parsed.hostname}:{port}"
    safe_url=urlunsplit((parsed.scheme,authority,parsed.path or "/","",""))
    origin=urlunsplit(("","",parsed.path or "/",parsed.query,""))
    if port not in {80,443}:raise ValueError("Only web ports 80 and 443 are allowed")
    return method.upper(),normalize_domain(parsed.hostname),port,safe_url,version,origin


async def write_event(device,source_ip,domain,url,protocol,port,action,rule_id=None):
    event_id=uuid.uuid4();occurred_at=datetime.now(UTC)
    payload={"event_id":str(event_id),"event_time":occurred_at.isoformat(),"device_id":str(device.id),"username":device.username,"hostname":device.hostname,"source_ip":source_ip,"destination_ip":None,"domain":domain,"url":url,"protocol":protocol,"port":port,"method":None,"status_code":None,"action":action,"policy_id":None,"matched_rule_id":str(rule_id) if rule_id else None,"category":None,"bytes_uploaded":0,"bytes_downloaded":0,"duration_ms":None}
    try:await _redis.xadd(settings.telemetry_stream,{"event":json.dumps(payload,separators=(",",":"))})
    except Exception:
        async with SessionLocal() as db:
            db.add(ProxyEvent(id=event_id,occurred_at=occurred_at,device_id=device.id,username=device.username,hostname=device.hostname,source_ip=source_ip,domain=domain,url=url,protocol=protocol,port=port,action=action,matched_rule_id=rule_id,bytes_up=0,bytes_down=0,idempotency_key=str(event_id)));await db.commit()
    return event_id,occurred_at


async def update_event(event_ref,bytes_up,bytes_down):
    if _redis:
        with contextlib.suppress(Exception):await _redis.incrby("netsentinel:metrics:web_gateway_bytes",bytes_up+bytes_down)


async def relay(reader,writer)->int:
    total=0
    try:
        while data:=await asyncio.wait_for(reader.read(65_536),IDLE_TIMEOUT_SECONDS):
            writer.write(data);await writer.drain();total+=len(data)
    except (TimeoutError, ConnectionError, OSError):pass
    finally:
        with contextlib.suppress(Exception):writer.close()
    return total


async def reject(writer,code:int,reason:str):
    body=(reason+"\n").encode()
    writer.write(f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()+body)
    await writer.drain()


async def handle(reader:asyncio.StreamReader,writer:asyncio.StreamWriter):
    source=client_ip(writer.get_extra_info("peername"));device=None;domain=None;url=None;protocol="http";port=80;action="ALLOW";rule_id=None;up=down=0;event_ref=None
    try:
        header=await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"),CONNECT_TIMEOUT_SECONDS)
        if len(header)>MAX_HEADER_BYTES:raise ValueError("Headers too large")
        lines=header.decode("iso-8859-1").split("\r\n");parsed=parse_target(lines[0]);method,domain,port,url,version=parsed[:5];protocol="https" if method=="CONNECT" or port==443 else "http"
        async with SessionLocal() as db:
            device=await controlled_device(db,source)
            if not device:
                log.warning("gateway_device_not_recognized",source_ip=source)
                await reject(writer,403,"NetSentinel Full control enrollment required");return
            blocked,rule_id=await policy_decision(db,domain,device.id)
        if blocked:
            action="BLOCK";event_ref=await write_event(device,source,domain,url,protocol,port,action,rule_id);await reject(writer,403,"Blocked by NetSentinel policy");return
        event_ref=await write_event(device,source,domain,url,protocol,port,action,rule_id)
        remote_reader,remote_writer=await asyncio.wait_for(asyncio.open_connection(domain,port),CONNECT_TIMEOUT_SECONDS)
        if method=="CONNECT":
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n");await writer.drain()
            client_to_remote=asyncio.create_task(relay(reader,remote_writer));remote_to_client=asyncio.create_task(relay(remote_reader,writer))
            _done,pending=await asyncio.wait({client_to_remote,remote_to_client},return_when=asyncio.FIRST_COMPLETED)
            for task in pending:task.cancel()
            results=await asyncio.gather(client_to_remote,remote_to_client,return_exceptions=True)
            up=results[0] if isinstance(results[0],int) else 0;down=results[1] if isinstance(results[1],int) else 0
        else:
            origin=parsed[5];filtered=[line for line in lines[1:] if line and not line.lower().startswith(("proxy-connection:","connection:"))]
            outbound=(f"{method} {origin} {version}\r\n"+"\r\n".join(filtered)+"\r\nConnection: close\r\n\r\n").encode("iso-8859-1")
            remote_writer.write(outbound);await remote_writer.drain()
            client_to_remote=asyncio.create_task(relay(reader,remote_writer));remote_to_client=asyncio.create_task(relay(remote_reader,writer))
            _done,pending=await asyncio.wait({client_to_remote,remote_to_client},return_when=asyncio.FIRST_COMPLETED)
            for task in pending:task.cancel()
            results=await asyncio.gather(client_to_remote,remote_to_client,return_exceptions=True)
            up=len(outbound)+(results[0] if isinstance(results[0],int) else 0);down=results[1] if isinstance(results[1],int) else 0
    except (asyncio.IncompleteReadError,asyncio.LimitOverrunError,ValueError,UnicodeError):
        with contextlib.suppress(Exception):await reject(writer,400,"Invalid proxy request")
    except (TimeoutError, ConnectionError, OSError):
        with contextlib.suppress(Exception):await reject(writer,502,"Destination unavailable")
    except Exception as exc:
        log.error("gateway_request_failed",error_type=type(exc).__name__,source_ip=source)
        with contextlib.suppress(Exception):await reject(writer,500,"Gateway error")
    finally:
        if event_ref:
            with contextlib.suppress(Exception):await update_event(event_ref,up,down)
        with contextlib.suppress(Exception):writer.close();await writer.wait_closed()


async def main():
    global _redis
    _redis=Redis.from_url(settings.redis_url,decode_responses=True)
    server=await asyncio.start_server(handle,"0.0.0.0",3128,limit=MAX_HEADER_BYTES+1)
    log.info("web_gateway_started",port=3128)
    try:
        async with server:await server.serve_forever()
    finally:await _redis.aclose()


if __name__=="__main__":
    try:asyncio.run(main())
    finally:asyncio.run(engine.dispose())
