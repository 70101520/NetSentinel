import asyncio
import uuid
from datetime import datetime,timezone
from fastapi import APIRouter,Depends,HTTPException,Request,status
from pysnmp.hlapi.v3arch.asyncio import ContextData,ObjectIdentity,ObjectType,SnmpEngine,USM_AUTH_HMAC192_SHA256,USM_AUTH_HMAC96_SHA,USM_PRIV_CFB128_AES,UdpTransportTarget,UsmUserData,get_cmd,walk_cmd
from sqlalchemy import delete,select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.audit import record
from app.db import SessionLocal,get_db
from app.models import AssetMetricSample,SnmpDevice,User
from app.schemas import SnmpDeviceInput,SnmpDeviceOut,SnmpDeviceUpdate
from app.security import require
from app.snmp_secrets import decrypt_snmp_secret,encrypt_snmp_secret

router=APIRouter(prefix="/api/v1/snmp",tags=["snmp"])
AUTH_PROTOCOLS={"SHA-256":USM_AUTH_HMAC192_SHA256,"SHA-1":USM_AUTH_HMAC96_SHA}

def _safe_error(indication,error_status)->str:
    text=f"{indication or ''} {error_status or ''}".lower()
    if "time" in text or "reach" in text:return "SNMP target timed out or is unreachable"
    if "auth" in text or "privacy" in text or "decrypt" in text:return "SNMPv3 authentication or privacy negotiation failed"
    return "SNMP target returned an error"

async def probe_v3(target:SnmpDevice,auth_password:str,privacy_password:str)->tuple[str,str]:
    engine=SnmpEngine()
    try:
        transport=await UdpTransportTarget.create((str(target.ip_address),target.port),timeout=2,retries=0)
        indication,error_status,_,bindings=await get_cmd(engine,UsmUserData(target.username,authKey=auth_password,privKey=privacy_password,authProtocol=AUTH_PROTOCOLS[target.auth_protocol],privProtocol=USM_PRIV_CFB128_AES),transport,ContextData(),ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),lookupMib=False)
        if indication or error_status:raise ConnectionError(_safe_error(indication,error_status))
        values=[binding[1].prettyPrint() for binding in bindings]
        return values[0][:1000],values[1][:255]
    finally:engine.close_dispatcher()

def _auth(item:SnmpDevice,auth_password:str,privacy_password:str):
    return UsmUserData(item.username,authKey=auth_password,privKey=privacy_password,authProtocol=AUTH_PROTOCOLS[item.auth_protocol],privProtocol=USM_PRIV_CFB128_AES)

async def _walk(engine,auth,transport,root:str,limit:int=512)->dict[int,object]:
    values={}
    async for indication,error_status,_,bindings in walk_cmd(engine,auth,transport,ContextData(),ObjectType(ObjectIdentity(root)),lexicographicMode=False,lookupMib=False):
        if indication or error_status:break
        for binding in bindings:
            oid=binding[0].prettyPrint()
            if not oid.startswith(root+"."):return values
            try:index=int(oid.rsplit(".",1)[1])
            except ValueError:continue
            raw=binding[1]
            try:values[index]=int(raw)
            except (TypeError,ValueError):values[index]=raw.prettyPrint()
            if len(values)>=limit:return values
    return values

async def probe_metrics_v3(target:SnmpDevice,auth_password:str,privacy_password:str,previous:AssetMetricSample|None=None)->dict:
    engine=SnmpEngine()
    try:
        transport=await UdpTransportTarget.create((str(target.ip_address),target.port),timeout=3,retries=0)
        auth=_auth(target,auth_password,privacy_password)
        indication,error_status,_,bindings=await get_cmd(engine,auth,transport,ContextData(),ObjectType(ObjectIdentity("1.3.6.1.2.1.1.3.0")),lookupMib=False)
        if indication or error_status:raise ConnectionError(_safe_error(indication,error_status))
        uptime_seconds=int(bindings[0][1])/100
        roots={"name":"1.3.6.1.2.1.31.1.1.1.1","description":"1.3.6.1.2.1.2.2.1.2","alias":"1.3.6.1.2.1.31.1.1.1.18","in":"1.3.6.1.2.1.31.1.1.1.6","out":"1.3.6.1.2.1.31.1.1.1.10","in32":"1.3.6.1.2.1.2.2.1.10","out32":"1.3.6.1.2.1.2.2.1.16","speed":"1.3.6.1.2.1.31.1.1.1.15","speed32":"1.3.6.1.2.1.2.2.1.5","status":"1.3.6.1.2.1.2.2.1.8","cpu":"1.3.6.1.2.1.25.3.3.1.2","storage_type":"1.3.6.1.2.1.25.2.3.1.2","storage_description":"1.3.6.1.2.1.25.2.3.1.3","storage_size":"1.3.6.1.2.1.25.2.3.1.5","storage_used":"1.3.6.1.2.1.25.2.3.1.6"}
        tables={key:await _walk(engine,auth,transport,root) for key,root in roots.items()}
        previous_by_index={int(value["index"]):value for value in (previous.interfaces if previous else []) if "index" in value}
        elapsed=max(1,(datetime.now(timezone.utc)-previous.sampled_at).total_seconds()) if previous else None
        interfaces=[];total_receive=0.0;total_send=0.0
        indexes=sorted(set(tables["name"])|set(tables["description"])|set(tables["status"])|set(tables["in"])|set(tables["in32"])|set(tables["out"])|set(tables["out32"]))
        for index in indexes:
            in_octets=tables["in"].get(index,tables["in32"].get(index));out_octets=tables["out"].get(index,tables["out32"].get(index));before=previous_by_index.get(index,{})
            receive_bps=send_bps=None
            if elapsed and isinstance(in_octets,int) and isinstance(before.get("in_octets"),int) and in_octets>=before["in_octets"]:receive_bps=(in_octets-before["in_octets"])/elapsed
            if elapsed and isinstance(out_octets,int) and isinstance(before.get("out_octets"),int) and out_octets>=before["out_octets"]:send_bps=(out_octets-before["out_octets"])/elapsed
            if receive_bps is not None:total_receive+=receive_bps
            if send_bps is not None:total_send+=send_bps
            interfaces.append({"index":index,"name":str(tables["alias"].get(index) or tables["name"].get(index) or tables["description"].get(index) or f"Interface {index}"),"port_name":str(tables["name"].get(index) or tables["description"].get(index) or f"if{index}"),"status":"up" if tables["status"].get(index)==1 else "down","speed_bps":int(tables["speed"].get(index,0))*1_000_000 or int(tables["speed32"].get(index,0)),"receive_bps":receive_bps,"send_bps":send_bps,"in_octets":in_octets,"out_octets":out_octets})
        cpu_values=[float(value) for value in tables["cpu"].values() if isinstance(value,int)]
        def storage_percent(indexes):
            values=[]
            for index in indexes:
                size=tables["storage_size"].get(index);used=tables["storage_used"].get(index)
                if isinstance(size,int) and isinstance(used,int) and size>0:values.append(used*100/size)
            return max(values) if values else None
        memory_indexes=[index for index,value in tables["storage_type"].items() if str(value).endswith(".1.3.6.1.2.1.25.2.1.2") or str(value).endswith("25.2.1.2")]
        disk_indexes=[index for index,value in tables["storage_type"].items() if str(value).endswith(".1.3.6.1.2.1.25.2.1.4") or str(value).endswith("25.2.1.4")]
        root_indexes=[index for index in disk_indexes if str(tables["storage_description"].get(index,"")).strip() in {"/","/root"}]
        return {"uptime_seconds":int(uptime_seconds),"cpu_percent":sum(cpu_values)/len(cpu_values) if cpu_values else None,"memory_percent":storage_percent(memory_indexes),"disk_percent":storage_percent(root_indexes or disk_indexes),"network_receive_bps":total_receive if previous else None,"network_send_bps":total_send if previous else None,"interfaces":interfaces}
    finally:engine.close_dispatcher()

async def _test(item:SnmpDevice,auth_password:str,privacy_password:str,db:AsyncSession|None=None)->None:
    item.last_polled_at=datetime.now(timezone.utc)
    try:
        description,name=await probe_v3(item,auth_password,privacy_password)
        item.status="ONLINE";item.system_description=description;item.system_name=name;item.last_success_at=item.last_polled_at;item.last_error=None
        if db:
            previous=await db.scalar(select(AssetMetricSample).where(AssetMetricSample.source_type=="snmp",AssetMetricSample.source_id==item.id).order_by(AssetMetricSample.sampled_at.desc()).limit(1))
            metrics=await probe_metrics_v3(item,auth_password,privacy_password,previous)
            db.add(AssetMetricSample(source_type="snmp",source_id=item.id,sampled_at=item.last_polled_at,**metrics))
    except Exception as exc:
        item.status="OFFLINE";item.last_error=str(exc) if isinstance(exc,ConnectionError) else "SNMP polling failed"

async def snmp_scheduler(stop:asyncio.Event):
    while not stop.is_set():
        try:
            async with SessionLocal() as db:
                devices=(await db.scalars(select(SnmpDevice).where(SnmpDevice.enabled.is_(True)))).all()
                now=datetime.now(timezone.utc)
                for item in devices:
                    if item.last_polled_at and (now-item.last_polled_at).total_seconds()<item.poll_interval_seconds:continue
                    try:await _test(item,decrypt_snmp_secret(item.auth_secret_encrypted),decrypt_snmp_secret(item.privacy_secret_encrypted),db)
                    except RuntimeError as exc:item.status="OFFLINE";item.last_error=str(exc)[:300];item.last_polled_at=now
                await db.commit()
        except Exception:
            pass
        try:await asyncio.wait_for(stop.wait(),timeout=5)
        except TimeoutError:pass

@router.get("/devices",response_model=list[SnmpDeviceOut])
async def list_devices(db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):
    return list((await db.scalars(select(SnmpDevice).order_by(SnmpDevice.name))).all())

@router.post("/devices",response_model=SnmpDeviceOut,status_code=status.HTTP_201_CREATED)
async def add_device(body:SnmpDeviceInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    try:
        item=SnmpDevice(name=body.name.strip(),vendor=body.vendor,ip_address=str(body.ip_address),port=body.port,version="3",username=body.username.strip(),auth_protocol=body.auth_protocol,privacy_protocol="AES-128",auth_secret_encrypted=encrypt_snmp_secret(body.auth_password),privacy_secret_encrypted=encrypt_snmp_secret(body.privacy_password),poll_interval_seconds=body.poll_interval_seconds,created_by=user.id)
    except RuntimeError as exc:raise HTTPException(503,str(exc)) from exc
    db.add(item)
    try:await db.flush()
    except IntegrityError as exc:
        await db.rollback();raise HTTPException(409,"SNMP device name or target already exists") from exc
    await _test(item,body.auth_password,body.privacy_password,db)
    await record(db,request,user,"snmp.device.create","snmp_device",str(item.id),"success",new={"name":item.name,"vendor":item.vendor,"ip_address":str(item.ip_address),"port":item.port,"version":"3","security_level":"authPriv","auth_protocol":item.auth_protocol,"privacy_protocol":item.privacy_protocol})
    await db.commit();await db.refresh(item);return item

@router.post("/devices/{device_id}/test",response_model=SnmpDeviceOut)
async def test_device(device_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    item=await db.get(SnmpDevice,device_id)
    if not item:raise HTTPException(404,"SNMP device not found")
    try:await _test(item,decrypt_snmp_secret(item.auth_secret_encrypted),decrypt_snmp_secret(item.privacy_secret_encrypted),db)
    except RuntimeError as exc:raise HTTPException(503,str(exc)) from exc
    await record(db,request,user,"snmp.device.test","snmp_device",str(item.id),"success" if item.status=="ONLINE" else "failed",new={"status":item.status})
    await db.commit();await db.refresh(item);return item

@router.put("/devices/{device_id}",response_model=SnmpDeviceOut)
async def update_device(device_id:uuid.UUID,body:SnmpDeviceUpdate,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    item=await db.get(SnmpDevice,device_id)
    if not item:raise HTTPException(404,"SNMP device not found")
    previous={"name":item.name,"vendor":item.vendor,"ip_address":str(item.ip_address),"port":item.port,"username":item.username,"auth_protocol":item.auth_protocol,"poll_interval_seconds":item.poll_interval_seconds}
    item.name=body.name.strip();item.vendor=body.vendor;item.ip_address=str(body.ip_address);item.port=body.port;item.username=body.username.strip();item.auth_protocol=body.auth_protocol;item.privacy_protocol="AES-128";item.poll_interval_seconds=body.poll_interval_seconds
    try:
        if body.auth_password:item.auth_secret_encrypted=encrypt_snmp_secret(body.auth_password)
        if body.privacy_password:item.privacy_secret_encrypted=encrypt_snmp_secret(body.privacy_password)
        await db.flush()
    except RuntimeError as exc:raise HTTPException(503,str(exc)) from exc
    except IntegrityError as exc:
        await db.rollback();raise HTTPException(409,"SNMP device name or target already exists") from exc
    try:await _test(item,decrypt_snmp_secret(item.auth_secret_encrypted),decrypt_snmp_secret(item.privacy_secret_encrypted),db)
    except RuntimeError as exc:raise HTTPException(503,str(exc)) from exc
    await record(db,request,user,"snmp.device.update","snmp_device",str(item.id),"success",previous=previous,new={"name":item.name,"vendor":item.vendor,"ip_address":str(item.ip_address),"port":item.port,"username":item.username,"auth_protocol":item.auth_protocol,"poll_interval_seconds":item.poll_interval_seconds,"credentials_changed":bool(body.auth_password or body.privacy_password)})
    await db.commit();await db.refresh(item);return item

@router.delete("/devices/{device_id}",status_code=status.HTTP_204_NO_CONTENT)
async def remove_device(device_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    item=await db.get(SnmpDevice,device_id)
    if not item:raise HTTPException(404,"SNMP device not found")
    await record(db,request,user,"snmp.device.delete","snmp_device",str(item.id),"success",previous={"name":item.name,"ip_address":str(item.ip_address),"port":item.port})
    await db.execute(delete(AssetMetricSample).where(AssetMetricSample.source_type=="snmp",AssetMetricSample.source_id==item.id));await db.delete(item);await db.commit()
