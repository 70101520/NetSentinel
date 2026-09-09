import uuid
from datetime import datetime,timezone
from fastapi import APIRouter,Depends,HTTPException,Request,status
from pysnmp.hlapi.v3arch.asyncio import ContextData,ObjectIdentity,ObjectType,SnmpEngine,USM_AUTH_HMAC192_SHA256,USM_PRIV_CFB128_AES,UdpTransportTarget,UsmUserData,get_cmd
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.audit import record
from app.db import get_db
from app.models import SnmpDevice,User
from app.schemas import SnmpDeviceInput,SnmpDeviceOut
from app.security import require
from app.snmp_secrets import decrypt_snmp_secret,encrypt_snmp_secret

router=APIRouter(prefix="/api/v1/snmp",tags=["snmp"])

def _safe_error(indication,error_status)->str:
    text=f"{indication or ''} {error_status or ''}".lower()
    if "time" in text or "reach" in text:return "SNMP target timed out or is unreachable"
    if "auth" in text or "privacy" in text or "decrypt" in text:return "SNMPv3 authentication or privacy negotiation failed"
    return "SNMP target returned an error"

async def probe_v3(target:SnmpDevice,auth_password:str,privacy_password:str)->tuple[str,str]:
    engine=SnmpEngine()
    try:
        transport=await UdpTransportTarget.create((str(target.ip_address),target.port),timeout=2,retries=0)
        indication,error_status,_,bindings=await get_cmd(engine,UsmUserData(target.username,authKey=auth_password,privKey=privacy_password,authProtocol=USM_AUTH_HMAC192_SHA256,privProtocol=USM_PRIV_CFB128_AES),transport,ContextData(),ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),lookupMib=False)
        if indication or error_status:raise ConnectionError(_safe_error(indication,error_status))
        values=[binding[1].prettyPrint() for binding in bindings]
        return values[0][:1000],values[1][:255]
    finally:engine.close_dispatcher()

async def _test(item:SnmpDevice,auth_password:str,privacy_password:str)->None:
    item.last_polled_at=datetime.now(timezone.utc)
    try:
        description,name=await probe_v3(item,auth_password,privacy_password)
        item.status="ONLINE";item.system_description=description;item.system_name=name;item.last_success_at=item.last_polled_at;item.last_error=None
    except Exception as exc:
        item.status="OFFLINE";item.last_error=str(exc) if isinstance(exc,ConnectionError) else "SNMP polling failed"

@router.get("/devices",response_model=list[SnmpDeviceOut])
async def list_devices(db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):
    return list((await db.scalars(select(SnmpDevice).order_by(SnmpDevice.name))).all())

@router.post("/devices",response_model=SnmpDeviceOut,status_code=status.HTTP_201_CREATED)
async def add_device(body:SnmpDeviceInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    try:
        item=SnmpDevice(name=body.name.strip(),ip_address=str(body.ip_address),port=body.port,version="3",username=body.username.strip(),auth_protocol="SHA-256",privacy_protocol="AES-128",auth_secret_encrypted=encrypt_snmp_secret(body.auth_password),privacy_secret_encrypted=encrypt_snmp_secret(body.privacy_password),poll_interval_seconds=body.poll_interval_seconds,created_by=user.id)
    except RuntimeError as exc:raise HTTPException(503,str(exc)) from exc
    db.add(item)
    try:await db.flush()
    except IntegrityError as exc:
        await db.rollback();raise HTTPException(409,"SNMP device name or target already exists") from exc
    await _test(item,body.auth_password,body.privacy_password)
    await record(db,request,user,"snmp.device.create","snmp_device",str(item.id),"success",new={"name":item.name,"ip_address":str(item.ip_address),"port":item.port,"version":"3","security_level":"authPriv"})
    await db.commit();await db.refresh(item);return item

@router.post("/devices/{device_id}/test",response_model=SnmpDeviceOut)
async def test_device(device_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    item=await db.get(SnmpDevice,device_id)
    if not item:raise HTTPException(404,"SNMP device not found")
    try:await _test(item,decrypt_snmp_secret(item.auth_secret_encrypted),decrypt_snmp_secret(item.privacy_secret_encrypted))
    except RuntimeError as exc:raise HTTPException(503,str(exc)) from exc
    await record(db,request,user,"snmp.device.test","snmp_device",str(item.id),"success" if item.status=="ONLINE" else "failed",new={"status":item.status})
    await db.commit();await db.refresh(item);return item

@router.delete("/devices/{device_id}",status_code=status.HTTP_204_NO_CONTENT)
async def remove_device(device_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("agents.manage"))):
    item=await db.get(SnmpDevice,device_id)
    if not item:raise HTTPException(404,"SNMP device not found")
    await record(db,request,user,"snmp.device.delete","snmp_device",str(item.id),"success",previous={"name":item.name,"ip_address":str(item.ip_address),"port":item.port})
    await db.delete(item);await db.commit()
