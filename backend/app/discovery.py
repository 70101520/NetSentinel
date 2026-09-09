import asyncio,ipaddress,socket,uuid
from datetime import datetime,timedelta,timezone
import structlog
from fastapi import APIRouter,Depends,HTTPException,Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import SessionLocal,get_db
from app.models import Device,DiscoveryHost,DiscoveryNetwork,User
from app.schemas import DiscoveryNetworkInput,DiscoveryNetworkOut
from app.security import require
from app.audit import record
router=APIRouter(prefix="/api/v1/discovery",tags=["discovery"])
log=structlog.get_logger("device_discovery")
def validated_network(value:str):
    try: network=ipaddress.ip_network(value,strict=True)
    except ValueError: raise HTTPException(422,"A canonical network CIDR is required")
    private_ranges=(ipaddress.ip_network("10.0.0.0/8"),ipaddress.ip_network("172.16.0.0/12"),ipaddress.ip_network("192.168.0.0/16"))
    if network.version!=4 or not any(network.subnet_of(allowed) for allowed in private_ranges): raise HTTPException(422,"Only RFC1918 IPv4 networks are allowed")
    if sum(1 for _ in network.hosts())>settings.discovery_max_hosts_per_network: raise HTTPException(422,"Network exceeds the configured discovery host limit")
    return network
async def probe(ip:str,ports:list[int],semaphore:asyncio.Semaphore):
    async with semaphore:
        open_ports=[];reachable=False
        for port in ports:
            try:
                _,writer=await asyncio.wait_for(asyncio.open_connection(ip,port),settings.discovery_probe_timeout_seconds);writer.close();await writer.wait_closed();open_ports.append(port);reachable=True
            except ConnectionRefusedError:reachable=True
            except (OSError,asyncio.TimeoutError):pass
        if not reachable:return None
        try: hostname=(await asyncio.to_thread(socket.gethostbyaddr,ip))[0][:255]
        except (OSError,socket.herror):hostname=None
        return ip,hostname,open_ports
def agent_ip_map(devices):
    result={}
    for device in devices:
        observed=[] if device.ip_address is None else [str(device.ip_address)];observed.extend(str(value) for value in (device.metadata_ or {}).get("active_ips",[]))
        for address in observed:result.setdefault(address,device.id)
    return result
def observed_agent_status(device,cutoff):
    if not device:return "not-installed"
    return "online" if device.current_status=="ONLINE" and device.last_heartbeat and device.last_heartbeat>=cutoff else "offline"
@router.get("/networks",response_model=list[DiscoveryNetworkOut])
async def networks(db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):return list((await db.scalars(select(DiscoveryNetwork).order_by(DiscoveryNetwork.name))).all())
@router.post("/networks",response_model=DiscoveryNetworkOut,status_code=201)
async def create_network(body:DiscoveryNetworkInput,db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.manage"))):
    network=validated_network(body.cidr);item=DiscoveryNetwork(**body.model_dump(exclude={"cidr"}),cidr=str(network));db.add(item)
    try:await db.commit()
    except IntegrityError:await db.rollback();raise HTTPException(409,"Discovery network name or CIDR already exists")
    await db.refresh(item);return item
@router.delete("/networks/{network_id}")
async def delete_network(network_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("devices.manage"))):
    item=await db.get(DiscoveryNetwork,network_id)
    if not item:raise HTTPException(404,"Discovery network not found")
    if item.last_status=="RUNNING":raise HTTPException(409,"A running discovery scan cannot be removed")
    host_count=len((await db.scalars(select(DiscoveryHost.id).where(DiscoveryHost.network_id==item.id))).all())
    await record(db,request,user,"discovery.network.remove","discovery_network",str(item.id),"success",previous={"cidr":item.cidr,"vlan":item.vlan,"observations_removed":host_count})
    await db.delete(item);await db.commit();return {"status":"removed"}
@router.get("/hosts")
async def hosts(db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):
    rows=(await db.execute(select(DiscoveryHost,DiscoveryNetwork,Device).join(DiscoveryNetwork).outerjoin(Device,DiscoveryHost.matched_device_id==Device.id).order_by(DiscoveryHost.ip_address))).all()
    cutoff=datetime.now(timezone.utc)-timedelta(seconds=settings.agent_heartbeat_timeout_seconds)
    services={22:"SSH",80:"HTTP",443:"HTTPS",445:"SMB",3128:"HTTP Proxy",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",8080:"HTTP Alternate"}
    return [{"id":h.id,"network_id":h.network_id,"network":n.name,"cidr":n.cidr,"vlan":n.vlan,"ip_address":str(h.ip_address),"hostname":d.hostname if d else h.hostname,"status":h.state.lower(),"first_seen":h.first_seen,"last_seen":h.last_seen,"open_ports":h.open_ports,"services":[services.get(port,f"TCP {port}") for port in h.open_ports],"agent_installed":d is not None,"agent_status":observed_agent_status(d,cutoff),"agent_last_seen":d.last_heartbeat if d else None,"device_id":h.matched_device_id} for h,n,d in rows]
async def execute_scan(item:DiscoveryNetwork,db:AsyncSession):
    network=validated_network(item.cidr);addresses=[str(ip) for ip in network.hosts()];now=datetime.now(timezone.utc);item.last_started_at=now;item.last_status="RUNNING";await db.commit()
    semaphore=asyncio.Semaphore(settings.discovery_concurrency)
    results=[v for v in await asyncio.gather(*(probe(ip,item.probe_ports,semaphore) for ip in addresses)) if v]
    existing={str(h.ip_address):h for h in (await db.scalars(select(DiscoveryHost).where(DiscoveryHost.network_id==item.id))).all()};devices={}
    enrolled=(await db.scalars(select(Device).where(Device.agent_identity.is_not(None),Device.enrollment_state=="ENROLLED").order_by(Device.last_heartbeat.desc().nullslast()))).all();devices=agent_ip_map(enrolled)
    for host in existing.values():host.state="OFFLINE"
    for ip,hostname,ports in results:
        host=existing.get(ip) or DiscoveryHost(network_id=item.id,ip_address=ip);db.add(host);host.hostname=hostname;host.open_ports=ports;host.last_seen=now;host.state="ONLINE";host.matched_device_id=devices.get(ip)
    item.last_completed_at=datetime.now(timezone.utc);item.last_status="SUCCESS";item.last_error=None;item.last_host_count=len(results);await db.commit()
    return {"status":"completed","hosts_online":len(results),"addresses_scanned":len(addresses)}
@router.post("/networks/{network_id}/scan")
async def scan(network_id:uuid.UUID,db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.manage"))):
    item=await db.get(DiscoveryNetwork,network_id)
    if not item:raise HTTPException(404,"Discovery network not found")
    try:return await execute_scan(item,db)
    except Exception as exc:
        await db.rollback();item=await db.get(DiscoveryNetwork,network_id);item.last_completed_at=datetime.now(timezone.utc);item.last_status="FAILED";item.last_error=type(exc).__name__[:300];await db.commit();raise
async def discovery_scheduler(stop:asyncio.Event):
    while not stop.is_set():
        try:
            async with SessionLocal() as db:
                now=datetime.now(timezone.utc);items=(await db.scalars(select(DiscoveryNetwork).where(DiscoveryNetwork.enabled.is_(True)))).all()
                due=[item for item in items if item.last_started_at is None or item.last_started_at+timedelta(seconds=item.interval_seconds)<=now]
                for item in due:
                    try:await execute_scan(item,db)
                    except Exception as exc:
                        await db.rollback();failed=await db.get(DiscoveryNetwork,item.id);failed.last_completed_at=datetime.now(timezone.utc);failed.last_status="FAILED";failed.last_error=type(exc).__name__[:300];await db.commit();log.error("scheduled_discovery_failed",network_id=str(item.id),error_type=type(exc).__name__)
        except Exception as exc:log.error("discovery_scheduler_failure",error_type=type(exc).__name__)
        try:await asyncio.wait_for(stop.wait(),settings.discovery_scheduler_interval_seconds)
        except asyncio.TimeoutError:pass
