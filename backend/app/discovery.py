import asyncio,ipaddress,socket,uuid
from datetime import datetime,timezone
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.db import get_db
from app.models import Device,DiscoveryHost,DiscoveryNetwork,User
from app.schemas import DiscoveryNetworkInput,DiscoveryNetworkOut
from app.security import require
router=APIRouter(prefix="/api/v1/discovery",tags=["discovery"])
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
@router.get("/networks",response_model=list[DiscoveryNetworkOut])
async def networks(db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):return list((await db.scalars(select(DiscoveryNetwork).order_by(DiscoveryNetwork.name))).all())
@router.post("/networks",response_model=DiscoveryNetworkOut,status_code=201)
async def create_network(body:DiscoveryNetworkInput,db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.manage"))):
    network=validated_network(body.cidr);item=DiscoveryNetwork(**body.model_dump(exclude={"cidr"}),cidr=str(network));db.add(item)
    try:await db.commit()
    except IntegrityError:await db.rollback();raise HTTPException(409,"Discovery network name or CIDR already exists")
    await db.refresh(item);return item
@router.get("/hosts")
async def hosts(db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):
    rows=(await db.execute(select(DiscoveryHost,DiscoveryNetwork).join(DiscoveryNetwork).order_by(DiscoveryHost.ip_address))).all()
    return [{"id":h.id,"network_id":h.network_id,"network":n.name,"vlan":n.vlan,"ip_address":str(h.ip_address),"hostname":h.hostname,"status":h.state.lower(),"last_seen":h.last_seen,"open_ports":h.open_ports,"agent_installed":h.matched_device_id is not None,"device_id":h.matched_device_id} for h,n in rows]
@router.post("/networks/{network_id}/scan")
async def scan(network_id:uuid.UUID,db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.manage"))):
    item=await db.get(DiscoveryNetwork,network_id); 
    if not item:raise HTTPException(404,"Discovery network not found")
    network=validated_network(item.cidr);addresses=[str(ip) for ip in network.hosts()];now=datetime.now(timezone.utc);item.last_started_at=now;item.last_status="RUNNING";await db.commit()
    semaphore=asyncio.Semaphore(settings.discovery_concurrency)
    results=[v for v in await asyncio.gather(*(probe(ip,item.probe_ports,semaphore) for ip in addresses)) if v]
    existing={str(h.ip_address):h for h in (await db.scalars(select(DiscoveryHost).where(DiscoveryHost.network_id==item.id))).all()};devices={str(d.ip_address):d.id for d in (await db.scalars(select(Device).where(Device.ip_address.is_not(None)))).all()}
    for host in existing.values():host.state="OFFLINE"
    for ip,hostname,ports in results:
        host=existing.get(ip) or DiscoveryHost(network_id=item.id,ip_address=ip);db.add(host);host.hostname=hostname;host.open_ports=ports;host.last_seen=now;host.state="ONLINE";host.matched_device_id=devices.get(ip)
    item.last_completed_at=now;item.last_status="SUCCESS";item.last_error=None;item.last_host_count=len(results);await db.commit()
    return {"status":"completed","hosts_online":len(results),"addresses_scanned":len(addresses)}
