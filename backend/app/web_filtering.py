import ipaddress
import uuid
from datetime import datetime,timedelta,timezone
from urllib.parse import urlsplit
from fastapi import APIRouter,Depends,HTTPException,Query,Request,status
from pydantic import BaseModel,Field,field_validator
from sqlalchemy import func,select
from sqlalchemy.ext.asyncio import AsyncSession
from app.audit import record
from app.config import settings
from app.db import get_db
from app.models import Device,ProxyEvent,User,WebBlockRule
from app.security import require

router=APIRouter(prefix="/api/v1/web",tags=["web-filtering"])

def normalize_domain(value:str)->str:
    candidate=value.strip()
    if "://" in candidate:candidate=urlsplit(candidate).hostname or ""
    else:candidate=candidate.split("/",1)[0].split(":",1)[0]
    candidate=candidate.strip().rstrip(".").lower()
    try:normalized=candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:raise ValueError("Invalid domain") from exc
    if not normalized or len(normalized)>253 or " " in normalized or "." not in normalized:raise ValueError("Enter a valid public domain or URL")
    try:ipaddress.ip_address(normalized)
    except ValueError:pass
    else:raise ValueError("Use a domain name instead of an IP address")
    labels=normalized.split(".")
    if any(not label or len(label)>63 or label.startswith("-") or label.endswith("-") or not label.replace("-","").isalnum() for label in labels):raise ValueError("Enter a valid domain")
    return normalized

class BlockInput(BaseModel):
    domain:str=Field(min_length=1,max_length=4096)
    include_subdomains:bool=True
    @field_validator("domain")
    @classmethod
    def valid_domain(cls,value):
        try:return normalize_domain(value)
        except ValueError as exc:raise ValueError(str(exc)) from exc

@router.get("/logs")
async def logs(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=200),domain:str|None=None,action:str|None=None,device_id:uuid.UUID|None=None,since_hours:int=Query(24,ge=0,le=8760),db:AsyncSession=Depends(get_db),_:User=Depends(require("web_logs.view"))):
    page_size=min(page_size,settings.max_page_size)
    filters=[Device.enrollment_state=="ENROLLED",Device.control_mode=="WEB_CONTROLLED"]
    if since_hours:filters.append(ProxyEvent.occurred_at>=datetime.now(timezone.utc)-timedelta(hours=since_hours))
    if domain:filters.append(ProxyEvent.domain.ilike(f"%{domain.strip()}%"))
    if action:
        action=action.upper()
        if action not in {"ALLOW","BLOCK"}:raise HTTPException(422,"action must be ALLOW or BLOCK")
        filters.append(ProxyEvent.action==action)
    if device_id:filters.append(ProxyEvent.device_id==device_id)
    base=select(ProxyEvent).join(Device,Device.id==ProxyEvent.device_id).where(*filters)
    total=await db.scalar(select(func.count()).select_from(base.subquery())) or 0
    statement=(select(ProxyEvent,Device.hostname.label("device_hostname"),Device.username.label("device_username")).join(Device,Device.id==ProxyEvent.device_id).where(*filters).order_by(ProxyEvent.occurred_at.desc()).offset((page-1)*page_size).limit(page_size))
    rows=(await db.execute(statement)).all();items=[]
    for event,device_hostname,device_username in rows:
        items.append({"id":event.id,"occurred_at":event.occurred_at,"device_id":event.device_id,"hostname":device_hostname or event.hostname,"username":device_username or event.username,"source_ip":str(event.source_ip) if event.source_ip else None,"domain":event.domain,"url":event.url,"protocol":event.protocol,"port":event.port,"action":event.action,"bytes_up":event.bytes_up,"bytes_down":event.bytes_down})
    return {"items":items,"meta":{"page":page,"page_size":page_size,"total":total,"pages":(total+page_size-1)//page_size}}
@router.get("/blocklist")
async def blocklist(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    rows=(await db.scalars(select(WebBlockRule).where(WebBlockRule.enabled.is_(True)).order_by(WebBlockRule.domain))).all()
    return [{"id":item.id,"domain":item.domain,"include_subdomains":item.include_subdomains,"created_at":item.created_at} for item in rows]

@router.post("/blocklist",status_code=status.HTTP_201_CREATED)
async def block(body:BlockInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.scalar(select(WebBlockRule).where(WebBlockRule.domain==body.domain))
    if item:previous={"enabled":item.enabled,"include_subdomains":item.include_subdomains};item.enabled=True;item.include_subdomains=body.include_subdomains
    else:previous=None;item=WebBlockRule(domain=body.domain,include_subdomains=body.include_subdomains,created_by=user.id);db.add(item)
    await db.flush();await record(db,request,user,"web.domain.block","web_block_rule",str(item.id),"success",previous=previous,new={"domain":item.domain,"include_subdomains":item.include_subdomains});await db.commit()
    return {"id":item.id,"domain":item.domain,"include_subdomains":item.include_subdomains,"created_at":item.created_at}

@router.delete("/blocklist/{rule_id}",status_code=status.HTTP_204_NO_CONTENT)
async def unblock(rule_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebBlockRule,rule_id)
    if not item:raise HTTPException(404,"Blocked domain not found")
    await record(db,request,user,"web.domain.unblock","web_block_rule",str(item.id),"success",previous={"domain":item.domain,"include_subdomains":item.include_subdomains},new=None);await db.delete(item);await db.commit()

async def domain_is_blocked(db:AsyncSession,domain:str)->tuple[bool,uuid.UUID|None]:
    domain=normalize_domain(domain);rules=(await db.scalars(select(WebBlockRule).where(WebBlockRule.enabled.is_(True)))).all()
    for item in rules:
        if domain==item.domain or (item.include_subdomains and domain.endswith("."+item.domain)):return True,item.id
    return False,None