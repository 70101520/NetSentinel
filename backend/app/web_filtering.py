import ipaddress
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import record
from app.config import settings
from app.db import get_db
from app.models import Device, ProxyEvent, User, WebAllowRule, WebBlockRule, WebCategory, WebTrustedNetwork
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


class DomainRuleInput(BaseModel):
    domain:str=Field(min_length=1,max_length=4096)
    include_subdomains:bool=True
    category_id:uuid.UUID|None=None
    @field_validator("domain")
    @classmethod
    def valid_domain(cls,value):
        try:return normalize_domain(value)
        except ValueError as exc:raise ValueError(str(exc)) from exc


class CategoryInput(BaseModel):
    name:str=Field(min_length=1,max_length=100)
    description:str|None=Field(None,max_length=300)
    @field_validator("name")
    @classmethod
    def clean_name(cls,value):return " ".join(value.split())


class TrustedNetworkInput(BaseModel):
    name:str=Field(min_length=1,max_length=100)
    cidr:str=Field(min_length=3,max_length=50)
    @field_validator("name")
    @classmethod
    def clean_name(cls,value):return " ".join(value.split())
    @field_validator("cidr")
    @classmethod
    def private_cidr(cls,value):
        try:network=ipaddress.ip_network(value.strip(),strict=False)
        except ValueError as exc:raise ValueError("Enter a valid IPv4 or IPv6 CIDR") from exc
        if not network.is_private:raise ValueError("Trusted network must be a private CIDR")
        return str(network)


@router.get("/logs")
async def logs(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=200),domain:str|None=None,action:str|None=None,device_id:uuid.UUID|None=None,since_hours:int=Query(24,ge=0,le=8760),db:AsyncSession=Depends(get_db),_:User=Depends(require("web_logs.view"))):
    page_size=min(page_size,settings.max_page_size);filters=[Device.enrollment_state=="ENROLLED",Device.control_mode=="WEB_CONTROLLED"]
    if since_hours:filters.append(ProxyEvent.occurred_at>=datetime.now(timezone.utc)-timedelta(hours=since_hours))
    if domain:filters.append(ProxyEvent.domain.ilike(f"%{domain.strip()}%"))
    if action:
        action=action.upper()
        if action not in {"ALLOW","BLOCK"}:raise HTTPException(422,"action must be ALLOW or BLOCK")
        filters.append(ProxyEvent.action==action)
    if device_id:filters.append(ProxyEvent.device_id==device_id)
    base=select(ProxyEvent).join(Device,Device.id==ProxyEvent.device_id).where(*filters);total=await db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows=(await db.execute(select(ProxyEvent,Device.hostname.label("device_hostname"),Device.username.label("device_username")).join(Device,Device.id==ProxyEvent.device_id).where(*filters).order_by(ProxyEvent.occurred_at.desc()).offset((page-1)*page_size).limit(page_size))).all();items=[]
    for event,device_hostname,device_username in rows:items.append({"id":event.id,"occurred_at":event.occurred_at,"device_id":event.device_id,"hostname":device_hostname or event.hostname,"username":device_username or event.username,"source_ip":str(event.source_ip) if event.source_ip else None,"domain":event.domain,"url":event.url,"protocol":event.protocol,"port":event.port,"action":event.action,"bytes_up":event.bytes_up,"bytes_down":event.bytes_down})
    return {"items":items,"meta":{"page":page,"page_size":page_size,"total":total,"pages":(total+page_size-1)//page_size}}


@router.get("/categories")
async def categories(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    rows=(await db.execute(select(WebCategory,func.count(WebBlockRule.id)).outerjoin(WebBlockRule,WebBlockRule.category_id==WebCategory.id).group_by(WebCategory.id).order_by(WebCategory.name))).all()
    return [{"id":item.id,"name":item.name,"description":item.description,"rule_count":count,"created_at":item.created_at} for item,count in rows]


@router.post("/categories",status_code=status.HTTP_201_CREATED)
async def create_category(body:CategoryInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    if await db.scalar(select(WebCategory.id).where(func.lower(WebCategory.name)==body.name.lower())):raise HTTPException(409,"Category already exists")
    item=WebCategory(name=body.name,description=body.description,created_by=user.id);db.add(item);await db.flush();await record(db,request,user,"web.category.create","web_category",str(item.id),"success",new={"name":item.name});await db.commit();return {"id":item.id,"name":item.name,"description":item.description,"rule_count":0,"created_at":item.created_at}


@router.delete("/categories/{category_id}",status_code=status.HTTP_204_NO_CONTENT)
async def delete_category(category_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebCategory,category_id)
    if not item:raise HTTPException(404,"Category not found")
    await record(db,request,user,"web.category.delete","web_category",str(item.id),"success",previous={"name":item.name});await db.delete(item);await db.commit()


@router.get("/blocklist")
async def blocklist(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    rows=(await db.execute(select(WebBlockRule,WebCategory.name).outerjoin(WebCategory,WebCategory.id==WebBlockRule.category_id).where(WebBlockRule.enabled.is_(True)).order_by(WebCategory.name.nulls_last(),WebBlockRule.domain))).all()
    return [{"id":item.id,"domain":item.domain,"category_id":item.category_id,"category_name":category_name,"include_subdomains":item.include_subdomains,"created_at":item.created_at} for item,category_name in rows]


@router.post("/blocklist",status_code=status.HTTP_201_CREATED)
async def block(body:DomainRuleInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    if body.category_id and not await db.get(WebCategory,body.category_id):raise HTTPException(422,"Category not found")
    item=await db.scalar(select(WebBlockRule).where(WebBlockRule.domain==body.domain));previous=None
    if item:previous={"enabled":item.enabled,"category_id":str(item.category_id) if item.category_id else None};item.enabled=True;item.include_subdomains=body.include_subdomains;item.category_id=body.category_id
    else:item=WebBlockRule(domain=body.domain,category_id=body.category_id,include_subdomains=body.include_subdomains,created_by=user.id);db.add(item)
    await db.flush();await record(db,request,user,"web.domain.block","web_block_rule",str(item.id),"success",previous=previous,new={"domain":item.domain,"category_id":str(item.category_id) if item.category_id else None});await db.commit();return {"id":item.id,"domain":item.domain,"category_id":item.category_id,"include_subdomains":item.include_subdomains,"created_at":item.created_at}


@router.delete("/blocklist/{rule_id}",status_code=status.HTTP_204_NO_CONTENT)
async def unblock(rule_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebBlockRule,rule_id)
    if not item:raise HTTPException(404,"Blocked domain not found")
    await record(db,request,user,"web.domain.unblock","web_block_rule",str(item.id),"success",previous={"domain":item.domain});await db.delete(item);await db.commit()


@router.get("/allowlist")
async def allowlist(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    rows=(await db.scalars(select(WebAllowRule).order_by(WebAllowRule.domain))).all();return [{"id":item.id,"domain":item.domain,"include_subdomains":item.include_subdomains,"created_at":item.created_at} for item in rows]


@router.post("/allowlist",status_code=status.HTTP_201_CREATED)
async def allow(body:DomainRuleInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.scalar(select(WebAllowRule).where(WebAllowRule.domain==body.domain))
    if item:item.include_subdomains=body.include_subdomains
    else:item=WebAllowRule(domain=body.domain,include_subdomains=body.include_subdomains,created_by=user.id);db.add(item)
    await db.flush();await record(db,request,user,"web.domain.allow","web_allow_rule",str(item.id),"success",new={"domain":item.domain});await db.commit();return {"id":item.id,"domain":item.domain,"include_subdomains":item.include_subdomains,"created_at":item.created_at}


@router.delete("/allowlist/{rule_id}",status_code=status.HTTP_204_NO_CONTENT)
async def remove_allow(rule_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebAllowRule,rule_id)
    if not item:raise HTTPException(404,"Allowed domain not found")
    await record(db,request,user,"web.domain.allow.remove","web_allow_rule",str(item.id),"success",previous={"domain":item.domain});await db.delete(item);await db.commit()


@router.get("/trusted-networks")
async def trusted_networks(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    rows=(await db.scalars(select(WebTrustedNetwork).order_by(WebTrustedNetwork.name))).all();return [{"id":item.id,"name":item.name,"cidr":item.cidr,"created_at":item.created_at} for item in rows]


@router.post("/trusted-networks",status_code=status.HTTP_201_CREATED)
async def trust_network(body:TrustedNetworkInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    if await db.scalar(select(WebTrustedNetwork.id).where(WebTrustedNetwork.cidr==body.cidr)):raise HTTPException(409,"Trusted network already exists")
    item=WebTrustedNetwork(name=body.name,cidr=body.cidr,created_by=user.id);db.add(item);await db.flush();await record(db,request,user,"web.network.trust","web_trusted_network",str(item.id),"success",new={"name":item.name,"cidr":item.cidr});await db.commit();return {"id":item.id,"name":item.name,"cidr":item.cidr,"created_at":item.created_at}


@router.delete("/trusted-networks/{network_id}",status_code=status.HTTP_204_NO_CONTENT)
async def untrust_network(network_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebTrustedNetwork,network_id)
    if not item:raise HTTPException(404,"Trusted network not found")
    await record(db,request,user,"web.network.untrust","web_trusted_network",str(item.id),"success",previous={"name":item.name,"cidr":item.cidr});await db.delete(item);await db.commit()


def rule_matches(domain:str,rule)->bool:return domain==rule.domain or (rule.include_subdomains and domain.endswith("."+rule.domain))


async def domain_is_blocked(db:AsyncSession,domain:str)->tuple[bool,uuid.UUID|None]:
    domain=normalize_domain(domain);allowed=(await db.scalars(select(WebAllowRule))).all()
    if any(rule_matches(domain,item) for item in allowed):return False,None
    rules=(await db.scalars(select(WebBlockRule).where(WebBlockRule.enabled.is_(True)))).all()
    for item in rules:
        if rule_matches(domain,item):return True,item.id
    return False,None