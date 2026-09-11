import ipaddress
import contextlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import record
from app.config import settings
from app.db import get_db
from app.models import Device, DeviceWebPolicyGroup, ProxyEvent, User, WebAllowRule, WebBlockRule, WebCategory, WebDirectBypassRule, WebPolicyGroup, WebPolicyGroupCategory, WebTrustedNetwork
from app.security import require

router=APIRouter(prefix="/api/v1/web",tags=["web-filtering"])

async def invalidate_policy(request:Request):
    with contextlib.suppress(Exception):await request.app.state.redis.incr("netsentinel:web-policy-version")


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

class DeviceAssignmentInput(BaseModel):
    device_id:uuid.UUID

class PolicyGroupInput(BaseModel):
    name:str=Field(min_length=1,max_length=100)
    description:Optional[str]=Field(None,max_length=300)
    default_action:Literal["ALLOW","BLOCK"]="ALLOW"

class CategoryActionInput(BaseModel):
    action:Literal["ALLOW","BLOCK"]


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
    item=WebCategory(name=body.name,description=body.description,created_by=user.id);db.add(item);await db.flush();await record(db,request,user,"web.category.create","web_category",str(item.id),"success",new={"name":item.name});await db.commit();await invalidate_policy(request);return {"id":item.id,"name":item.name,"description":item.description,"rule_count":0,"created_at":item.created_at}


@router.delete("/categories/{category_id}",status_code=status.HTTP_204_NO_CONTENT)
async def delete_category(category_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebCategory,category_id)
    if not item:raise HTTPException(404,"Category not found")
    await record(db,request,user,"web.category.delete","web_category",str(item.id),"success",previous={"name":item.name});await db.delete(item);await db.commit();await invalidate_policy(request)


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
    await db.flush();await record(db,request,user,"web.domain.block","web_block_rule",str(item.id),"success",previous=previous,new={"domain":item.domain,"category_id":str(item.category_id) if item.category_id else None});await db.commit();await invalidate_policy(request);return {"id":item.id,"domain":item.domain,"category_id":item.category_id,"include_subdomains":item.include_subdomains,"created_at":item.created_at}


@router.delete("/blocklist/{rule_id}",status_code=status.HTTP_204_NO_CONTENT)
async def unblock(rule_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebBlockRule,rule_id)
    if not item:raise HTTPException(404,"Blocked domain not found")
    await record(db,request,user,"web.domain.unblock","web_block_rule",str(item.id),"success",previous={"domain":item.domain});await db.delete(item);await db.commit();await invalidate_policy(request)


@router.get("/allowlist")
async def allowlist(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    rows=(await db.scalars(select(WebAllowRule).order_by(WebAllowRule.domain))).all();return [{"id":item.id,"domain":item.domain,"include_subdomains":item.include_subdomains,"created_at":item.created_at} for item in rows]


@router.post("/allowlist",status_code=status.HTTP_201_CREATED)
async def allow(body:DomainRuleInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.scalar(select(WebAllowRule).where(WebAllowRule.domain==body.domain))
    if item:item.include_subdomains=body.include_subdomains
    else:item=WebAllowRule(domain=body.domain,include_subdomains=body.include_subdomains,created_by=user.id);db.add(item)
    await db.flush();await record(db,request,user,"web.domain.allow","web_allow_rule",str(item.id),"success",new={"domain":item.domain});await db.commit();await invalidate_policy(request);return {"id":item.id,"domain":item.domain,"include_subdomains":item.include_subdomains,"created_at":item.created_at}


@router.delete("/allowlist/{rule_id}",status_code=status.HTTP_204_NO_CONTENT)
async def remove_allow(rule_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebAllowRule,rule_id)
    if not item:raise HTTPException(404,"Allowed domain not found")
    await record(db,request,user,"web.domain.allow.remove","web_allow_rule",str(item.id),"success",previous={"domain":item.domain});await db.delete(item);await db.commit();await invalidate_policy(request)


@router.get("/trusted-networks")
async def trusted_networks(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    rows=(await db.scalars(select(WebTrustedNetwork).order_by(WebTrustedNetwork.name))).all();return [{"id":item.id,"name":item.name,"cidr":item.cidr,"created_at":item.created_at} for item in rows]

@router.get("/direct-bypass")
async def direct_bypass(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    rows=(await db.scalars(select(WebDirectBypassRule).order_by(WebDirectBypassRule.domain))).all()
    return [{"id":x.id,"domain":x.domain,"include_subdomains":x.include_subdomains,"description":x.description,"created_at":x.created_at} for x in rows]

@router.post("/direct-bypass",status_code=status.HTTP_201_CREATED)
async def add_direct_bypass(body:DomainRuleInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.scalar(select(WebDirectBypassRule).where(WebDirectBypassRule.domain==body.domain))
    if item:item.include_subdomains=body.include_subdomains
    else:item=WebDirectBypassRule(domain=body.domain,include_subdomains=body.include_subdomains,created_by=user.id);db.add(item)
    await db.flush();await record(db,request,user,"web.direct_bypass.create","web_direct_bypass_rule",str(item.id),"success",new={"domain":item.domain});await db.commit()
    return {"id":item.id,"domain":item.domain,"include_subdomains":item.include_subdomains,"created_at":item.created_at}

@router.delete("/direct-bypass/{rule_id}",status_code=status.HTTP_204_NO_CONTENT)
async def remove_direct_bypass(rule_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebDirectBypassRule,rule_id)
    if not item:raise HTTPException(404,"Direct bypass domain not found")
    await record(db,request,user,"web.direct_bypass.delete","web_direct_bypass_rule",str(item.id),"success",previous={"domain":item.domain});await db.delete(item);await db.commit()


@router.post("/trusted-networks",status_code=status.HTTP_201_CREATED)
async def trust_network(body:TrustedNetworkInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    if await db.scalar(select(WebTrustedNetwork.id).where(WebTrustedNetwork.cidr==body.cidr)):raise HTTPException(409,"Trusted network already exists")
    item=WebTrustedNetwork(name=body.name,cidr=body.cidr,created_by=user.id);db.add(item);await db.flush();await record(db,request,user,"web.network.trust","web_trusted_network",str(item.id),"success",new={"name":item.name,"cidr":item.cidr});await db.commit();return {"id":item.id,"name":item.name,"cidr":item.cidr,"created_at":item.created_at}


@router.delete("/trusted-networks/{network_id}",status_code=status.HTTP_204_NO_CONTENT)
async def untrust_network(network_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebTrustedNetwork,network_id)
    if not item:raise HTTPException(404,"Trusted network not found")
    await record(db,request,user,"web.network.untrust","web_trusted_network",str(item.id),"success",previous={"name":item.name,"cidr":item.cidr});await db.delete(item);await db.commit()


@router.get("/policy-groups")
async def policy_groups(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    groups=(await db.scalars(select(WebPolicyGroup).order_by(WebPolicyGroup.name))).all()
    action_rows=(await db.execute(select(WebPolicyGroupCategory,WebCategory.name).join(WebCategory,WebCategory.id==WebPolicyGroupCategory.category_id))).all()
    device_rows=(await db.execute(select(DeviceWebPolicyGroup.group_id,Device).join(Device,Device.id==DeviceWebPolicyGroup.device_id))).all()
    actions={group.id:[] for group in groups};devices={group.id:[] for group in groups}
    for item,name in action_rows:actions.setdefault(item.group_id,[]).append({"category_id":item.category_id,"category_name":name,"action":item.action})
    for group_id,device in device_rows:devices.setdefault(group_id,[]).append({"id":device.id,"hostname":device.hostname,"username":device.username})
    return [{"id":group.id,"name":group.name,"description":group.description,"default_action":group.default_action,"category_actions":actions[group.id],"devices":devices[group.id]} for group in groups]

@router.get("/policy-devices")
async def policy_devices(db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.view"))):
    rows=(await db.scalars(select(Device).where(Device.enrollment_state=="ENROLLED",Device.control_mode=="WEB_CONTROLLED").order_by(Device.hostname).limit(5000))).all()
    return [{"id":item.id,"hostname":item.hostname,"username":item.username,"current_status":item.current_status} for item in rows]

@router.post("/policy-groups",status_code=status.HTTP_201_CREATED)
async def create_policy_group(body:PolicyGroupInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    if await db.scalar(select(WebPolicyGroup.id).where(func.lower(WebPolicyGroup.name)==body.name.lower())):raise HTTPException(409,"Policy group already exists")
    item=WebPolicyGroup(name=" ".join(body.name.split()),description=body.description,default_action=body.default_action,created_by=user.id);db.add(item);await db.flush()
    await record(db,request,user,"web.policy_group.create","web_policy_group",str(item.id),"success",new={"name":item.name});await db.commit();await invalidate_policy(request)
    return {"id":item.id,"name":item.name,"default_action":item.default_action}

@router.delete("/policy-groups/{group_id}",status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy_group(group_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(WebPolicyGroup,group_id)
    if not item:raise HTTPException(404,"Policy group not found")
    await record(db,request,user,"web.policy_group.delete","web_policy_group",str(item.id),"success",previous={"name":item.name});await db.delete(item);await db.commit();await invalidate_policy(request)

def rule_matches(domain:str,rule)->bool:return domain==rule.domain or (rule.include_subdomains and domain.endswith("."+rule.domain))

@dataclass(frozen=True)
class CompiledWebPolicy:
    allowed_exact:frozenset
    allowed_suffix:frozenset
    blocked_exact:dict
    blocked_suffix:dict
    assignments:dict
    groups:dict
    actions:dict

async def compile_web_policy(db:AsyncSession)->CompiledWebPolicy:
    allow_rows=(await db.scalars(select(WebAllowRule))).all()
    block_rows=(await db.scalars(select(WebBlockRule).where(WebBlockRule.enabled.is_(True)))).all()
    allowed_exact=frozenset(x.domain for x in allow_rows if not x.include_subdomains)
    allowed_suffix=frozenset(x.domain for x in allow_rows if x.include_subdomains)
    blocked_exact={x.domain:(x.id,x.category_id) for x in block_rows if not x.include_subdomains}
    blocked_suffix={x.domain:(x.id,x.category_id) for x in block_rows if x.include_subdomains}
    assignments={x.device_id:x.group_id for x in (await db.scalars(select(DeviceWebPolicyGroup))).all()}
    groups={x.id:(x.enabled,x.default_action) for x in (await db.scalars(select(WebPolicyGroup))).all()}
    actions={(x.group_id,x.category_id):x.action for x in (await db.scalars(select(WebPolicyGroupCategory))).all()}
    return CompiledWebPolicy(allowed_exact,allowed_suffix,blocked_exact,blocked_suffix,assignments,groups,actions)

def evaluate_compiled_policy(policy:CompiledWebPolicy,domain:str,device_id:uuid.UUID):
    domain=normalize_domain(domain)
    suffixes=[".".join(domain.split(".")[index:]) for index in range(len(domain.split("."))-1)]
    if domain in policy.allowed_exact or any(x in policy.allowed_suffix for x in suffixes):return False,None
    group_id=policy.assignments.get(device_id);group=policy.groups.get(group_id)
    match=policy.blocked_exact.get(domain)
    if not match:
        match=next((policy.blocked_suffix[x] for x in suffixes if x in policy.blocked_suffix),None)
    if match:
        rule_id,category_id=match
        if group and group[0] and category_id:
            action=policy.actions.get((group_id,category_id),group[1])
            return action=="BLOCK",rule_id
        return True,rule_id
    return False,None

@router.put("/policy-groups/{group_id}/categories/{category_id}")
async def set_category_action(group_id:uuid.UUID,category_id:uuid.UUID,body:CategoryActionInput,request:Request,db:AsyncSession=Depends(get_db),_:User=Depends(require("policies.manage"))):
    if not await db.get(WebPolicyGroup,group_id) or not await db.get(WebCategory,category_id):raise HTTPException(404,"Policy group or category not found")
    item=await db.scalar(select(WebPolicyGroupCategory).where(WebPolicyGroupCategory.group_id==group_id,WebPolicyGroupCategory.category_id==category_id))
    if item:item.action=body.action
    else:item=WebPolicyGroupCategory(group_id=group_id,category_id=category_id,action=body.action);db.add(item)
    await db.commit();await invalidate_policy(request);return {"group_id":group_id,"category_id":category_id,"action":body.action}

@router.put("/policy-groups/{group_id}/devices")
async def assign_policy_device(group_id:uuid.UUID,body:DeviceAssignmentInput,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    device=await db.get(Device,body.device_id)
    if not await db.get(WebPolicyGroup,group_id) or not device:raise HTTPException(404,"Policy group or device not found")
    if device.control_mode!="WEB_CONTROLLED":raise HTTPException(409,"Only Full control devices can receive web policy")
    item=await db.get(DeviceWebPolicyGroup,body.device_id)
    if item:item.group_id=group_id;item.assigned_by=user.id
    else:db.add(DeviceWebPolicyGroup(device_id=body.device_id,group_id=group_id,assigned_by=user.id))
    await db.commit();await invalidate_policy(request);return {"group_id":group_id,"device_id":body.device_id}

@router.delete("/policy-groups/{group_id}/devices/{device_id}",status_code=status.HTTP_204_NO_CONTENT)
async def unassign_policy_device(group_id:uuid.UUID,device_id:uuid.UUID,request:Request,db:AsyncSession=Depends(get_db),user:User=Depends(require("policies.manage"))):
    item=await db.get(DeviceWebPolicyGroup,device_id)
    if not item or item.group_id!=group_id:raise HTTPException(404,"Device assignment not found")
    await record(db,request,user,"web.policy_group.unassign","device",str(device_id),"success",previous={"group_id":str(group_id)});await db.delete(item);await db.commit();await invalidate_policy(request)


async def domain_is_blocked(db:AsyncSession,domain:str,device_id:Optional[uuid.UUID]=None)->tuple[bool,Optional[uuid.UUID]]:
    domain=normalize_domain(domain);allowed=(await db.scalars(select(WebAllowRule))).all()
    if any(rule_matches(domain,item) for item in allowed):return False,None
    rules=(await db.scalars(select(WebBlockRule).where(WebBlockRule.enabled.is_(True)))).all()
    for item in rules:
        if not rule_matches(domain,item):continue
        if device_id and item.category_id:
            assignment=await db.get(DeviceWebPolicyGroup,device_id)
            if assignment:
                group=await db.get(WebPolicyGroup,assignment.group_id)
                action=await db.scalar(select(WebPolicyGroupCategory.action).where(WebPolicyGroupCategory.group_id==assignment.group_id,WebPolicyGroupCategory.category_id==item.category_id))
                if group and group.enabled:return (action or group.default_action)=="BLOCK",item.id
        return True,item.id
    return False,None
