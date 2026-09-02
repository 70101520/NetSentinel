import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
class Token(BaseModel): access_token:str; token_type:str="bearer"; expires_in:int
class PageMeta(BaseModel): page:int; page_size:int; total:int; pages:int
class DeviceOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:uuid.UUID; device_identifier:str; hostname:str; username:str|None; ip_address:str|None; os_name:str|None; agent_version:str|None; last_heartbeat:datetime|None; status:str
class DevicePage(BaseModel): items:list[DeviceOut]; meta:PageMeta
class PolicyRuleInput(BaseModel):
    priority:int=Field(ge=1,le=100000); action:str; domain_pattern:str=Field(max_length=253); expires_at:datetime|None=None
    @field_validator("action")
    @classmethod
    def action_valid(cls,v):
        if v not in {"ALLOW","BLOCK"}: raise ValueError("must be ALLOW or BLOCK")
        return v
    @field_validator("domain_pattern")
    @classmethod
    def domain_valid(cls,v):
        v=v.strip().rstrip(".").lower()
        bare=v[2:] if v.startswith("*.") else v
        if not bare or "/" in bare or "*" in bare: raise ValueError("invalid domain pattern")
        return v
class DecisionRequest(BaseModel): domain:str; policy_id:uuid.UUID
class Decision(BaseModel): action:str; policy_id:uuid.UUID; policy_version:int; matched_rule_id:uuid.UUID|None; reason:str
class ProxyEventInput(BaseModel):
    idempotency_key:str=Field(min_length=8,max_length=100); occurred_at:datetime; domain:str=Field(max_length=253); protocol:str; port:int=Field(ge=1,le=65535); action:str; hostname:str|None=None; source_ip:str|None=None; url:str|None=None; bytes_up:int=Field(default=0,ge=0); bytes_down:int=Field(default=0,ge=0)
