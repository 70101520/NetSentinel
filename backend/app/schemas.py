import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator
class Token(BaseModel): access_token:str; token_type:str="bearer"; expires_in:int
class PageMeta(BaseModel): page:int; page_size:int; total:int; pages:int
class DeviceOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:uuid.UUID; device_identifier:str; hostname:str; username:str|None; ip_address:str|None; os_name:str|None; agent_version:str|None; last_heartbeat:datetime|None; status:str; uptime_seconds:int|None=None; group_name:str|None=None; department:str|None=None
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
class TelemetryEvent(BaseModel):
    event_id:uuid.UUID
    event_time:datetime
    device_id:uuid.UUID|None=None
    username:str|None=Field(default=None,max_length=255)
    hostname:str|None=Field(default=None,max_length=255)
    source_ip:IPvAnyAddress|None=None
    destination_ip:IPvAnyAddress|None=None
    domain:str=Field(min_length=1,max_length=253)
    url:str|None=Field(default=None,max_length=4096)
    protocol:str=Field(min_length=1,max_length=20)
    port:int=Field(ge=1,le=65535)
    action:str
    policy_id:uuid.UUID|None=None
    category:str|None=Field(default=None,max_length=100)
    bytes_uploaded:int=Field(default=0,ge=0,le=9_223_372_036_854_775_807)
    bytes_downloaded:int=Field(default=0,ge=0,le=9_223_372_036_854_775_807)
    @field_validator("action")
    @classmethod
    def telemetry_action(cls,v):
        v=v.upper()
        if v not in {"ALLOW","BLOCK"}: raise ValueError("unsupported action")
        return v
    @field_validator("domain")
    @classmethod
    def telemetry_domain(cls,v):
        v=v.strip().rstrip(".").lower()
        if not v or "/" in v or " " in v: raise ValueError("invalid domain")
        return v.encode("idna").decode()
    @field_validator("event_time")
    @classmethod
    def aware_time(cls,v):
        if v.tzinfo is None or v.utcoffset() is None: raise ValueError("event_time must include a timezone")
        return v
class TelemetryBatch(BaseModel):
    events:list[TelemetryEvent]=Field(min_length=1)
class TelemetryAccepted(BaseModel): accepted:int; rejected:int=0; status:str="queued"
class EnrollRequest(BaseModel):
    enrollment_token:str=Field(min_length=20,max_length=200); installation_id:str=Field(min_length=8,max_length=200); hostname:str=Field(min_length=1,max_length=255); os_name:str=Field(max_length=100); os_version:str|None=Field(None,max_length=100); architecture:str|None=Field(None,max_length=30); initial_ip:IPvAnyAddress|None=None; mac_address:str|None=Field(None,max_length=17); agent_version:str=Field(max_length=50)
class Heartbeat(BaseModel):
    device_id:uuid.UUID; timestamp:datetime; hostname:str=Field(max_length=255); username:str|None=Field(None,max_length=255); agent_version:str=Field(max_length=50); os_name:str=Field(max_length=100); os_version:str|None=Field(None,max_length=100); active_ips:list[IPvAnyAddress]=Field(default_factory=list,max_length=32); mac_addresses:list[str]=Field(default_factory=list,max_length=32); gateway:IPvAnyAddress|None=None; dns:list[IPvAnyAddress]=Field(default_factory=list,max_length=16); boot_time:datetime|None=None; uptime_seconds:int=Field(ge=0)
class DeviceAssignment(BaseModel):
    group_name:str|None=Field(None,max_length=100)
    department:str|None=Field(None,max_length=100)
