from __future__ import annotations

import re
import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator
class Token(BaseModel): access_token:str; token_type:str="bearer"; expires_in:int
class PageMeta(BaseModel): page:int; page_size:int; total:int; pages:int
class SystemMetrics(BaseModel):
    cpu_percent:float|None=Field(None,ge=0,le=100);memory_percent:float|None=Field(None,ge=0,le=100);disk_percent:float|None=Field(None,ge=0,le=100);network_receive_bps:float|None=Field(None,ge=0);network_send_bps:float|None=Field(None,ge=0);network_utilization_percent:float|None=Field(None,ge=0,le=100);sampled_at:datetime;network_adapter:str|None=Field(None,max_length=255);sample_window_seconds:float|None=Field(None,ge=0,le=300)
class DeviceOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:uuid.UUID; device_identifier:str; hostname:str; username:str|None; ip_address:str|None; active_ips:list[str]=Field(default_factory=list); os_name:str|None; os_version:str|None=None; agent_version:str|None; last_heartbeat:datetime|None; status:str; uptime_seconds:int|None=None; group_name:str|None=None; department:str|None=None; enrollment_state:str|None=None; control_mode:str="MONITOR_ONLY"; system_metrics:SystemMetrics|None=None
class DevicePage(BaseModel): items:list[DeviceOut]; meta:PageMeta
class SnmpDeviceInput(BaseModel):
    name:str=Field(min_length=1,max_length=100);vendor:str="generic";ip_address:IPvAnyAddress;port:int=Field(default=161,ge=1,le=65535);version:str="3";username:str=Field(min_length=1,max_length=64);auth_protocol:str="SHA-256";privacy_protocol:str="AES-128";auth_password:str=Field(min_length=8,max_length=255);privacy_password:str=Field(min_length=8,max_length=255);poll_interval_seconds:int=Field(default=60,ge=30,le=86400)
    @field_validator("ip_address")
    @classmethod
    def private_ipv4_only(cls,value):
        import ipaddress
        address=ipaddress.ip_address(str(value));allowed=[ipaddress.ip_network("10.0.0.0/8"),ipaddress.ip_network("172.16.0.0/12"),ipaddress.ip_network("192.168.0.0/16")]
        if address.version!=4 or not any(address in network for network in allowed):raise ValueError("must be an RFC1918 private IPv4 address")
        return value
    @field_validator("version")
    @classmethod
    def snmp_v3_only(cls,value):
        if value!="3":raise ValueError("only SNMPv3 authPriv is supported")
        return value
    @field_validator("vendor")
    @classmethod
    def supported_vendor(cls,value):
        if value not in {"pfsense","fortigate","cisco","juniper","aruba","sonicwall","generic"}:raise ValueError("unsupported SNMP vendor template")
        return value
    @field_validator("auth_protocol")
    @classmethod
    def supported_auth_protocol(cls,value):
        if value not in {"SHA-256","SHA-1"}:raise ValueError("authentication protocol must be SHA-256 or SHA-1")
        return value
    @field_validator("privacy_protocol")
    @classmethod
    def aes_privacy_only(cls,value):
        if value!="AES-128":raise ValueError("only AES-128 privacy is supported")
        return value
class SnmpDeviceUpdate(SnmpDeviceInput):
    auth_password:str|None=Field(default=None,min_length=8,max_length=255)
    privacy_password:str|None=Field(default=None,min_length=8,max_length=255)
class SnmpDeviceOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:uuid.UUID;name:str;vendor:str;ip_address:IPvAnyAddress;port:int;version:str;username:str;auth_protocol:str;privacy_protocol:str;enabled:bool;poll_interval_seconds:int;status:str;system_name:str|None;system_description:str|None;last_polled_at:datetime|None;last_success_at:datetime|None;last_error:str|None;created_at:datetime
class DiscoveryNetworkInput(BaseModel):
    name:str=Field(min_length=1,max_length=100);cidr:str;vlan:str|None=Field(None,max_length=100);enabled:bool=True;interval_seconds:int=Field(default=900,ge=60,le=86400);probe_ports:list[int]=Field(default=[80,443,445,3389],min_length=1,max_length=16)
    @field_validator("probe_ports")
    @classmethod
    def ports_valid(cls,values): return sorted(set(values)) if all(1<=v<=65535 for v in values) else (_ for _ in ()).throw(ValueError("ports must be between 1 and 65535"))
class DiscoveryNetworkOut(DiscoveryNetworkInput):
    model_config=ConfigDict(from_attributes=True)
    id:uuid.UUID;last_started_at:datetime|None;last_completed_at:datetime|None;last_status:str;last_error:str|None;last_host_count:int
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
    method:str|None=Field(default=None,max_length=20)
    status_code:int|None=Field(default=None,ge=100,le=599)
    action:str
    policy_id:uuid.UUID|None=None
    matched_rule_id:uuid.UUID|None=None
    category:str|None=Field(default=None,max_length=100)
    bytes_uploaded:int=Field(default=0,ge=0,le=9_223_372_036_854_775_807)
    bytes_downloaded:int=Field(default=0,ge=0,le=9_223_372_036_854_775_807)
    duration_ms:int|None=Field(default=None,ge=0)
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
class PairingRequestInput(BaseModel):
    pairing_secret:str=Field(min_length=32,max_length=200);installation_id:str=Field(min_length=8,max_length=200);hostname:str=Field(min_length=1,max_length=255);os_name:str=Field(max_length=100);os_version:str|None=Field(None,max_length=100);architecture:str|None=Field(None,max_length=30);agent_version:str=Field(max_length=50);initial_ip:IPvAnyAddress|None=None;requested_control_mode:str="MONITOR_ONLY"
    @field_validator("requested_control_mode")
    @classmethod
    def supported_requested_control_mode(cls,value):
        value=value.strip().upper()
        if value not in {"MONITOR_ONLY","WEB_CONTROLLED"}:raise ValueError("requested control mode must be MONITOR_ONLY or WEB_CONTROLLED")
        return value
class PairingClaimInput(BaseModel):pairing_secret:str=Field(min_length=32,max_length=200)
class PairingApprovalInput(BaseModel):
    group_name:str|None=Field(None,max_length=100)
    department:str|None=Field(None,max_length=100)
    control_mode:str="MONITOR_ONLY"

    @field_validator("control_mode")
    @classmethod
    def supported_control_mode(cls,value):
        value=value.strip().upper()
        if value not in {"MONITOR_ONLY","WEB_CONTROLLED"}:raise ValueError("control mode must be MONITOR_ONLY or WEB_CONTROLLED")
        return value
class Heartbeat(BaseModel):
    device_id:uuid.UUID; timestamp:datetime; hostname:str=Field(max_length=255); username:str|None=Field(None,max_length=255); agent_version:str=Field(max_length=50); os_name:str=Field(max_length=100); os_version:str|None=Field(None,max_length=100); active_ips:list[IPvAnyAddress]=Field(default_factory=list,max_length=32); mac_addresses:list[str]=Field(default_factory=list,max_length=32); gateway:IPvAnyAddress|None=None; dns:list[IPvAnyAddress]=Field(default_factory=list,max_length=16); boot_time:datetime|None=None; uptime_seconds:int=Field(ge=0); proxy_status:ProxyStatus|None=None;system_metrics:SystemMetrics|None=None
class DeviceAssignment(BaseModel):
    group_name:str|None=Field(None,max_length=100)
    department:str|None=Field(None,max_length=100)

class DeviceControlModeInput(BaseModel):
    control_mode:str

    @field_validator("control_mode")
    @classmethod
    def supported_control_mode(cls,value):
        value=value.strip().upper()
        if value not in {"MONITOR_ONLY","WEB_CONTROLLED"}:raise ValueError("control mode must be MONITOR_ONLY or WEB_CONTROLLED")
        return value

class ProxyStatus(BaseModel):
    desired_version:int=Field(ge=1); applied_version:int|None=Field(None,ge=1); current_state:str=Field(max_length=30); drift_detected:bool=False; last_apply_result:str|None=Field(None,max_length=50); last_error:str|None=Field(None,max_length=500); effective_host:str|None=Field(None,max_length=253); effective_port:int|None=Field(None,ge=1,le=65535); bypass_summary:str|None=Field(None,max_length=500)

class ProxyConfigurationInput(BaseModel):
    enabled:bool=False
    host:str|None=Field(None,max_length=253)
    port:int|None=Field(None,ge=1,le=65535)
    bypass:list[str]=Field(default_factory=list,max_length=256)
    mode:str="disabled"

    @field_validator("host")
    @classmethod
    def valid_host(cls,value):
        if value is None:return value
        value=value.strip()
        if not value or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?",value):raise ValueError("invalid proxy host")
        return value.lower()

    @field_validator("bypass")
    @classmethod
    def valid_bypass(cls,values):
        cleaned=[]
        for value in values:
            value=value.strip()
            if len(value)>253 or not re.fullmatch(r"(?:<local>|[A-Za-z0-9*._:\[\]-]+)",value,re.IGNORECASE):raise ValueError("invalid bypass entry")
            if value not in cleaned:cleaned.append(value)
        return cleaned

    @model_validator(mode="after")
    def valid_combination(self):
        if self.mode not in {"disabled","configured"}:raise ValueError("unsupported proxy mode")
        if self.enabled and (not self.host or not self.port or self.mode!="configured"):raise ValueError("enabled proxy requires host, port, and configured mode")
        if not self.enabled and self.mode!="disabled":raise ValueError("disabled proxy requires disabled mode")
        return self
