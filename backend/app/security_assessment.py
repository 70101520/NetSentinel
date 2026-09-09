import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models import Device, DiscoveryHost, SnmpDevice, User
from app.security import require

router=APIRouter(prefix="/api/v1/security",tags=["security-assessment"])

class AssessmentRequest(BaseModel):
    device_ids:list[uuid.UUID]=Field(min_length=1,max_length=100)

class SnmpAssessmentRequest(BaseModel):
    snmp_device_ids:list[uuid.UUID]=Field(min_length=1,max_length=100)

PORT_FINDINGS={
    23:("high","Telnet service is reachable","Telnet does not protect credentials or session contents.","Disable Telnet and use SSH or a secured management channel."),
    445:("medium","SMB service is reachable","TCP 445 is reachable from the discovery network.","Restrict SMB to required management and file-service segments."),
    3389:("medium","RDP service is reachable","TCP 3389 is reachable from the discovery network.","Restrict RDP by firewall policy, require NLA and use a managed access path."),
    3128:("medium","Proxy service is reachable","TCP 3128 is reachable from the discovery network.","Require authentication and restrict proxy access to approved networks."),
    80:("low","Unencrypted HTTP service is reachable","TCP 80 is reachable and may expose clear-text web traffic.","Redirect to HTTPS or disable HTTP when it is not required."),
    8080:("low","Alternate HTTP service is reachable","TCP 8080 is reachable from the discovery network.","Verify the service owner and restrict or protect the endpoint with TLS."),
}

def finding(severity,title,evidence,remediation,category="security"):
    return {"severity":severity,"title":title,"category":category,"evidence":evidence,"remediation":remediation}

def evaluate_security(device,open_ports:list[int]):
    findings=[]
    if device.current_status!="ONLINE":findings.append(finding("high","Agent is offline","The enrolled agent is not currently reporting.","Restore endpoint connectivity and verify the NetSentinelAgent service.","health"))
    metrics=(device.metadata_ or {}).get("system_metrics")
    if not metrics:findings.append(finding("info","System health metrics unavailable","The installed agent has not reported CPU, memory, disk or bandwidth metrics.","Upgrade the endpoint agent to version 0.3.0 or later.","health"))
    else:
        for key,label,severity in (("cpu_percent","CPU","medium"),("memory_percent","Memory","medium"),("disk_percent","Disk","high")):
            value=metrics.get(key)
            if value is not None and value>=90:findings.append(finding(severity,f"High {label.lower()} utilization",f"Latest reported {label} utilization is {value:.1f}%.",f"Review {label.lower()} consumers and restore sustained utilization below 90%.","health"))
    for port in sorted(set(open_ports)):
        if port in PORT_FINDINGS:
            severity,title,evidence,remediation=PORT_FINDINGS[port]
            findings.append(finding(severity,title,evidence,remediation))
    if not open_ports:findings.append(finding("info","No common service port detected","The latest discovery probe found no open port in its limited configured port set.","Run an explicitly authorized expanded port scan for broader coverage."))
    return findings


def evaluate_snmp_security(device,open_ports:list[int]):
    findings=[]
    if device.status!="ONLINE":findings.append(finding("high","SNMP monitoring is offline","The appliance did not answer the latest authenticated SNMPv3 poll.","Verify device availability, UDP 161 access and the configured SNMPv3 credentials.","health"))
    if device.auth_protocol=="SHA-1":findings.append(finding("medium","Legacy SNMP authentication protocol","This appliance is configured with SHA-1 authentication compatibility.","Use SHA-256 when the appliance firmware supports it and keep UDP 161 source-restricted.","configuration"))
    if not device.system_description:findings.append(finding("info","System identity unavailable","No authenticated system description has been collected.","Test SNMP connectivity and confirm the read-only view includes the SNMPv2-MIB system objects.","evidence"))
    for port in sorted(set(open_ports)):
        if port in PORT_FINDINGS:
            severity,title,evidence,remediation=PORT_FINDINGS[port]
            findings.append(finding(severity,title,evidence,remediation,"service-exposure"))
    if not open_ports:findings.append(finding("info","No bounded service evidence","This device was not matched to an open port in the latest configured discovery probe.","Run discovery for the appliance subnet before relying on service-exposure results.","evidence"))
    return findings
@router.post("/assess")
async def assess(body:AssessmentRequest,db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):
    requested=list(dict.fromkeys(body.device_ids))
    devices=(await db.scalars(select(Device).where(Device.id.in_(requested),Device.enrollment_state=="ENROLLED"))).all()
    if len(devices)!=len(requested):raise HTTPException(404,"One or more enrolled devices were not found")
    results=[]
    for device in devices:
        host=await db.scalar(select(DiscoveryHost).where(DiscoveryHost.matched_device_id==device.id).order_by(DiscoveryHost.last_seen.desc()).limit(1))
        if not host and device.ip_address:
            host=await db.scalar(select(DiscoveryHost).where(DiscoveryHost.ip_address==device.ip_address).order_by(DiscoveryHost.last_seen.desc()).limit(1))
        ports=list(host.open_ports or []) if host else []
        results.append({"device_id":device.id,"hostname":device.hostname,"ip_address":str(device.ip_address) if device.ip_address else None,"findings":evaluate_security(device,ports),"evidence":{"discovery_observed_at":host.last_seen if host else None,"agent_heartbeat_at":device.last_heartbeat,"open_ports":ports}})
    counts={severity:sum(1 for result in results for item in result["findings"] if item["severity"]==severity) for severity in ("high","medium","low","info")}
    return {"assessment_id":uuid.uuid4(),"assessed_at":datetime.now(timezone.utc),"mode":"non-invasive","counts":counts,"devices":results,"limitations":["Uses the latest bounded discovery port set and agent health report.","Does not exploit vulnerabilities, authenticate to services or attempt lateral movement.","A missing finding does not prove that a device is secure."]}
@router.post("/assess-snmp")
async def assess_snmp(body:SnmpAssessmentRequest,db:AsyncSession=Depends(get_db),_:User=Depends(require("devices.view"))):
    requested=list(dict.fromkeys(body.snmp_device_ids))
    devices=(await db.scalars(select(SnmpDevice).where(SnmpDevice.id.in_(requested)))).all()
    if len(devices)!=len(requested):raise HTTPException(404,"One or more SNMP devices were not found")
    results=[]
    for device in devices:
        host=await db.scalar(select(DiscoveryHost).where(DiscoveryHost.ip_address==device.ip_address).order_by(DiscoveryHost.last_seen.desc()).limit(1))
        ports=list(host.open_ports or []) if host else []
        results.append({"device_id":device.id,"hostname":device.system_name or device.name,"ip_address":str(device.ip_address),"findings":evaluate_snmp_security(device,ports),"evidence":{"discovery_observed_at":host.last_seen if host else None,"agent_heartbeat_at":None,"open_ports":ports,"snmp_last_polled_at":device.last_polled_at,"system_description":device.system_description}})
    counts={severity:sum(1 for result in results for item in result["findings"] if item["severity"]==severity) for severity in ("high","medium","low","info")}
    return {"assessment_id":uuid.uuid4(),"assessed_at":datetime.now(timezone.utc),"mode":"non-invasive","counts":counts,"devices":results,"limitations":["Uses authenticated read-only SNMP identity/health and the latest bounded discovery port set.","Does not change appliance configuration, exploit vulnerabilities, authenticate to exposed services or attempt lateral movement.","Firmware CVE correlation is not claimed until a maintained vulnerability feed and reliable product/version normalization are configured."]}
