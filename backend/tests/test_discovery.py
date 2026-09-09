import asyncio
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from app.discovery import probe,validated_network
from app.discovery import agent_ip_map,observed_agent_status

def test_discovery_accepts_only_bounded_rfc1918_networks():
    assert str(validated_network("192.168.32.0/24"))=="192.168.32.0/24"
    for value in ("8.8.8.0/24","192.0.2.0/24","192.168.32.1/24","10.0.0.0/16","::1/128"):
        with pytest.raises(HTTPException):validated_network(value)

@pytest.mark.asyncio
async def test_refused_port_still_identifies_reachable_host(monkeypatch):
    async def refused(*_args,**_kwargs):raise ConnectionRefusedError()
    monkeypatch.setattr(asyncio,"open_connection",refused)
    result=await probe("192.168.32.10",[445],asyncio.Semaphore(1))
    assert result[0]=="192.168.32.10" and result[2]==[]

@pytest.mark.asyncio
async def test_timeout_does_not_invent_a_host(monkeypatch):
    async def timeout(*_args,**_kwargs):raise asyncio.TimeoutError()
    monkeypatch.setattr(asyncio,"open_connection",timeout)
    assert await probe("192.168.32.11",[445],asyncio.Semaphore(1)) is None

def test_agent_matching_includes_reported_active_ips():
    device=SimpleNamespace(id="device-1",ip_address="fe80::1",metadata_={"active_ips":["fe80::1","192.168.32.100"]})
    assert agent_ip_map([device])["192.168.32.100"]=="device-1"

def test_agent_health_is_reported_separately_from_node_discovery():
    now=datetime.now(timezone.utc)
    online=SimpleNamespace(current_status="ONLINE",last_heartbeat=now)
    stopped=SimpleNamespace(current_status="OFFLINE",last_heartbeat=now)
    stale=SimpleNamespace(current_status="ONLINE",last_heartbeat=now-timedelta(minutes=2))
    cutoff=now-timedelta(seconds=45)
    assert observed_agent_status(online,cutoff)=="online"
    assert observed_agent_status(stopped,cutoff)=="offline"
    assert observed_agent_status(stale,cutoff)=="offline"
    assert observed_agent_status(None,cutoff)=="not-installed"
