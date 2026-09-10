from types import SimpleNamespace

import pytest

from app.web_filtering import TrustedNetworkInput, domain_is_blocked, normalize_domain
from app.web_gateway import controlled_device, parse_target


@pytest.mark.parametrize(("value","expected"),[("https://www.YouTube.com/watch?v=abc","www.youtube.com"),("facebook.com/path","facebook.com"),("sub.example.com:443","sub.example.com")])
def test_normalize_domain(value,expected):assert normalize_domain(value)==expected

@pytest.mark.parametrize("value",["localhost","192.168.1.1","bad domain.com","https:///missing"])
def test_normalize_domain_rejects_invalid_targets(value):
    with pytest.raises(ValueError):normalize_domain(value)
def test_gateway_parses_https_connect_without_decrypting_url():
    assert parse_target("CONNECT www.youtube.com:443 HTTP/1.1")== ("CONNECT","www.youtube.com",443,None,"HTTP/1.1")

def test_gateway_redacts_http_query_from_stored_url():
    parsed=parse_target("GET http://example.com/path?token=secret HTTP/1.1")
    assert parsed[1]=="example.com" and parsed[3]=="http://example.com/path" and parsed[5]=="/path?token=secret"

def test_gateway_rejects_non_web_tunnels():
    with pytest.raises(ValueError):parse_target("CONNECT example.com:22 HTTP/1.1")

class _Scalars:
    def __init__(self,items):self.items=items
    def all(self):return self.items

class _Db:
    def __init__(self,items):self.items=items
    async def scalars(self,_query):return _Scalars(self.items)

@pytest.mark.asyncio
async def test_gateway_matches_any_agent_reported_active_ip():
    device=SimpleNamespace(ip_address="fe80::1",last_heartbeat_ip="172.20.0.1",metadata_={"active_ips":["fe80::1","192.168.32.100"]})
    assert await controlled_device(_Db([device]),"192.168.32.100") is device
class _SequencedDb:
    def __init__(self,*groups):self.groups=list(groups)
    async def scalars(self,_query):return _Scalars(self.groups.pop(0))

@pytest.mark.asyncio
async def test_whitelist_takes_priority_over_category_block():
    allowed=SimpleNamespace(domain="safe.example.com",include_subdomains=True)
    blocked=SimpleNamespace(id="blocked",domain="example.com",include_subdomains=True)
    assert await domain_is_blocked(_SequencedDb([allowed],[blocked]),"safe.example.com")== (False,None)

def test_trusted_lan_is_canonical_and_public_network_is_rejected():
    assert TrustedNetworkInput(name="Office",cidr="192.168.32.25/24").cidr=="192.168.32.0/24"
    with pytest.raises(ValueError):TrustedNetworkInput(name="Public",cidr="8.8.8.0/24")