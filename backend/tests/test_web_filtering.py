import pytest
from app.web_filtering import normalize_domain
from app.web_gateway import parse_target

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