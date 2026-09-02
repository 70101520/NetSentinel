import uuid
from types import SimpleNamespace
from app.policy import domain_matches,evaluate
def test_wildcard_does_not_match_apex():
    assert domain_matches("www.example.com","*.example.com")
    assert not domain_matches("example.com","*.example.com")
def test_priority_and_default():
    policy=SimpleNamespace(id=uuid.uuid4(),default_action="BLOCK")
    broad=SimpleNamespace(id=uuid.uuid4(),enabled=True,expires_at=None,priority=20,domain_pattern="*.example.com",action="ALLOW")
    deny=SimpleNamespace(id=uuid.uuid4(),enabled=True,expires_at=None,priority=10,domain_pattern="bad.example.com",action="BLOCK")
    assert evaluate(policy,[broad,deny],"bad.example.com")[0]=="BLOCK"
    assert evaluate(policy,[broad,deny],"unknown.test")[0]=="BLOCK"
