import uuid
from datetime import datetime,timezone
import pytest
from pydantic import ValidationError
from app.schemas import EnrollRequest,Heartbeat
def test_enrollment_payload():
    value=EnrollRequest(enrollment_token="x"*32,installation_id="install-001",hostname="PC-001",os_name="Windows",agent_version="0.1")
    assert value.installation_id=="install-001"
def test_short_enrollment_token_rejected():
    with pytest.raises(ValidationError): EnrollRequest(enrollment_token="short",installation_id="install-001",hostname="PC",os_name="Windows",agent_version="1")
def test_bounded_heartbeat_payload():
    value=Heartbeat(device_id=uuid.uuid4(),timestamp=datetime.now(timezone.utc),hostname="PC",agent_version="1",os_name="Windows",active_ips=["192.0.2.1"],uptime_seconds=10)
    assert str(value.active_ips[0])=="192.0.2.1"
def test_negative_uptime_rejected():
    with pytest.raises(ValidationError): Heartbeat(device_id=uuid.uuid4(),timestamp=datetime.now(timezone.utc),hostname="PC",agent_version="1",os_name="Windows",uptime_seconds=-1)
