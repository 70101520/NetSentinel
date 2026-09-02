import uuid
from datetime import datetime,timezone
import pytest
from pydantic import ValidationError
from app.schemas import TelemetryBatch,TelemetryEvent
from app.worker import decode
from app.service_auth import derive_secret
def event(**changes):
    value={"event_id":uuid.uuid4(),"event_time":datetime.now(timezone.utc),"domain":"example.com","protocol":"HTTPS","port":443,"action":"BLOCK"}
    value.update(changes); return value
def test_valid_event_and_batch():
    parsed=TelemetryBatch(events=[event()]); assert len(parsed.events)==1 and parsed.events[0].action=="BLOCK"
@pytest.mark.parametrize("change",[{"event_id":"bad"},{"port":70000},{"action":"OBSERVE"},{"domain":"bad/domain"},{"url":"x"*4097},{"event_time":datetime.now()}])
def test_rejects_malformed_event(change):
    with pytest.raises(ValidationError): TelemetryEvent(**event(**change))
def test_batch_cannot_be_empty():
    with pytest.raises(ValidationError): TelemetryBatch(events=[])
def test_worker_decodes_wire_types():
    wire=TelemetryEvent(**event()).model_dump_json()
    decoded=decode({"event":wire})
    assert isinstance(decoded["id"],uuid.UUID)
    assert decoded["occurred_at"].tzinfo is not None
def test_service_secret_derivation_is_deterministic_and_not_plaintext():
    first=derive_secret("service-secret")
    assert first==derive_secret("service-secret") and first!="service-secret" and len(first)==64
