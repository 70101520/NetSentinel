import uuid
from datetime import datetime,timezone
import pytest
from sqlalchemy.exc import OperationalError,DataError
from pydantic import ValidationError
from app.schemas import TelemetryBatch,TelemetryEvent
from app.worker import decode,is_retryable
from app.service_auth import credential_cache_ttl,derive_secret
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
def test_transient_database_errors_never_classify_as_poison():
    assert is_retryable(OperationalError("statement",{},ConnectionError("down")))
    assert is_retryable(TimeoutError("pool exhausted"))
def test_event_specific_data_error_can_reach_dlq_policy():
    assert not is_retryable(DataError("statement",{},ValueError("invalid value")))
def test_credential_cache_never_outlives_configured_ttl_or_expiry():
    now=datetime.now(timezone.utc)
    assert credential_cache_ttl(None,now)==60
    assert credential_cache_ttl(now.replace(microsecond=0),now)==1
