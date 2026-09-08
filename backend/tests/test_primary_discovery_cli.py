import pytest
from app.cli import primary_network

def test_primary_network_derives_canonical_subnet():
    assert primary_network("192.168.32.101/24")=="192.168.32.0/24"

@pytest.mark.parametrize("value",["8.8.8.8/24","192.0.2.10/24","not-an-interface","::1/64","10.0.0.1/16"])
def test_primary_network_rejects_unsafe_or_oversized_ranges(value):
    with pytest.raises(SystemExit):primary_network(value)
