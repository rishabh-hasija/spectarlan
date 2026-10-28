import pytest

from specterlan.network import classify_device, validate_scan_scope


def test_rejects_public_network():
    with pytest.raises(ValueError):
        validate_scan_scope("8.8.8.0/24", "8.8.8.8")


def test_rejects_network_not_containing_local_ip():
    with pytest.raises(ValueError):
        validate_scan_scope("192.168.2.0/24", "192.168.1.10")


def test_rejects_broad_scan():
    with pytest.raises(ValueError):
        validate_scan_scope("192.168.0.0/16", "192.168.1.10")


def test_classifies_tv():
    assert classify_device("living-room-tv", "Hisense") == "tv"


def test_unknown_is_honest():
    assert classify_device(None, None) == "unknown"
