import subprocess

import pytest

from specterlan import network
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


@pytest.mark.parametrize(
    ("candidates", "expected"),
    [
        (
            [("169.254.1.8", "255.255.255.0"), ("10.1.2.3", "255.255.0.0")],
            ("10.1.2.3", "10.1.2.0/24"),
        ),
        (
            [("10.1.2.3", "255.255.0.0"), ("192.168.1.10", "255.255.255.0")],
            ("192.168.1.10", "192.168.1.0/24"),
        ),
        (
            [("192.168.1.10", "255.255.255.0"), ("192.168.2.10", "255.255.255.0")],
            ("192.168.1.10", "192.168.1.0/24"),
        ),
        (
            [("192.168.2.10", "255.255.255.0"), ("192.168.1.10", "255.255.255.0")],
            ("192.168.2.10", "192.168.2.0/24"),
        ),
    ],
)
def test_interface_selection_preserves_preference_and_ties(monkeypatch, candidates, expected):
    monkeypatch.setattr(network, "_private_ipv4_candidates", lambda: candidates)

    assert network.detect_local_network() == expected


@pytest.mark.parametrize(
    "probe_error",
    [
        OSError("Cannot start ping"),
        subprocess.TimeoutExpired(cmd=["ping"], timeout=2),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid output"),
    ],
)
def test_failed_ping_probe_does_not_abort_scan(monkeypatch, caplog, probe_error):
    def ping(ip):
        if ip == "192.168.1.1":
            raise probe_error
        return True

    monkeypatch.setattr(network, "_ping", ping)
    monkeypatch.setattr(network, "_arp_table", lambda: {"192.168.1.2": "AA:BB:CC:DD:EE:FF"})
    monkeypatch.setattr(network.socket, "gethostbyaddr", lambda ip: ("laptop", [], [ip]))

    devices = network._scan_with_ping("192.168.1.0/30")

    assert [device.ip for device in devices] == ["192.168.1.2"]
    assert devices[0].mac == "AA:BB:CC:DD:EE:FF"
    assert devices[0].hostname == "laptop"
    assert devices[0].automatic_device_type == "computer"
    assert devices[0].classification_reason == "Hostname contains 'laptop'"
    assert "Ping probe failed for 192.168.1.1" in caplog.text
    assert any(record.exc_info for record in caplog.records)


def test_nmap_discovery_carries_explainable_classification(monkeypatch):
    xml = """<nmaprun><host><status state="up"/>
        <address addr="192.168.1.2" addrtype="ipv4"/>
        <address addr="AA:BB:CC:DD:EE:01" addrtype="mac" vendor="Microsoft"/>
        <hostnames><hostname name="Xbox-Series-X"/></hostnames>
        </host></nmaprun>"""
    monkeypatch.setattr(
        network.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout=xml),
    )
    device = network._scan_with_nmap("192.168.1.0/24")[0]
    assert device.device_type == "gaming_console"
    assert device.automatic_device_type == "gaming_console"
    assert device.classification_reason == "Hostname contains 'xbox'"
