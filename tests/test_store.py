import ipaddress
import json
import sqlite3

import pytest
from pydantic import ValidationError

from specterlan.models import Device, DeviceMetadata, ScanResult
from specterlan.store import SnapshotStore, device_identity

NETWORK = "192.168.1.0/24"
MAC = "AA:BB:CC:DD:EE:01"


@pytest.fixture
def store(tmp_path):
    return SnapshotStore(tmp_path / "devices.db")


def scan(store, devices, network=NETWORK):
    current, vanished = store.annotate_states(devices, network)
    result = ScanResult(
        network=network,
        local_ip=str(next(ipaddress.ip_network(network).hosts())),
        devices=current,
        vanished=vanished,
        scanner="test",
    )
    store.save(result)
    return result


def test_new_device_defaults_to_unreviewed(store):
    device = Device(ip="192.168.1.2", mac=MAC)
    result = scan(store, [device])

    assert result.devices[0].trust_status == "unreviewed"
    assert result.devices[0].friendly_name == ""
    assert result.devices[0].state == "new"
    assert store.apply_metadata([device], NETWORK)[0].trust_status == "unreviewed"


@pytest.mark.parametrize("trust_status", ["trusted", "unreviewed", "ignored"])
def test_metadata_survives_reopening_database_and_ip_change(store, trust_status):
    original = Device(ip="192.168.1.2", mac=MAC)
    scan(store, [original])
    store.update_metadata(
        original,
        NETWORK,
        DeviceMetadata(
            friendly_name="Office printer", device_type="printer", trust_status=trust_status
        ),
    )

    reopened = SnapshotStore(store.path)
    moved = Device(ip="192.168.1.99", mac="aa-bb-cc-dd-ee-01", device_type="computer")
    result = scan(reopened, [moved])

    assert result.devices[0].friendly_name == "Office printer"
    assert result.devices[0].device_type == "printer"
    assert result.devices[0].trust_status == trust_status
    assert result.devices[0].state == "known"
    assert result.vanished == []


def test_vanished_device_uses_latest_metadata_and_can_be_edited(store):
    original = Device(ip="192.168.1.2", mac=MAC)
    scan(store, [original])
    store.update_metadata(
        original,
        NETWORK,
        DeviceMetadata(friendly_name="Kitchen radio", device_type="iot", trust_status="ignored"),
    )

    result = scan(store, [])
    vanished = result.vanished[0]
    assert vanished.state == "vanished"
    assert vanished.friendly_name == "Kitchen radio"
    assert vanished.device_type == "smart_home"
    assert vanished.trust_status == "ignored"

    store.update_metadata(
        vanished, NETWORK, DeviceMetadata(friendly_name="Radio", trust_status="trusted")
    )
    assert store.apply_metadata([vanished], NETWORK)[0].friendly_name == "Radio"


def test_returning_device_retains_identity_after_empty_scan(store):
    device = Device(ip="192.168.1.2", mac=MAC)
    scan(store, [device])
    store.update_metadata(
        device, NETWORK, DeviceMetadata(friendly_name="Laptop", trust_status="trusted")
    )
    scan(store, [])

    result = scan(store, [Device(ip="192.168.1.99", mac=MAC)])
    assert result.devices[0].state == "known"
    assert result.devices[0].friendly_name == "Laptop"
    assert result.devices[0].trust_status == "trusted"


def test_no_mac_uses_provisional_subnet_and_ip_identity(store):
    device = Device(ip="192.168.1.2")
    scan(store, [device])
    store.update_metadata(
        device, NETWORK, DeviceMetadata(friendly_name="Provisional", trust_status="ignored")
    )

    same = scan(store, [Device(ip=device.ip)])
    assert same.devices[0].friendly_name == "Provisional"
    assert same.devices[0].trust_status == "ignored"

    moved = scan(store, [Device(ip="192.168.1.3")])
    assert moved.devices[0].state == "new"
    assert moved.devices[0].friendly_name == ""
    assert moved.devices[0].trust_status == "unreviewed"
    assert moved.vanished[0].friendly_name == "Provisional"

    assert device_identity(device, NETWORK) != device_identity(device, "192.168.0.0/16")


@pytest.mark.parametrize(
    "first_mac,second_mac", [(None, MAC), (MAC, None), (MAC, "AA:BB:CC:DD:EE:02")]
)
def test_ip_reuse_does_not_transfer_metadata_to_different_identity(store, first_mac, second_mac):
    device = Device(ip="192.168.1.2", mac=first_mac)
    scan(store, [device])
    store.update_metadata(
        device, NETWORK, DeviceMetadata(friendly_name="Private", trust_status="trusted")
    )

    result = scan(store, [Device(ip=device.ip, mac=second_mac)])
    assert result.devices[0].state == "new"
    assert result.devices[0].friendly_name == ""
    assert result.devices[0].trust_status == "unreviewed"


@pytest.mark.parametrize(
    "mac", [None, "", "not-a-mac", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01"]
)
def test_unusable_mac_falls_back_safely(mac):
    device = Device(ip="192.168.1.2", mac=mac)
    assert device_identity(device, NETWORK) == "ip:192.168.1.0/24:192.168.1.2"


@pytest.mark.parametrize(
    "mac", [MAC, "aa:bb:cc:dd:ee:01", "aa-bb-cc-dd-ee-01", "aabb.ccdd.ee01", " AABBCCDDEE01 "]
)
def test_mac_formatting_does_not_split_identity(mac):
    assert device_identity(Device(ip="192.168.1.2", mac=mac), NETWORK) == "mac:AABBCCDDEE01"


def test_unedited_device_type_still_uses_current_discovery(store):
    scan(store, [Device(ip="192.168.1.2", mac=MAC)])
    result = scan(
        store, [Device(ip="192.168.1.2", mac=MAC, hostname="office-printer", device_type="printer")]
    )
    assert result.devices[0].device_type == "printer"


def test_scan_comparisons_are_scoped_to_subnet(store):
    scan(store, [Device(ip="192.168.1.2", mac=MAC)])
    other = scan(store, [], network="10.0.0.0/24")
    assert other.vanished == []
    local = scan(store, [])
    assert local.vanished[0].mac == MAC


def test_migration_and_edits_leave_old_scan_rows_unchanged(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as con:
        con.execute(
            """CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL, network TEXT NOT NULL, local_ip TEXT NOT NULL,
                scanner TEXT NOT NULL, devices_json TEXT NOT NULL
            )"""
        )
        for devices in [[{"ip": "192.168.1.2", "mac": MAC, "device_type": "printer"}], []]:
            con.execute(
                "INSERT INTO scans(scanned_at, network, local_ip, scanner, devices_json) VALUES (?, ?, ?, ?, ?)",
                (
                    "2026-10-28T10:00:00+00:00",
                    NETWORK,
                    "192.168.1.1",
                    "legacy",
                    json.dumps(devices),
                ),
            )
        before = con.execute("SELECT * FROM scans ORDER BY id").fetchall()

    migrated = SnapshotStore(path)
    returning, _ = migrated.annotate_states([Device(ip="192.168.1.99", mac=MAC)], NETWORK)
    assert returning[0].state == "known"
    assert returning[0].trust_status == "unreviewed"
    migrated.update_metadata(
        returning[0], NETWORK, DeviceMetadata(friendly_name="Printer", trust_status="trusted")
    )
    SnapshotStore(path)  # Repeated startup must neither reseed nor reset edited metadata.

    with sqlite3.connect(path) as con:
        assert con.execute("PRAGMA user_version").fetchone()[0] == 3
        assert con.execute("SELECT * FROM scans ORDER BY id").fetchall() == before
        assert con.execute("SELECT COUNT(*) FROM device_metadata").fetchone()[0] == 1
    restored = SnapshotStore(path).apply_metadata(returning, NETWORK)[0]
    assert restored.friendly_name == "Printer"
    assert restored.trust_status == "trusted"


def test_metadata_edit_does_not_rewrite_recent_scan(store):
    device = Device(ip="192.168.1.2", mac=MAC)
    scan(store, [device])
    with sqlite3.connect(store.path) as con:
        before = con.execute("SELECT * FROM scans").fetchall()
    store.update_metadata(device, NETWORK, DeviceMetadata(friendly_name="My device"))
    with sqlite3.connect(store.path) as con:
        assert con.execute("SELECT * FROM scans").fetchall() == before


def test_invalid_trust_status_is_rejected():
    with pytest.raises(ValidationError):
        DeviceMetadata(trust_status="suspicious")
