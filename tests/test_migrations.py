import json
import sqlite3
from typing import get_args

import pytest

from specterlan.models import Device, DeviceMetadata, DeviceType
from specterlan.store import SnapshotStore

NETWORK = "192.168.1.0/24"


@pytest.fixture
def version_one_database(tmp_path):
    path = tmp_path / "v1.db"
    with sqlite3.connect(path) as con:
        con.execute(
            """CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL, network TEXT NOT NULL, local_ip TEXT NOT NULL,
                scanner TEXT NOT NULL, devices_json TEXT NOT NULL
            )"""
        )
        con.execute(
            """CREATE TABLE device_metadata (
                identity TEXT PRIMARY KEY,
                friendly_name TEXT NOT NULL DEFAULT '',
                device_type TEXT CHECK (
                    device_type IN ('router', 'computer', 'phone', 'tv', 'printer', 'iot', 'unknown')
                ),
                trust_status TEXT NOT NULL DEFAULT 'unreviewed'
                    CHECK (trust_status IN ('trusted', 'unreviewed', 'ignored'))
            )"""
        )
        con.executemany(
            "INSERT INTO device_metadata(identity, friendly_name, device_type, trust_status) VALUES (?, ?, ?, ?)",
            [
                ("mac:AABBCCDDEE01", "Kitchen", "iot", "trusted"),
                ("mac:AABBCCDDEE02", "Office", "printer", "ignored"),
                ("ip:192.168.1.0/24:192.168.1.4", "Temporary", None, "unreviewed"),
            ],
        )
        con.execute(
            "INSERT INTO scans(scanned_at, network, local_ip, scanner, devices_json) VALUES (?, ?, ?, ?, ?)",
            (
                "2026-10-28T10:00:00+00:00",
                NETWORK,
                "192.168.1.1",
                "old",
                json.dumps(
                    [{"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01", "device_type": "iot"}]
                ),
            ),
        )
        con.execute("PRAGMA user_version = 1")
    return path


def test_version_two_preserves_overrides_and_historical_scan_json(version_one_database):
    path = version_one_database
    with sqlite3.connect(path) as con:
        scans_before = con.execute("SELECT * FROM scans").fetchall()
        metadata_before = con.execute("SELECT * FROM device_metadata ORDER BY identity").fetchall()

    store = SnapshotStore(path)
    legacy_device = next(iter(store.last_devices(NETWORK).values()))
    assert legacy_device.device_type == "smart_home"
    refreshed = store.apply_metadata([legacy_device], NETWORK)[0]
    assert refreshed.device_type == "smart_home"
    assert refreshed.friendly_name == "Kitchen"
    assert refreshed.trust_status == "trusted"
    assert refreshed.automatic_device_type == "unknown"
    assert DeviceMetadata(device_type="iot").device_type == "smart_home"

    SnapshotStore(path)  # Migration is safe to repeat and must preserve edited overrides.
    with sqlite3.connect(path) as con:
        expected_metadata = [
            (identity, name, "smart_home" if kind == "iot" else kind, trust)
            for identity, name, kind, trust in metadata_before
        ]
        assert (
            con.execute("SELECT * FROM device_metadata ORDER BY identity").fetchall()
            == expected_metadata
        )
        assert con.execute("SELECT * FROM scans").fetchall() == scans_before
        assert con.execute("PRAGMA user_version").fetchone()[0] == 3
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_migrated_database_accepts_every_new_type(version_one_database):
    store = SnapshotStore(version_one_database)
    device = Device(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01")
    for kind in get_args(DeviceType):
        store.update_metadata(device, NETWORK, DeviceMetadata(device_type=kind))
        assert store.apply_metadata([device], NETWORK)[0].device_type == kind


def test_failed_migration_rolls_back_schema_and_data(version_one_database, monkeypatch):
    path = version_one_database
    migrate = SnapshotStore._migrate_classification

    def fail_after_table_replacement(con):
        migrate(con)
        raise sqlite3.OperationalError("Simulated migration failure")

    monkeypatch.setattr(
        SnapshotStore, "_migrate_classification", staticmethod(fail_after_table_replacement)
    )
    with sqlite3.connect(path) as con:
        schema_before = con.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
        metadata_before = con.execute("SELECT * FROM device_metadata ORDER BY identity").fetchall()
        scans_before = con.execute("SELECT * FROM scans").fetchall()
    with pytest.raises(sqlite3.OperationalError, match="Simulated migration failure"):
        SnapshotStore(path)

    with sqlite3.connect(path) as con:
        assert con.execute("PRAGMA user_version").fetchone()[0] == 1
        assert (
            con.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
            == schema_before
        )
        assert (
            con.execute("SELECT * FROM device_metadata ORDER BY identity").fetchall()
            == metadata_before
        )
        assert con.execute("SELECT * FROM scans").fetchall() == scans_before
