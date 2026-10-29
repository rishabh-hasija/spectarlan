import sqlite3

import pytest

from specterlan.changes import compare_scans
from specterlan.models import Device, DeviceMetadata, ScanResult
from specterlan.store import SnapshotStore

NETWORK = "192.168.1.0/24"
MAC = "AA:BB:CC:DD:EE:01"
OTHER_MAC = "AA:BB:CC:DD:EE:02"


@pytest.fixture
def store(tmp_path):
    return SnapshotStore(tmp_path / "history.db")


def record(store, devices, network=NETWORK, timestamp=None):
    devices, vanished = store.annotate_states(devices, network)
    kwargs = {"scanned_at": timestamp} if timestamp else {}
    store.save(
        ScanResult(
            network=network,
            local_ip="192.168.1.1" if network == NETWORK else "10.0.0.1",
            scanner="test",
            devices=devices,
            vanished=vanished,
            **kwargs,
        )
    )
    return store.recent_scans(network, limit=1)[0]


def test_no_history_and_first_scan_have_no_comparison(store):
    assert store.recent_scans(NETWORK) == []
    first = record(store, [Device(ip="192.168.1.2", mac=MAC)])
    assert store.previous_scan(first) is None
    assert first.vanished == []
    assert compare_scans(first, None) == []


def test_new_device_is_distinct_from_existing_device(store):
    record(store, [Device(ip="192.168.1.2", mac=MAC)])
    current = record(
        store,
        [Device(ip="192.168.1.2", mac=MAC), Device(ip="192.168.1.3", mac=OTHER_MAC)],
    )
    events = compare_scans(current, store.previous_scan(current))
    assert [(event.kind, event.device.mac) for event in events] == [("new", OTHER_MAC)]


def test_vanished_device_retains_saved_metadata_and_last_seen_time(store):
    device = Device(ip="192.168.1.2", mac=MAC)
    store.update_metadata(
        device,
        NETWORK,
        DeviceMetadata(friendly_name="Work laptop", device_type="computer", trust_status="trusted"),
    )
    previous = record(store, [device], timestamp="2026-10-29T19:42:00+00:00")
    current = record(store, [])
    events = compare_scans(current, store.previous_scan(current))

    assert len(current.vanished) == 1
    assert len(events) == 1
    assert events[0].kind == "vanished"
    assert events[0].device.friendly_name == "Work laptop"
    assert events[0].device.trust_status == "trusted"
    assert previous.scanned_at.isoformat(timespec="seconds") in events[0].details[0]


def test_same_normalized_mac_with_changed_ip_is_not_new_or_vanished(store):
    record(store, [Device(ip="192.168.1.2", mac=MAC)])
    current = record(store, [Device(ip="192.168.1.99", mac="aa-bb-cc-dd-ee-01")])
    events = compare_scans(current, store.previous_scan(current))

    assert current.vanished == []
    assert current.devices[0].state == "known"
    assert [event.kind for event in events] == ["ip_changed"]
    assert events[0].details == ("192.168.1.2 -> 192.168.1.99",)


def test_classification_changes_are_compared_as_recorded(store):
    record(store, [Device(ip="192.168.1.2", mac=MAC, hostname="office-laptop")])
    current = record(store, [Device(ip="192.168.1.2", mac=MAC, hostname="office-printer")])
    events = compare_scans(current, store.previous_scan(current))

    assert [event.kind for event in events] == ["classification_changed"]
    assert "Automatic type: computer -> printer" in events[0].details


def test_changed_reason_with_same_classification_does_not_create_noise(store):
    record(store, [Device(ip="192.168.1.2", mac=MAC, hostname="office-tv")])
    current = record(
        store, [Device(ip="192.168.1.2", mac=MAC, hostname="office-tv", vendor="Hisense")]
    )
    assert compare_scans(current, store.previous_scan(current)) == []


def test_user_metadata_changes_are_grouped_and_not_mislabelled_as_classification(store):
    device = Device(ip="192.168.1.2", mac=MAC, hostname="office-laptop")
    record(store, [device])
    store.update_metadata(
        device,
        NETWORK,
        DeviceMetadata(friendly_name="Office", trust_status="trusted", device_type="server"),
    )
    current = record(store, [device])
    events = compare_scans(current, store.previous_scan(current))

    assert [event.kind for event in events] == ["metadata_changed"]
    assert events[0].device.automatic_device_type == "computer"
    assert events[0].details == (
        "Friendly name: (blank) -> Office",
        "Trust: unreviewed -> trusted",
        "User type override: automatic -> server",
    )


def test_automatic_classification_change_is_visible_even_under_same_override(store):
    device = Device(ip="192.168.1.2", mac=MAC, hostname="office-laptop")
    store.update_metadata(device, NETWORK, DeviceMetadata(device_type="server"))
    record(store, [device])
    current = record(store, [device.model_copy(update={"hostname": "office-printer"})])
    events = compare_scans(current, store.previous_scan(current))
    assert current.devices[0].device_type == "server"
    assert [event.kind for event in events] == ["classification_changed"]
    assert events[0].details == ("Automatic type: computer -> printer",)


def test_returning_identity_is_seen_again_instead_of_new(store):
    device = Device(ip="192.168.1.2", mac=MAC)
    record(store, [device])
    record(store, [])
    current = record(store, [device])
    events = compare_scans(current, store.previous_scan(current))
    assert [event.kind for event in events] == ["returned"]


def test_empty_scan_remains_a_valid_previous_scan(store):
    record(store, [])
    current = record(store, [Device(ip="192.168.1.2", mac=MAC)])
    previous = store.previous_scan(current)
    assert previous is not None
    assert previous.devices == []
    assert [event.kind for event in compare_scans(current, previous)] == ["new"]


def test_comparison_uses_previous_scan_of_same_subnet(store):
    first = record(store, [Device(ip="192.168.1.2", mac=MAC)])
    other = record(store, [Device(ip="10.0.0.2", mac=OTHER_MAC)], network="10.0.0.0/24")
    current = record(store, [Device(ip="192.168.1.99", mac=MAC)])

    assert [scan.id for scan in store.recent_scans(NETWORK)] == [current.id, first.id]
    previous = store.previous_scan(current)
    assert previous.id == first.id
    assert [event.kind for event in compare_scans(current, previous)] == ["ip_changed"]
    with pytest.raises(ValueError, match="same subnet"):
        compare_scans(current, other)


def test_history_is_ordered_by_saved_id_even_if_clock_moves_back(store):
    first = record(store, [], timestamp="2026-10-29T20:00:00+00:00")
    second = record(store, [], timestamp="2026-10-29T19:00:00+00:00")
    assert [scan.id for scan in store.recent_scans(NETWORK)] == [second.id, first.id]


def test_history_limit_and_oldest_visible_vanished_count(store):
    record(store, [])
    predecessor = record(store, [Device(ip="192.168.1.2", mac=MAC)])
    oldest_visible = record(store, [])
    for _ in range(9):
        record(store, [])

    history = store.recent_scans(NETWORK)
    assert len(history) == 10
    assert history[-1].id == oldest_visible.id
    assert history[-1].vanished[0].mac == MAC
    assert store.previous_scan(history[-1]).id == predecessor.id


@pytest.mark.parametrize("limit", [0, -1, 11])
def test_invalid_history_limits_are_rejected(store, limit):
    with pytest.raises(ValueError, match="between 1 and 10"):
        store.recent_scans(NETWORK, limit)


def test_reads_and_comparisons_never_overlay_metadata_or_rewrite_scans(store, monkeypatch):
    device = Device(ip="192.168.1.2", mac=MAC, hostname="office-laptop")
    record(store, [device])
    record(store, [device])
    with sqlite3.connect(store.path) as con:
        before = con.execute("SELECT * FROM scans ORDER BY id").fetchall()

    store.update_metadata(
        device,
        NETWORK,
        DeviceMetadata(friendly_name="Edited later", device_type="camera", trust_status="ignored"),
    )

    def unexpected_overlay(_):
        pytest.fail("History must not reclassify saved devices")

    monkeypatch.setattr("specterlan.store.classify_observation", unexpected_overlay)
    history = store.recent_scans(NETWORK)
    assert history[0].devices[0].friendly_name == ""
    assert history[0].devices[0].trust_status == "unreviewed"
    assert history[0].devices[0].device_type == "computer"
    assert compare_scans(history[0], store.previous_scan(history[0])) == []
    with sqlite3.connect(store.path) as con:
        assert con.execute("SELECT * FROM scans ORDER BY id").fetchall() == before
        assert con.execute("PRAGMA user_version").fetchone()[0] == 2


def test_legacy_snapshots_do_not_fabricate_override_or_automatic_changes(store):
    with sqlite3.connect(store.path) as con:
        for kind in ["phone", "tablet"]:
            con.execute(
                "INSERT INTO scans(scanned_at, network, local_ip, scanner, devices_json) VALUES (?, ?, ?, ?, ?)",
                (
                    "2026-10-29T19:42:00+00:00",
                    NETWORK,
                    "192.168.1.1",
                    "legacy",
                    '[{"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01", "device_type": "'
                    + kind
                    + '"}]',
                ),
            )
    history = store.recent_scans(NETWORK)
    changes = compare_scans(history[0], history[1])
    assert [event.kind for event in changes] == ["classification_changed"]
    assert changes[0].details == ("Effective type: phone -> tablet",)


def test_no_mac_ip_change_remains_a_new_provisional_identity(store):
    record(store, [Device(ip="192.168.1.2")])
    current = record(store, [Device(ip="192.168.1.99")])
    assert {event.kind for event in compare_scans(current, store.previous_scan(current))} == {
        "new",
        "vanished",
    }
