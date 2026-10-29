import pytest

from specterlan.classification import classify, classify_observation
from specterlan.models import Device, DeviceMetadata
from specterlan.store import SnapshotStore

NETWORK = "192.168.1.0/24"


@pytest.mark.parametrize(
    ("hostname", "vendor", "expected"),
    [
        ("home-router", None, "router"),
        ("FRITZ-Box", None, "router"),
        (None, "AVM GmbH", "router"),
        ("work-laptop", "Intel Corporate", "computer"),
        ("DESKTOP-ABC123", None, "computer"),
        ("MacBook-Pro", "Apple, Inc.", "computer"),
        ("Alice-iPhone15", "Apple, Inc.", "phone"),
        ("PIXEL-9-PRO", "Google", "phone"),
        ("Samsung-Galaxy-S23", "Samsung Electronics", "phone"),
        ("iPad-Pro", "Apple", "tablet"),
        ("kids-Galaxy-Tab", "Samsung Electronics", "tablet"),
        ("living-room-tv", "Hisense", "tv"),
        (None, "Hisense", "tv"),
        ("Chromecast", "Google", "tv"),
        ("office-printer", "HP", "printer"),
        (None, "Seiko Epson Corporation", "printer"),
        ("Brother-Office", "Brother Industries", "printer"),
        ("LaserJet-Pro", None, "printer"),
        ("bedroom-speaker", None, "speaker"),
        ("Echo_Dot", "Amazon Technologies", "speaker"),
        (None, "Sonos, Inc.", "speaker"),
        ("HomePod-mini", "Apple", "speaker"),
        ("Xbox-Series-X", "Microsoft", "gaming_console"),
        ("PlayStation", "Sony", "gaming_console"),
        ("PS5", "Sony", "gaming_console"),
        ("Nintendo-Switch", "Nintendo", "gaming_console"),
        ("driveway-camera01", None, "camera"),
        (None, "Reolink Innovation", "camera"),
        ("smart-plug", None, "smart_home"),
        ("shelly1-living-room", None, "smart_home"),
        ("esphome-light", None, "smart_home"),
        (None, "Tuya Smart", "smart_home"),
        ("home-server01", "Dell", "server"),
        ("NAS01", None, "server"),
        (None, "Synology Incorporated", "server"),
        ("Proxmox", "Intel", "server"),
    ],
)
def test_specific_local_evidence_classifies_each_category(hostname, vendor, expected):
    result = classify(hostname, vendor)
    assert result.device_type == expected
    assert "Hostname contains" in result.reason or "Vendor matched" in result.reason


@pytest.mark.parametrize(
    ("hostname", "vendor"),
    [
        (None, None),
        ("", ""),
        ("device-a1b2", "Apple"),
        (None, "Samsung Electronics"),
        (None, "Sony"),
        (None, "ASUS"),
        (None, "Intel Corporate"),
        (None, "TP-Link"),
        (None, "Canon"),
        (None, "Amazon Technologies"),
        ("android", None),
        ("pixel", None),
        ("raspberrypi", None),
        ("activity", None),
        ("esp", "Espressif"),
        ("notiphone", None),
        ("NASAL", None),
        ("pcworld", None),
        ("mystery-printerish", None),
        ("generic.example.tv", None),
        ("generic", "NotHisense"),
    ],
)
def test_weak_or_substring_evidence_stays_unknown(hostname, vendor):
    result = classify(hostname, vendor)
    assert result.device_type == "unknown"
    assert result.reason == "No sufficiently specific hostname or vendor evidence."


@pytest.mark.parametrize(
    ("hostname", "vendor"),
    [
        ("iphone", "Hisense"),
        ("printer-server", None),
        ("laptop", "Sonos"),
        ("camera", "AVM"),
        ("ipad-phone", None),
        ("xbox", "Epson"),
    ],
)
def test_conflicting_evidence_abstains_instead_of_using_rule_order(hostname, vendor):
    result = classify(hostname, vendor)
    assert result.device_type == "unknown"
    assert result.reason.startswith("Conflicting local evidence:")
    assert classify(hostname, vendor) == result


def test_reason_identifies_each_agreeing_evidence_source():
    result = classify("LiViNg-RoOm-TV", "HiSeNsE")
    assert result.device_type == "tv"
    assert result.reason == "Hostname contains 'tv'; Vendor matched 'hisense'"


@pytest.mark.parametrize("override", ["tablet", "camera", "server", "unknown"])
def test_explicit_user_type_overrides_automatic_suggestion(tmp_path, override):
    store = SnapshotStore(tmp_path / "override.db")
    observation = Device(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", hostname="office-printer")
    store.update_metadata(
        observation,
        NETWORK,
        DeviceMetadata(device_type=override, friendly_name="Office", trust_status="trusted"),
    )
    refreshed = store.apply_metadata([observation], NETWORK)[0]
    assert refreshed.device_type == override
    assert refreshed.automatic_device_type == "printer"
    assert refreshed.classification_reason == "Hostname contains 'printer'"
    assert refreshed.friendly_name == "Office"
    assert refreshed.trust_status == "trusted"

    vanished = refreshed.model_copy(update={"state": "vanished", "ip": "192.168.1.99"})
    again = SnapshotStore(store.path).apply_metadata([vanished], NETWORK)[0]
    assert again.device_type == override
    assert again.state == "vanished"


def test_classification_does_not_mutate_original_or_use_friendly_name_as_evidence():
    original = Device(ip="192.168.1.2", friendly_name="Router", device_type="phone")
    refreshed = classify_observation(original)
    assert refreshed.device_type == "unknown"
    assert original.device_type == "phone"
    assert refreshed.trust_status == "unreviewed"
