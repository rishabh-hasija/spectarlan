import pytest

from specterlan.models import Device
from specterlan.ui import device_name, device_rows


@pytest.mark.parametrize(
    "friendly,hostname,expected",
    [
        ("TV", "host", "TV"),
        ("", "laptop", "laptop"),
        ("", None, "Unknown device"),
        ("  ", "  ", "Unknown device"),
    ],
)
def test_friendly_device_name_never_blank(friendly, hostname, expected):
    assert (
        device_name(Device(ip="192.168.1.2", friendly_name=friendly, hostname=hostname)) == expected
    )


@pytest.mark.parametrize(
    "state,trust,status,label",
    [
        ("new", "unreviewed", "New", "Need review"),
        ("known", "trusted", "Known", "Trusted"),
        ("vanished", "ignored", "Offline", "Ignored"),
    ],
)
def test_primary_table_uses_plain_labels_and_hides_technical_fields(state, trust, status, label):
    device = Device(
        ip="192.168.1.2",
        state=state,
        trust_status=trust,
        mac="AA:BB:CC:DD:EE:01",
        vendor="Vendor",
        classification_reason="Detailed reason",
    )
    row = device_rows([device])[0]
    assert list(row) == ["Device", "Status", "Type", "Trust", "IP address"]
    assert row["Status"] == status and row["Trust"] == label
    assert "Vendor" not in row and "MAC" not in row and "classification_reason" not in row
    assert device.state == state and device.trust_status == trust


def test_returned_is_display_only_without_changing_saved_state():
    device = Device(ip="192.168.1.2", state="known")
    assert device_rows([device], {device.ip})[0]["Status"] == "Returned"
    assert device.state == "known"
