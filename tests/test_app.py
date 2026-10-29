import sqlite3
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from specterlan import network
from specterlan import store as store_module
from specterlan.models import Device, DeviceMetadata

NETWORK = "192.168.1.0/24"
MAC = "AA:BB:CC:DD:EE:01"


@pytest.fixture
def app(tmp_path, monkeypatch):
    store = store_module.SnapshotStore(tmp_path / "ui.db")
    monkeypatch.setattr(store_module, "SnapshotStore", lambda: store)
    monkeypatch.setattr(network, "detect_local_network", lambda: ("192.168.1.1", NETWORK))
    monkeypatch.setattr(
        network,
        "discover",
        lambda *_: ([Device(ip="192.168.1.2", mac=MAC), Device(ip="192.168.1.3")], "test"),
    )
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"), default_timeout=15)
    app.run()
    assert not app.exception
    app.button[0].click().run()
    assert not app.exception
    return app, store


def save_button(app):
    return next(button for button in app.button if button.label == "Save device")


def test_editor_saves_metadata_and_refreshes_table(app):
    ui, store = app
    before = ui.dataframe[0].value
    assert list(before.columns) == [
        "Friendly name",
        "State",
        "IP",
        "Hostname",
        "MAC",
        "Vendor",
        "Device type",
        "Trust status",
    ]
    assert before.iloc[0]["Trust status"] == "unreviewed"
    with sqlite3.connect(store.path) as con:
        scans_before = con.execute("SELECT * FROM scans").fetchall()

    next(widget for widget in ui.text_input if widget.label == "Friendly name").set_value(
        "Desk printer"
    )
    next(widget for widget in ui.selectbox if widget.label == "Device type").select("printer")
    next(widget for widget in ui.selectbox if widget.label == "Trust status").select("trusted")
    save_button(ui).click().run()

    assert not ui.exception
    row = ui.dataframe[0].value.iloc[0]
    assert row["Friendly name"] == "Desk printer"
    assert row["Device type"] == "printer"
    assert row["Trust status"] == "trusted"
    with sqlite3.connect(store.path) as con:
        assert con.execute("SELECT * FROM scans").fetchall() == scans_before

    next(widget for widget in ui.selectbox if widget.label == "Device").select(
        "ip:192.168.1.0/24:192.168.1.3"
    ).run()
    assert not ui.exception
    assert next(widget for widget in ui.text_input if widget.label == "Friendly name").value == ""
    assert (
        next(widget for widget in ui.selectbox if widget.label == "Trust status").value
        == "unreviewed"
    )
    assert any("No usable MAC" in warning.value for warning in ui.warning)


def test_vanished_devices_show_metadata_and_remain_editable(app, monkeypatch):
    ui, store = app
    store.update_metadata(
        Device(ip="192.168.1.2", mac=MAC),
        NETWORK,
        DeviceMetadata(friendly_name="Office", device_type="computer", trust_status="ignored"),
    )
    monkeypatch.setattr(network, "discover", lambda *_: ([], "test"))
    ui.button[0].click().run()
    assert not ui.exception
    rows = ui.dataframe[1].value
    assert rows.iloc[0]["Friendly name"] == "Office"
    assert rows.iloc[0]["Device type"] == "computer"
    assert rows.iloc[0]["Trust status"] == "ignored"
    assert rows.iloc[0]["State"] == "vanished"

    next(widget for widget in ui.text_input if widget.label == "Friendly name").set_value(
        "Office laptop"
    )
    save_button(ui).click().run()
    assert not ui.exception
    assert ui.dataframe[1].value.iloc[0]["Friendly name"] == "Office laptop"


def test_automatic_reason_is_in_editor_and_user_override_wins(app, monkeypatch):
    ui, store = app
    store.update_metadata(
        Device(ip="192.168.1.2", mac=MAC),
        NETWORK,
        DeviceMetadata(device_type="tablet"),
    )
    monkeypatch.setattr(
        network,
        "discover",
        lambda *_: (
            [Device(ip="192.168.1.99", mac=MAC, hostname="living-room-tv", vendor="Hisense")],
            "test",
        ),
    )
    ui.button[0].click().run()
    assert not ui.exception
    assert ui.dataframe[0].value.iloc[0]["Device type"] == "tablet"
    assert "Classification reason" not in ui.dataframe[0].value.columns
    explanation = next(
        caption.value for caption in ui.caption if "Automatic suggestion:" in caption.value
    )
    assert "Automatic suggestion: tv" in explanation
    assert "Vendor matched 'hisense'" in explanation
    assert "saved device type takes precedence" in explanation
    options = next(widget.options for widget in ui.selectbox if widget.label == "Device type")
    assert "tablet" in options and "gaming_console" in options and "smart_home" in options
    assert "iot" not in options


def test_history_summary_and_ip_change_view_use_saved_values(app, monkeypatch):
    ui, store = app
    first = store.recent_scans(NETWORK)[0]
    assert any("baseline saved" in message.value for message in ui.info)
    store.update_metadata(
        Device(ip="192.168.1.2", mac=MAC),
        NETWORK,
        DeviceMetadata(friendly_name="Work laptop", trust_status="trusted"),
    )
    monkeypatch.setattr(
        network,
        "discover",
        lambda *_: ([Device(ip="192.168.1.99", mac=MAC, hostname="laptop")], "test"),
    )
    ui.button[0].click().run()
    assert not ui.exception
    assert any("IP CHANGED (1)" in text.value for text in ui.markdown)
    assert any("VANISHED (1)" in text.value for text in ui.markdown)
    assert any("METADATA CHANGED (1)" in text.value for text in ui.markdown)
    assert not any("**NEW" in text.value for text in ui.markdown)
    assert any("192.168.1.2 -> 192.168.1.99" in text.value for text in ui.text)
    summary = next(frame.value for frame in ui.dataframe if "Scan" in frame.value.columns)
    assert list(summary["Online"]) == [1, 2]
    assert list(summary["New"]) == [0, 2]
    assert list(summary["Vanished"]) == [1, 0]
    assert list(summary["Trusted"]) == [1, 0]
    assert list(summary["Unreviewed"]) == [0, 2]
    assert list(summary["Subnet"]) == [NETWORK, NETWORK]
    assert "Timestamp" in summary.columns

    next(widget for widget in ui.selectbox if widget.label == "Inspect scan").select(first.id).run()
    assert not ui.exception
    historical = ui.dataframe[-1].value
    assert list(historical["Friendly name"]) == ["", ""]
    assert list(historical["Trust status"]) == ["unreviewed", "unreviewed"]
    assert ui.dataframe[0].value.iloc[0]["Friendly name"] == "Work laptop"


def test_history_is_available_after_restart_without_running_another_scan(app):
    _, store = app
    before = [scan.id for scan in store.recent_scans(NETWORK)]
    restarted = AppTest.from_file(
        str(Path(__file__).resolve().parents[1] / "app.py"),
        default_timeout=15,
    ).run()
    assert not restarted.exception
    assert any(widget.label == "Inspect scan" for widget in restarted.selectbox)
    assert [scan.id for scan in store.recent_scans(NETWORK)] == before
    assert any("baseline saved" in message.value for message in restarted.info)


def test_switching_subnet_does_not_show_other_subnet_history_or_live_result(app, monkeypatch):
    ui, store = app
    monkeypatch.setattr(network, "detect_local_network", lambda: ("10.0.0.1", "10.0.0.0/24"))
    ui.run()
    assert not ui.exception
    assert any("No saved scans for 10.0.0.0/24" in message.value for message in ui.info)
    assert not any(widget.label == "Inspect scan" for widget in ui.selectbox)
    assert not any(widget.label == "Device" for widget in ui.selectbox)
    assert len(store.recent_scans(NETWORK)) == 1


def test_editing_metadata_does_not_retroactively_change_history_counts(app):
    ui, store = app
    next(widget for widget in ui.text_input if widget.label == "Friendly name").set_value("Office")
    next(widget for widget in ui.selectbox if widget.label == "Trust status").select("trusted")
    save_button(ui).click().run()
    assert not ui.exception
    assert ui.dataframe[0].value.iloc[0]["Trust status"] == "trusted"
    summary = next(frame.value for frame in ui.dataframe if "Scan" in frame.value.columns)
    assert summary.iloc[0]["Trusted"] == 0
    assert summary.iloc[0]["Unreviewed"] == 2
    assert len(store.recent_scans(NETWORK)) == 1


def test_large_change_groups_are_compact_but_can_be_expanded(app, monkeypatch):
    ui, store = app
    devices = [Device(ip="192.168.1.2", mac=MAC)]
    devices.extend(
        Device(ip=f"192.168.1.{number + 8}", mac=f"AA:BB:CC:DD:EE:{number:02X}")
        for number in range(2, 8)
    )
    monkeypatch.setattr(network, "discover", lambda *_: (devices, "test"))
    ui.button[0].click().run()
    assert not ui.exception
    assert any("NEW (6)" in message.value for message in ui.markdown)
    assert any("Showing 5 of 6" in message.value for message in ui.caption)
    assert not any("192.168.1.15" in message.value for message in ui.text)
    ui.checkbox[0].check().run()
    assert not ui.exception
    assert any("192.168.1.15" in message.value for message in ui.text)
    assert len(store.recent_scans(NETWORK)) == 2
