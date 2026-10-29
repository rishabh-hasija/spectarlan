import json
import sqlite3
from pathlib import Path

import httpx
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


def install_ui_ollama(monkeypatch):
    real_client = httpx.Client
    state = {"failure": None, "requests": []}
    report = {
        "overview": "Two devices were recorded in this subnet [current.scan].",
        "notable_changes": [
            {
                "title": "New unreviewed device",
                "explanation": "SpecterLAN newly observed 192.168.1.2; identify it manually.",
                "evidence": ["current.device.0", "change.0"],
                "confidence": "high",
            }
        ],
        "devices_to_verify": [
            {
                "identity": "192.168.1.2",
                "reason": "Its saved trust status is unreviewed.",
                "evidence": ["current.device.0"],
                "confidence": "medium",
            }
        ],
        "suggested_checks": [
            {
                "check": "Identify which of your devices uses 192.168.1.2.",
                "evidence": ["current.device.0"],
            }
        ],
        "evidence_summary": [
            {
                "summary": "This report uses the latest saved subnet snapshot.",
                "evidence": ["current.scan"],
            }
        ],
    }

    state["report"] = report

    def handler(request):
        state["requests"].append(request)
        failure = state["failure"]
        if failure == "connection":
            raise httpx.ConnectError("not running", request=request)
        if failure == "timeout":
            raise httpx.ReadTimeout("timeout", request=request)
        if failure == "missing":
            return httpx.Response(404, json={"error": "model not found"})
        if request.url.path == "/api/show":
            return httpx.Response(
                200,
                json={
                    "details": {"format": "gguf"},
                    "model_info": {"general.architecture": "gemma3"},
                },
            )
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": payload["model"],
                "done": True,
                "message": {"content": "{}" if failure == "invalid" else json.dumps(report)},
            },
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    monkeypatch.delenv("OLLAMA_NUM_CTX", raising=False)
    return state


def analyze_button(ui):
    return next(button for button in ui.button if button.label == "Analyze with Ollama")


def test_ask_ghost_displays_structured_local_analysis_and_actual_model(app, monkeypatch):
    ui, store = app
    state = install_ui_ollama(monkeypatch)
    next(widget for widget in ui.text_input if widget.label == "Ollama model").set_value(
        "local-example:4b"
    ).run()
    analyze_button(ui).click().run()
    assert not ui.exception
    assert any(header.value == "Ask the Ghost" for header in ui.subheader)
    assert any("no cloud AI" in caption.value for caption in ui.caption)
    assert any("Model used: local-example:4b" in caption.value for caption in ui.caption)
    for heading in ["Notable changes", "Devices to verify", "Suggested checks"]:
        assert any(heading in item.value for item in ui.markdown)
    assert any(expander.label == "Evidence used" for expander in ui.expander)
    assert any("Two devices were recorded" in item.value for item in ui.text)
    assert len(state["requests"]) == 2
    assert len(store.recent_scans(NETWORK)) == 1

    next(widget for widget in ui.text_input if widget.label == "Ollama model").set_value(
        "another-local-model"
    ).run()
    assert any("Model used: local-example:4b" in caption.value for caption in ui.caption)


@pytest.mark.parametrize(
    "failure,expected",
    [
        ("connection", "Start Ollama"),
        ("timeout", "timed out"),
        ("missing", "was not found"),
        ("invalid", "structured report"),
    ],
)
def test_ai_failure_clears_old_report_and_keeps_scanning_and_history(
    app, monkeypatch, failure, expected
):
    ui, store = app
    state = install_ui_ollama(monkeypatch)
    analyze_button(ui).click().run()
    assert any("Two devices were recorded" in item.value for item in ui.text)
    state["failure"] = failure
    analyze_button(ui).click().run()
    assert not ui.exception
    assert any(expected in item.value for item in ui.error)
    assert not any("Two devices were recorded" in item.value for item in ui.text)
    assert any(widget.label == "Inspect scan" for widget in ui.selectbox)
    assert len(store.recent_scans(NETWORK)) == 1

    ui.button[0].click().run()
    assert not ui.exception
    assert len(store.recent_scans(NETWORK)) == 2
    assert any(widget.label == "Inspect scan" for widget in ui.selectbox)


def test_network_detection_failure_is_actionable_and_demo_still_opens(app, monkeypatch):
    ui, store = app

    def fail():
        raise RuntimeError("internal adapter detail")

    monkeypatch.setattr(network, "detect_local_network", fail)
    monkeypatch.setattr("specterlan.demo.SnapshotStore", type(store))
    ui.run()
    assert not ui.exception
    assert any("Connect to a private Wi-Fi or Ethernet" in item.value for item in ui.error)
    assert not any("internal adapter detail" in item.value for item in ui.error)
    ui.radio[0].set_value("Demo Séance").run()
    assert not ui.exception
    assert any(button.label == "Start Demo" for button in ui.button)
    ui.session_state["demo_session"].close()


def test_missing_nmap_notice_does_not_block_fallback_scan(app, monkeypatch):
    ui, store = app
    monkeypatch.setattr("shutil.which", lambda *args, **kwargs: None)
    ui.run()
    assert any("Nmap unavailable" in item.value for item in ui.info)
    assert any("ping + the local neighbor table" in item.value for item in ui.info)
    ui.button[0].click().run()
    assert not ui.exception
    assert len(store.recent_scans(NETWORK)) == 2


def test_scan_failure_keeps_previous_snapshot_and_hides_internal_error(app, monkeypatch):
    ui, store = app

    def fail(*_):
        raise OSError("internal scanner detail")

    monkeypatch.setattr(network, "discover", fail)
    ui.button[0].click().run()
    assert not ui.exception
    assert any("Scan failed. Check your network" in item.value for item in ui.error)
    assert not any("internal scanner detail" in item.value for item in ui.error)
    assert any("previous observations retained" in item.value for item in ui.markdown)
    assert len(store.recent_scans(NETWORK)) == 1
    assert len(ui.dataframe[0].value) == 2


def test_storage_startup_failure_is_handled_without_raw_details(app, monkeypatch):
    ui, _ = app

    def fail():
        raise sqlite3.OperationalError("internal database path")

    monkeypatch.setattr(store_module, "SnapshotStore", fail)
    ui.run()
    assert not ui.exception
    assert any("Could not open local scan history" in item.value for item in ui.error)
    assert not any("internal database path" in item.value for item in ui.error)


def test_empty_ai_sections_are_explicit_without_claiming_network_safety(app, monkeypatch):
    ui, _ = app
    state = install_ui_ollama(monkeypatch)
    state["report"]["notable_changes"] = []
    state["report"]["devices_to_verify"] = []
    state["report"]["suggested_checks"] = []
    analyze_button(ui).click().run()
    assert not ui.exception
    assert any("No devices needing verification in this report." in item.value for item in ui.info)
    assert any("No notable changes in this report." in item.value for item in ui.caption)
    assert any("No additional checks suggested." in item.value for item in ui.caption)


def test_ai_evidence_load_error_hides_internal_details(app, monkeypatch):
    ui, store = app

    def fail(*_):
        raise sqlite3.OperationalError("private database path and internal detail")

    monkeypatch.setattr(store, "latest_scan_pair", fail)
    ui.run()
    assert not ui.exception
    assert any("Could not load evidence for analysis" in item.value for item in ui.error)
    assert not any("private database path" in item.value for item in ui.error)
    assert any(widget.label == "Inspect scan" for widget in ui.selectbox)


@pytest.mark.parametrize("error", [sqlite3.OperationalError, ValueError])
def test_ai_analysis_storage_error_hides_details_and_keeps_history(app, monkeypatch, error):
    ui, store = app

    def fail(*args, **kwargs):
        raise error("private scan contents")

    monkeypatch.setattr("specterlan.ai_ui.analyze_latest", fail)
    analyze_button(ui).click().run()
    assert not ui.exception
    assert ui.session_state["ai_report"] is None
    assert any("Analysis could not load saved evidence" in item.value for item in ui.error)
    assert not any("private scan contents" in item.value for item in ui.error)
    assert any(widget.label == "Inspect scan" for widget in ui.selectbox)
    assert len(store.recent_scans(NETWORK)) == 1
