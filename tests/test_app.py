import json
import sqlite3
from pathlib import Path

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from specterlan import network, readiness_ui
from specterlan import store as store_module
from specterlan.models import Device, DeviceMetadata
from specterlan.readiness import ModelInventory

INSTALLED_MODELS = (
    "gemma3:4b",
    "gemma4:e4b",
    "qwen3.5:4b",
    "llama3.2:3b",
    "local-example:4b",
    "another-local-model",
    "other-local-model",
)


def set_model_inventory(monkeypatch, inventory):
    monkeypatch.setattr(readiness_ui, "discover_local_models", lambda *args: inventory)
    monkeypatch.setattr(
        readiness_ui,
        "cached_model_inventory",
        lambda *args: readiness_ui.discover_local_models(*args),
    )


NETWORK = "192.168.1.0/24"
MAC = "AA:BB:CC:DD:EE:01"


@pytest.fixture
def app(tmp_path, monkeypatch):
    set_model_inventory(monkeypatch, ModelInventory(True, INSTALLED_MODELS, INSTALLED_MODELS))
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
    assert list(before.columns) == ["Device", "Status", "Type", "Trust", "IP address"]
    assert before.iloc[0]["Trust"] == "Need review"
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
    assert row["Device"] == "Desk printer"
    assert row["Type"] == "Printer"
    assert row["Trust"] == "Trusted"
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
    assert rows.iloc[0]["Device"] == "Office"
    assert rows.iloc[0]["Type"] == "Computer"
    assert rows.iloc[0]["Trust"] == "Ignored"
    assert rows.iloc[0]["Status"] == "Offline"

    next(widget for widget in ui.text_input if widget.label == "Friendly name").set_value(
        "Office laptop"
    )
    save_button(ui).click().run()
    assert not ui.exception
    assert ui.dataframe[1].value.iloc[0]["Device"] == "Office laptop"


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
    assert ui.dataframe[0].value.iloc[0]["Type"] == "Tablet"
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
    assert any("First scan complete." in message.value for message in ui.info)
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
    assert any("Address updated (1)" in text.value for text in ui.markdown)
    assert any("Offline since last scan (1)" in text.value for text in ui.markdown)
    assert any("Device details updated (1)" in text.value for text in ui.markdown)
    assert not any("**New devices" in text.value for text in ui.markdown)
    assert any("192.168.1.2 -> 192.168.1.99" in text.value for text in ui.text)
    summary = next(frame.value for frame in ui.dataframe if "Scan" in frame.value.columns)
    assert list(summary["Online"]) == [1, 2]
    assert list(summary["New"]) == [0, 2]
    assert list(summary["Offline since last scan"]) == [1, 0]
    assert list(summary["Trusted"]) == [1, 0]
    assert list(summary["Need review"]) == [0, 2]
    assert list(summary["Subnet"]) == [NETWORK, NETWORK]
    assert "Timestamp" in summary.columns

    next(widget for widget in ui.selectbox if widget.label == "Inspect scan").select(first.id).run()
    assert not ui.exception
    historical = ui.dataframe[-1].value
    assert list(historical["Device"]) == ["Unknown device", "Unknown device"]
    assert list(historical["Trust"]) == ["Need review", "Need review"]
    assert ui.dataframe[0].value.iloc[0]["Device"] == "Work laptop"


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
    assert any("First scan complete." in message.value for message in restarted.info)


def test_switching_subnet_does_not_show_other_subnet_history_or_live_result(app, monkeypatch):
    ui, store = app
    monkeypatch.setattr(network, "detect_local_network", lambda: ("10.0.0.1", "10.0.0.0/24"))
    ui.run()
    assert not ui.exception
    assert any("No scan yet. Scan your network" in message.value for message in ui.info)
    assert not any(widget.label == "Inspect scan" for widget in ui.selectbox)
    assert not any(widget.label == "Device" for widget in ui.selectbox)
    assert len(store.recent_scans(NETWORK)) == 1


def test_editing_metadata_does_not_retroactively_change_history_counts(app):
    ui, store = app
    next(widget for widget in ui.text_input if widget.label == "Friendly name").set_value("Office")
    next(widget for widget in ui.selectbox if widget.label == "Trust status").select("trusted")
    save_button(ui).click().run()
    assert not ui.exception
    assert ui.dataframe[0].value.iloc[0]["Trust"] == "Trusted"
    summary = next(frame.value for frame in ui.dataframe if "Scan" in frame.value.columns)
    assert summary.iloc[0]["Trusted"] == 0
    assert summary.iloc[0]["Need review"] == 2
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
    assert any("New devices (6)" in message.value for message in ui.markdown)
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
        "overview": "Two devices were recorded in this subnet [E1].",
        "notable_changes": [
            {
                "title": "New unreviewed device",
                "explanation": "SpecterLAN newly observed 192.168.1.2; identify it manually.",
                "evidence": ["E2", "E4"],
                "confidence": "high",
            }
        ],
        "devices_to_verify": [
            {
                "reason": "Its saved trust status is unreviewed.",
                "evidence": ["E2"],
                "confidence": "medium",
            }
        ],
        "suggested_checks": [
            {
                "check": "Identify which of your devices uses 192.168.1.2.",
                "evidence": ["E2"],
            }
        ],
        "evidence_summary": [
            {
                "summary": "This report uses the latest saved subnet snapshot.",
                "evidence": ["E1"],
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
    next(widget for widget in ui.selectbox if widget.label == "Local AI model").select(
        "local-example:4b"
    ).run()
    analyze_button(ui).click().run()
    assert not ui.exception
    assert any(header.value == "Ask the Ghost" for header in ui.subheader)
    assert any("Runs locally. No cloud AI." in caption.value for caption in ui.caption)
    assert any("Model used: local-example:4b" in caption.value for caption in ui.caption)
    for heading in ["Notable changes", "Devices to verify", "Suggested checks"]:
        assert any(heading in item.value for item in ui.markdown)
    assert any(expander.label == "Evidence used" for expander in ui.expander)
    assert any("Two devices were recorded" in item.value for item in ui.text)
    assert len(state["requests"]) == 2
    assert len(store.recent_scans(NETWORK)) == 1

    next(widget for widget in ui.selectbox if widget.label == "Local AI model").select(
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
    assert any(
        "Ask the Ghost couldn't get a response from the local AI." in item.value
        for item in ui.error
    )
    assert any(expected in item.value for item in ui.text)
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
    assert any("Nmap unavailable" in item.value for item in ui.caption)
    assert any("ping + the local neighbor table" in item.value for item in ui.caption)
    assert any("**Nmap:** fallback mode" in item.value for item in ui.markdown)
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


def test_local_model_preference_survives_restart_and_ignores_ui_env_override(app, monkeypatch):
    ui, store = app
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    next(widget for widget in ui.selectbox if widget.label == "Local AI model").select(
        "qwen3.5:4b"
    ).run()
    assert not ui.exception
    assert store.model_preference() == "qwen3.5:4b"
    app_path = str(Path(__file__).resolve().parents[1] / "app.py")
    restarted = AppTest.from_file(app_path, default_timeout=15).run()
    assert not restarted.exception
    assert next(w for w in restarted.selectbox if w.label == "Local AI model").value == "qwen3.5:4b"
    assert any(
        item.value == "Your SpecterLAN data is stored locally on this device."
        for item in restarted.caption
    )
    assert not any(store.path in item.value for item in restarted.caption)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.2:3b")
    configured = AppTest.from_file(app_path, default_timeout=15).run()
    assert not configured.exception
    assert (
        next(w for w in configured.selectbox if w.label == "Local AI model").value == "qwen3.5:4b"
    )
    assert store.model_preference() == "qwen3.5:4b"


def test_preference_write_error_hides_filesystem_details(app, monkeypatch):
    ui, store = app

    def denied(model):
        raise sqlite3.OperationalError("private Windows account path")

    monkeypatch.setattr(store, "save_model_preference", denied)
    next(w for w in ui.selectbox if w.label == "Local AI model").select("other-local-model").run()
    assert not ui.exception
    assert any("Could not save the local model preference" in item.value for item in ui.error)
    assert not any("private Windows account path" in item.value for item in ui.error)


@pytest.mark.parametrize("status", [ModelInventory(False), ModelInventory(True)])
def test_missing_ai_keeps_scanning_and_history_available(app, monkeypatch, status):
    ui, store = app
    set_model_inventory(monkeypatch, status)
    ui.run()
    assert not ui.exception
    assert analyze_button(ui).disabled
    assert any("ollama pull gemma3:4b" in item.value for item in ui.code)
    assert any("Local data storage:** ready" in item.value for item in ui.markdown)
    ui.button[0].click().run()
    assert len(store.recent_scans(NETWORK)) == 2
    assert any(widget.label == "Inspect scan" for widget in ui.selectbox)


def test_selected_override_works_when_default_model_is_missing(app, monkeypatch):
    ui, _ = app
    set_model_inventory(monkeypatch, ModelInventory(True, ("gemma4:e4b",), ("gemma4:e4b",)))
    ui.run()
    assert not analyze_button(ui).disabled


def test_unwritable_storage_blocks_live_scan_and_still_allows_demo(app, monkeypatch):
    from specterlan import readiness as readiness_module

    ui, _ = app
    check_storage = readiness_module.writable_storage
    monkeypatch.setattr(readiness_module, "writable_storage", lambda path: False)
    ui.run()
    assert not ui.exception
    assert any("writable data directory" in item.value for item in ui.error)
    assert not any(widget.label == "Scan network" for widget in ui.button)
    monkeypatch.setattr(readiness_module, "writable_storage", check_storage)
    ui.radio[0].set_value("Demo Séance").run()
    assert not ui.exception
    assert any(widget.label == "Start Demo" for widget in ui.button)
    ui.session_state["demo_session"].close()


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


def test_native_header_summary_and_technical_details_are_separate(app):
    ui, _ = app
    assert ui.title[0].value == "👻 SpecterLAN"
    assert any(c.value == "Find the ghosts on your network." for c in ui.caption)
    assert [metric.label for metric in ui.metric] == [
        "Devices online",
        "New devices",
        "Need review",
        "Offline since last scan",
    ]
    assert not any(w.label in {"Local IP", "Target subnet"} for w in ui.sidebar.text_input)
    technical = next(e for e in ui.expander if e.label == "Technical details" and e.json)
    assert not technical.proto.expanded
    assert any("Local IP:" in item.value for item in technical.text)
    assert any(
        "MAC address" in item.value and "Automatic classification reason" in item.value
        for item in technical.json
    )
    assert any(
        "First scan complete. SpecterLAN will show changes after your next scan." == item.value
        for item in ui.info
    )


def test_no_scan_and_no_changes_messages_are_plain(app):
    ui, _ = app
    app_path = str(Path(__file__).resolve().parents[1] / "app.py")
    restarted = AppTest.from_file(app_path, default_timeout=15).run()
    assert any(
        "No scan yet. Scan your network to see which devices are currently connected." == item.value
        for item in restarted.info
    )
    ui.button[0].click().run()
    assert any("No important changes since your last scan." == item.value for item in ui.info)


def test_http_500_message_is_friendly_and_diagnostic_is_collapsed(app, monkeypatch):
    from specterlan.ai import AIAnalysisError

    ui, store = app

    def fail(*args, **kwargs):
        raise AIAnalysisError("Local Ollama request failed (HTTP 500). Scan history is unchanged.")

    monkeypatch.setattr("specterlan.ai_ui.analyze_latest", fail)
    analyze_button(ui).click().run()
    assert not ui.exception
    assert [item.value for item in ui.error] == [
        "Ask the Ghost couldn't get a response from the local AI."
    ]
    assert any(
        "Check that Ollama is running and the selected model is available." == item.value
        for item in ui.caption
    )
    assert not any("HTTP 500" in item.value for item in [*ui.error, *ui.caption, *ui.info])
    technical = next(
        e
        for e in ui.expander
        if e.label == "Technical details" and any("HTTP 500" in item.value for item in e.text)
    )
    assert not technical.proto.expanded
    ui.button[0].click().run()
    assert len(store.recent_scans(NETWORK)) == 2


def test_returned_device_label_uses_history_without_rewriting_snapshots(app, monkeypatch):
    ui, store = app
    monkeypatch.setattr(network, "discover", lambda *_: ([], "test"))
    ui.button[0].click().run()
    monkeypatch.setattr(
        network, "discover", lambda *_: ([Device(ip="192.168.1.2", mac=MAC)], "test")
    )
    ui.button[0].click().run()
    assert not ui.exception
    assert ui.dataframe[0].value.iloc[0]["Status"] == "Returned"
    assert store.recent_scans(NETWORK)[0].devices[0].state == "known"


def test_local_model_dropdown_auto_selects_default_and_has_no_free_text(app):
    ui, store = app
    dropdown = next(w for w in ui.sidebar.selectbox if w.label == "Local AI model")
    assert dropdown.options == list(INSTALLED_MODELS)
    assert dropdown.value == "gemma3:4b"
    assert not dropdown.disabled
    assert not any(w.label in {"Ollama model", "Local AI model"} for w in ui.sidebar.text_input)
    dropdown.select("gemma4:e4b").run()
    assert not ui.exception
    assert store.model_preference() == "gemma4:e4b"
    assert not analyze_button(ui).disabled


@pytest.mark.parametrize(
    "saved,expected", [("gemma4:e4b", "gemma4:e4b"), ("removed:model", "gemma3:4b")]
)
def test_saved_model_is_preserved_or_falls_back_when_removed(app, saved, expected):
    _, store = app
    store.save_model_preference(saved)
    ui = AppTest.from_file(
        str(Path(__file__).resolve().parents[1] / "app.py"), default_timeout=15
    ).run()
    assert not ui.exception
    assert next(w for w in ui.selectbox if w.label == "Local AI model").value == expected
    assert store.model_preference() == (saved if saved == expected else None)


def test_missing_default_selects_first_local_model_and_shows_pull_instructions(app, monkeypatch):
    ui, _ = app
    set_model_inventory(monkeypatch, ModelInventory(True, ("gemma4:e4b",), ("gemma4:e4b",)))
    ui.run()
    assert not ui.exception
    assert next(w for w in ui.selectbox if w.label == "Local AI model").value == "gemma4:e4b"
    assert any(w.value == "Default model gemma3:4b is not installed." for w in ui.sidebar.info)
    assert any(w.value == "Run: ollama pull gemma3:4b" for w in ui.sidebar.caption)
    assert not analyze_button(ui).disabled


@pytest.mark.parametrize("running", [True, False])
def test_empty_or_unavailable_ollama_disables_dropdown_and_analysis(app, monkeypatch, running):
    ui, store = app
    store.save_model_preference("gemma4:e4b")
    set_model_inventory(monkeypatch, ModelInventory(running))
    ui.run()
    assert not ui.exception
    dropdown = next(w for w in ui.selectbox if w.label == "Local AI model")
    assert dropdown.disabled and dropdown.options == [] and dropdown.value is None
    assert analyze_button(ui).disabled
    assert store.model_preference() == (None if running else "gemma4:e4b")
    if not running:
        assert any(
            w.value == "Ollama is not running. Network scanning still works."
            for w in ui.sidebar.info
        )


def test_model_removed_between_listing_and_selection_is_not_saved(app, monkeypatch):
    ui, store = app
    # Keep the displayed cached list, but emulate fresh save-time discovery after removal.
    monkeypatch.setattr(
        readiness_ui,
        "cached_model_inventory",
        lambda *a: ModelInventory(True, INSTALLED_MODELS, INSTALLED_MODELS),
    )
    monkeypatch.setattr(
        readiness_ui,
        "discover_local_models",
        lambda *a: ModelInventory(True, ("gemma3:4b",), ("gemma3:4b",)),
    )
    next(w for w in ui.selectbox if w.label == "Local AI model").select("gemma4:e4b").run()
    assert not ui.exception
    assert store.model_preference() is None
    assert any("no longer available" in w.value for w in ui.warning)


def test_unsuitable_saved_model_is_not_retained(app, monkeypatch):
    _, store = app
    store.save_model_preference("remote-cloud:latest")
    set_model_inventory(
        monkeypatch, ModelInventory(True, ("gemma3:4b", "remote-cloud:latest"), ("gemma3:4b",))
    )
    ui = AppTest.from_file(
        str(Path(__file__).resolve().parents[1] / "app.py"), default_timeout=15
    ).run()
    assert not ui.exception
    assert next(w for w in ui.selectbox if w.label == "Local AI model").value == "gemma3:4b"
    assert store.model_preference() is None


def test_automatic_fallback_does_not_become_a_saved_user_override(app, monkeypatch):
    ui, store = app
    set_model_inventory(monkeypatch, ModelInventory(True, ("gemma4:e4b",), ("gemma4:e4b",)))
    ui.run()
    assert next(w for w in ui.selectbox if w.label == "Local AI model").value == "gemma4:e4b"
    assert store.model_preference() is None
    set_model_inventory(monkeypatch, ModelInventory(True, INSTALLED_MODELS, INSTALLED_MODELS))
    ui.run()
    assert next(w for w in ui.selectbox if w.label == "Local AI model").value == "gemma3:4b"
    assert store.model_preference() is None


def test_grounding_error_is_distinct_and_does_not_expose_raw_payload(app, monkeypatch):
    from specterlan.ai import AIGroundingError

    ui, store = app

    def fail(*args, **kwargs):
        raise AIGroundingError("PRIVATE_MODEL_PAYLOAD_E404")

    monkeypatch.setattr("specterlan.ai_ui.analyze_latest", fail)
    analyze_button(ui).click().run()
    assert not ui.exception
    assert [error.value for error in ui.error] == [
        "Ask the Ghost couldn't verify enough of the AI response against the saved network evidence."
    ]
    assert any(
        c.value == "Your scan data is unchanged. Try the analysis again." for c in ui.caption
    )
    assert not any(
        "PRIVATE_MODEL_PAYLOAD" in item.value for item in [*ui.error, *ui.caption, *ui.text]
    )
    assert any(
        item.value
        == "The local model returned observations or references that could not be matched to the saved evidence."
        for item in ui.text
    )
    assert not any(e.label == "Evidence used" for e in ui.expander)
    assert len(store.recent_scans(NETWORK)) == 1
    ui.button[0].click().run()
    assert len(store.recent_scans(NETWORK)) == 2


def test_partial_grounded_response_is_shown_with_notice_and_citations(app, monkeypatch):
    ui, store = app
    state = install_ui_ollama(monkeypatch)
    state["report"]["suggested_checks"][0]["evidence"] = ["E404"]
    analyze_button(ui).click().run()
    assert not ui.exception and not ui.error
    assert any("Some AI items could not be verified" in item.value for item in ui.warning)
    assert any("newly observed" in item.value.lower() for item in ui.text)
    assert not ui.session_state["ai_report"].report.suggested_checks
    assert any(e.label == "Evidence used" for e in ui.expander)
    assert len(state["requests"]) == 3
    assert len(store.recent_scans(NETWORK)) == 1
