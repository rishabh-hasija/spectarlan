import json
from pathlib import Path

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from specterlan import demo as demo_module
from specterlan import network, readiness_ui
from specterlan import store as store_module
from specterlan.changes import compare_scans
from specterlan.classification import classify
from specterlan.demo import (
    BASE_TIME,
    DEMO_LOCAL_IP,
    DEMO_NETWORK,
    ESP_MAC,
    PHONE_MAC,
    TV_MAC,
    DemoSession,
    demo_devices,
)
from specterlan.evidence import build_evidence
from specterlan.models import DeviceMetadata, ScanResult
from specterlan.readiness import ModelInventory
from specterlan.store import SnapshotStore


@pytest.fixture
def demo():
    session = DemoSession()
    yield session
    session.close()


def test_first_demo_scan_is_a_known_trusted_baseline(demo):
    result = demo.advance()
    assert result.scanned_at == BASE_TIME
    assert result.network == DEMO_NETWORK
    assert result.local_ip == DEMO_LOCAL_IP
    assert [device.device_type for device in result.devices] == [
        "router",
        "computer",
        "tv",
        "phone",
    ]
    assert all(device.state == "known" for device in result.devices)
    assert all(device.trust_status == "trusted" for device in result.devices)
    assert all(device.device_type_override is None for device in result.devices)
    assert result.vanished == []
    assert demo.store.latest_scan_pair(DEMO_NETWORK)[1] is None


def test_second_scan_has_exactly_one_new_unreviewed_esp_with_normal_override(demo):
    demo.advance()
    result = demo.advance()
    new = [device for device in result.devices if device.state == "new"]
    assert len(new) == 1
    assert new[0].mac == ESP_MAC
    assert new[0].hostname == "ESP_32A1"
    assert new[0].vendor == "Espressif"
    assert new[0].trust_status == "unreviewed"
    assert new[0].device_type == "smart_home"
    assert new[0].device_type_override == "smart_home"
    assert new[0].automatic_device_type == "unknown"
    assert classify("ESP_32A1", "Espressif").device_type == "unknown"
    current, previous = demo.store.latest_scan_pair(DEMO_NETWORK)
    assert [(event.kind, event.device.mac) for event in compare_scans(current, previous)] == [
        ("new", ESP_MAC),
    ]


def test_third_scan_has_ip_move_and_vanished_phone_not_a_new_tv(demo):
    demo.advance()
    demo.advance()
    result = demo.advance()
    tv = next(device for device in result.devices if device.mac == TV_MAC)
    assert tv.ip == "192.168.178.31"
    assert tv.state == "known"
    assert tv.friendly_name == "Living Room TV"
    assert tv.trust_status == "trusted"
    assert [device.mac for device in result.vanished] == [PHONE_MAC]
    assert result.vanished[0].friendly_name == "Alice's Phone"
    assert next(device for device in result.devices if device.mac == ESP_MAC).state == "known"
    current, previous = demo.store.latest_scan_pair(DEMO_NETWORK)
    assert {(event.kind, event.device.mac) for event in compare_scans(current, previous)} == {
        ("ip_changed", TV_MAC),
        ("vanished", PHONE_MAC),
    }


def test_demo_is_deterministic_across_sessions_and_reset(demo):
    expected = [demo.advance().model_dump(mode="json") for _ in range(3)]
    another = DemoSession()
    try:
        assert [another.advance().model_dump(mode="json") for _ in range(3)] == expected
    finally:
        another.close()
    demo.reset()
    assert demo.stage == 0
    assert demo.store.recent_scans(DEMO_NETWORK) == []
    assert [demo.advance().model_dump(mode="json") for _ in range(3)] == expected
    assert [scan.id for scan in demo.store.recent_scans(DEMO_NETWORK)] == [3, 2, 1]


def test_reset_discards_only_demo_edits_and_restores_baseline_metadata(demo):
    first = demo.advance()
    demo.store.update_metadata(
        first.devices[0],
        DEMO_NETWORK,
        DeviceMetadata(friendly_name="Edited", device_type="server", trust_status="ignored"),
    )
    demo.advance()
    demo.reset()
    replay = demo.advance()
    assert replay.devices[0].friendly_name == "Home Router"
    assert replay.devices[0].trust_status == "trusted"
    assert replay.devices[0].device_type == "router"
    assert replay.devices[0].device_type_override is None
    assert all(device.mac != ESP_MAC for device in replay.devices)


def test_demo_reset_does_not_change_live_database_even_with_same_subnet_and_mac(demo, tmp_path):
    live = SnapshotStore(tmp_path / "live.db")
    device = demo_devices(1)[2]
    live.update_metadata(
        device,
        DEMO_NETWORK,
        DeviceMetadata(friendly_name="Actual live TV", device_type="tv", trust_status="trusted"),
    )
    devices, vanished = live.annotate_states([device], DEMO_NETWORK)
    live.save(
        ScanResult(
            network=DEMO_NETWORK,
            local_ip=DEMO_LOCAL_IP,
            scanner="live",
            devices=devices,
            vanished=vanished,
        )
    )
    before = Path(live.path).read_bytes()
    for _ in range(3):
        demo.advance()
    demo.reset()
    assert Path(live.path).read_bytes() == before
    assert len(live.recent_scans(DEMO_NETWORK)) == 1
    assert live.apply_metadata([device], DEMO_NETWORK)[0].friendly_name == "Actual live TV"


def test_independent_demo_sessions_do_not_share_history_or_metadata(demo):
    second = DemoSession()
    try:
        first = demo.advance()
        second.advance()
        demo.store.update_metadata(
            first.devices[0],
            DEMO_NETWORK,
            DeviceMetadata(friendly_name="Private edit"),
        )
        demo.advance()
        assert len(second.store.recent_scans(DEMO_NETWORK)) == 1
        assert (
            second.store.apply_metadata([first.devices[0]], DEMO_NETWORK)[0].friendly_name
            == "Home Router"
        )
        demo.reset()
        assert len(second.store.recent_scans(DEMO_NETWORK)) == 1
    finally:
        second.close()


def test_demo_fixtures_return_fresh_models():
    first = demo_devices(1)
    first[0].hostname = "Changed"
    assert demo_devices(1)[0].hostname == "fritzbox"


@pytest.mark.parametrize("stage", [0, 4])
def test_invalid_fixture_stage_is_rejected(stage):
    with pytest.raises(ValueError, match="1, 2, or 3"):
        demo_devices(stage)


def test_demo_cannot_advance_past_final_stage(demo):
    for _ in range(3):
        demo.advance()
    with pytest.raises(ValueError, match="Reset Demo"):
        demo.advance()
    assert len(demo.store.recent_scans(DEMO_NETWORK)) == 3


def test_shared_ai_evidence_contains_simulated_changes_and_only_two_scans(demo):
    demo.advance()
    demo.advance()
    current, previous = demo.store.latest_scan_pair(DEMO_NETWORK)
    evidence = build_evidence(current, previous)
    assert len(evidence["changes"]["new_devices"]) == 1
    esp = next(fact for fact in evidence["facts"].values() if fact.get("hostname") == "ESP_32A1")
    assert esp["device_type"] == "smart_home"
    assert esp["automatic_device_type"] == "unknown"
    assert esp["trust_status"] == "unreviewed"
    assert esp["mac_present"] is True
    assert "simulated" in evidence["facts"][evidence["current_scan"]]["scanner"]
    demo.advance()
    current, previous = demo.store.latest_scan_pair(DEMO_NETWORK)
    evidence = build_evidence(current, previous)
    assert (current.id, previous.id) == (3, 2)
    assert len(evidence["changes"]["ip_changes"]) == 1
    assert len(evidence["changes"]["vanished_devices"]) == 1
    assert evidence["changes"]["new_devices"] == []


def test_temporary_demo_database_can_be_removed_on_windows():
    session = DemoSession()
    path = Path(session.store.path).parent
    session.advance()
    session.store.recent_scans(DEMO_NETWORK)
    session.close()
    assert not path.exists()


def button(ui, label):
    return next(widget for widget in ui.button if widget.label == label)


@pytest.fixture
def demo_app(tmp_path, monkeypatch):
    monkeypatch.setattr(
        readiness_ui,
        "cached_model_inventory",
        lambda *args: ModelInventory(
            True, ("gemma3:4b", "gemma4:e4b"), ("gemma3:4b", "gemma4:e4b")
        ),
    )
    session = DemoSession()
    live = SnapshotStore(tmp_path / "live-ui.db")
    calls = {"detect": 0, "discover": 0, "live_store": 0}

    def live_store():
        calls["live_store"] += 1
        return live

    def detect():
        calls["detect"] += 1
        return DEMO_LOCAL_IP, DEMO_NETWORK

    def discover(*_):
        calls["discover"] += 1
        return [demo_devices(1)[0]], "live test"

    monkeypatch.setattr(demo_module, "DemoSession", lambda: session)
    monkeypatch.setattr(store_module, "SnapshotStore", live_store)
    monkeypatch.setattr(network, "detect_local_network", detect)
    monkeypatch.setattr(network, "discover", discover)
    ui = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"), default_timeout=15)
    ui.session_state["mode"] = "Demo Séance"
    ui.run()
    assert not ui.exception
    yield ui, session, live, calls
    session.close()


def test_demo_mode_is_explicit_and_never_calls_live_detection_or_discovery(demo_app):
    ui, session, _, calls = demo_app
    assert ui.radio[0].options == ["Live Network", "Demo Séance"]
    assert any("Demo Séance: simulated network evidence" in info.value for info in ui.info)
    assert not any(widget.label == "Scan network" for widget in ui.button)
    button(ui, "Start Demo").click().run()
    button(ui, "Next Scan").click().run()
    button(ui, "Next Scan").click().run()
    assert not ui.exception
    assert session.stage == 3
    assert button(ui, "Next Scan").disabled
    assert calls == {"detect": 0, "discover": 0, "live_store": 0}
    assert any("Address updated (1)" in item.value for item in ui.markdown)
    assert any("Offline since last scan (1)" in item.value for item in ui.markdown)


def test_ui_reset_removes_demo_history_and_replays_same_first_scan(demo_app):
    ui, session, _, _ = demo_app
    button(ui, "Start Demo").click().run()
    before = ui.dataframe[0].value.copy()
    button(ui, "Next Scan").click().run()
    button(ui, "Reset Demo").click().run()
    assert not ui.exception
    assert session.stage == 0
    assert session.store.recent_scans(DEMO_NETWORK) == []
    assert not button(ui, "Start Demo").disabled
    assert button(ui, "Next Scan").disabled
    assert not any(widget.label == "Inspect scan" for widget in ui.selectbox)
    button(ui, "Start Demo").click().run()
    assert ui.dataframe[0].value.equals(before)


def test_mode_switching_preserves_live_history_and_does_not_mix_results(demo_app):
    ui, session, live, calls = demo_app
    ui.radio[0].set_value("Live Network").run()
    assert not ui.exception
    assert any(widget.label == "Scan network" for widget in ui.button)
    assert not any(widget.label == "Start Demo" for widget in ui.button)
    button(ui, "Scan network").click().run()
    live_before = Path(live.path).read_bytes()
    assert calls["discover"] == 1
    ui.radio[0].set_value("Demo Séance").run()
    button(ui, "Start Demo").click().run()
    button(ui, "Next Scan").click().run()
    assert len(ui.dataframe[0].value) == 5
    ui.radio[0].set_value("Live Network").run()
    assert len(ui.dataframe[0].value) == 1
    assert Path(live.path).read_bytes() == live_before
    assert len(live.recent_scans(DEMO_NETWORK)) == 1
    ui.radio[0].set_value("Demo Séance").run()
    assert session.stage == 2
    assert len(ui.dataframe[0].value) == 5
    button(ui, "Reset Demo").click().run()
    assert Path(live.path).read_bytes() == live_before


def test_ask_ghost_uses_demo_evidence_with_mocked_ollama(demo_app, monkeypatch):
    ui, session, live, calls = demo_app
    button(ui, "Start Demo").click().run()
    button(ui, "Next Scan").click().run()
    real_client = httpx.Client
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/api/show":
            return httpx.Response(
                200,
                json={
                    "details": {"format": "gguf"},
                    "model_info": {"general.architecture": "gemma3"},
                },
            )
        data = json.loads(request.content)
        report = {
            "overview": "A simulated device is newly observed [E6].",
            "notable_changes": [
                {
                    "title": "New simulated ESP-style device",
                    "explanation": "192.168.178.47 is unreviewed; its saved type override is smart_home.",
                    "evidence": ["E6", "E12"],
                    "confidence": "high",
                }
            ],
            "devices_to_verify": [
                {
                    "reason": "Identify the simulated unreviewed device.",
                    "evidence": ["E6"],
                    "confidence": "medium",
                }
            ],
            "suggested_checks": [],
            "evidence_summary": [
                {
                    "summary": "Only two simulated scans were supplied.",
                    "evidence": ["E1", "E7"],
                }
            ],
        }
        return httpx.Response(
            200,
            json={
                "done": True,
                "model": data["model"],
                "message": {"content": json.dumps(report)},
            },
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(handler),
            **kwargs,
        ),
    )
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    monkeypatch.delenv("OLLAMA_NUM_CTX", raising=False)
    button(ui, "Analyze with Ollama").click().run()
    assert not ui.exception
    assert not ui.error
    assert any("A simulated device" in item.value for item in ui.text)
    assert len(requests) == 2
    prompt = json.loads(requests[-1].content)["messages"][1]["content"]
    assert "E6: Device E" in prompt and "ESP_32A1" in prompt
    assert "demo fixture 2 (simulated)" in prompt
    assert "demo fixture 1 (simulated)" in prompt
    assert calls == {"detect": 0, "discover": 0, "live_store": 0}
    # Identical scan IDs across stores must not reuse a cached simulated AI report.
    for _ in range(2):
        live.save(
            ScanResult(
                network=DEMO_NETWORK,
                local_ip=DEMO_LOCAL_IP,
                scanner="live",
                devices=demo_devices(1),
            )
        )
    ui.radio[0].set_value("Live Network").run()
    assert not ui.exception
    assert ui.session_state["ai_report"] is None
    assert not any("A simulated device" in item.value for item in ui.text)
    ui.radio[0].set_value("Demo Séance").run()
    button(ui, "Reset Demo").click().run()
    assert not any("A simulated device" in item.value for item in ui.text)
    assert session.stage == 0


def test_live_network_remains_the_default_mode(demo_app):
    _, _, _, calls = demo_app
    ui = AppTest.from_file(
        str(Path(__file__).resolve().parents[1] / "app.py"),
        default_timeout=15,
    ).run()
    assert not ui.exception
    assert ui.radio[0].value == "Live Network"
    assert any(widget.label == "Scan network" for widget in ui.button)
    assert not any("Demo Séance: simulated" in item.value for item in ui.info)
    assert calls == {"detect": 1, "discover": 0, "live_store": 1}


def test_demo_model_selection_does_not_change_live_preferences(demo_app):
    ui, _, live, calls = demo_app
    live.save_model_preference("live-local-model")
    next(w for w in ui.selectbox if w.label == "Local AI model").select("gemma4:e4b").run()
    assert not ui.exception
    assert live.model_preference() == "live-local-model"
    assert calls == {"detect": 0, "discover": 0, "live_store": 0}
