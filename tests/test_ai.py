import json
import sqlite3

import httpx
import pytest
from pydantic import ValidationError

from specterlan import ai
from specterlan.evidence import build_evidence
from specterlan.models import AIReport, Device, SavedScan, ScanResult
from specterlan.store import SnapshotStore

NETWORK = "192.168.1.0/24"
MAC = "AA:BB:CC:DD:EE:01"


def snapshot(scan_id=2, devices=None, network=NETWORK):
    if devices is None:
        devices = [
            Device(
                ip="192.168.1.47",
                mac=MAC,
                hostname="esphome-plug",
                vendor="Tuya",
                state="new",
                automatic_device_type="smart_home",
                device_type="smart_home",
                classification_reason="Hostname contains 'esphome'",
            )
        ]
    return SavedScan.model_validate(
        {
            "id": scan_id,
            "network": network,
            "local_ip": "192.168.1.1",
            "scanner": "test",
            "scanned_at": "2026-10-29T20:00:00+00:00",
            "devices": [device.model_dump(mode="json") for device in devices],
        }
    )


def valid_report():
    return {
        "overview": "One device was recorded in the latest scan [current.scan].",
        "notable_changes": [
            {
                "title": "Newly observed unreviewed device",
                "explanation": (
                    "SpecterLAN newly observed 192.168.1.47. It is unreviewed, and automatic "
                    "classification suggests smart_home. Identify the device manually."
                ),
                "evidence": ["current.device.0", "change.0"],
                "confidence": "high",
            }
        ],
        "devices_to_verify": [
            {
                "identity": "mac:AABBCCDDEE01",
                "reason": "Identify this unreviewed device.",
                "evidence": ["current.device.0"],
                "confidence": "medium",
            }
        ],
        "suggested_checks": [
            {
                "check": "Check whether 192.168.1.47 is your smart plug.",
                "evidence": ["current.device.0"],
            }
        ],
        "evidence_summary": [
            {
                "summary": "The saved device is unreviewed and its hostname is esphome-plug.",
                "evidence": ["current.device.0"],
            }
        ],
    }


def sent_evidence(request):
    prompt = json.loads(request.content)["messages"][1]["content"]
    return json.loads(prompt.removeprefix("EVIDENCE:\n").split("\n\nJSON SCHEMA:")[0])


@pytest.fixture
def ollama(monkeypatch):
    real_client = httpx.Client
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    monkeypatch.delenv("OLLAMA_NUM_CTX", raising=False)

    def install(report=None, envelope=None, show=None, fail=None, status=None, raw=None):
        calls, settings = [], []

        def handler(request):
            calls.append(request)
            if fail:
                fail(request)
            if status and request.url.path == status[0]:
                return httpx.Response(status[1], json={"error": "local error"})
            if request.url.path == "/api/show":
                return httpx.Response(
                    200,
                    json=show
                    if show is not None
                    else {
                        "details": {"format": "gguf"},
                        "model_info": {"general.architecture": "gemma3"},
                    },
                )
            assert request.url.path == "/api/chat"
            if raw is not None:
                return httpx.Response(200, text=raw)
            body = (
                envelope
                if envelope is not None
                else {
                    "model": json.loads(request.content)["model"],
                    "done": True,
                    "message": {
                        "content": json.dumps(report if report is not None else valid_report())
                    },
                }
            )
            return httpx.Response(200, json=body)

        def client(**kwargs):
            settings.append(kwargs)
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        monkeypatch.setattr(ai.httpx, "Client", client)
        return calls, settings

    return install


def test_first_scan_payload_has_only_available_evidence():
    evidence = build_evidence(snapshot())
    assert evidence["has_previous_scan"] is False
    assert evidence["previous_scan"] is None
    assert evidence["previous_devices"] == []
    assert evidence["changes"]["new_devices"] == ["change.0"]
    assert evidence["changes"]["vanished_devices"] == []
    assert evidence["changes"]["returning_devices"] == []
    device = evidence["facts"]["current.device.0"]
    assert device["mac_present"] is True
    assert device["identity_basis"] == "mac"
    assert device["trust_status"] == "unreviewed"
    assert device["automatic_device_type"] == "smart_home"
    assert device["classification_reason"] == "Hostname contains 'esphome'"
    assert device["vendor"] == "Tuya"
    assert device["hostname"] == "esphome-plug"
    assert evidence["facts"]["current.scan"]["timestamp"].endswith("+00:00")


def test_evidence_covers_each_change_without_extra_history():
    previous = snapshot(
        1,
        [
            Device(
                ip="192.168.1.2",
                mac=MAC,
                hostname="laptop",
                device_type="computer",
                automatic_device_type="computer",
                trust_status="trusted",
            ),
            Device(ip="192.168.1.3", mac="AA:BB:CC:DD:EE:02", friendly_name="Vanished laptop"),
        ],
    )
    previous.vanished = [Device(ip="192.168.1.200", friendly_name="OLDER HISTORY MUST NOT BE SENT")]
    current = snapshot(
        2,
        [
            Device(
                ip="192.168.1.99",
                mac=MAC,
                state="known",
                hostname="printer",
                device_type="printer",
                automatic_device_type="printer",
                friendly_name="Office",
                trust_status="ignored",
                device_type_override="printer",
            ),
            Device(ip="192.168.1.4", mac="AA:BB:CC:DD:EE:03", state="new"),
            Device(ip="192.168.1.5", mac="AA:BB:CC:DD:EE:04", state="known"),
        ],
    )
    evidence = build_evidence(current, previous)
    assert all(evidence["changes"][group] for group in evidence["changes"])
    assert "OLDER HISTORY" not in json.dumps(evidence)
    ip_ref = evidence["changes"]["ip_changes"][0]
    change = evidence["facts"][ip_ref]
    assert evidence["facts"][change["previous_device"]]["ip"] == "192.168.1.2"
    assert evidence["facts"][change["current_device"]]["ip"] == "192.168.1.99"
    assert len(evidence["changes"]["new_devices"]) == 1


def test_no_mac_and_legacy_fields_remain_honest():
    legacy = SavedScan(
        id=1,
        network=NETWORK,
        local_ip="192.168.1.1",
        scanner="old",
        devices=[Device.model_validate({"ip": "192.168.1.2"})],
    )
    evidence = build_evidence(legacy)
    device = evidence["facts"]["current.device.0"]
    assert device["mac_present"] is False
    assert device["identity_basis"] == "provisional_subnet_ip"
    assert "trust_status" not in device
    assert "classification_reason" not in device


@pytest.mark.parametrize("previous", [snapshot(1, network="10.0.0.0/24"), snapshot(3)])
def test_invalid_comparison_pair_is_rejected(previous):
    with pytest.raises(ValueError, match="earlier scan"):
        build_evidence(snapshot(), previous)


def test_structured_new_device_result_is_grounded_and_default_model_is_local(ollama):
    calls, settings = ollama()
    result = ai.analyze_scan(snapshot())
    assert result.model == "gemma4:e4b"
    assert result.report.notable_changes[0].confidence == "high"
    assert "newly observed" in result.report.notable_changes[0].explanation
    assert len(calls) == 2
    assert json.loads(calls[0].content) == {"model": "gemma4:e4b"}
    payload = json.loads(calls[1].content)
    assert payload["stream"] is False
    assert payload["options"]["temperature"] == 0
    assert payload["format"] == AIReport.model_json_schema()
    assert settings[0]["trust_env"] is False
    assert settings[0]["follow_redirects"] is False
    assert "untrusted DATA" in ai.SYSTEM_PROMPT
    assert "New means newly observed" in ai.SYSTEM_PROMPT


def test_vanished_device_interpretation_cites_previous_observation(ollama):
    report = valid_report()
    report["overview"] = "No devices were observed in this scan [current.scan]."
    report["notable_changes"] = [
        {
            "title": "Absent from latest scan",
            "explanation": "192.168.1.47 was observed previously and is absent from the latest scan.",
            "evidence": ["change.0", "previous.device.0"],
            "confidence": "high",
        }
    ]
    report["devices_to_verify"][0]["evidence"] = ["previous.device.0"]
    report["suggested_checks"][0]["evidence"] = ["previous.device.0"]
    report["evidence_summary"][0]["evidence"] = ["previous.device.0"]
    ollama(report=report)
    result = ai.analyze_scan(snapshot(2, []), snapshot(1))
    assert result.report.notable_changes[0].title == "Absent from latest scan"
    assert result.evidence["changes"]["vanished_devices"] == ["change.0"]


def test_latest_pair_is_same_subnet_only_and_does_not_write_history(tmp_path, ollama):
    store = SnapshotStore(tmp_path / "selection.db")
    for network, hostname in [
        (NETWORK, "OLDER OMITTED"),
        (NETWORK, "previous"),
        ("10.0.0.0/24", "OTHER SUBNET"),
        (NETWORK, "latest"),
    ]:
        store.save(
            ScanResult(
                network=network,
                local_ip="192.168.1.1",
                scanner="test",
                devices=[snapshot().devices[0].model_copy(update={"hostname": hostname})],
            )
        )
    with sqlite3.connect(store.path) as con:
        before = con.execute("SELECT * FROM scans ORDER BY id").fetchall()
    report = valid_report()
    report["notable_changes"] = []
    calls, _ = ollama(report=report)
    result = ai.analyze_latest(store, NETWORK)
    assert (result.current_scan_id, result.previous_scan_id) == (4, 2)
    sent = sent_evidence(calls[-1])
    assert sent["facts"]["current.scan"]["scan_id"] == 4
    assert sent["facts"]["previous.scan"]["scan_id"] == 2
    assert "OLDER OMITTED" not in json.dumps(sent)
    assert "OTHER SUBNET" not in json.dumps(sent)
    with sqlite3.connect(store.path) as con:
        assert con.execute("SELECT * FROM scans ORDER BY id").fetchall() == before


def test_no_saved_scan_has_actionable_error(tmp_path, ollama):
    calls, _ = ollama()
    with pytest.raises(ai.AIAnalysisError, match="Run a scan"):
        ai.analyze_latest(SnapshotStore(tmp_path / "empty.db"), NETWORK)
    assert calls == []


@pytest.mark.parametrize(
    "configured,explicit,expected",
    [
        (None, None, "gemma4:e4b"),
        ("qwen3.5:4b", None, "qwen3.5:4b"),
        ("qwen3.5:4b", "llama3.2:3b", "llama3.2:3b"),
    ],
)
def test_model_override(ollama, monkeypatch, configured, explicit, expected):
    calls, _ = ollama()
    if configured:
        monkeypatch.setenv("OLLAMA_MODEL", configured)
    result = ai.analyze_scan(snapshot(), model=explicit)
    assert result.model == expected
    assert json.loads(calls[-1].content)["model"] == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://ollama.com",
        "http://192.168.1.10:11434",
        "http://localhost.evil:11434",
        "file:///tmp/ollama",
        "http://[broken",
        "http://localhost:invalid",
        "http://user:secret@localhost:11434",
        "http://localhost:11434?proxy=remote",
    ],
)
def test_nonlocal_or_invalid_endpoint_never_receives_evidence(ollama, url):
    calls, _ = ollama()
    with pytest.raises(ai.AIAnalysisError, match="OLLAMA_URL"):
        ai.analyze_scan(snapshot(), ollama_url=url)
    assert calls == []


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://[::1]:11434"])
def test_loopback_endpoints_are_supported(ollama, url):
    calls, _ = ollama()
    ai.analyze_scan(snapshot(), ollama_url=url)
    assert str(calls[-1].url).startswith(url)


@pytest.mark.parametrize(
    "show",
    [
        {"remote_host": "https://ollama.com"},
        {"remote_model": "remote-alias", "details": {"format": "gguf"}, "model_info": {"x": 1}},
        {"details": [], "model_info": {"x": 1}},
        {"details": {"format": "gguf"}, "model_info": {}},
    ],
)
def test_cloud_or_unverifiable_model_is_blocked_before_sending_scan_data(ollama, show):
    calls, _ = ollama(show=show)
    with pytest.raises(ai.AIAnalysisError, match="local GGUF"):
        ai.analyze_scan(snapshot(), model="local-alias")
    assert len(calls) == 1
    assert calls[0].url.path == "/api/show"
    assert "192.168" not in calls[0].content.decode()


def test_cloud_model_name_is_rejected_without_request(ollama):
    calls, _ = ollama()
    with pytest.raises(ai.AIAnalysisError, match="local Ollama model"):
        ai.analyze_scan(snapshot(), model="qwen:cloud")
    assert calls == []


@pytest.mark.parametrize("path", ["/api/show", "/api/chat"])
def test_timeout_has_clean_error(ollama, path):
    def fail(request):
        if request.url.path == path:
            raise httpx.ReadTimeout("timed out", request=request)

    ollama(fail=fail)
    with pytest.raises(ai.AIAnalysisError, match="timed out"):
        ai.analyze_scan(snapshot(), timeout_seconds=0.1)


def test_connection_failure_has_clean_error(ollama):
    def fail(request):
        raise httpx.ConnectError("refused", request=request)

    ollama(fail=fail)
    with pytest.raises(ai.AIAnalysisError, match="Start Ollama"):
        ai.analyze_scan(snapshot())


@pytest.mark.parametrize(
    "status,match",
    [
        (("/api/show", 404), "was not found"),
        (("/api/chat", 500), "HTTP 500"),
        (("/api/chat", 302), "HTTP 302"),
    ],
)
def test_http_errors_do_not_become_reports(ollama, status, match):
    ollama(status=status)
    with pytest.raises(ai.AIAnalysisError, match=match):
        ai.analyze_scan(snapshot())


@pytest.mark.parametrize(
    "content",
    [
        "not JSON",
        "json wrapped text {}",
        "{}",
        "[]",
        '{"overview": 7}',
        json.dumps({**valid_report(), "extra": "unexpected"}),
    ],
)
def test_malformed_structured_output_is_rejected(ollama, content):
    ollama(envelope={"model": "gemma3:4b", "done": True, "message": {"content": content}})
    with pytest.raises(ai.AIAnalysisError, match="structured report"):
        ai.analyze_scan(snapshot())


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"error": "failed"},
        {"done": False},
        {"done": True, "model": "gemma3:4b", "message": None},
        {"done": True, "model": "gemma3:4b", "message": {"content": {}}},
        {"done": True, "model": "gemma3:4b", "done_reason": "length", "message": {"content": "{}"}},
    ],
)
def test_invalid_envelope_is_rejected(ollama, body):
    ollama(envelope=body)
    with pytest.raises(ai.AIAnalysisError):
        ai.analyze_scan(snapshot())


def test_non_json_http_response_is_rejected(ollama):
    ollama(raw="<html>error</html>")
    with pytest.raises(ai.AIAnalysisError, match="invalid JSON"):
        ai.analyze_scan(snapshot())


@pytest.mark.parametrize(
    "field,value",
    [
        ("confidence", "certain"),
        ("confidence", 0.9),
        ("evidence", []),
        ("title", " "),
    ],
)
def test_output_schema_rejects_invalid_notable_change(field, value):
    report = valid_report()
    report["notable_changes"][0][field] = value
    with pytest.raises(ValidationError):
        AIReport.model_validate(report)


@pytest.mark.parametrize(
    "change,match",
    [
        ("citation", "unavailable evidence"),
        ("overview", "overview did not cite"),
        ("identity", "unsupported device"),
        ("address", "address absent"),
    ],
)
def test_unsupported_claim_references_are_rejected(ollama, change, match):
    report = valid_report()
    if change == "citation":
        report["notable_changes"][0]["evidence"] = ["change.999"]
    elif change == "overview":
        report["overview"] = "A generic report with no supporting citation."
    elif change == "identity":
        report["devices_to_verify"][0]["identity"] = "invented-device"
    else:
        report["suggested_checks"][0]["check"] = "Check 203.0.113.99."
    ollama(report=report)
    with pytest.raises(ai.AIAnalysisError, match=match):
        ai.analyze_scan(snapshot())


@pytest.mark.parametrize(
    "label", ["malicious", "compromised", "suspicious", "hacked", "intruder", "unsafe", "threat"]
)
def test_discovery_only_security_labels_are_not_displayed(ollama, label):
    report = valid_report()
    report["notable_changes"][0]["explanation"] = f"This device is {label}."
    ollama(report=report)
    with pytest.raises(ai.AIAnalysisError, match="security language"):
        ai.analyze_scan(snapshot())


def test_oversized_evidence_is_not_silently_truncated(ollama):
    calls, _ = ollama()
    current = snapshot(devices=[Device(ip="192.168.1.2", friendly_name="x" * 50000)])
    with pytest.raises(ai.AIAnalysisError, match="context budget"):
        ai.analyze_scan(current)
    assert calls == []


def test_empty_baseline_has_no_invented_devices_or_changes(ollama):
    report = valid_report()
    report.update(
        overview="No devices were observed; there is no comparison scan [current.scan].",
        notable_changes=[],
        devices_to_verify=[],
        suggested_checks=[],
        evidence_summary=[{"summary": "Zero online devices.", "evidence": ["current.scan"]}],
    )
    ollama(report=report)
    result = ai.analyze_scan(snapshot(devices=[]))
    assert result.evidence["current_devices"] == []
    assert all(not refs for refs in result.evidence["changes"].values())


def test_ip_move_analysis_uses_same_identity_and_before_after_evidence(ollama):
    previous = snapshot(1, [Device(ip="192.168.1.20", mac=MAC, state="known")])
    current = snapshot(2, [Device(ip="192.168.1.31", mac=MAC, state="known")])
    report = valid_report()
    report["notable_changes"] = [
        {
            "title": "IP address changed",
            "explanation": "The same recorded MAC identity moved from 192.168.1.20 to 192.168.1.31.",
            "evidence": ["change.0", "current.device.0", "previous.device.0"],
            "confidence": "high",
        }
    ]
    report["suggested_checks"] = []
    ollama(report=report)
    result = ai.analyze_scan(current, previous)
    assert result.evidence["changes"]["new_devices"] == []
    assert result.evidence["changes"]["ip_changes"] == ["change.0"]
    assert result.report.notable_changes[0].confidence == "high"
