import json
import sqlite3

import httpx
import pytest
from pydantic import ValidationError

from specterlan import ai
from specterlan.evidence import build_evidence, format_evidence, safe_diagnostics
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
        "overview": "One device was recorded in the latest scan [E1].",
        "notable_changes": [
            {
                "title": "Newly observed unreviewed device",
                "explanation": (
                    "SpecterLAN newly observed 192.168.1.47. It is unreviewed, and automatic "
                    "classification suggests smart_home. Identify the device manually."
                ),
                "evidence": ["E2", "E3"],
                "confidence": "high",
            }
        ],
        "devices_to_verify": [
            {
                "reason": "Identify this unreviewed device.",
                "evidence": ["E2"],
                "confidence": "medium",
            }
        ],
        "suggested_checks": [
            {
                "check": "Check whether 192.168.1.47 is your smart plug.",
                "evidence": ["E2"],
            }
        ],
        "evidence_summary": [
            {
                "summary": "The saved device is unreviewed and its hostname is esphome-plug.",
                "evidence": ["E2"],
            }
        ],
    }


def sent_evidence(request):
    prompt = json.loads(request.content)["messages"][1]["content"]
    return prompt.split("AVAILABLE EVIDENCE:\n", 1)[1].split("\n\nJSON SCHEMA:")[0]


@pytest.fixture
def ollama(monkeypatch):
    real_client = httpx.Client
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    monkeypatch.delenv("OLLAMA_NUM_CTX", raising=False)

    def install(
        report=None, envelope=None, show=None, fail=None, status=None, raw=None, reports=None
    ):
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
            output = report if report is not None else valid_report()
            if reports is not None:
                index = sum(call.url.path == "/api/chat" for call in calls) - 1
                output = reports[min(index, len(reports) - 1)]
            body = (
                envelope
                if envelope is not None
                else {
                    "model": json.loads(request.content)["model"],
                    "done": True,
                    "message": {"content": json.dumps(output)},
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
    assert evidence["changes"]["new_devices"] == ["E3"]
    assert evidence["changes"]["vanished_devices"] == []
    assert evidence["changes"]["returning_devices"] == []
    device = evidence["facts"]["E2"]
    assert device["mac_present"] is True
    assert device["identity_basis"] == "mac"
    assert device["trust_status"] == "unreviewed"
    assert device["automatic_device_type"] == "smart_home"
    assert device["classification_reason"] == "Hostname contains 'esphome'"
    assert device["vendor"] == "Tuya"
    assert device["hostname"] == "esphome-plug"
    assert evidence["facts"][evidence["current_scan"]]["timestamp"].endswith("+00:00")


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
    device = evidence["facts"]["E2"]
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
    assert result.model == "gemma3:4b"
    assert result.report.notable_changes[0].confidence == "high"
    assert "newly observed" in result.report.notable_changes[0].explanation
    assert len(calls) == 2
    assert json.loads(calls[0].content) == {"model": "gemma3:4b"}
    payload = json.loads(calls[1].content)
    assert payload["stream"] is False
    assert payload["options"]["temperature"] == 0
    assert payload["format"] == AIReport.citation_schema(list(result.evidence["facts"]))
    assert "Use only evidence IDs listed in AVAILABLE_EVIDENCE_IDS." in ai.SYSTEM_PROMPT
    assert payload["messages"][1]["content"].startswith("AVAILABLE_EVIDENCE_IDS:\nE1\nE2\nE3\n")
    assert settings[0]["trust_env"] is False
    assert settings[0]["follow_redirects"] is False
    assert "untrusted DATA" in ai.SYSTEM_PROMPT
    assert "New means newly observed" in ai.SYSTEM_PROMPT


def test_vanished_device_interpretation_cites_previous_observation(ollama):
    report = valid_report()
    report["overview"] = "No devices were observed in this scan [E1]."
    report["notable_changes"] = [
        {
            "title": "Absent from latest scan",
            "explanation": "192.168.1.47 was observed previously and is absent from the latest scan.",
            "evidence": ["E4", "E3"],
            "confidence": "high",
        }
    ]
    report["devices_to_verify"][0]["evidence"] = ["E3"]
    report["suggested_checks"][0]["evidence"] = ["E3"]
    report["evidence_summary"][0]["evidence"] = ["E3"]
    ollama(report=report)
    result = ai.analyze_scan(snapshot(2, []), snapshot(1))
    assert result.report.notable_changes[0].title == "Absent from latest scan"
    assert result.evidence["changes"]["vanished_devices"] == ["E4"]


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
    assert result.evidence["facts"][result.evidence["current_scan"]]["scan_id"] == 4
    assert result.evidence["facts"][result.evidence["previous_scan"]]["scan_id"] == 2
    assert "latest" in sent and "previous" in sent
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
        (None, None, "gemma3:4b"),
        ("gemma4:e4b", None, "gemma4:e4b"),
        (None, "gemma4:e4b", "gemma4:e4b"),
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
        ("identity", "devices_to_verify"),
        ("address", "suggested_checks"),
    ],
)
def test_unsupported_claim_references_are_rejected(ollama, change, match):
    report = valid_report()
    if change == "identity":
        report["devices_to_verify"][0]["evidence"] = ["E1"]
    else:
        report["suggested_checks"][0]["check"] = "Check 203.0.113.99."
    ollama(report=report)
    result = ai.analyze_scan(snapshot())
    assert result.partial and not getattr(result.report, match)


@pytest.mark.parametrize(
    "label", ["malicious", "compromised", "suspicious", "hacked", "intruder", "unsafe", "threat"]
)
def test_discovery_only_security_labels_are_not_displayed(ollama, label):
    report = valid_report()
    report["notable_changes"][0]["explanation"] = f"This device is {label}."
    ollama(report=report)
    result = ai.analyze_scan(snapshot())
    assert result.partial and not result.report.notable_changes
    assert label not in result.report.model_dump_json()


def test_oversized_evidence_is_not_silently_truncated(ollama):
    calls, _ = ollama()
    current = snapshot(devices=[Device(ip="192.168.1.2", hostname="x" * 50000)])
    with pytest.raises(ai.AIAnalysisError, match="context budget"):
        ai.analyze_scan(current)
    assert calls == []


def test_empty_baseline_has_no_invented_devices_or_changes(ollama):
    report = valid_report()
    report.update(
        overview="No devices were observed; there is no comparison scan [E1].",
        notable_changes=[],
        devices_to_verify=[],
        suggested_checks=[],
        evidence_summary=[{"summary": "Zero online devices.", "evidence": ["E1"]}],
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
            "evidence": ["E5", "E2", "E4"],
            "confidence": "high",
        }
    ]
    report["suggested_checks"] = []
    ollama(report=report)
    result = ai.analyze_scan(current, previous)
    assert result.evidence["changes"]["new_devices"] == []
    assert result.evidence["changes"]["ip_changes"] == ["E5"]
    assert result.report.notable_changes[0].confidence == "high"


def test_short_evidence_ids_are_deterministic_and_all_links_resolve():
    current, previous = snapshot(2), snapshot(1)
    evidence = build_evidence(current, previous)
    assert evidence == build_evidence(current.model_copy(deep=True), previous.model_copy(deep=True))
    assert list(evidence["facts"]) == [f"E{n}" for n in range(1, len(evidence["facts"]) + 1)]
    refs = [
        evidence["current_scan"],
        evidence["previous_scan"],
        *evidence["current_devices"],
        *evidence["previous_devices"],
    ]
    refs += [ref for group in evidence["changes"].values() for ref in group]
    assert all(ref in evidence["facts"] for ref in refs)
    for fact in evidence["facts"].values():
        for field in ("current_device", "previous_device"):
            assert fact.get(field) is None or fact[field] in evidence["facts"]


def test_every_wire_citation_is_constrained_to_available_ids():
    schema = AIReport.citation_schema(["E1", "E2"])
    definitions = [
        definition
        for definition in schema["$defs"].values()
        if "evidence" in definition.get("properties", {})
    ]
    assert len(definitions) == 4
    assert all(d["properties"]["evidence"]["items"]["enum"] == ["E1", "E2"] for d in definitions)
    assert (
        "enum"
        not in AIReport.model_json_schema()["$defs"]["NotableChange"]["properties"]["evidence"][
            "items"
        ]
    )


def test_plain_overview_is_allowed_when_structured_sections_are_grounded(ollama):
    report = valid_report()
    report["overview"] = "One device was recorded in the latest scan."
    calls, _ = ollama(report=report)
    result = ai.analyze_scan(snapshot())
    assert result.report.overview == report["overview"]
    assert not result.retried and not result.partial and len(calls) == 2


@pytest.mark.parametrize(
    "invented", ["E999", "current.scan", "new_devices", "Device ESP", "[E2]", "e2"]
)
def test_unavailable_ids_reject_the_whole_item_not_just_the_bad_reference(ollama, invented):
    report = valid_report()
    report["notable_changes"][0]["evidence"] = ["E2", invented]
    calls, _ = ollama(report=report)
    result = ai.analyze_scan(snapshot())
    assert result.report.notable_changes == []
    assert len(result.report.devices_to_verify) == 1
    assert result.partial and result.retried
    assert len(calls) == 3
    assert all(
        ref in result.evidence["facts"]
        for section in (
            result.report.devices_to_verify,
            result.report.suggested_checks,
            result.report.evidence_summary,
        )
        for item in section
        for ref in item.evidence
    )


def test_gemma3_structurally_valid_response_with_one_unavailable_id_is_retried_and_corrected(
    ollama,
):
    first = valid_report()
    first["suggested_checks"][0]["evidence"] = ["E404"]
    calls, settings = ollama(reports=[first, valid_report()])
    result = ai.analyze_scan(snapshot(), model="gemma3:4b")
    chats = [json.loads(call.content) for call in calls if call.url.path == "/api/chat"]
    assert len(chats) == 2 and result.retried and not result.partial
    assert all(chat["model"] == "gemma3:4b" for chat in chats)
    assert chats[0]["format"] == chats[1]["format"]
    assert chats[0]["options"] == chats[1]["options"]
    assert chats[0]["messages"] == chats[1]["messages"][:2]
    assert sent_evidence(calls[1]) == sent_evidence(calls[2])
    correction = chats[1]["messages"][-1]["content"]
    assert "AVAILABLE_EVIDENCE_IDS:\nE1\nE2\nE3" in correction
    assert "Correct only" in correction
    assert settings[0] == {"trust_env": False, "follow_redirects": False, "timeout": 180.0}
    assert len(result.report.suggested_checks) == 1


def invalid_report():
    report = valid_report()
    for section in ("notable_changes", "devices_to_verify", "suggested_checks", "evidence_summary"):
        for item in report[section]:
            item["evidence"] = ["E404"]
    return report


def test_all_invalid_citations_fail_after_exactly_one_retry(ollama):
    calls, _ = ollama(report=invalid_report())
    with pytest.raises(ai.AIGroundingError) as caught:
        ai.analyze_scan(snapshot())
    assert len(calls) == 3
    assert "could not be matched to the saved evidence" in str(caught.value)
    assert "E404" not in str(caught.value)


def test_valid_sections_survive_even_if_the_only_summary_item_is_invalid(ollama):
    report = valid_report()
    report["evidence_summary"][0]["evidence"] = ["E404"]
    ollama(report=report)
    result = ai.analyze_scan(snapshot())
    assert result.partial
    assert result.report.evidence_summary == []
    assert result.report.notable_changes and result.report.devices_to_verify
    assert "One device was recorded" not in result.report.overview
    # The original response schema still requires a summary; only safe display subsets may omit it.
    report["evidence_summary"] = []
    with pytest.raises(ValidationError):
        AIReport.model_validate(report)


def test_first_valid_parts_survive_when_retry_is_entirely_ungrounded(ollama):
    first = valid_report()
    first["suggested_checks"][0]["evidence"] = ["E404"]
    ollama(reports=[first, invalid_report()])
    result = ai.analyze_scan(snapshot())
    assert result.partial and result.retried
    assert result.report.notable_changes and result.report.evidence_summary
    assert not result.report.suggested_checks


def test_retry_can_salvage_valid_items_after_an_entirely_invalid_first_response(ollama):
    second = valid_report()
    second["notable_changes"][0]["evidence"] = ["E404"]
    ollama(reports=[invalid_report(), second])
    result = ai.analyze_scan(snapshot())
    assert result.partial and result.report.suggested_checks
    assert not result.report.notable_changes


def test_invalid_overview_reference_does_not_borrow_valid_items_citations(ollama):
    report = valid_report()
    report["overview"] = "A claim with invented support [E404]."
    ollama(report=report)
    result = ai.analyze_scan(snapshot())
    assert result.partial and result.retried
    assert (
        result.report.overview
        == "Some AI observations could not be verified against the saved scan evidence. Verified findings are shown below."
    )
    assert result.report.notable_changes


def test_invented_inline_citation_rejects_its_item(ollama):
    report = valid_report()
    report["suggested_checks"][0]["check"] += " [E404]"
    ollama(report=report)
    result = ai.analyze_scan(snapshot())
    assert result.partial and not result.report.suggested_checks


def test_retry_connection_failure_is_distinct_when_nothing_can_be_salvaged(ollama):
    chats = []

    def fail(request):
        if request.url.path == "/api/chat":
            chats.append(request)
            if len(chats) == 2:
                raise httpx.ConnectError("refused", request=request)

    ollama(report=invalid_report(), fail=fail)
    with pytest.raises(ai.AIAnalysisError, match="Start Ollama") as caught:
        ai.analyze_scan(snapshot())
    assert not isinstance(caught.value, ai.AIGroundingError)


def test_retry_transport_failure_preserves_safe_first_response_items(ollama):
    report = valid_report()
    report["suggested_checks"][0]["evidence"] = ["E404"]
    chats = []

    def fail(request):
        if request.url.path == "/api/chat":
            chats.append(request)
            if len(chats) == 2:
                raise httpx.ReadTimeout("timed out", request=request)

    ollama(report=report, fail=fail)
    result = ai.analyze_scan(snapshot())
    assert result.partial and result.retried
    assert result.report.notable_changes and not result.report.suggested_checks


def test_retry_with_a_different_returned_model_is_not_accepted(ollama, monkeypatch):
    first = valid_report()
    first["notable_changes"][0]["evidence"] = ["E404"]
    ollama(reports=[first, valid_report()])
    request_report = ai._request_report
    responses = []

    def different_model(*args):
        report, model = request_report(*args)
        responses.append(report)
        return report, model if len(responses) == 1 else "different:local"

    monkeypatch.setattr(ai, "_request_report", different_model)
    result = ai.analyze_scan(snapshot())
    assert result.partial and result.retried and result.model == "gemma3:4b"
    assert not result.report.notable_changes


def test_repair_never_truncates_evidence_to_fit_the_context_budget(ollama):
    report = valid_report()
    report["notable_changes"][0]["explanation"] = "x" * 20000
    report["notable_changes"][0]["evidence"] = ["E404"]
    calls, _ = ollama(report=report)
    result = ai.analyze_scan(snapshot())
    assert result.partial and not result.retried
    assert len(calls) == 2
    assert sent_evidence(calls[-1]) == format_evidence(result.evidence)


def test_unavailable_citation_item_is_dropped_without_displaying_its_unsafe_claims(ollama):
    report = valid_report()
    report["notable_changes"][0].update(
        explanation="An intruder is at 203.0.113.99.", evidence=["E404"]
    )
    ollama(report=report)
    result = ai.analyze_scan(snapshot())
    assert result.partial and not result.report.notable_changes
    assert "203.0.113.99" not in result.report.model_dump_json()
    assert "intruder" not in result.report.model_dump_json()


@pytest.fixture
def live_pair():
    # Documentation-only addresses and locally administered synthetic MACs.
    router = Device(
        ip="192.0.2.1", mac="02:00:5E:10:00:01", hostname="router-example", device_type="unknown"
    )
    phone = Device(
        ip="192.0.2.20",
        mac="02:00:5E:10:00:02",
        hostname="phone-example",
        device_type="phone",
        automatic_device_type="phone",
    )
    local = Device(ip="192.0.2.30", hostname="workstation-docker-example", device_type="unknown")
    unknown = Device(ip="192.0.2.40", mac="02:00:5E:10:00:04", state="new")
    hostname_only = Device(ip="192.0.2.50", hostname="unidentified-example", state="new")
    vanished = Device(ip="192.0.2.60", mac="02:00:5E:10:00:06", hostname="previous-example")
    previous = snapshot(
        1,
        [router, phone.model_copy(update={"ip": "192.0.2.19"}), local, vanished],
        network="192.0.2.0/24",
    )
    current = snapshot(2, [router, phone, local, unknown, hostname_only], network="192.0.2.0/24")
    return current, previous


def live_report(evidence):
    provisional = next(
        ref
        for ref in evidence["current_devices"]
        if evidence["facts"][ref]["identity_basis"] == "provisional_subnet_ip"
    )
    vanished = evidence["changes"]["vanished_devices"][0]
    return {
        "overview": "One previously observed device is absent from the latest scan.",
        "notable_changes": [
            {
                "title": "Device absent",
                "explanation": "A device was present before but was not seen in the latest scan.",
                "confidence": "high",
                "evidence": [vanished],
            }
        ],
        "devices_to_verify": [
            {
                "reason": "Review this unreviewed device; its identity is provisional.",
                "confidence": "medium",
                "evidence": [provisional],
            }
        ],
        "suggested_checks": [
            {"check": "Confirm whether this device belongs to you.", "evidence": [provisional]}
        ],
        "evidence_summary": [
            {"summary": "The recorded device is unreviewed.", "evidence": [provisional]}
        ],
    }


def test_live_flat_mapping_is_deterministic_complete_and_explicit(live_pair):
    first = build_evidence(*live_pair)
    second = build_evidence(*(scan.model_copy(deep=True) for scan in live_pair))
    flat = format_evidence(first)
    assert flat == format_evidence(second)
    lines = flat.splitlines()
    assert len(lines) == len(first["facts"])
    assert [line.split(": ", 1)[0] for line in lines] == list(first["facts"])
    assert 'Trust: "unreviewed"' in flat
    assert 'Automatic type: "unknown"' in flat
    assert "Identity is provisional" in flat
    for scan in live_pair:
        for device in scan.devices:
            assert not device.mac or device.mac not in flat
    assert '"current_device":' not in flat


def test_live_no_mac_and_unknown_devices_have_valid_citable_facts(live_pair, ollama):
    evidence = build_evidence(*live_pair)
    report = live_report(evidence)
    calls, _ = ollama(report=report)
    result = ai.analyze_scan(*live_pair)
    assert not result.partial
    target = evidence["facts"][report["devices_to_verify"][0]["evidence"][0]]
    assert target["identity_basis"] == "provisional_subnet_ip"
    assert result.report.devices_to_verify[0].identity == target["identity"]
    assert len(calls) == 2
    assert sent_evidence(calls[-1]) == format_evidence(evidence)


def test_device_review_contract_does_not_require_model_generated_identity():
    schema = AIReport.citation_schema(["E1", "E2"])
    assert "identity" not in schema["$defs"]["DeviceToVerify"]["properties"]
    report = valid_report()
    report["devices_to_verify"][0]["identity"] = "invented-device"
    with pytest.raises(ValidationError):
        AIReport.model_validate(report)


def test_live_vanished_and_ip_movement_references_resolve(live_pair):
    evidence = build_evidence(*live_pair)
    vanished = evidence["facts"][evidence["changes"]["vanished_devices"][0]]
    assert vanished["current_device"] is None
    assert vanished["previous_device"] in evidence["previous_devices"]
    move = evidence["facts"][evidence["changes"]["ip_changes"][0]]
    before, after = (
        evidence["facts"][move["previous_device"]],
        evidence["facts"][move["current_device"]],
    )
    assert before["identity"] == after["identity"]
    assert before["device_label"] == after["device_label"]
    assert before["ip"] != after["ip"]


def test_live_retry_contains_exact_invalid_ids_and_can_correct_them(live_pair, ollama):
    evidence = build_evidence(*live_pair)
    first = live_report(evidence)
    first["suggested_checks"][0]["evidence"] = ["E999"]
    calls, _ = ollama(reports=[first, live_report(evidence)])
    result = ai.analyze_scan(*live_pair)
    assert result.retried and not result.partial
    feedback = json.loads(calls[-1].content)["messages"][-1]["content"]
    assert 'INVALID_EVIDENCE_IDS:\n["E999"]' in feedback
    assert "You referenced IDs that do not exist." in feedback
    assert "Replace or remove ONLY those references." in feedback
    assert "Do not invent new evidence IDs." in feedback
    assert "Return only IDs from the allowed list." in feedback
    assert "\n".join(evidence["facts"]) in feedback
    assert sent_evidence(calls[1]) == sent_evidence(calls[2])


def test_live_retry_can_remove_unsupported_item_without_repeating_its_overview(live_pair, ollama):
    evidence = build_evidence(*live_pair)
    first = live_report(evidence)
    first["overview"] = "UNSUPPORTED_OVERVIEW_CLAIM"
    first["suggested_checks"][0]["evidence"] = ["E999"]
    second = live_report(evidence)
    second["overview"] = first["overview"]
    second["suggested_checks"] = []
    ollama(reports=[first, second])
    result = ai.analyze_scan(*live_pair)
    assert result.report.notable_changes and not result.report.suggested_checks
    assert "UNSUPPORTED_OVERVIEW_CLAIM" not in result.report.overview


def test_live_valid_parts_survive_repeated_invalid_citations(live_pair, ollama):
    report = live_report(build_evidence(*live_pair))
    report["suggested_checks"][0]["evidence"] = ["E999"]
    ollama(report=report)
    result = ai.analyze_scan(*live_pair)
    assert result.partial and result.report.notable_changes
    assert result.report.devices_to_verify and result.report.evidence_summary
    assert not result.report.suggested_checks


def test_live_all_invalid_result_still_fails_closed(live_pair, ollama):
    report = live_report(build_evidence(*live_pair))
    for section in ("notable_changes", "devices_to_verify", "suggested_checks", "evidence_summary"):
        for item in report[section]:
            item["evidence"] = ["E999"]
    calls, _ = ollama(report=report)
    with pytest.raises(ai.AIGroundingError):
        ai.analyze_scan(*live_pair)
    assert len(calls) == 3


def test_live_ambiguous_device_review_is_removed_while_other_items_survive(live_pair, ollama):
    evidence = build_evidence(*live_pair)
    report = live_report(evidence)
    report["devices_to_verify"][0]["evidence"] = evidence["current_devices"][:2]
    ollama(report=report)
    result = ai.analyze_scan(*live_pair)
    assert result.partial and not result.report.devices_to_verify
    assert result.report.notable_changes and result.report.evidence_summary


def test_safe_diagnostics_never_expose_underlying_values(live_pair):
    evidence = build_evidence(*live_pair)
    report = live_report(evidence)
    report["suggested_checks"][0]["evidence"] = ["E999", "192.0.2.1", "router-example"]
    diagnostic = safe_diagnostics(evidence, AIReport.model_validate(report))
    output = json.dumps(diagnostic)
    assert diagnostic["Evidence facts"] == len(evidence["facts"])
    assert diagnostic["Allowed IDs"] == list(evidence["facts"])
    assert diagnostic["Invalid citations"] == ["<redacted non-ID>", "E999"]
    assert diagnostic["Device count"] == 5
    assert diagnostic["Provisional identities"] == 2
    assert diagnostic["Unknown classifications"] == 4
    for scan in live_pair:
        for device in scan.devices:
            for value in (device.ip, device.mac, device.hostname, device.friendly_name):
                assert not value or value not in output


def test_live_trust_metadata_and_historical_only_records_are_not_confused(live_pair):
    current, previous = live_pair
    current.devices[0] = current.devices[0].model_copy(update={"trust_status": "trusted"})
    previous.vanished = [Device(ip="198.51.100.99", hostname="outside-two-scans")]
    evidence = build_evidence(current, previous)
    assert evidence["changes"]["metadata_changes"]
    flat = format_evidence(evidence)
    assert 'Trust: "trusted"' in flat and 'Trust: "unreviewed"' in flat
    assert "outside-two-scans" not in flat


def test_review_cannot_claim_another_device_label_from_uncited_facts(live_pair, ollama):
    report = live_report(build_evidence(*live_pair))
    report["devices_to_verify"][0]["reason"] = "Device B requires review."
    ollama(report=report)
    result = ai.analyze_scan(*live_pair)
    assert result.partial and not result.report.devices_to_verify
    assert result.report.notable_changes
