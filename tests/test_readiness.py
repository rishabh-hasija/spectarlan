import sqlite3
import tomllib
from pathlib import Path

import httpx
import pytest

from specterlan import readiness
from specterlan.readiness import DEFAULT_MODEL, check_local_ai, supported_python, writable_storage


@pytest.mark.parametrize("version,expected", [((3, 10), False), ((3, 11), True), ((3, 14), True)])
def test_python_support_matches_package_minimum(version, expected):
    assert supported_python(version) is expected


def mock_ollama(monkeypatch, handler):
    real_client = httpx.Client
    settings = []

    def factory(**kwargs):
        settings.append(kwargs)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    return settings


def local_info():
    return {"details": {"format": "gguf"}, "model_info": {"general.architecture": "gemma4"}}


def test_ready_checks_only_metadata_without_generating_or_sending_evidence(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": DEFAULT_MODEL}]})
        assert request.url.path == "/api/show"
        assert request.content == b'{"model":"gemma3:4b"}'
        return httpx.Response(200, json=local_info())

    settings = mock_ollama(monkeypatch, handler)
    result = check_local_ai(DEFAULT_MODEL)
    assert result.ollama_ready and result.default_model_ready and result.selected_model_ready
    assert len(requests) == 2
    assert settings == [{"trust_env": False, "follow_redirects": False, "timeout": 2.0}]


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout])
def test_missing_or_unresponsive_ollama_is_optional(monkeypatch, error):
    def handler(request):
        raise error("private diagnostic", request=request)

    mock_ollama(monkeypatch, handler)
    result = check_local_ai(DEFAULT_MODEL)
    assert not result.ollama_ready and not result.selected_model_ready
    assert result.message == "Ollama is not running. Network scanning still works."
    assert "private diagnostic" not in result.message


def test_missing_default_does_not_block_selected_local_override(monkeypatch):
    def handler(request):
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"model": "custom:latest"}]})
        return httpx.Response(200, json=local_info())

    mock_ollama(monkeypatch, handler)
    result = check_local_ai("custom")
    assert result.ollama_ready and result.selected_model_ready
    assert not result.default_model_ready


def test_missing_model_is_reported_without_pulling(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"models": []})

    mock_ollama(monkeypatch, handler)
    result = check_local_ai(DEFAULT_MODEL)
    assert result.ollama_ready
    assert not result.default_model_ready and not result.selected_model_ready
    assert [(r.method, r.url.path) for r in requests] == [("GET", "/api/tags")]


@pytest.mark.parametrize("url", ["https://remote.example", "http://192.168.1.2:11434", "invalid"])
def test_remote_endpoints_are_rejected_without_requests(monkeypatch, url):
    def forbidden(**kwargs):
        pytest.fail("No client should be created for a nonlocal endpoint")

    monkeypatch.setattr(httpx, "Client", forbidden)
    result = check_local_ai(DEFAULT_MODEL, url)
    assert not result.ollama_ready
    assert "loopback" in result.message


@pytest.mark.parametrize(
    "info",
    [
        {**local_info(), "remote_host": "https://remote.example"},
        {**local_info(), "remote_model": "remote"},
        {"details": {"format": "gguf"}, "model_info": {}},
        {"details": {"format": "other"}, "model_info": {"x": 1}},
    ],
)
def test_remote_or_unverifiable_models_are_not_ready(monkeypatch, info):
    def handler(request):
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": DEFAULT_MODEL}]})
        return httpx.Response(200, json=info)

    mock_ollama(monkeypatch, handler)
    result = check_local_ai(DEFAULT_MODEL)
    assert result.ollama_ready and not result.selected_model_ready


@pytest.mark.parametrize("body", [None, {}, {"models": "invalid"}])
def test_malformed_ollama_responses_are_nonblocking(monkeypatch, body):
    mock_ollama(monkeypatch, lambda r: httpx.Response(200, json=body))
    assert not check_local_ai(DEFAULT_MODEL).ollama_ready


def test_redirects_are_not_followed(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "https://remote.example"})

    mock_ollama(monkeypatch, handler)
    assert not check_local_ai(DEFAULT_MODEL).ollama_ready
    assert len(requests) == 1


def test_nmap_absent_is_fallback_status(monkeypatch):
    monkeypatch.setattr(readiness.shutil, "which", lambda name: None)
    assert not readiness.nmap_available()
    monkeypatch.setattr(readiness.shutil, "which", lambda name: "nmap.exe")
    assert readiness.nmap_available()


def test_storage_probe_cleans_up_and_does_not_change_database(tmp_path):
    database = tmp_path / "local.db"
    with sqlite3.connect(database) as con:
        con.execute("CREATE TABLE saved (value TEXT)")
    before = database.read_bytes()
    assert writable_storage(database)
    assert database.read_bytes() == before
    assert list(tmp_path.iterdir()) == [database]


def test_unwritable_storage_returns_problem_without_raw_paths(tmp_path, monkeypatch):
    def denied(**kwargs):
        raise PermissionError("private path")

    monkeypatch.setattr(readiness, "NamedTemporaryFile", denied)
    assert not writable_storage(tmp_path / "local.db")


def test_streamlit_configuration_keeps_first_run_local_and_without_onboarding():
    config = tomllib.loads(
        (Path(__file__).resolve().parents[1] / ".streamlit/config.toml").read_text()
    )
    assert config["server"]["address"] == "127.0.0.1"
    assert config["server"]["headless"] is True
    assert config["browser"]["gatherUsageStats"] is False
    assert config["client"]["showErrorDetails"] == "none"


@pytest.mark.parametrize(
    "models,saved,current,expected",
    [
        (("gemma4:e4b", DEFAULT_MODEL), None, None, DEFAULT_MODEL),
        ((DEFAULT_MODEL, "gemma4:e4b"), "gemma4:e4b", None, "gemma4:e4b"),
        ((DEFAULT_MODEL, "gemma4:e4b"), "removed:model", None, DEFAULT_MODEL),
        (("gemma4:e4b", "other:local"), "removed:model", None, "gemma4:e4b"),
        ((), DEFAULT_MODEL, None, None),
        ((DEFAULT_MODEL, "gemma4:e4b"), DEFAULT_MODEL, "gemma4:e4b", "gemma4:e4b"),
        ((DEFAULT_MODEL,), None, "not-installed", DEFAULT_MODEL),
    ],
)
def test_selection_priority_uses_only_discovered_models(models, saved, current, expected):
    assert readiness.choose_model(models, saved, current) == expected


def test_discovery_deduplicates_filters_nonchat_and_preserves_api_order(monkeypatch):
    names = [
        "gemma4:e4b",
        DEFAULT_MODEL,
        "embed:latest",
        "large-cloud:latest",
        "remote:local",
        "bad:local",
    ]
    seen = []

    def handler(request):
        if request.url.path == "/api/tags":
            assert str(request.url) == "http://127.0.0.1:11434/api/tags"
            return httpx.Response(
                200,
                json={
                    "models": [
                        *[{"name": name} for name in names],
                        {"name": DEFAULT_MODEL},
                        {"name": "  "},
                        {"name": 7},
                        {},
                        "invalid",
                    ]
                },
            )
        import json

        model = json.loads(request.content)["model"]
        seen.append(model)
        info = {**local_info(), "capabilities": ["completion"]}
        if model == "embed:latest":
            info["capabilities"] = ["embedding"]
        if model == "remote:local":
            info["remote_model"] = "remote"
        if model == "bad:local":
            return httpx.Response(500)
        return httpx.Response(200, json=info)

    mock_ollama(monkeypatch, handler)
    inventory = readiness.discover_local_models()
    assert inventory.models == ("gemma4:e4b", DEFAULT_MODEL)
    assert inventory.ollama_ready
    assert "large-cloud:latest" not in seen
    assert seen.count(DEFAULT_MODEL) == 1
    assert inventory.readiness("gemma4:e4b").selected_model_ready
    assert not inventory.readiness("not-installed").selected_model_ready


def test_tagged_remote_model_is_excluded_before_inspection(monkeypatch):
    def handler(request):
        assert request.url.path == "/api/tags"
        return httpx.Response(
            200, json={"models": [{"name": "remote:local", "remote_model": "remote"}]}
        )

    mock_ollama(monkeypatch, handler)
    inventory = readiness.discover_local_models()
    assert inventory.ollama_ready and inventory.models == ()
