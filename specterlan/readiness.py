"""Small, evidence-free checks for local startup prerequisites."""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import httpx

from .ai import AIAnalysisError, _local_url

DEFAULT_MODEL = "gemma4:e4b"


@dataclass(frozen=True)
class AIReadiness:
    ollama_ready: bool
    default_model_ready: bool
    selected_model_ready: bool
    message: str = ""


def supported_python(version: tuple[int, ...] | None = None) -> bool:
    return (version if version is not None else sys.version_info) >= (3, 11)


def writable_storage(database: str | Path) -> bool:
    """Test actual directory writes and cleanup; do not rely on permission bits."""
    try:
        with NamedTemporaryFile(dir=Path(database).parent, prefix="readiness-", suffix=".tmp"):
            pass
    except OSError:
        return False
    return True


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def check_local_ai(model: str, url: str = "http://localhost:11434") -> AIReadiness:
    """Read local model metadata only; never pull, generate, or send inventory."""
    try:
        base_url = _local_url(url)
    except AIAnalysisError:
        return AIReadiness(False, False, False, "Set OLLAMA_URL to a loopback Ollama endpoint.")
    try:
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=2.0) as client:
            response = client.get(f"{base_url}/api/tags")
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("models"), list):
                return AIReadiness(
                    False,
                    False,
                    False,
                    "Local Ollama returned an invalid model list. Restart Ollama and refresh.",
                )
            installed = {
                name
                for entry in body["models"]
                if isinstance(entry, dict)
                for name in (entry.get("name"), entry.get("model"))
                if isinstance(name, str)
            }

            def local_model_ready(name: str) -> bool:
                if not name or "cloud" in name.casefold():
                    return False
                tag = name if ":" in name else f"{name}:latest"
                if name not in installed and tag not in installed:
                    return False
                try:
                    details = client.post(f"{base_url}/api/show", json={"model": name})
                    details.raise_for_status()
                    info = details.json()
                    return (
                        isinstance(info, dict)
                        and not info.get("remote_model")
                        and not info.get("remote_host")
                        and isinstance(info.get("details"), dict)
                        and info["details"].get("format") == "gguf"
                        and isinstance(info.get("model_info"), dict)
                        and bool(info["model_info"])
                    )
                except (httpx.HTTPError, ValueError):
                    return False

            default_ready = local_model_ready(DEFAULT_MODEL)
            selected_ready = (
                default_ready
                if model.strip() == DEFAULT_MODEL
                else local_model_ready(model.strip())
            )
            return AIReadiness(True, default_ready, selected_ready)
    except (httpx.HTTPError, ValueError):
        return AIReadiness(
            False,
            False,
            False,
            "Start Ollama on this computer, then refresh this page. Scanning works without it.",
        )
