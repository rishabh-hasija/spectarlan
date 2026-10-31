"""Small, evidence-free checks for local startup prerequisites."""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import httpx

from .ai import AIAnalysisError, _local_url

DEFAULT_MODEL = "gemma3:4b"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"


@dataclass(frozen=True)
class AIReadiness:
    ollama_ready: bool
    default_model_ready: bool
    selected_model_ready: bool
    message: str = ""


@dataclass(frozen=True)
class ModelInventory:
    ollama_ready: bool
    installed_models: tuple[str, ...] = ()
    models: tuple[str, ...] = ()
    message: str = ""

    def readiness(self, model: str | None) -> AIReadiness:
        selected = model if model in self.models else f"{model}:latest" if model else None
        return AIReadiness(
            self.ollama_ready,
            DEFAULT_MODEL in self.models,
            selected in self.models,
            self.message,
        )


def choose_model(
    models: tuple[str, ...], saved: str | None = None, current: str | None = None
) -> str | None:
    """Return only an API-discovered suitable model, never invent a selectable name."""
    for candidate in (current, saved, DEFAULT_MODEL):
        if candidate in models:
            return candidate
    return models[0] if models else None


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


def discover_local_models(url: str = DEFAULT_OLLAMA_URL) -> ModelInventory:
    """Read local model metadata only; never pull, generate, or send inventory."""
    try:
        base_url = _local_url(url)
    except AIAnalysisError:
        return ModelInventory(False, message="Set OLLAMA_URL to a loopback Ollama endpoint.")
    try:
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=2.0) as client:
            response = client.get(f"{base_url}/api/tags")
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get("models"), list):
                return ModelInventory(
                    False,
                    message="Local Ollama returned an invalid model list. Restart Ollama and refresh.",
                )
            installed: list[str] = []
            remote_names: set[str] = set()
            for entry in body["models"]:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name") or entry.get("model")
                if (
                    isinstance(name, str)
                    and name
                    and name == name.strip()
                    and name not in installed
                ):
                    installed.append(name)
                if isinstance(name, str) and (
                    entry.get("remote_model") or entry.get("remote_host")
                ):
                    remote_names.add(name)

            def local_model_ready(name: str) -> bool:
                if not name or "cloud" in name.casefold() or name in remote_names:
                    return False
                if name not in installed:
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
                        and (
                            "capabilities" not in info
                            or isinstance(info["capabilities"], list)
                            and "completion" in info["capabilities"]
                        )
                    )
                except (httpx.HTTPError, ValueError):
                    return False

            suitable = tuple(name for name in installed if local_model_ready(name))
            return ModelInventory(True, tuple(installed), suitable)
    except (httpx.HTTPError, ValueError):
        return ModelInventory(
            False,
            message="Ollama is not running. Network scanning still works.",
        )


def check_local_ai(model: str, url: str = DEFAULT_OLLAMA_URL) -> AIReadiness:
    return discover_local_models(url).readiness(model.strip())
