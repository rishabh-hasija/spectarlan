from __future__ import annotations

import json
import os

import httpx

from .models import AIReport, ScanResult


SYSTEM_PROMPT = """
You are SpecterLAN, a local network presence analyst.

Use only the supplied scan evidence.
Never claim a device is malicious, compromised, an intruder, or unsafe from host-presence data alone.
Clearly separate observations from guesses.
Treat "new" as newly observed by SpecterLAN, not newly connected to the network.
Treat "vanished" as absent from the latest scan, not deleted or compromised.
Keep explanations short and useful.
Return only data matching the requested JSON schema.
""".strip()


def analyze_scan(
    result: ScanResult,
    model: str | None = None,
    ollama_url: str | None = None,
    timeout_seconds: float = 180.0,
) -> AIReport:
    model = model or os.getenv("OLLAMA_MODEL", "gemma3:4b")
    base_url = (ollama_url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")

    evidence = {
        "network": result.network,
        "scanner": result.scanner,
        "online_devices": [device.model_dump(mode="json") for device in result.devices],
        "vanished_devices": [device.model_dump(mode="json") for device in result.vanished],
    }

    schema = AIReport.model_json_schema()
    prompt = (
        "Analyze this home/local-network presence snapshot. "
        "Focus on what changed, what is unidentified, and what the user should verify manually.\\n\\n"
        f"EVIDENCE:\\n{json.dumps(evidence, indent=2)}\\n\\n"
        f"JSON SCHEMA:\\n{json.dumps(schema)}"
    )

    payload = {
        "model": model,
        "stream": False,
        "format": schema,
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    }

    try:
        response = httpx.post(
            f"{base_url}/api/chat",
            json=payload,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Ollama request failed: {exc}") from exc

    content = response.json()["message"]["content"]
    return AIReport.model_validate_json(content)
