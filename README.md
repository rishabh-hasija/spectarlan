# SpecterLAN 👻

**Find the ghosts on your network.**

SpecterLAN is a local-first network presence monitor built for the Hacktoberfest
"Ghost in the Machine" challenge. It discovers devices on the private subnet
containing your computer, remembers previous scans, and uses a local Ollama model
to explain what changed.

## What the MVP does

- Detects the current private IPv4 subnet.
- Caps discovery to 256 addresses and refuses public targets.
- Uses `nmap -sn` when Nmap is installed.
- Falls back to ping + the local neighbor/ARP table.
- Tracks devices as:
  - `new`: first observed by SpecterLAN
  - `known`: observed in a prior scan
  - `vanished`: present previously, absent now
- Uses basic local evidence to classify common device types.
- Sends the scan evidence only to local Ollama.
- Uses structured JSON output for reliable AI reports.
- Avoids claiming that an unknown device is malicious without evidence.

## Why open innovation matters

Network inventory data is sensitive. A home-network map can reveal device names,
hardware vendors, addresses, and household technology.

SpecterLAN keeps analysis on the user's machine. Ollama provides the local model
runtime, and the model is replaceable. The user can inspect the prompts, change
models, or run the project without sending the network inventory to a hosted AI
provider.

That local model layer is not decoration. It interprets device evidence, explains
changes between scans, and asks the user what should be verified next.

## Quick start

### 1. Create an environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### 2. Make sure Ollama is running

The default model is:

```text
gemma3:4b
```

Override it with:

```powershell
$env:OLLAMA_MODEL="qwen3.5:9b"
```

### 3. Optional but recommended: install Nmap

If `nmap` is available on PATH, SpecterLAN uses:

```text
nmap -sn
```

This performs host discovery without a port scan.

Without Nmap, the MVP falls back to ping plus the operating system's neighbor table.

### 4. Run

```powershell
streamlit run app.py
```

### 5. Test

```powershell
pytest -q
ruff check .
```

## Demo flow

1. Open SpecterLAN.
2. Run the first scan.
3. Show discovered devices.
4. Turn on or connect another device.
5. Scan again.
6. Show `New apparitions: 1`.
7. Run `Analyze with Ollama`.
8. Show that the local model describes the new device only from available evidence.
9. End on the message: **Network evidence stays local.**

## 3-day build plan

### Day 1
- Make network discovery reliable on Windows.
- Validate Nmap and fallback modes.
- Validate SQLite change tracking.
- Confirm Ollama structured output.

### Day 2
- Improve device classification.
- Add device naming/trust labels.
- Improve UI and Halloween visual treatment.
- Add scan history.

### Day 3
- Tests and error handling.
- README screenshots and architecture diagram.
- Sample/demo mode for predictable judging.
- Record a demo under 60 seconds.
- Prepare the Hacktoberfest submission post.

## Guardrails

SpecterLAN is a presence monitor for networks you own or administer.

The MVP intentionally:
- restricts targets to the private subnet containing the current machine,
- limits scans to at most 256 addresses,
- performs no vulnerability exploitation,
- performs no credential testing,
- performs no automatic attack or remediation actions,
- does not label a device malicious based only on being unknown.
