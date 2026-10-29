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

## Device identity and trust

After scanning, open **Edit a device** to set a friendly name, device type, and
trust status: `trusted`, `unreviewed` (the default), or `ignored`. Current and
recently vanished devices can be edited. Ignored devices remain visible and are
still scanned; trust is an inventory label, not an access-control decision.

A usable MAC address is the primary identity. Letter case and common separators
are normalized, so labels follow a MAC when its IP changes. Saved device types
override automatic classification. A returning MAC is known even after a gap
in scans, and vanished devices retain their current metadata.

Without a usable MAC, identity is provisional: the scanned subnet plus the IP
address. Invalid, all-zero, broadcast, and multicast MAC values also use this
fallback. Metadata does not follow an IP change, cross subnets, or automatically
transfer between IP-only and MAC identities. Two no-MAC devices reusing the same
subnet/IP cannot be distinguished; recheck such labels before trusting them.
MAC randomization can also make one physical device appear as a new identity.
Hostnames and vendors are supporting evidence, never identity keys.

Metadata is stored locally in a separate SQLite `device_metadata` table.
Startup applies versioned migrations, registering identities from existing scans
with unreviewed trust. Historical scan rows are never rewritten or deleted.
The UI overlays current metadata; editing a device does not create a scan or
change a historical snapshot. Scan comparisons use the previous scan of the
same subnet.

## Local device classification

Classification is deterministic and lives in `specterlan/classification.py`.
It uses the hostname and vendor string already supplied by discovery, plus any
saved user device-type override. It performs no port scans, service fingerprinting,
internet vendor lookups, cloud calls, or vulnerability detection.

Supported types are `router`, `computer`, `phone`, `tablet`, `tv`, `printer`,
`speaker`, `gaming_console`, `camera`, `smart_home`, `server`, and `unknown`.

- Hostname rules match naming tokens or explicit model families, ignoring case
  and common separators. DNS suffixes are ignored. For example, `iphone15`,
  `ipad`, `laserjet`, `xbox`, `smart-plug`, and `nas01` are useful evidence.
- A small vendor allowlist provides suggestions such as AVM/FritzBox for routers,
  Hisense for TVs, Sonos for speakers, and Synology/QNAP for servers/NAS devices.
  Streaming devices such as Roku and Chromecast use the `tv` category.
- Broad vendor names (Apple, Samsung, Sony, ASUS, Intel, and others) alone are
  insufficient. Likewise, Android, Pixel without a phone model number, and
  Raspberry Pi alone do not establish a device's role.
- All matching categories are considered. Agreeing matches are combined;
  conflicting categories return `unknown` with the conflicting evidence.
  Missing or weak evidence also returns `unknown`.
- A saved user device type always wins, including an explicit `unknown`.
  Friendly names and trust labels are not used to infer hardware type.

| Local evidence | Automatic suggestion | Reason |
| --- | --- | --- |
| Hostname `Alice-iPhone15`, vendor Apple | phone | Hostname contains 'iphone15' |
| Vendor Hisense | tv | Vendor matched 'hisense' |
| Hostname `PS5`, vendor Sony | gaming_console | Hostname contains 'ps5' |
| Hostname `smart-plug` | smart_home | Hostname contains 'smart plug' |
| Hostname `home-server01`, vendor Dell | server | Hostname contains 'server01' |
| Vendor Samsung only | unknown | Insufficient specific evidence |
| Hostname `iphone`, vendor Hisense | unknown | Conflicting phone and TV evidence |

The main table shows the effective type. Open **Edit a device** to see the
automatic suggestion and its explanation, even when your saved type overrides it.
New scan JSON includes `automatic_device_type` and `classification_reason`.
Displayed observations, including vanished devices, are re-evaluated from their
recorded hostname/vendor using the current rules; historical scan rows stay unchanged.

Database migration v2 expands the metadata table's allowed device types inside a
transaction, preserving identities, names, and trust labels. Legacy `iot`
overrides map to `smart_home`; old scan JSON also accepts `iot` on read without
rewriting it. Both original and Milestone 1 databases upgrade automatically.

These are suggestions, not verified hardware identities. Vendor strings may be
missing or inaccurate, vendors can sell multiple product types, and hostnames may
be misleading. MAC randomization and missing MACs retain the identity limitations
described above. Use a manual override when you know the device.

## Scan history and changes

**What changed since the last scan?** compares the latest saved scan with the
immediately preceding saved scan of the current subnet. The first scan establishes
a baseline without generating a list of change events. Empty scans are valid
comparison points.

Events are grouped as new, vanished, IP changed, classification changed, metadata
changed, and seen again. A known identity absent from the preceding scan is
**seen again**, rather than newly observed. A normalized MAC keeps its identity
when its IP changes, so that move is not shown as new plus vanished. Devices
without a usable MAC retain the provisional subnet/IP identity limitation.

Classification changes compare recorded automatic suggestions and effective
types. A reason-only change does not create an event. Friendly-name, trust, and
explicit device-type override edits are grouped as metadata changes. New snapshots
record the override in `device_type_override` inside device JSON; no SQLite schema
change or new migration is required. When older snapshots lack that field, a type
change is reported as an effective classification change without guessing whether
a user override caused it.

Each nonempty event group shows up to five devices by default. Select **Show all
changes** for the remaining events. Vanished entries show their previous scan's
timestamp as the last observed time; this is not an exact disconnect time.

Open **Recent scans (latest 10)** to inspect saved observations. The summary lists
timestamp (with timezone offset), subnet, online, new, vanished, trusted, and
unreviewed counts. Select a scan to inspect its devices and, for an older scan,
its own comparison with the preceding scan. History is ordered by saved scan ID,
so duplicate timestamps or clock changes do not reorder scans. The ten-scan limit
only limits the view; older database records are retained.

Historical views use saved device values without applying current metadata or
rerunning classification. The editable network-presence view still uses current
metadata. Edits do not create or rewrite scans: they appear in history and change
comparisons after the next scan captures them. Older snapshots may lack labels,
trust, or automatic-classification details; defaults are shown and missing details
are not treated as evidence of a change. Legacy `iot` values retain the existing
read-time mapping to `smart_home`.

The scan table stores online devices, so historical vanished lists are derived
from the preceding scan. Labels on those entries come from that previous snapshot.
No complete audit trail of edits between scans is recorded.

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
