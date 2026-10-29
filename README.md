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

## Local Ollama evidence analysis

Open **Ask the Ghost** and select **Analyze with Ollama**. Analysis runs only
through Ollama on this computer. The selected model defaults to `gemma3:4b`;
the sidebar or `OLLAMA_MODEL` can override it. The report shows the model
actually returned by Ollama and the IDs of the two analyzed scans.

Only the latest saved scan and immediately preceding saved scan of the current
subnet are used. No older device history is included. Stored first-observation
state can identify a new device even on the first scan; without a previous scan,
there is no evidence for vanished, returning, IP, classification, or metadata
changes. Run another scan after editing labels to include those edits in analysis.

The payload contains a fact catalog with stable IDs for the request:

- Current and previous scan IDs, timestamps, subnet, scanner, and online counts.
- Current and previous device observations: identity, IP, MAC visibility and
  identity basis, hostname, vendor, friendly name, trust, effective device type,
  user type override, automatic type, and classification reason where recorded.
- Deterministic new, vanished, returning, IP-change, classification-change, and
  metadata-change events, linked to the corresponding device facts.
- Missing legacy fields stay unavailable rather than being presented as observed
  defaults. Previous scans' vanished lists are not sent because they would expose
  unnecessary older observations.

The strict JSON response schema has five required sections:

| Section | Contents |
| --- | --- |
| `overview` | Short interpretation with a supplied fact-ID citation |
| `notable_changes` | Title, explanation, evidence IDs, confidence |
| `devices_to_verify` | Identity or IP, reason, evidence IDs, confidence |
| `suggested_checks` | A manual check and its supporting evidence IDs |
| `evidence_summary` | A short summary and supporting evidence IDs |

Confidence is `low`, `medium`, or `high`; it describes support for an observation,
not a security risk score. The prompt distinguishes recorded observations from
possibilities: vendor names are hints, classification is a suggestion, and trust
is a user label. New means newly observed by SpecterLAN; vanished means absent
from the latest scan. Neither establishes ownership, intent, or compromise.
Device-supplied strings are treated as untrusted data, never instructions.

Ollama receives the JSON schema through its structured-output API. The client
then validates the schema, checks fact references and cited device identities,
rejects addresses absent from evidence, and rejects prohibited security labels.
The UI displays cited facts and the submitted evidence for review. These checks
do not prove the truth of every generated sentence: a model may misinterpret a
valid citation. Treat the output as an interpretation and verify it against the
displayed observations. The conservative language filter can also reject a
response that quotes a device name containing a prohibited word.

`OLLAMA_URL` defaults to `http://localhost:11434` and must use a loopback
endpoint (`localhost`, `127.0.0.1`, or `::1`). Proxy environment settings and
redirects are disabled. Before sending scan evidence, SpecterLAN calls local
`/api/show` and requires local GGUF model metadata without remote-model fields.
Cloud-named, remote, or unverifiable models are refused. This assumes a trusted
local Ollama installation; SpecterLAN cannot attest the server's internals.
For additional server-side isolation, configure Ollama with `OLLAMA_NO_CLOUD=1`
and restart Ollama; see the [Ollama local-only FAQ](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features).

Missing model, connection failure, timeout, invalid JSON/schema, and unsupported
evidence produce a local error message. Failed output is not shown and does not
affect scans or history. No model is automatically downloaded, no cloud fallback
is attempted, and the application does not execute suggested checks.

The default request timeout is 180 seconds. The request uses a 16,384-token
context and a conservative input byte budget with output space reserved.
Oversized evidence fails clearly instead of silently dropping devices.
`OLLAMA_NUM_CTX` can increase the context if the local model and memory support
it, for example in PowerShell:

~~~powershell
$env:OLLAMA_NUM_CTX="32768"
~~~

The byte budget is a conservative safeguard, not an exact tokenizer measurement.
Large subnets or limited hardware may still require a different installed local
model, more context, or more time. Tests mock Ollama and do not require a running
model; live model quality and performance are not established by those tests.

## Deterministic Demo Seance

Choose **Demo Seance** (shown as **Demo Séance** in the UI) in the sidebar.
The banner **Demo Séance: simulated network evidence** remains visible.
Demo mode skips local interface detection and all network discovery; it can be
used without an active LAN. **Live Network** remains the default mode, with the
existing discovery commands and scan processing behavior.

Use these controls for a short judging walkthrough:

1. **Start Demo** saves scan 1: Home Router, Work Laptop, Living Room TV,
   and Alice's Phone. The curated baseline inventory is already known/trusted.
   Inspect their automatic types and open scan history to show the baseline.
2. **Next Scan** saves scan 2: the same devices plus `ESP_32A1` at
   `192.168.178.47`, vendor Espressif, with unreviewed trust and a
   `smart_home` effective device type. The change view shows one new apparition.
3. **Next Scan** saves scan 3: the TV retains its MAC while moving from
   `192.168.178.20` to `192.168.178.31`; Alice's Phone vanishes; the ESP remains
   present. The TV is an IP change, not a new device.
4. Use **Ask the Ghost** at any stage to explain the saved simulated evidence
   with your installed local Ollama model. This uses the same evidence builder,
   validation, and local-only client as live mode.
5. **Reset Demo** clears only the session's simulated history and edits, then
   returns to the initial controls. Start Demo replays identical observations,
   timestamps, metadata defaults, and scan IDs. Progress stops after scan 3.

The ESP scenario deliberately uses the normal saved `smart_home` type override.
Its automatic type stays `unknown`: ESP/Espressif alone is weak evidence under
the live classification rules. The demo does not pretend that this is a strong
automatic classification or mark the unreviewed device as trusted. Baseline
router, computer, TV, and phone types use the existing automatic rules.

Fixtures live in `specterlan/demo.py` and construct fresh observations with fixed
locally administered MAC addresses, IPs, and timestamps (October 29, 2026,
20:00-20:02 UTC). Every stage passes through the existing metadata, classification,
SQLite storage, history, comparison, and AI evidence paths. There is no parallel
demo change detector or AI implementation.

Each Streamlit session owns a separate temporary SQLite database. Demo never opens
the live `.specterlan.db`, even if the real subnet or device MACs match fixtures.
Mode-specific widget state and clearing AI reports prevent accidental mixing.
Returning to Live Network restores that mode's session result; no demo rows or
metadata enter live history. SQLite connections close after transactions for
reliable Windows temporary-file cleanup. No schema migration is added.

Demo data is session-scoped rather than durable across application restarts.
Edits made during a demo are real edits to its isolated metadata, so Reset Demo
restores the prescribed story. Only fixture scans are deterministic: Ollama's
wording and response time depend on the installed model and hardware. Ollama must
be running for Ask the Ghost; failures remain isolated from the demo and history.
Tests mock AI requests and do not require a running model. Demo does not download
models or create any cloud AI calls.

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
