# SpecterLAN behavior reference

[Setup and demo guide](../README.md)

## Windows launch and first run

`setup_windows.ps1` creates/reuses the checkout's `.venv` and installs runtime
dependencies with that environment's Python. `-Dev` also installs test/lint tools;
`-Python` selects the bootstrap interpreter when creating `.venv`. Python 3.11+
is required. Setup never installs Ollama, Nmap, or model weights and never asks
for account details. Initial Python package downloads require internet access.

`run_specterlan.ps1` uses `.venv\Scripts\python.exe` directly, checks Python and
runtime imports, and launches from the script's directory so project configuration
loads regardless of the invoking directory. Missing dependencies give setup
instructions. `-Check` performs preflight without starting a server. The launcher
binds Streamlit to `127.0.0.1`, disables usage statistics, and uses headless mode
to avoid Streamlit's email onboarding. Open the printed local URL manually.

The UI's **Local setup and status** section reports:

- Local data storage: ready/problem, using an actual temporary write-and-cleanup
  check in the opened database directory. Live storage failures block Live use;
  the mode selector remains available. Demo checks only its temporary directory
  and does not resolve, migrate, or open Live storage.
- Python: unsupported versions stop with instructions to recreate the environment.
- Ollama: ready/unavailable, determined through the loopback API rather than
  requiring an `ollama` executable on PATH.
- Model: `gemma4:e4b` ready/missing. A selected override is checked independently,
  so a missing default model never disables another ready local model.
- Nmap: available/fallback mode, based on PATH discovery. No startup scan runs.

Readiness requests contain only model names, never network evidence. They use the
same loopback endpoint validation as analysis, disable environment proxies and
redirects, and use two-second HTTP timeouts. `/api/tags` lists models; `/api/show`
checks local GGUF metadata and rejects remote/unverifiable models. Results are
cached for 15 seconds per model/endpoint and rechecked on a subsequent rerun or
page refresh. No model is pulled or loaded for generation during these checks.

Unavailable Ollama or a selected model disables the analysis button while keeping
scanning/history usable. Pull instructions are shown for the default model. Model
readiness does not guarantee sufficient RAM, response time, or valid AI output;
all existing validation remains in force when analysis runs. Nmap absence keeps
the existing fallback discovery behavior. Displayed storage guidance uses the
symbolic Windows app-data path, never account names or diagnostic filesystem paths.

Executable packaging remains future work: browser assets, dependency metadata,
configuration and subprocess behavior need validation in a frozen Windows build.
This milestone distributes scripts and source, without a bundler or installer EXE.

## Local storage and privacy

SpecterLAN does not operate a backend service and does not require registration.
Each installation stores its own network history locally on the device where it
runs. Laptops on the same LAN maintain independent SQLite databases. SpecterLAN
has no accounts, login system, registration, cloud sync, remote database, or
application telemetry, and does not collect Windows account information.

The OS resolves the local application-data directory automatically, without
asking for a username, password, email, or account ID. Windows uses
`%LOCALAPPDATA%\SpecterLAN\specterlan.db`, rather than roaming app data.
SpecterLAN does not display or transmit the resolved storage path or extract an
OS account name from it. OS-managed directory separation is sufficient; there
are no SpecterLAN user profiles.

Live history, device metadata, friendly names, trust labels, classification
overrides, and the selected Ollama model preference stay in this local database.
At startup, `OLLAMA_MODEL` takes precedence over the saved model preference, then
the default applies. Sidebar selections are saved locally; model compatibility
and loopback-only Ollama checks still apply at analysis time.

On first startup without the new database, a legacy `.specterlan.db` in the
working directory is copied with SQLite's backup API, including committed WAL
data. The original remains intact. A complete copy is published without
overwriting an existing destination, then versioned schema migrations run.
Failures do not fall back to writing history in the working directory. Stop
older instances before migration; later legacy writes are not synchronized.
Demo Séance continues to use only its separate temporary database.

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
through Ollama on this computer. The selected model defaults to `gemma4:e4b`;
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

