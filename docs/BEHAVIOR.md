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
- Models: distinguishes an unavailable Ollama server, an available server with
  no installed models, an installed default `gemma3:4b`, a missing default with
  other installed models, and a ready selected local model.
- Nmap: available/fallback mode, based on PATH discovery. No startup scan runs.

Readiness requests contain only model names, never network evidence. They use the
same loopback endpoint validation as analysis, disable environment proxies and
redirects, and use two-second HTTP timeouts. `/api/tags` lists models; `/api/show`
checks local GGUF metadata and rejects remote/unverifiable models. Embedding-only
models are excluded when reported capabilities do not include completion. Older
local GGUF models without capabilities metadata retain the existing compatibility
checks. Results are cached for 15 seconds per endpoint and rechecked on a subsequent rerun or
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

## Presentation and local AI failures

The main screen uses a native Streamlit title, four summary cards (Devices online,
New devices, Need review, Offline since last scan), and a compact device table.
Friendly names fall back to a hostname or "Unknown device". New, Known, Offline,
and Returned are display labels; underlying snapshot states and trust values are
unchanged. Returned is derived from saved comparisons, not written into history.
Demo Séance uses the same presentation with its unchanged simulated fixtures.

The sidebar keeps mode, model selection, and the local-data privacy message.
Local IP, subnet, discovery method, Nmap details, MAC addresses, hostnames, vendors,
and classification reasons remain available in collapsed **Technical details**.
Saved observations and AI citations remain inspectable in history and **Evidence
used**. Local setup stays collapsed unless storage has a problem.

Ask the Ghost appears below scanning and history. Failures show "Ask the Ghost
couldn't get a response from the local AI." and an Ollama/model check suggestion.
HTTP codes and validation diagnostics appear only in collapsed Technical details
and the local server console. Scan history and scanning remain independent.

An HTTP 500 alone does not establish a request/schema incompatibility. The
investigated Ollama server log recorded model-loading failure while allocating
a CUDA host-memory buffer. Direct `gemma4:e4b` simple chat succeeded, and the
unchanged full structured request with simulated Demo evidence also succeeded
and passed evidence validation using the normal 180-second timeout. A shorter
90-second diagnostic request timed out. The investigation did not change the
request, prompt, schema, inference options, or timeout default. The application
now defaults to `gemma3:4b` for broader local hardware compatibility;
`gemma4:e4b` remains available as an explicit local override.

If this recurs, check Ollama's local server log for model-loading errors and
available memory. Freeing memory or explicitly choosing a smaller compatible local
model may help; SpecterLAN never silently switches models or uses cloud AI.
Successful metadata readiness does not guarantee that a model can load or respond
within the timeout.

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
The sidebar uses **Local AI model**, a selectbox with only suitable models returned
by Ollama. Its default endpoint is `http://127.0.0.1:11434/api/tags`; configured
Ollama endpoints must still pass the existing loopback-only validation. No arbitrary
model names, cloud models, or remote URLs can be added through the UI.

Selection priority is a still-valid current choice, a valid saved choice,
`gemma3:4b` when available, then the first suitable installed model in API order.
Only explicit selections become user preferences; an automatic fallback does
not override the default when it later becomes available.
An unavailable saved model is never inserted into the dropdown. Missing or unsuitable
preferences are cleared after successful discovery; an unavailable server does
not discard a saved choice. If no suitable models are available, the dropdown and
Ask the Ghost are disabled, while scanning and history remain usable.

When the default is absent, the sidebar says "Default model gemma3:4b is not
installed." and "Run: ollama pull gemma3:4b". When Ollama is unavailable it says
"Ollama is not running. Network scanning still works." Model downloads remain
explicit user actions. A live selection is rechecked against a fresh local listing
before it is written to the existing preferences table. Demo choices are session-only
and never access Live preferences. No database schema changes are required.

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
through Ollama on this computer. The selected model defaults to `gemma3:4b` for
broader local hardware compatibility. The dropdown can select `gemma4:e4b` or
another suitable installed local Ollama model and preserves valid saved choices.
`OLLAMA_MODEL` still configures direct Python API calls; it cannot inject a model
name into the UI. All inference remains local. The report shows the model
actually returned by Ollama and the IDs of the two analyzed scans.

Only the latest saved scan and immediately preceding saved scan of the current
subnet are used. No older device history is included. Stored first-observation
state can identify a new device even on the first scan; without a previous scan,
there is no evidence for vanished, returning, IP, classification, or metadata
changes. Run another scan after editing labels to include those edits in analysis.

The payload contains a fact catalog with short, deterministic IDs for the request:
`E1`, `E2`, `E3`, and so on. Allocation follows current scan/device order,
previous scan/device order, then deterministic change order. Identical supplied
snapshots produce the same mapping. These are request-local citations, not durable
device identities; MAC-based identity and stored snapshots are unchanged.
Scan/device facts retain their current/previous role, and change facts link to
their before/after device facts using those same IDs.
The model receives a flat `AVAILABLE EVIDENCE` list, with exactly one
`E#: observation` line per fact. It does not need to navigate nested JSON to find
an ID. Request-local Device A/Device B labels follow recorded identity across the
two snapshots. Provisional address-based identities remain explicitly provisional.
Recorded trust, effective/automatic type, override, hostname and vendor are shown
when available; absent legacy fields remain "not recorded". Raw MAC strings and
internal identity keys are not needed in the model prompt. The full saved-fact
catalog remains available locally for validation and the Evidence used view.

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
| `overview` | Short interpretation supported by the structured sections; inline citations optional |
| `notable_changes` | Title, explanation, evidence IDs, confidence |
| `devices_to_verify` | Reason, evidence IDs for one device, confidence; display identity resolved locally |
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
The prompt prominently lists `AVAILABLE_EVIDENCE_IDS` and instructs the model to
use only those IDs. Each citation array's item schema also enumerates the allowed
IDs. Client-side membership validation still runs independently, even if a model
returns schema-shaped JSON containing an invented or descriptive reference.

A citation error triggers at most one correction request to the same local model,
using the same snapshots, fact catalog, schema, inference options, and endpoint.
The model sees its previous response and the valid ID list, with instructions to
correct only invalid citations and omit claims it cannot support. No extra scans
or private facts are loaded. Repair is skipped if it would exceed the existing
context byte budget; evidence is never truncated to make it fit.
Correction feedback includes the exact invalid references in `INVALID_EVIDENCE_IDS`
alongside all allowed IDs. If the issue is device/prose consistency rather than
an unknown citation, that list is empty and the instruction is to omit unsupported
items. The same single retry limit applies.

An item with any unavailable citation is rejected in full, including when another
citation on that item is valid. Unsupported references are never guessed, remapped,
or removed to make the remaining references appear sufficient. If correction fails,
safe first-response items are preserved; when the first response has no safe items,
independently valid corrected items can be retained. The UI warns when items were
omitted. An overview that may depend on omitted items is replaced by a neutral
display notice, not a claim about network evidence. A plain overview is accepted
only with grounded structured support; explicit invalid prose citations are rejected.

The original wire schema remains strict, including a required nonempty evidence
summary. A separate validated display subset permits an empty summary after its
items are rejected, but must retain at least one supporting item in another section.
Safety, address, and cited-device checks still apply to displayed content. These
checks establish citation/identity consistency, not the truth of every model claim.
The model no longer generates a free-form device `identity`. A device review must
cite observations or changes identifying exactly one recorded device; the client
derives its identity from those facts. A scan-only or ambiguous review is rejected.
IP addresses and Device A/B labels in an item must belong to its cited supporting
facts. Failed identity/label, address, or safety checks reject that item rather than
raising before partial-response handling. Even a repaired report uses the neutral
overview so an unsupported earlier overview cannot survive an omitted item.

The remaining Live failure was reproduced with valid citation IDs: generated device
identity strings did not match the cited records. Previously that check raised
before repair/partial handling, and the UI misleadingly described every grounding
failure as a missing citation. Live and Demo share evidence generation; Live can
contain more unknown, unreviewed, provisional, and historical device variants than
the curated Demo. Anonymized fixtures exercise those shapes without storing real
network values in tests.

For local developer diagnostics, call `safe_diagnostics(evidence, report)` from
`specterlan.evidence`. It returns only fact/device counts, allowed IDs, change
category counts, provisional/unknown counts, and returned/invalid citation IDs.
Non-ID strings are redacted, since a mistaken citation may itself contain an IP
or hostname. Never print `evidence`, `format_evidence(evidence)`, model responses,
or raw exceptions while diagnosing real scans.
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

Missing model, connection failure, timeout, and invalid JSON/schema remain distinct
from grounding failure. If neither attempt yields enough grounded content, the UI
says "Ask the Ghost couldn't verify enough of the AI response against the saved
network evidence." and "Your scan data is unchanged. Try the analysis again."
Technical details use a static explanation without raw payload/model-output contents.
Unsupported output is not displayed and does not affect scans or history.
No model is automatically downloaded, no cloud fallback
is attempted, and the application does not execute suggested checks.

The default timeout remains 180 seconds per request; one correction attempt may
add another request's latency. The request uses a 16,384-token
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

