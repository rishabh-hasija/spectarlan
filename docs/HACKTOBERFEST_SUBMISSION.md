# SpecterLAN: finding network ghosts with local evidence and local AI

**Submission draft — not published.** Adapt to the official template before posting.

## Short description

SpecterLAN is a local-first network presence monitor. It remembers devices,
shows what changed between scans, and uses a local Ollama model to explain the
observations without uploading a household network inventory to hosted AI.

## What I built

SpecterLAN is open-source software released under the [MIT License](../LICENSE).

A small Python/Streamlit application with MAC-based identity, friendly names,
user-managed types and trust labels, explainable classification, immutable SQLite
snapshots, and subnet-specific change detection. Ask the Ghost turns the latest
two snapshots into an evidence-cited report. It cannot execute commands or checks.

Demo Séance makes the story reproducible without discovery: four known devices,
then a new unreviewed ESP-style device, then a TV IP change and vanished phone.
Demo and Live share the processing pipeline but use separate databases. The ESP's
smart_home type is curated user metadata, not a claimed automatic inference.

## Open AI components and why open innovation mattered

[Ollama](https://github.com/ollama/ollama) provides the open-source local runtime.
The default is the open-weight **Gemma 3 4B**, selected as `gemma3:4b`; its
[model terms](https://ai.google.dev/gemma/terms) are separate from the app's license.
Compatible installed local models are replaceable through configuration.

Network inventories expose private names, addresses, and hardware. Local inference
keeps this evidence on the user's machine, requires no hosted AI provider/API key,
and leaves prompts, evidence, and validation available for inspection. Users can
keep scanning and inspecting history without a model or API subscription.
Downloads require internet initially; the app does not make cloud AI calls.

## Ghost in the Machine

Devices appear, disappear, and return like apparitions. Forgotten gadgets become
“ghosts” until identified. The local model interprets these changes, but Halloween
language never turns discovery evidence into a threat verdict. New means newly
observed; vanished means absent from a scan. Unknown does not mean malicious.

## Code and demo

- [GitHub repository](https://github.com/rishabh-hasija/spectarlan)
- **Video: [ADD RECORDED DEMO URL BEFORE SUBMISSION]**
- [60-second walkthrough](../README.md#60-second-demo-sequence)
- [Simulated inventory screenshot](screenshots/demo-inventory.jpg)
- [Simulated changes screenshot](screenshots/demo-changes.jpg)

Judges can clone, install, and select Demo Séance without LAN access. Ask the
Ghost needs a running local Ollama and downloaded model. No login is required.

## Lessons learned

An address is not a durable identity: retaining a MAC prevents an IP move from
looking like two devices. Missing MACs require an explicitly provisional fallback.
Snapshot immutability keeps past observations separate from current user labels.
Structured JSON is only the beginning of grounding: citations and identities must
also be validated, and a model can still misinterpret a valid fact. Repeatable
fixtures make those boundaries easier to demonstrate than a changing live LAN.

## Before adapting this draft

- Record and link a real local-model demo; do not present mocked test output as inference.
- Add your own observed results, hardware/model details, and personal lessons.
- Review the official submission template and required `hf26challenge` tag.
- Disclose coding/writing AI assistance accurately and credit any collaborators.
- Verify the challenge window and eligibility; the event API's end timestamp and
  prose deadline disagree as checked on October 29, 2026. Confirm on the official
  page/with organizers, and use the earlier cutoff until resolved.

Reference: [Week 4 challenge](https://dev.to/events/challenges/hacktoberfest-week4-2026-10-26).
