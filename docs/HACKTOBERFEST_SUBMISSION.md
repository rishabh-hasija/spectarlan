# SpecterLAN: finding network ghosts with local evidence and local AI

## Short description

SpecterLAN is a local-first network presence monitor. It remembers devices,
shows what changed between scans, and uses a local Ollama model to explain the
observations without uploading a household network inventory to hosted AI.

## What I built

SpecterLAN is open-source software released under the [MIT License](../LICENSE).

I built a Python/Streamlit app that helps people recognize their network's devices
and understand what changed. Friendly names, device types, and personal trust
labels turn a list of addresses into a familiar inventory. Saved snapshots show
new arrivals, vanished devices, and IP changes.

**Ask the Ghost** analyzes the latest two snapshots of the selected subnet and
produces an evidence-based report with citations to recorded observations. It
suggests manual checks; it cannot execute them. Citations make the explanation
inspectable, though a model can still misinterpret the evidence.

## Open AI components and why open innovation mattered

[Ollama](https://github.com/ollama/ollama) provides the open-source local runtime.
The default is **Gemma 4 E4B** (`gemma4:e4b`), a local open-weight model designed
for edge deployment. Its [model license terms](https://ai.google.dev/gemma/docs/core/model_card_4)
are separate from SpecterLAN's MIT license.
Users can swap in compatible locally installed models.

Network inventory stays local. No hosted AI provider or cloud API key is required,
and scanning and history still work without an AI model. Initial software and
model downloads require internet access; analysis runs locally.

Open-source software and open-weight models made it possible to build an
inspectable tool that users can adapt, with control over both their evidence and
their choice of local model.

## Why this fits Ghost in the Machine

Devices appear and disappear like apparitions. Unfamiliar or forgotten gadgets
become network “ghosts” until their owner identifies them. Local AI interprets
changes between observations. Halloween language is presentation; findings remain
evidence-based. Unknown does not mean malicious.

## Demo story

**Demo Séance uses simulated evidence**, isolated from Live Network history.
Demo and Live reuse the same core processing pipeline.

1. The baseline contains a familiar router, laptop, TV, and phone.
2. The second scan introduces **ESP_32A1**, a new, unreviewed device.
3. Ask the Ghost explains the change using the two snapshots and cites its
   evidence, without treating an unfamiliar device as a threat.
4. The final scan shows the TV changing IP address while retaining its identity,
   and the phone vanishing from the latest observation.

## What I learned

I learned that IP addresses are not durable device identities. MAC-based identity
avoids false new-device events after DHCP changes; devices without a usable MAC
need a provisional subnet/IP fallback. Immutable snapshots protect historical
observations from later label edits.

I also learned that structured JSON alone does not ground AI output: citations
and device identities need validation too. Deterministic demo fixtures proved
more reliable for demonstrating changes than a changing live LAN.

## Code and demo

- [GitHub repository](https://github.com/rishabh-hasija/spectarlan)
- Demo video: [ADD VIDEO URL]
- [Simulated inventory screenshot](screenshots/demo-inventory.jpg)
- [Simulated changes screenshot](screenshots/demo-changes.jpg)

Demo Séance runs without LAN access or a login. Ask the Ghost requires a running
local Ollama and a downloaded compatible model.
