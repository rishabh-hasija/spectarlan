from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd
import streamlit as st

from .models import Device, ScanResult

logger = logging.getLogger(__name__)

COLUMNS = ["Device", "Status", "Type", "Trust", "IP address"]
STATUS_LABELS = {"new": "New", "known": "Known", "vanished": "Offline", "returned": "Returned"}
TRUST_LABELS = {"trusted": "Trusted", "unreviewed": "Need review", "ignored": "Ignored"}
STATE_STYLES = {
    "Trusted": "color: #99d8b6; background-color: #18302a;",
    "Need review": "color: #f4c07c; background-color: #34291d;",
    "Ignored": "color: #b3bdcd; background-color: #242b36;",
    "New": "color: #d5b8fa; background-color: #2b2338;",
    "Known": "color: #bbc8dd; background-color: #202b3b;",
    "Returned": "color: #99d8b6; background-color: #18302a;",
    "Offline": "color: #e8acac; background-color: #35262b;",
}


def apply_style() -> None:
    css = Path(__file__).with_name("style.css").read_text(encoding="utf-8")
    st.html(f"<style>{css}</style>")


def render_overview(
    mode: str, network: str, result: ScanResult | None, status: str | None = None
) -> None:
    context = st.columns([1, 2])
    context[0].markdown(
        "**Demo Séance · simulated**" if mode == "Demo Séance" else "**Live Network**"
    )
    if status:
        context[1].markdown(f"**{status}**")
    elif result is None:
        context[1].markdown("**Ready to scan**")
    else:
        context[1].caption(f"Last scanned: {result.scanned_at.strftime('%H:%M:%S')}")

    cards = st.columns(4)
    devices = result.devices if result is not None else []
    values = [
        ("Devices online", len(devices)),
        ("New devices", sum(device.state == "new" for device in devices)),
        ("Need review", sum(device.trust_status == "unreviewed" for device in devices)),
        ("Offline since last scan", len(result.vanished) if result is not None else 0),
    ]
    for card, (label, value) in zip(cards, values, strict=True):
        card.metric(label, value if result is not None else "—")
    st.caption("New devices are newly seen on this network. Unknown does not mean malicious.")


def device_name(device: Device) -> str:
    return device.friendly_name.strip() or (device.hostname or "").strip() or "Unknown device"


def device_rows(
    devices: list[Device], returned_ips: set[str] | None = None
) -> list[dict[str, str]]:
    return [
        {
            "Device": device_name(device),
            "Status": "Returned"
            if device.ip in (returned_ips or set())
            else STATUS_LABELS[device.state],
            "Type": "TV"
            if device.device_type == "tv"
            else device.device_type.replace("_", " ").capitalize(),
            "Trust": TRUST_LABELS[device.trust_status],
            "IP address": device.ip,
        }
        for device in devices
    ]


def render_technical_devices(devices: list[Device]) -> None:
    for device in devices:
        st.text(device_name(device))
        st.json(
            {
                "IP address": device.ip,
                "MAC address": device.mac,
                "Hostname": device.hostname,
                "Vendor": device.vendor,
                "Automatic type": device.automatic_device_type,
                "Automatic classification reason": device.classification_reason,
                "Classification override": device.device_type_override,
            },
            expanded=False,
        )


def render_device_table(devices: list[Device], returned_ips: set[str] | None = None) -> None:
    rows = device_rows(devices, returned_ips)
    frame = pd.DataFrame(rows, columns=COLUMNS)
    styled = frame.style.apply(
        lambda column: [STATE_STYLES.get(value, "") for value in column],
        subset=["Status", "Trust"],
    )
    st.dataframe(
        styled,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Device": st.column_config.TextColumn("Device", width=180),
            "Status": st.column_config.TextColumn(
                "Status", width=100, help="New, known, offline, or returned."
            ),
            "Trust": st.column_config.TextColumn(
                "Trust", width=110, help="Your inventory label, not an access-control decision."
            ),
            "IP address": st.column_config.TextColumn("IP address", width=140),
            "Type": st.column_config.TextColumn("Type", width=130),
        },
        height=min(380, max(120, 38 + len(rows) * 35)),
    )


def render_footer() -> None:
    st.divider()
    with st.expander("How SpecterLAN works"):
        st.markdown("**Local Network → Discovery → SQLite → Change Detection → Ollama**")
        st.caption(
            "Discovery observes host presence on your private subnet. SQLite keeps local "
            "snapshots and your device labels. Deterministic comparisons explain what changed. "
            "Optional local Ollama interprets only the latest two snapshots. "
            "Demo Séance replaces discovery with isolated, fixed simulated observations."
        )
    st.caption("SpecterLAN · local-first · open-source AI · no cloud AI")


def show_ui_error(message: str) -> None:
    """Keep diagnostic tracebacks in the server log, never in a user-facing alert."""
    logger.exception(message)
    st.error(message)
