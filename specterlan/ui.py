from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd
import streamlit as st

from .models import Device, ScanResult

logger = logging.getLogger(__name__)

COLUMNS = [
    "Friendly name",
    "State",
    "IP",
    "Hostname",
    "MAC",
    "Vendor",
    "Device type",
    "Trust status",
]
DISPLAY_ORDER = [
    "Friendly name",
    "State",
    "IP",
    "Device type",
    "Trust status",
    "Hostname",
    "MAC",
    "Vendor",
]
STATE_STYLES = {
    "trusted": "color: #99d8b6; background-color: #18302a;",
    "unreviewed": "color: #f4c07c; background-color: #34291d;",
    "ignored": "color: #b3bdcd; background-color: #242b36;",
    "new": "color: #d5b8fa; background-color: #2b2338;",
    "known": "color: #bbc8dd; background-color: #202b3b;",
    "vanished": "color: #e8acac; background-color: #35262b;",
}


def apply_style() -> None:
    css = Path(__file__).with_name("style.css").read_text(encoding="utf-8")
    st.html(f"<style>{css}</style>")


def render_overview(
    mode: str, network: str, result: ScanResult | None, status: str | None = None
) -> None:
    context = st.columns([1, 1, 1.5])
    context[0].caption("CURRENT MODE")
    context[0].markdown(
        "**Demo Séance · simulated**" if mode == "Demo Séance" else "**Live Network**"
    )
    context[1].caption("PRIVATE SUBNET")
    context[1].markdown(f"**{network}**")
    context[2].caption("SCAN STATUS")
    if status:
        context[2].markdown(f"**{status}**")
    elif result is None:
        context[2].markdown("**Ready · no scan this session**")
    else:
        context[2].markdown("**Snapshot saved**")
        context[2].caption(f"{result.scanned_at.isoformat(timespec='seconds')} · {result.scanner}")

    cards = st.columns(4)
    devices = result.devices if result is not None else []
    values = [
        ("Online", len(devices)),
        ("New apparitions", sum(device.state == "new" for device in devices)),
        ("Unreviewed", sum(device.trust_status == "unreviewed" for device in devices)),
        ("Vanished", len(result.vanished) if result is not None else 0),
    ]
    for card, (label, value) in zip(cards, values, strict=True):
        card.metric(label, value if result is not None else "—")
    if result is not None:
        st.caption(
            f"Trusted {sum(device.trust_status == 'trusted' for device in devices)} · "
            f"Known {sum(device.state == 'known' for device in devices)} · "
            f"Ignored {sum(device.trust_status == 'ignored' for device in devices)} · "
            f"Unidentified {sum(device.device_type == 'unknown' for device in devices)}"
        )


def render_device_table(devices: list[Device]) -> None:
    rows = [
        {
            "Friendly name": device.friendly_name,
            "State": device.state,
            "IP": device.ip,
            "Hostname": device.hostname or "",
            "MAC": device.mac or "",
            "Vendor": device.vendor or "",
            "Device type": device.device_type,
            "Trust status": device.trust_status,
        }
        for device in devices
    ]
    frame = pd.DataFrame(rows, columns=COLUMNS)
    styled = frame.style.apply(
        lambda column: [STATE_STYLES.get(value, "") for value in column],
        subset=["State", "Trust status"],
    )
    st.dataframe(
        styled,
        hide_index=True,
        use_container_width=True,
        column_order=DISPLAY_ORDER,
        column_config={
            "Friendly name": st.column_config.TextColumn("Friendly name", width=160),
            "State": st.column_config.TextColumn(
                "Presence", width=90, help="Newly observed, known, or absent."
            ),
            "Trust status": st.column_config.TextColumn(
                "Trust", width=110, help="Your inventory label, not an access-control decision."
            ),
            "IP": st.column_config.TextColumn("IP address", width=140),
            "Device type": st.column_config.TextColumn("Type", width=130),
            "Hostname": st.column_config.TextColumn("Hostname", width=180),
            "MAC": st.column_config.TextColumn("MAC address", width=180),
            "Vendor": st.column_config.TextColumn("Vendor hint", width="medium"),
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
