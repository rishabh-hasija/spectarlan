from __future__ import annotations

import sqlite3
from collections import Counter

import streamlit as st

from .changes import compare_scans
from .models import SavedScan
from .store import SnapshotStore
from .ui import device_name, render_device_table, render_technical_devices, show_ui_error

CHANGE_LABELS = (
    ("new", "New devices"),
    ("vanished", "Offline since last scan"),
    ("ip_changed", "Address updated"),
    ("classification_changed", "Device type updated"),
    ("metadata_changed", "Device details updated"),
    ("returned", "Returned"),
)


def _show_changes(current: SavedScan, previous: SavedScan | None, key_prefix: str) -> None:
    if previous is None:
        st.info("First scan complete. SpecterLAN will show changes after your next scan.")
        return
    changes = compare_scans(current, previous)
    if not changes:
        st.info("No important changes since your last scan.")
        return
    counts = Counter(change.kind for change in changes)
    st.caption(
        " · ".join(
            f"{label.lower()}: {counts[kind]}" for kind, label in CHANGE_LABELS if counts[kind]
        )
    )
    show_all = False
    if any(count > 5 for count in counts.values()):
        show_all = st.checkbox(
            "Show all changes",
            key=f"changes_all:{current.id}"
            if key_prefix == "live"
            else f"changes_all:{key_prefix}:{current.id}",
        )
    for kind, label in CHANGE_LABELS:
        group = [change for change in changes if change.kind == kind]
        if not group:
            continue
        st.markdown(f"**{label} ({len(group)})**")
        visible = group if show_all else group[:5]
        for change in visible:
            device = change.device
            name = device_name(device)
            with st.container(border=True):
                descriptions = {
                    "new": "Newly seen on this network.",
                    "vanished": "Not seen in the latest scan; it may be asleep or unavailable.",
                    "returned": "Back online after being absent from the previous scan.",
                    "ip_changed": "The same device has a different IP address.",
                    "classification_changed": "The suggested device type changed.",
                    "metadata_changed": "Saved device details changed.",
                }
                st.text(f"{name}\n{descriptions[kind]}")
                with st.expander("Technical details"):
                    st.text("\n".join(change.details))
        if len(group) > 5 and not show_all:
            st.caption(f"Showing 5 of {len(group)}. Select Show all changes to see the rest.")


def _summary(scan: SavedScan) -> dict[str, object]:
    states = Counter(device.trust_status for device in scan.devices)
    return {
        "Scan": scan.id,
        "Timestamp": scan.scanned_at.isoformat(timespec="seconds"),
        "Subnet": scan.network,
        "Online": len(scan.devices),
        "New": sum(device.state == "new" for device in scan.devices),
        "Offline since last scan": len(scan.vanished),
        "Trusted": states["trusted"],
        "Need review": states["unreviewed"],
    }


def render_history(store: SnapshotStore, network: str, key_prefix: str = "live") -> None:
    """Show saved observations separately from the editable, live metadata view."""
    st.subheader("What changed since the last scan?")
    try:
        scans = store.recent_scans(network)
        previous = store.previous_scan(scans[0]) if scans else None
    except (sqlite3.Error, ValueError):
        show_ui_error("Scan history could not load. Check local database access, then refresh.")
        return
    if not scans:
        st.info("No scan yet. Scan your network to see which devices are currently connected.")
        return

    st.caption("Device edits appear in comparisons after your next scan.")
    _show_changes(scans[0], previous, key_prefix)

    with st.expander("Recent scans (latest 10)"):
        st.dataframe([_summary(scan) for scan in scans], hide_index=True, use_container_width=True)
        by_id = {scan.id: scan for scan in scans}
        selected_id = st.selectbox(
            "Inspect scan",
            options=list(by_id),
            key=None if key_prefix == "live" else f"history_selection:{key_prefix}",
            format_func=lambda scan_id: (
                f"#{scan_id} | {by_id[scan_id].scanned_at.isoformat(timespec='seconds')}"
            ),
        )
        selected = by_id[selected_id]
        st.caption(
            f"Saved scan #{selected.id} | {selected.network} | {selected.scanner}. "
            "Values below are from the saved snapshot, without current metadata overlays. "
            "Older scans may lack metadata or automatic classification details."
        )
        if selected.devices:
            try:
                selected_previous = store.previous_scan(selected)
            except (sqlite3.Error, ValueError):
                show_ui_error(
                    "The preceding scan could not load. Refresh or inspect another saved scan."
                )
                return
            returned_ips = {
                change.device.ip
                for change in compare_scans(selected, selected_previous)
                if change.kind == "returned"
            }
            render_device_table(selected.devices, returned_ips)
            with st.expander("Technical details"):
                render_technical_devices(selected.devices)
        else:
            st.info("This scan recorded no online devices.")
        if selected.id != scans[0].id:
            st.markdown("**Changes for selected scan**")
            try:
                selected_previous = store.previous_scan(selected)
            except (sqlite3.Error, ValueError):
                show_ui_error(
                    "The preceding scan could not load. Refresh or inspect another saved scan."
                )
                return
            _show_changes(selected, selected_previous, key_prefix)
