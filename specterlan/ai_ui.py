from __future__ import annotations

import sqlite3

import streamlit as st

from .ai import AIAnalysisError, Analysis, analyze_latest
from .store import SnapshotStore
from .ui import show_ui_error


def render_ai(store: SnapshotStore, network: str, model: str, key_prefix: str = "live") -> None:
    st.subheader("Ask the Ghost")
    st.caption(f"Local-only · open-source AI · no cloud AI · Selected model: {model}")
    st.caption(
        "Explains the latest two saved scans of this subnet. "
        "Run another scan after editing labels to include those edits."
    )
    try:
        current, previous = store.latest_scan_pair(network)
    except (sqlite3.Error, ValueError):
        show_ui_error("Could not load evidence for analysis. Check local history access and refresh.")
        return
    if current is None:
        st.info("Run a scan of this subnet before asking the Ghost.")
        return

    pair = (current.id, previous.id if previous else None)
    cached = st.session_state.get("ai_report")
    if (
        not isinstance(cached, Analysis)
        or (cached.current_scan_id, cached.previous_scan_id) != pair
    ):
        st.session_state.ai_report = None

    if st.button(
        "Analyze with Ollama",
        use_container_width=True,
        key=None if key_prefix == "live" else f"analyze:{key_prefix}",
    ):
        st.session_state.ai_report = None
        with st.spinner(f"Asking local {model} to explain the saved evidence..."):
            try:
                st.session_state.ai_report = analyze_latest(store, network, model=model)
            except AIAnalysisError as exc:
                st.error(str(exc))
            except (sqlite3.Error, ValueError):
                show_ui_error("Analysis could not load saved evidence. Check local history and retry.")

    analysis = st.session_state.ai_report
    if analysis is None:
        st.caption(
            "Optional: ask your local model to explain the saved evidence. Scanning works without Ollama."
        )
        return
    st.caption(
        f"Model used: {analysis.model} | latest saved scan #{analysis.current_scan_id} | "
        f"previous scan: {analysis.previous_scan_id if analysis.previous_scan_id is not None else 'none'}. "
        "Local model interpretation; review the cited observations."
    )
    report = analysis.report
    with st.container(border=True):
        st.caption("OVERVIEW")
        st.text(report.overview)
    st.markdown(f"**Notable changes ({len(report.notable_changes)})**")
    if report.notable_changes:
        for item in report.notable_changes:
            with st.expander(f"{item.title} | {item.confidence} confidence"):
                st.text(item.explanation)
                st.json({ref: analysis.evidence["facts"][ref] for ref in item.evidence})
    else:
        st.caption("No notable changes in this report.")
    st.markdown(f"**Devices to verify ({len(report.devices_to_verify)})**")
    if report.devices_to_verify:
        for device in report.devices_to_verify:
            with st.expander(f"{device.identity} | {device.confidence} confidence"):
                st.text(device.reason)
                st.json({ref: analysis.evidence["facts"][ref] for ref in device.evidence})
    else:
        st.info("No devices needing verification in this report.")
    st.markdown(f"**Suggested checks ({len(report.suggested_checks)})**")
    if report.suggested_checks:
        for check in report.suggested_checks:
            st.text(check.check)
            st.caption("Evidence: " + ", ".join(check.evidence))
    else:
        st.caption("No additional checks suggested.")
    with st.expander("Evidence used"):
        for item in report.evidence_summary:
            st.text(item.summary)
            st.caption("Evidence: " + ", ".join(item.evidence))
        st.json(analysis.evidence)
