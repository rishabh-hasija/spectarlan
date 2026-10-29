from __future__ import annotations

import sqlite3

import streamlit as st

from .ai import AIAnalysisError, Analysis, analyze_latest
from .store import SnapshotStore


def render_ai(store: SnapshotStore, network: str, model: str, key_prefix: str = "live") -> None:
    st.subheader("Ask the Ghost")
    st.caption(
        f"Local Ollama inference on this computer; no cloud AI. Selected model: {model}. "
        "Uses only the latest saved scan and its preceding scan of this subnet. "
        "Run another scan after editing labels to include those edits."
    )
    try:
        current, previous = store.latest_scan_pair(network)
    except (sqlite3.Error, ValueError) as exc:
        st.error(f"Could not load evidence for analysis: {exc}")
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
            except (AIAnalysisError, sqlite3.Error, ValueError) as exc:
                st.error(str(exc))

    analysis = st.session_state.ai_report
    if analysis is None:
        return
    st.caption(
        f"Model used: {analysis.model} | latest saved scan #{analysis.current_scan_id} | "
        f"previous scan: {analysis.previous_scan_id if analysis.previous_scan_id is not None else 'none'}. "
        "Local model interpretation; review the cited observations."
    )
    report = analysis.report
    st.text(report.overview)
    if report.notable_changes:
        st.markdown("**Notable changes**")
        for item in report.notable_changes:
            with st.expander(f"{item.title} | {item.confidence} confidence"):
                st.text(item.explanation)
                st.json({ref: analysis.evidence["facts"][ref] for ref in item.evidence})
    if report.devices_to_verify:
        st.markdown("**Devices to verify**")
        for device in report.devices_to_verify:
            with st.expander(f"{device.identity} | {device.confidence} confidence"):
                st.text(device.reason)
                st.json({ref: analysis.evidence["facts"][ref] for ref in device.evidence})
    if report.suggested_checks:
        st.markdown("**Suggested checks**")
        for check in report.suggested_checks:
            st.text(check.check)
            st.caption("Evidence: " + ", ".join(check.evidence))
    with st.expander("Evidence used"):
        for item in report.evidence_summary:
            st.text(item.summary)
            st.caption("Evidence: " + ", ".join(item.evidence))
        st.json(analysis.evidence)
