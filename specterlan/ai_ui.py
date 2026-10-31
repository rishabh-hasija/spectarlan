from __future__ import annotations

import logging
import sqlite3

import streamlit as st

from .ai import AIAnalysisError, AIGroundingError, Analysis, analyze_latest
from .store import SnapshotStore
from .ui import show_ui_error

logger = logging.getLogger(__name__)


def render_ai(
    store: SnapshotStore,
    network: str,
    model: str | None,
    key_prefix: str = "live",
    *,
    available: bool = True,
) -> None:
    st.subheader("Ask the Ghost")
    st.caption("Let your local AI explain what changed on your network.")
    st.caption("Runs locally. No cloud AI.")
    st.caption(f"Selected model: {model or 'none'}")
    if not available:
        st.info(
            "Ask the Ghost is unavailable. Check Local setup and status. Scanning and history still work."
        )
    try:
        current, previous = store.latest_scan_pair(network)
    except (sqlite3.Error, ValueError):
        show_ui_error(
            "Could not load evidence for analysis. Check local history access and refresh."
        )
        return
    if current is None:
        st.info("Scan your network before asking the Ghost.")
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
        disabled=not available or model is None,
    ):
        st.session_state.ai_report = None
        with st.spinner(f"Asking local {model} to explain the saved evidence..."):
            try:
                st.session_state.ai_report = analyze_latest(store, network, model=model)
            except AIGroundingError:
                logger.warning("Local AI response failed grounding checks.")
                st.error(
                    "Ask the Ghost couldn't verify enough of the AI response against the saved network evidence."
                )
                st.caption("Your scan data is unchanged. Try the analysis again.")
                with st.expander("Technical details"):
                    st.text(
                        "The local model returned observations or references that could not be matched to the saved evidence."
                    )
            except AIAnalysisError as exc:
                logger.warning("Local AI analysis failed: %s", exc)
                st.error("Ask the Ghost couldn't get a response from the local AI.")
                st.caption("Check that Ollama is running and the selected model is available.")
                with st.expander("Technical details"):
                    st.text(str(exc))
            except (sqlite3.Error, ValueError):
                show_ui_error(
                    "Analysis could not load saved evidence. Check local history and retry."
                )

    analysis = st.session_state.ai_report
    if analysis is None:
        st.caption(
            "Optional: ask your local model to explain the saved evidence. Scanning works without Ollama."
        )
        return
    st.caption(f"Model used: {analysis.model}. Review the explanation against its evidence.")
    if analysis.partial:
        st.warning(
            "Some AI items could not be verified and were omitted. Showing only parts that passed evidence checks."
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
        if analysis.retried:
            st.caption("One local citation-correction retry was attempted with the same evidence.")
        st.caption(
            "Explains the latest two saved scans of this subnet. "
            "Run another scan after editing labels to include those edits. "
            f"Latest scan #{analysis.current_scan_id}; previous scan: {analysis.previous_scan_id}."
        )
        for item in report.evidence_summary:
            st.text(item.summary)
            st.caption("Evidence: " + ", ".join(item.evidence))
        st.json(analysis.evidence)
