from __future__ import annotations

import os
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from typing import get_args

import httpx
import streamlit as st

from specterlan.ai import analyze_scan
from specterlan.history_ui import render_history
from specterlan.models import DeviceMetadata, DeviceType, ScanResult, TrustStatus
from specterlan.network import detect_local_network, discover
from specterlan.store import SnapshotStore, device_identity

st.set_page_config(
    page_title="SpecterLAN",
    page_icon="👻",
    layout="wide",
)

st.title("👻 SpecterLAN")
st.caption("Find the ghosts on your network. Local discovery + local AI.")

store = SnapshotStore()

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "ai_report" not in st.session_state:
    st.session_state.ai_report = None

try:
    local_ip, network = detect_local_network()
except (OSError, RuntimeError, ValueError) as exc:
    st.error(f"Network detection failed: {exc}")
    st.stop()

if (
    st.session_state.scan_result is not None
    and st.session_state.scan_result.network != network
):
    st.session_state.scan_result = None
    st.session_state.ai_report = None

with st.sidebar:
    st.subheader("Scan boundary")
    st.text_input("Local IP", value=local_ip, disabled=True)
    st.text_input("Target subnet", value=network, disabled=True)
    model = st.text_input("Ollama model", value=os.getenv("OLLAMA_MODEL", "gemma3:4b"))
    st.caption("SpecterLAN scans only the private subnet containing this computer.")
    st.caption("MVP discovery does not perform a port scan.")

if st.button("Scan for apparitions", type="primary", use_container_width=True):
    with st.spinner("Listening for devices on the local network..."):
        try:
            devices, scanner = discover(network, local_ip)
            devices, vanished = store.annotate_states(devices, network)
            result = ScanResult(
                network=network,
                local_ip=local_ip,
                devices=devices,
                vanished=vanished,
                scanner=scanner,
            )
            store.save(result)
            st.session_state.scan_result = result
            st.session_state.ai_report = None
        except (
            OSError,
            RuntimeError,
            ValueError,
            subprocess.SubprocessError,
            ET.ParseError,
            sqlite3.Error,
        ) as exc:
            st.error(str(exc))

result: ScanResult | None = st.session_state.scan_result

if result:
    try:
        result.devices = store.apply_metadata(result.devices, result.network)
        result.vanished = store.apply_metadata(result.vanished, result.network)
    except (sqlite3.Error, ValueError) as exc:
        st.error(f"Could not load device metadata: {exc}")
        st.stop()

    editable = {
        device_identity(device, result.network): device
        for device in [*result.devices, *result.vanished]
    }
    if editable:
        with st.expander("Edit a device"):
            identity = st.selectbox(
                "Device",
                options=list(editable),
                format_func=lambda key: (
                    f"{editable[key].friendly_name or editable[key].hostname or editable[key].ip}"
                    f" | {editable[key].ip} | {editable[key].mac or 'no MAC'}"
                    f" | {editable[key].state}"
                ),
            )
            selected = editable[identity]
            st.caption(
                f"Automatic suggestion: {selected.automatic_device_type}. "
                f"{selected.classification_reason} "
                "A saved device type takes precedence over this suggestion."
            )
            st.caption(
                "Trust is your inventory label; it does not allow or block network access. "
                "Ignored devices remain visible and are still scanned."
            )
            if identity.startswith("ip:"):
                st.warning(
                    "No usable MAC is visible. Metadata applies only to this subnet and IP. "
                    "Another device could reuse the address. Verify identity before trusting; "
                    "metadata will not follow an IP change or transfer to a MAC identity."
                )
            with st.form(f"edit:{identity}"):
                friendly_name = st.text_input("Friendly name", value=selected.friendly_name)
                device_types = get_args(DeviceType)
                device_type = st.selectbox(
                    "Device type",
                    options=device_types,
                    index=device_types.index(selected.device_type),
                )
                trust_statuses = get_args(TrustStatus)
                trust_status = st.selectbox(
                    "Trust status",
                    options=trust_statuses,
                    index=trust_statuses.index(selected.trust_status),
                )
                if st.form_submit_button("Save device"):
                    try:
                        store.update_metadata(
                            selected,
                            result.network,
                            DeviceMetadata(
                                friendly_name=friendly_name,
                                device_type=device_type,
                                trust_status=trust_status,
                            ),
                        )
                    except (sqlite3.Error, ValueError) as exc:
                        st.error(f"Could not save device metadata: {exc}")
                    else:
                        st.session_state.ai_report = None
                        st.rerun()

    new_count = sum(device.state == "new" for device in result.devices)
    unknown_count = sum(device.device_type == "unknown" for device in result.devices)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Online", len(result.devices))
    c2.metric("New apparitions", new_count)
    c3.metric("Unidentified", unknown_count)
    c4.metric("Vanished", len(result.vanished))

    st.subheader("Network presence")
    rows = []
    for device in result.devices:
        rows.append(
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
        )
    st.dataframe(rows, use_container_width=True, hide_index=True)

    if result.vanished:
        with st.expander("Vanished since the previous scan"):
            st.dataframe(
                [
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
                    for device in result.vanished
                ],
                use_container_width=True,
                hide_index=True,
            )

    st.divider()
    st.subheader("Ask the local ghost")

    if st.button("Analyze with Ollama", use_container_width=True):
        with st.spinner(f"Asking {model} to interpret the scan evidence..."):
            try:
                st.session_state.ai_report = analyze_scan(result, model=model)
            except (RuntimeError, ValueError, KeyError, TypeError, httpx.InvalidURL) as exc:
                st.error(str(exc))

    report = st.session_state.ai_report
    if report:
        st.write(report.overview)

        if report.attention_items:
            st.markdown("#### Items to verify")
            for item in report.attention_items:
                label = f"{item.title} · {item.confidence} confidence"
                with st.expander(label):
                    st.write(item.explanation)
                    if item.device_ips:
                        st.caption("Devices: " + ", ".join(item.device_ips))

        if report.questions_to_ask:
            st.markdown("#### Questions for you")
            for question in report.questions_to_ask:
                st.write(f"• {question}")

        if report.evidence_summary:
            with st.expander("Evidence used"):
                for line in report.evidence_summary:
                    st.write(f"• {line}")
else:
    st.info("Run a scan to refresh network presence. Saved observations are available in scan history below.")


render_history(store, network)
