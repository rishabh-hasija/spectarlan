from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from typing import get_args

import streamlit as st

from specterlan.ai_ui import render_ai
from specterlan.demo import DEMO_LOCAL_IP, DEMO_NETWORK, DEMO_STAGES, DemoSession
from specterlan.history_ui import render_history
from specterlan.models import DeviceMetadata, DeviceType, ScanResult, TrustStatus
from specterlan.network import detect_local_network, discover
from specterlan.store import SnapshotStore, device_identity
from specterlan.ui import (
    apply_style,
    render_device_table,
    render_footer,
    render_overview,
    show_ui_error,
)

st.set_page_config(
    page_title="SpecterLAN",
    page_icon="👻",
    layout="wide",
)

apply_style()
st.title("👻 SpecterLAN")
st.caption("Find the ghosts on your network. Local discovery + local AI.")

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "ai_report" not in st.session_state:
    st.session_state.ai_report = None

mode = st.sidebar.radio("Mode", ["Live Network", "Demo Séance"], key="mode")
previous_mode = st.session_state.get("active_mode", mode)
if previous_mode != mode:
    st.session_state[f"result:{previous_mode}"] = st.session_state.scan_result
    st.session_state.scan_result = st.session_state.get(f"result:{mode}")
    st.session_state.ai_report = None
st.session_state.active_mode = mode

if mode == "Demo Séance":
    st.info("Demo Séance: simulated network evidence")
    if "demo_session" not in st.session_state:
        try:
            st.session_state.demo_session = DemoSession()
        except (OSError, sqlite3.Error, ValueError):
            show_ui_error("Demo could not start. Check temporary-folder permissions, then refresh.")
            render_footer()
            st.stop()
    demo = st.session_state.demo_session
    store = demo.store
    local_ip, network = DEMO_LOCAL_IP, DEMO_NETWORK
    view_key = f"demo:{demo.generation}"
else:
    try:
        store = SnapshotStore()
    except (OSError, sqlite3.Error, RuntimeError, ValueError):
        show_ui_error(
            "Could not open local scan history. Check database permissions and app compatibility."
        )
        render_footer()
        st.stop()
    view_key = "live"
    try:
        local_ip, network = detect_local_network()
    except (OSError, RuntimeError, ValueError):
        show_ui_error(
            "Network detection failed. Connect to a private Wi-Fi or Ethernet network, then refresh. "
            "You can use Demo Séance without a network connection."
        )
        render_footer()
        st.stop()

if st.session_state.scan_result is not None and st.session_state.scan_result.network != network:
    st.session_state.scan_result = None
    st.session_state.ai_report = None

with st.sidebar:
    st.subheader("Scan boundary")
    st.text_input("Local IP", value=local_ip, disabled=True)
    st.text_input("Target subnet", value=network, disabled=True)
    model = st.text_input("Ollama model", value=os.getenv("OLLAMA_MODEL", "gemma3:4b"))
    if mode == "Live Network":
        st.caption("SpecterLAN scans only the private subnet containing this computer.")
        st.caption("MVP discovery does not perform a port scan.")
        if shutil.which("nmap") is None:
            st.info(
                "Nmap unavailable. Scans use ping + the local neighbor table; Nmap is optional."
            )
    else:
        st.caption("Fixed simulated subnet. No network detection or discovery is performed.")

header_area = st.empty()
with header_area.container():
    render_overview(mode, network, st.session_state.scan_result)
scan_status = None

if mode == "Live Network":
    if st.button("Scan for apparitions", type="primary", use_container_width=True):
        with header_area.container():
            render_overview(
                mode, network, st.session_state.scan_result, status="Scanning private subnet…"
            )
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
            ):
                scan_status = "Scan failed · previous observations retained"
                show_ui_error(
                    "Scan failed. Check your network connection, scanner permissions, and local "
                    "database access, then retry. Previous scan history is unchanged."
                )

else:
    controls = st.columns(3)
    start_demo = controls[0].button(
        "Start Demo", type="primary", disabled=demo.stage != 0, key=f"start:{view_key}"
    )
    next_scan = controls[1].button(
        "Next Scan", disabled=demo.stage == 0 or demo.stage >= DEMO_STAGES, key=f"next:{view_key}"
    )
    reset_demo = controls[2].button("Reset Demo", key=f"reset:{view_key}")
    if reset_demo:
        try:
            demo.reset()
        except sqlite3.Error:
            show_ui_error("Demo reset failed. Check temporary-folder permissions and retry.")
        else:
            st.session_state.scan_result = None
            st.session_state["result:Demo Séance"] = None
            st.session_state.ai_report = None
            st.rerun()
    if start_demo or next_scan:
        try:
            st.session_state.scan_result = demo.advance()
        except (sqlite3.Error, ValueError):
            show_ui_error("Demo could not advance. Retry or reset the simulated session.")
        else:
            st.session_state.ai_report = None
            st.rerun()
    st.caption(f"Demo scan {demo.stage} of {DEMO_STAGES}. Reset Demo replays the same story.")

result: ScanResult | None = st.session_state.scan_result

if result:
    try:
        result.devices = store.apply_metadata(result.devices, result.network)
        result.vanished = store.apply_metadata(result.vanished, result.network)
    except (sqlite3.Error, ValueError):
        show_ui_error(
            "Device labels could not load. Refresh the app or check local history access."
        )
        render_footer()
        st.stop()
    with header_area.container():
        render_overview(mode, network, result, status=scan_status)

    st.subheader("Network presence")
    st.caption(
        "Presence: new · known · vanished. Trust: trusted · unreviewed · ignored. "
        "Labels describe observations and your inventory, not security verdicts."
    )
    render_device_table(result.devices)
    if not result.devices:
        st.info(
            "No devices responded in this snapshot. Sleeping or filtered devices may be missed."
        )
    if result.vanished:
        with st.expander(f"Vanished since the previous scan ({len(result.vanished)})"):
            render_device_table(result.vanished)

    editable = {
        device_identity(device, result.network): device
        for device in [*result.devices, *result.vanished]
    }
    if editable:
        with st.expander("Edit a device"):
            identity = st.selectbox(
                "Device",
                options=list(editable),
                key=None if mode == "Live Network" else f"device_selector:{view_key}",
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
            with st.form(
                f"edit:{identity}" if mode == "Live Network" else f"edit:{view_key}:{identity}"
            ):
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
                    except (sqlite3.Error, ValueError):
                        show_ui_error(
                            "Device labels could not be saved. Check local database access and retry."
                        )
                    else:
                        st.session_state.ai_report = None
                        st.rerun()


else:
    with header_area.container():
        render_overview(mode, network, None, status=scan_status)
    if mode == "Demo Séance":
        st.info("No scan yet. Start Demo for the baseline, then use Next Scan to reveal changes.")
    else:
        st.info(
            "No scan this session. Scan for apparitions to refresh presence, or inspect saved history below."
        )

render_history(store, network, key_prefix=view_key)
render_ai(store, network, model, key_prefix=view_key)
render_footer()
