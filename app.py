from __future__ import annotations

import os
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

st.set_page_config(
    page_title="SpecterLAN",
    page_icon="👻",
    layout="wide",
)

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
        st.session_state.demo_session = DemoSession()
    demo = st.session_state.demo_session
    store = demo.store
    local_ip, network = DEMO_LOCAL_IP, DEMO_NETWORK
    view_key = f"demo:{demo.generation}"
else:
    store = SnapshotStore()
    view_key = "live"
    try:
        local_ip, network = detect_local_network()
    except (OSError, RuntimeError, ValueError) as exc:
        st.error(f"Network detection failed: {exc}")
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
    else:
        st.caption("Fixed simulated subnet. No network detection or discovery is performed.")

if mode == "Live Network":
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
        except sqlite3.Error as exc:
            st.error(f"Could not reset demo data: {exc}")
        else:
            st.session_state.scan_result = None
            st.session_state["result:Demo Séance"] = None
            st.session_state.ai_report = None
            st.rerun()
    if start_demo or next_scan:
        try:
            st.session_state.scan_result = demo.advance()
        except (sqlite3.Error, ValueError) as exc:
            st.error(f"Could not advance the demo: {exc}")
        else:
            st.session_state.ai_report = None
            st.rerun()
    st.caption(f"Demo scan {demo.stage} of {DEMO_STAGES}. Reset Demo replays the same story.")

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


else:
    if mode == "Demo Séance":
        st.info(
            "Select Start Demo for the baseline, then Next Scan to advance the simulated story."
        )
    else:
        st.info(
            "Run a scan to refresh network presence. Saved observations are available in scan history below."
        )


render_history(store, network, key_prefix=view_key)

render_ai(store, network, model, key_prefix=view_key)
