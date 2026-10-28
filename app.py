from __future__ import annotations

import os

import streamlit as st

from specterlan.ai import analyze_scan
from specterlan.models import ScanResult
from specterlan.network import detect_local_network, discover
from specterlan.store import SnapshotStore


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
except Exception as exc:
    st.error(f"Network detection failed: {exc}")
    st.stop()

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
            devices, vanished = store.annotate_states(devices)
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
        except Exception as exc:
            st.error(str(exc))

result: ScanResult | None = st.session_state.scan_result

if result:
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
                "State": device.state,
                "IP": device.ip,
                "Hostname": device.hostname or "",
                "MAC": device.mac or "",
                "Vendor": device.vendor or "",
                "Type": device.device_type,
            }
        )
    st.dataframe(rows, use_container_width=True, hide_index=True)

    if result.vanished:
        with st.expander("Vanished since the previous scan"):
            st.dataframe(
                [
                    {
                        "IP": device.ip,
                        "Hostname": device.hostname or "",
                        "MAC": device.mac or "",
                        "Type": device.device_type,
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
            except Exception as exc:
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
    st.info("Run the first scan. The next scan will let SpecterLAN distinguish new, known, and vanished devices.")
