from __future__ import annotations

import streamlit as st

from .readiness import DEFAULT_MODEL, AIReadiness, check_local_ai, nmap_available


@st.cache_data(ttl=15, show_spinner=False)
def cached_ai_readiness(model: str, url: str) -> AIReadiness:
    return check_local_ai(model, url)


def render_readiness(storage_ready: bool, model: str, url: str, *, demo: bool) -> AIReadiness:
    status = cached_ai_readiness(model, url)
    with st.expander("Local setup and status", expanded=not status.selected_model_ready):
        st.caption("Runs locally. No registration, login, or hosted AI is required.")
        st.markdown("**Python:** ready (3.11+)")
        st.markdown(f"**Local data storage:** {'ready' if storage_ready else 'problem'}")
        if demo:
            st.caption(
                "Demo uses temporary local storage; Live history is separate and not checked."
            )
        else:
            st.caption("Windows data location: %LOCALAPPDATA%\\SpecterLAN\\")
        st.markdown(f"**Ollama:** {'ready' if status.ollama_ready else 'unavailable'}")
        st.markdown(
            f"**Model:** {DEFAULT_MODEL} {'ready' if status.default_model_ready else 'missing'}"
        )
        if model.strip() != DEFAULT_MODEL:
            st.text(
                f"Selected model: {model} — {'ready' if status.selected_model_ready else 'unavailable'}"
            )
        st.markdown(f"**Nmap:** {'available' if nmap_available() else 'fallback mode'}")
        st.caption(
            "Ollama is needed only for Ask the Ghost. Nmap is recommended, not mandatory. "
            "Demo Séance works without live network discovery."
        )
        if status.message:
            st.info(status.message)
        if not status.default_model_ready:
            st.caption("To install the default model after installing Ollama, run:")
            st.code("ollama pull gemma4:e4b", language="powershell")
        if not status.selected_model_ready and model.strip() != DEFAULT_MODEL:
            st.info("Choose a compatible installed local model, or pull it using Ollama.")
        st.caption("After changing Ollama or installed models, refresh this page after 15 seconds.")
    return status
