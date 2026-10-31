from __future__ import annotations

import sqlite3

import streamlit as st

from .readiness import (
    DEFAULT_MODEL,
    AIReadiness,
    ModelInventory,
    choose_model,
    discover_local_models,
    nmap_available,
)
from .store import SnapshotStore


@st.cache_data(ttl=15, show_spinner=False)
def cached_model_inventory(url: str) -> ModelInventory:
    return discover_local_models(url)


def _save_selection(store: SnapshotStore, url: str, key: str) -> None:
    selected = st.session_state.get(key)
    # Recheck at save time so a model removed since the cached listing is not saved.
    inventory = discover_local_models(url)
    if selected not in inventory.models:
        getattr(cached_model_inventory, "clear", lambda: None)()
        st.warning("That local model is no longer available. Refresh the model list.")
        st.session_state[key] = None
        st.session_state.pop(f"{key}:choice", None)
        return
    st.session_state[f"{key}:choice"] = selected
    try:
        store.save_model_preference(selected)
    except (OSError, sqlite3.Error):
        st.error("Could not save the local model preference. Check local history access.")


def _remember_demo_selection(key: str) -> None:
    st.session_state[f"{key}:choice"] = st.session_state.get(key)


def render_model_selector(
    store: SnapshotStore,
    saved: str | None,
    url: str,
    *,
    demo: bool,
) -> tuple[str | None, ModelInventory]:
    inventory = cached_model_inventory(url)
    if not demo and inventory.ollama_ready and saved and saved not in inventory.models:
        try:
            store.clear_model_preference()
        except (OSError, sqlite3.Error):
            st.error(
                "Could not clear the unavailable local model preference. Check local history access."
            )
    key = "demo_local_model" if demo else "local_model_preference"
    chosen = st.session_state.get(f"{key}:choice")
    if chosen not in inventory.models:
        st.session_state.pop(f"{key}:choice", None)
        chosen = None
    selected = choose_model(inventory.models, saved, chosen)
    # Reset stale widget values before constructing it; all options come from Ollama.
    if key in st.session_state and st.session_state[key] != selected:
        del st.session_state[key]
    model = st.selectbox(
        "Local AI model",
        options=inventory.models,
        index=inventory.models.index(selected) if selected else None,
        key=key,
        disabled=not inventory.models,
        placeholder="No local models available",
        on_change=_remember_demo_selection if demo else _save_selection,
        args=(key,) if demo else (store, url, key),
    )
    st.caption("Detected from Ollama on this device.")
    if not inventory.ollama_ready:
        st.info("Ollama is not running. Network scanning still works.")
    else:
        if DEFAULT_MODEL not in inventory.installed_models:
            st.info("Default model gemma3:4b is not installed.")
            st.caption("Run: ollama pull gemma3:4b")
        if not inventory.models:
            st.info("No compatible local AI models are available. Ask the Ghost is disabled.")
    return model, inventory


def render_readiness(
    storage_ready: bool, model: str | None, inventory: ModelInventory, *, demo: bool
) -> AIReadiness:
    status = inventory.readiness(model)
    with st.expander("Local setup and status", expanded=not storage_ready):
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
        if model and model != DEFAULT_MODEL:
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
        if DEFAULT_MODEL not in inventory.installed_models:
            st.caption("To install the default model after installing Ollama, run:")
            st.code(f"ollama pull {DEFAULT_MODEL}", language="powershell")
        elif not status.default_model_ready:
            st.caption(
                "The default model is listed but could not be verified as a local chat model."
            )
        if not inventory.installed_models and inventory.ollama_ready:
            st.caption("Ollama is available, but no models are installed.")
        if not status.selected_model_ready:
            st.info("Choose a compatible installed local model, or pull it using Ollama.")
        st.caption("After changing Ollama or installed models, refresh this page after 15 seconds.")
    return status
