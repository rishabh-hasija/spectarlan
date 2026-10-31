from __future__ import annotations

import json
import re

from .changes import DeviceChange, compare_scans
from .models import AIReport, SavedScan
from .store import device_identity


def build_evidence(current: SavedScan, previous: SavedScan | None = None) -> dict:
    """Serialize the two snapshots and change facts with request-local, deterministic E IDs."""
    if previous is not None and (previous.network != current.network or previous.id >= current.id):
        raise ValueError("Evidence requires an earlier scan of the same subnet.")

    facts: dict[str, dict] = {}
    scans: dict[str, str] = {}
    devices: dict[str, dict[str, str]] = {"current": {}, "previous": {}}
    labels: dict[str, str] = {}
    for side, scan in (("current", current), ("previous", previous)):
        if scan is None:
            continue
        scan_ref = f"E{len(facts) + 1}"
        scans[side] = scan_ref
        facts[scan_ref] = {
            "kind": "scan",
            "snapshot": side,
            "scan_id": scan.id,
            "subnet": scan.network,
            "timestamp": scan.scanned_at.isoformat(),
            "scanner": scan.scanner,
            "online_count": len(scan.devices),
        }
        for device in scan.devices:
            ref = f"E{len(facts) + 1}"
            identity = device_identity(device, scan.network)
            if identity not in labels:
                number = len(labels)
                labels[identity] = f"Device {chr(65 + number) if number < 26 else number + 1}"
            devices[side][identity] = ref
            # Missing legacy fields remain absent, rather than becoming invented observations.
            facts[ref] = {
                "kind": "device",
                "snapshot": side,
                "identity": identity,
                "device_label": labels[identity],
                "identity_basis": "mac" if identity.startswith("mac:") else "provisional_subnet_ip",
                "mac_present": bool(device.mac and device.mac.strip()),
                "recorded_fields": sorted(device.model_fields_set),
                **device.model_dump(mode="json", exclude_unset=True),
            }

    events = compare_scans(current, previous)
    if previous is None:
        # Stored first-observation state is valid even without a comparison baseline.
        events = [
            DeviceChange(
                "new",
                device,
                ("Newly observed by SpecterLAN; there is no previous scan for comparison.",),
            )
            for device in current.devices
            if device.state == "new"
        ]
    change_refs: dict[str, list[str]] = {
        kind: []
        for kind in (
            "new_devices",
            "vanished_devices",
            "returning_devices",
            "ip_changes",
            "classification_changes",
            "metadata_changes",
        )
    }
    groups = {
        "new": "new_devices",
        "vanished": "vanished_devices",
        "returned": "returning_devices",
        "ip_changed": "ip_changes",
        "classification_changed": "classification_changes",
        "metadata_changed": "metadata_changes",
    }
    for event in events:
        ref = f"E{len(facts) + 1}"
        identity = device_identity(event.device, current.network)
        before = devices["previous"].get(identity)
        after = devices["current"].get(identity)
        facts[ref] = {
            "kind": event.kind,
            "identity": identity,
            "device_label": labels[identity],
            "previous_device": before,
            "current_device": after,
            "details": list(event.details),
        }
        change_refs[groups[event.kind]].append(ref)

    return {
        "subnet": current.network,
        "has_previous_scan": previous is not None,
        "current_scan": scans["current"],
        "previous_scan": scans.get("previous"),
        "current_devices": list(devices["current"].values()),
        "previous_devices": list(devices["previous"].values()),
        "changes": change_refs,
        "facts": facts,
    }


def format_evidence(evidence: dict) -> str:
    """One explicit ID-to-observation line per fact; never log this private prompt text."""
    lines = []
    for ref, fact in evidence["facts"].items():
        if fact["kind"] == "scan":
            statement = (
                f"{fact['snapshot'].capitalize()} saved scan: {fact['online_count']} devices online; "
                f"discovery method {json.dumps(fact['scanner'], ensure_ascii=False)}."
            )
        elif fact["kind"] == "device":
            statement = (
                f"{fact['device_label']} was present in the {fact['snapshot']} saved scan. "
                + "; ".join(
                    f"{label}: {json.dumps(fact.get(field, 'not recorded'), ensure_ascii=False)}"
                    for field, label in (
                        ("trust_status", "Trust"),
                        ("device_type", "Recorded type"),
                        ("automatic_device_type", "Automatic type"),
                        ("device_type_override", "Type override"),
                        ("hostname", "Recorded hostname"),
                        ("vendor", "Recorded vendor"),
                    )
                )
                + ". Identity is "
                + (
                    "provisional and address-based; do not link it across IP changes."
                    if fact["identity_basis"] == "provisional_subnet_ip"
                    else "MAC-based."
                )
            )
        else:
            meanings = {
                "new": "was newly observed by SpecterLAN",
                "vanished": "was present previously but is absent from the current scan",
                "returned": "returned after being absent from the preceding scan",
                "ip_changed": "kept its identity while its IP address changed",
                "classification_changed": "has a changed recorded device classification",
                "metadata_changed": "has changed saved device metadata",
            }
            statement = (
                f"{fact['device_label']} {meanings[fact['kind']]}. "
                f"Previous observation: {fact['previous_device'] or 'none'}; "
                f"current observation: {fact['current_device'] or 'none'}. "
                f"Recorded change: {json.dumps(fact['details'], ensure_ascii=False)}"
            )
        lines.append(f"{ref}: {statement}")
    return "\n".join(lines)


def citation_ids(report: AIReport) -> set[str]:
    refs = set(re.findall(r"\[([^\[\]]+)\]", report.overview))
    for section in ("notable_changes", "devices_to_verify", "suggested_checks", "evidence_summary"):
        for item in getattr(report, section):
            refs.update(item.evidence)
            refs.update(
                re.findall(r"\[([^\[\]]+)\]", json.dumps(item.model_dump(exclude={"evidence"})))
            )
    return refs


def safe_diagnostics(evidence: dict, report: AIReport | None = None) -> dict:
    """Allowlisted counts/IDs only. Non-ID references may be private and are redacted."""
    refs = citation_ids(report) if report is not None else set()

    def safe(ref: str) -> str:
        return ref if re.fullmatch(r"E[1-9][0-9]{0,5}", ref) else "<redacted non-ID>"

    devices = [fact for fact in evidence["facts"].values() if fact.get("kind") == "device"]
    return {
        "Evidence facts": len(evidence["facts"]),
        "Allowed IDs": [safe(ref) for ref in evidence["facts"]],
        "Change category counts": {key: len(value) for key, value in evidence["changes"].items()},
        "Device count": len(evidence["current_devices"]),
        "Provisional identities": len(
            {
                fact["identity"]
                for fact in devices
                if fact["identity_basis"] == "provisional_subnet_ip"
            }
        ),
        "Unknown classifications": sum(
            fact.get("device_type") == "unknown"
            for fact in devices
            if fact["snapshot"] == "current"
        ),
        "Returned citations": sorted({safe(ref) for ref in refs}),
        "Invalid citations": sorted({safe(ref) for ref in refs if ref not in evidence["facts"]}),
    }
