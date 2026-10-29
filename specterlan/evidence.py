from __future__ import annotations

from .changes import DeviceChange, compare_scans
from .models import SavedScan
from .store import device_identity


def build_evidence(current: SavedScan, previous: SavedScan | None = None) -> dict:
    """Serialize only the two supplied snapshots and deterministic change facts."""
    if previous is not None and (previous.network != current.network or previous.id >= current.id):
        raise ValueError("Evidence requires an earlier scan of the same subnet.")

    facts: dict[str, dict] = {}
    devices: dict[str, dict[str, str]] = {"current": {}, "previous": {}}
    for side, scan in (("current", current), ("previous", previous)):
        if scan is None:
            continue
        facts[f"{side}.scan"] = {
            "scan_id": scan.id,
            "subnet": scan.network,
            "timestamp": scan.scanned_at.isoformat(),
            "scanner": scan.scanner,
            "online_count": len(scan.devices),
        }
        for index, device in enumerate(scan.devices):
            ref = f"{side}.device.{index}"
            identity = device_identity(device, scan.network)
            devices[side][identity] = ref
            # Missing legacy fields remain absent, rather than becoming invented observations.
            facts[ref] = {
                "identity": identity,
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
    for index, event in enumerate(events):
        ref = f"change.{index}"
        identity = device_identity(event.device, current.network)
        before = devices["previous"].get(identity)
        after = devices["current"].get(identity)
        facts[ref] = {
            "kind": event.kind,
            "identity": identity,
            "previous_device": before,
            "current_device": after,
            "details": list(event.details),
        }
        change_refs[groups[event.kind]].append(ref)

    return {
        "subnet": current.network,
        "has_previous_scan": previous is not None,
        "current_scan": "current.scan",
        "previous_scan": "previous.scan" if previous is not None else None,
        "current_devices": list(devices["current"].values()),
        "previous_devices": list(devices["previous"].values()),
        "changes": change_refs,
        "facts": facts,
    }
