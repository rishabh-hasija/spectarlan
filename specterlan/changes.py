from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .models import Device, SavedScan
from .store import device_identity

ChangeKind = Literal[
    "new", "returned", "vanished", "ip_changed", "classification_changed", "metadata_changed"
]


@dataclass(frozen=True)
class DeviceChange:
    kind: ChangeKind
    device: Device
    details: tuple[str, ...]


def _difference(label: str, old: object, new: object) -> str:
    return f"{label}: {old or '(blank)'} -> {new or '(blank)'}"


def compare_scans(current: SavedScan, previous: SavedScan | None) -> list[DeviceChange]:
    """Compare recorded values only: never reclassify or overlay current metadata."""
    if previous is None:
        return []
    if previous.network != current.network:
        raise ValueError("Scan comparisons must use the same subnet.")

    before = {device_identity(device, previous.network): device for device in previous.devices}
    after = {device_identity(device, current.network): device for device in current.devices}
    changes: list[DeviceChange] = []

    for key in sorted(after.keys() - before.keys()):
        device = after[key]
        kind: ChangeKind = "new" if device.state == "new" else "returned"
        changes.append(
            DeviceChange(
                kind, device, (f"{device.ip} | {device.device_type} | {device.trust_status}",)
            )
        )
    for key in sorted(before.keys() - after.keys()):
        device = before[key]
        changes.append(
            DeviceChange(
                "vanished",
                device,
                (
                    f"{device.ip} | Last seen in scan at {previous.scanned_at.isoformat(timespec='seconds')}",
                ),
            )
        )
    for key in sorted(after.keys() & before.keys()):
        old, new = before[key], after[key]
        if old.ip != new.ip:
            changes.append(DeviceChange("ip_changed", new, (f"{old.ip} -> {new.ip}",)))

        shared_fields = old.model_fields_set & new.model_fields_set
        automatic_known = "automatic_device_type" in shared_fields
        override_known = "device_type_override" in shared_fields
        classification = []
        if automatic_known and old.automatic_device_type != new.automatic_device_type:
            classification.append(
                _difference("Automatic type", old.automatic_device_type, new.automatic_device_type)
            )
        if old.device_type != new.device_type and (
            not override_known or old.device_type_override == new.device_type_override
        ):
            classification.append(_difference("Effective type", old.device_type, new.device_type))
        if classification:
            changes.append(DeviceChange("classification_changed", new, tuple(classification)))

        metadata = []
        for field, label in (("friendly_name", "Friendly name"), ("trust_status", "Trust")):
            if field in shared_fields and getattr(old, field) != getattr(new, field):
                metadata.append(_difference(label, getattr(old, field), getattr(new, field)))
        if override_known and old.device_type_override != new.device_type_override:
            metadata.append(
                _difference(
                    "User type override",
                    old.device_type_override or "automatic",
                    new.device_type_override or "automatic",
                )
            )
        if metadata:
            changes.append(DeviceChange("metadata_changed", new, tuple(metadata)))
    return changes
