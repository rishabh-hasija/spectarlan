from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Device, DeviceType

# Match complete naming tokens/model families, never arbitrary substrings.
HOSTNAME_RULES: dict[DeviceType, tuple[str, ...]] = {
    "router": (r"router\d*", r"gateway\d*", r"fritz(?:box)?\d*", r"fritz box"),
    "computer": (
        r"desktop\d*",
        r"laptop\d*",
        r"notebook\d*",
        r"macbook",
        r"imac",
        r"thinkpad",
        r"pc\d*",
    ),
    "phone": (
        r"iphone\d*",
        r"phone\d*",
        r"smartphone",
        r"pixel ?\d+(?: ?pro)?",
        r"galaxy s\d+",
    ),
    "tablet": (r"ipad\d*", r"tablet\d*", r"galaxy tab"),
    "tv": (r"tv\d*", r"smart tv", r"roku\d*", r"chromecast\d*"),
    "printer": (r"printer\d*", r"laserjet", r"officejet", r"deskjet", r"pixma", r"ecotank"),
    "speaker": (r"speaker\d*", r"sonos", r"homepod", r"echo dot", r"echo studio"),
    "gaming_console": (r"xbox", r"playstation", r"ps[345]", r"nintendo switch"),
    "camera": (r"camera\d*", r"ipcam\d*", r"webcam\d*", r"reolink"),
    "smart_home": (
        r"tuya",
        r"shelly\d*",
        r"tasmota",
        r"esphome",
        r"smart plug",
        r"smart bulb",
        r"smart switch",
        r"thermostat\d*",
        r"hue bridge",
        r"hue bulb",
    ),
    "server": (r"server\d*", r"nas\d*", r"synology", r"qnap", r"truenas", r"proxmox", r"unraid"),
}

# Broad vendors (Apple, Samsung, Sony, ASUS, Intel, etc.) are deliberately absent.
# These are suggestions from locally supplied vendor names, not hardware verification.
VENDOR_RULES: dict[DeviceType, tuple[str, ...]] = {
    "router": ("avm", "fritzbox"),
    "tv": ("hisense", "roku"),
    "printer": ("epson", "brother", "xerox"),
    "speaker": ("sonos",),
    "gaming_console": ("nintendo",),
    "camera": ("reolink",),
    "smart_home": ("tuya", "shelly"),
    "server": ("synology", "qnap"),
}


@dataclass(frozen=True)
class Classification:
    device_type: DeviceType
    reason: str


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def classify(hostname: str | None, vendor: str | None) -> Classification:
    """Return an explainable local suggestion, abstaining when categories conflict."""
    # DNS suffixes are not evidence of the device's type.
    host = _normalized((hostname or "").split(".", 1)[0])
    maker = _normalized(vendor or "")
    matches: dict[DeviceType, list[str]] = {}

    for device_type, patterns in HOSTNAME_RULES.items():
        for pattern in patterns:
            match = re.search(rf"(?<![a-z0-9])(?:{pattern})(?![a-z0-9])", host)
            if match:
                matches.setdefault(device_type, []).append(f"Hostname contains '{match.group(0)}'")

    for device_type, markers in VENDOR_RULES.items():
        for marker in markers:
            if re.search(rf"(?<![a-z0-9]){re.escape(marker)}(?![a-z0-9])", maker):
                matches.setdefault(device_type, []).append(f"Vendor matched '{marker}'")

    if not matches:
        return Classification("unknown", "No sufficiently specific hostname or vendor evidence.")
    evidence = "; ".join(
        f"{device_type}: {', '.join(reasons)}" for device_type, reasons in matches.items()
    )
    if len(matches) > 1:
        return Classification("unknown", f"Conflicting local evidence: {evidence}.")
    device_type = next(iter(matches))
    return Classification(device_type, "; ".join(matches[device_type]))


def classify_observation(device: Device) -> Device:
    """Refresh automatic fields without treating an old inferred type as user metadata."""
    suggestion = classify(device.hostname, device.vendor)
    return device.model_copy(
        update={
            "device_type": suggestion.device_type,
            "automatic_device_type": suggestion.device_type,
            "classification_reason": suggestion.reason,
        }
    )
