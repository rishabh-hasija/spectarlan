from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

DeviceType = Literal[
    "router",
    "computer",
    "phone",
    "tablet",
    "tv",
    "printer",
    "speaker",
    "gaming_console",
    "camera",
    "smart_home",
    "server",
    "unknown",
]
PresenceState = Literal["new", "known", "vanished"]
TrustStatus = Literal["trusted", "unreviewed", "ignored"]


class DeviceMetadata(BaseModel):
    friendly_name: str = ""
    device_type: DeviceType | None = None
    trust_status: TrustStatus = "unreviewed"

    @field_validator("device_type", mode="before")
    @classmethod
    def read_legacy_iot(cls, value: object) -> object:
        return "smart_home" if value == "iot" else value


class Device(BaseModel):
    friendly_name: str = ""
    trust_status: TrustStatus = "unreviewed"
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    device_type: DeviceType = "unknown"
    device_type_override: DeviceType | None = None
    automatic_device_type: DeviceType = "unknown"
    classification_reason: str = "Not classified from local evidence yet."
    state: PresenceState = "known"

    @field_validator("device_type", mode="before")
    @classmethod
    def read_legacy_iot(cls, value: object) -> object:
        return "smart_home" if value == "iot" else value


class ScanResult(BaseModel):
    network: str
    local_ip: str
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    devices: list[Device] = Field(default_factory=list)
    vanished: list[Device] = Field(default_factory=list)
    scanner: str


class SavedScan(ScanResult):
    id: int


class AttentionItem(BaseModel):
    title: str
    explanation: str
    device_ips: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"]


class AIReport(BaseModel):
    overview: str
    attention_items: list[AttentionItem] = Field(default_factory=list)
    questions_to_ask: list[str] = Field(default_factory=list)
    evidence_summary: list[str] = Field(default_factory=list)
