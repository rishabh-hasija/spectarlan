from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


DeviceType = Literal["router", "computer", "phone", "tv", "printer", "iot", "unknown"]
PresenceState = Literal["new", "known", "vanished"]


class Device(BaseModel):
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    device_type: DeviceType = "unknown"
    state: PresenceState = "known"


class ScanResult(BaseModel):
    network: str
    local_ip: str
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    devices: list[Device] = Field(default_factory=list)
    vanished: list[Device] = Field(default_factory=list)
    scanner: str


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
