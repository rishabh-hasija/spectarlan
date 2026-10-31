from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


class AIOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


class NotableChange(AIOutput):
    title: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)
    confidence: Literal["low", "medium", "high"]


class DeviceToVerify(AIOutput):
    reason: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)
    confidence: Literal["low", "medium", "high"]


class GroundedDeviceToVerify(DeviceToVerify):
    identity: str = Field(min_length=1)


class SuggestedCheck(AIOutput):
    check: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)


class EvidenceSummary(AIOutput):
    summary: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)


class AIReport(AIOutput):
    overview: str = Field(min_length=1)
    notable_changes: list[NotableChange]
    devices_to_verify: list[DeviceToVerify]
    suggested_checks: list[SuggestedCheck]
    evidence_summary: list[EvidenceSummary] = Field(min_length=1)

    @classmethod
    def citation_schema(cls, evidence_ids: list[str]) -> dict:
        """Constrain generation without replacing independent client-side grounding checks."""
        schema = cls.model_json_schema()
        for definition in schema.get("$defs", {}).values():
            citation = definition.get("properties", {}).get("evidence")
            if citation is not None:
                citation["items"]["enum"] = list(evidence_ids)
        return schema


class GroundedReport(AIReport):
    """Display only retained validated items, including when all summary items were rejected."""

    evidence_summary: list[EvidenceSummary]
    devices_to_verify: list[GroundedDeviceToVerify]

    @model_validator(mode="after")
    def require_support(self) -> GroundedReport:
        if not any(
            (
                self.notable_changes,
                self.devices_to_verify,
                self.suggested_checks,
                self.evidence_summary,
            )
        ):
            raise ValueError("A displayed report requires at least one grounded supporting item.")
        return self
