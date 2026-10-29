from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from .models import Device, DeviceMetadata, ScanResult
from .store import SnapshotStore

DEMO_NETWORK = "192.168.178.0/24"
DEMO_LOCAL_IP = "192.168.178.10"
DEMO_STAGES = 3
BASE_TIME = datetime(2026, 10, 29, 20, 0, tzinfo=UTC)

ROUTER_MAC = "02:53:4C:00:00:01"
LAPTOP_MAC = "02:53:4C:00:00:02"
TV_MAC = "02:53:4C:00:00:03"
PHONE_MAC = "02:53:4C:00:00:04"
ESP_MAC = "02:53:4C:00:00:05"


def demo_devices(stage: int) -> list[Device]:
    """Return fresh local observations; no clock, randomness, or discovery calls."""
    if not 1 <= stage <= DEMO_STAGES:
        raise ValueError("Demo scan must be 1, 2, or 3.")
    devices = [
        Device(ip="192.168.178.1", mac=ROUTER_MAC, hostname="fritzbox", vendor="AVM"),
        Device(ip=DEMO_LOCAL_IP, mac=LAPTOP_MAC, hostname="work-laptop", vendor="Intel Corporate"),
        Device(
            ip="192.168.178.31" if stage == 3 else "192.168.178.20",
            mac=TV_MAC,
            hostname="living-room-tv",
            vendor="Hisense",
        ),
    ]
    if stage < 3:
        devices.append(
            Device(
                ip="192.168.178.40",
                mac=PHONE_MAC,
                hostname="alice-iphone",
                vendor="Apple",
            )
        )
    if stage >= 2:
        devices.append(
            Device(
                ip="192.168.178.47",
                mac=ESP_MAC,
                hostname="ESP_32A1",
                vendor="Espressif",
            )
        )
    return devices


class DemoSession:
    """Own only a temporary demo store; never accept a live database path."""

    def __init__(self) -> None:
        self._directory = TemporaryDirectory(prefix="specterlan-demo-")
        self.store = SnapshotStore(Path(self._directory.name) / "demo.db")
        self.stage = 0
        self.generation = 0
        self._seed_baseline_metadata()

    def _seed_baseline_metadata(self) -> None:
        names = {
            ROUTER_MAC: "Home Router",
            LAPTOP_MAC: "Work Laptop",
            TV_MAC: "Living Room TV",
            PHONE_MAC: "Alice's Phone",
        }
        for device in demo_devices(1):
            self.store.update_metadata(
                device,
                DEMO_NETWORK,
                DeviceMetadata(friendly_name=names[device.mac], trust_status="trusted"),
            )

    def advance(self) -> ScanResult:
        if self.stage >= DEMO_STAGES:
            raise ValueError("Demo is complete. Reset Demo to replay it.")
        next_stage = self.stage + 1
        devices, vanished = self.store.annotate_states(demo_devices(next_stage), DEMO_NETWORK)
        if next_stage == 2:
            esp = next(device for device in devices if device.mac == ESP_MAC)
            # Curated scenario metadata, not an automatic inference from weak ESP/vendor evidence.
            # Apply after state annotation so its first observation remains new.
            self.store.update_metadata(
                esp,
                DEMO_NETWORK,
                DeviceMetadata(device_type="smart_home", trust_status="unreviewed"),
            )
            devices = self.store.apply_metadata(devices, DEMO_NETWORK)
        result = ScanResult(
            network=DEMO_NETWORK,
            local_ip=DEMO_LOCAL_IP,
            scanned_at=BASE_TIME + timedelta(minutes=next_stage - 1),
            scanner=f"demo fixture {next_stage} (simulated)",
            devices=devices,
            vanished=vanished,
        )
        self.store.save(result)
        self.stage = next_stage
        return result

    def reset(self) -> None:
        # This connection belongs exclusively to the temporary store created above.
        with self.store._connect() as con:
            con.execute("DELETE FROM scans")
            con.execute("DELETE FROM device_metadata")
            con.execute("DELETE FROM sqlite_sequence WHERE name = 'scans'")
        self.stage = 0
        self.generation += 1
        self._seed_baseline_metadata()

    def close(self) -> None:
        self._directory.cleanup()
