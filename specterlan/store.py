from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from itertools import pairwise
from pathlib import Path

from .classification import classify_observation
from .models import Device, DeviceMetadata, SavedScan, ScanResult


def device_identity(device: Device, network: str) -> str:
    """Use a MAC when usable; otherwise identify only this subnet/IP observation."""
    mac = re.sub(r"[:.\-]", "", (device.mac or "").strip()).upper()
    if re.fullmatch(r"[0-9A-F]{12}", mac) and mac != "000000000000" and not int(mac[:2], 16) & 1:
        return f"mac:{mac}"
    subnet = ipaddress.ip_network(network, strict=False)
    return f"ip:{subnet}:{ipaddress.ip_address(device.ip)}"


class SnapshotStore:
    def __init__(self, path: str | Path = ".specterlan.db") -> None:
        self.path = str(path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with self._connect() as con:
            # Serialize startup migrations, including concurrent Streamlit sessions.
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT NOT NULL,
                    network TEXT NOT NULL,
                    local_ip TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    devices_json TEXT NOT NULL
                )
                """
            )
            version = con.execute("PRAGMA user_version").fetchone()[0]
            if version > 2:
                raise RuntimeError("This database requires a newer version of SpecterLAN.")
            if version < 1:
                con.execute(
                    """
                    CREATE TABLE IF NOT EXISTS device_metadata (
                        identity TEXT PRIMARY KEY,
                        friendly_name TEXT NOT NULL DEFAULT '',
                        device_type TEXT CHECK (
                            device_type IN (
                                'router', 'computer', 'phone', 'tv', 'printer', 'iot', 'unknown'
                            )
                        ),
                        trust_status TEXT NOT NULL DEFAULT 'unreviewed'
                            CHECK (trust_status IN ('trusted', 'unreviewed', 'ignored'))
                    )
                    """
                )
                # Register old identities without altering any historical scan JSON.
                for row in con.execute("SELECT network, devices_json FROM scans ORDER BY id"):
                    devices = [
                        Device.model_validate(item) for item in json.loads(row["devices_json"])
                    ]
                    con.executemany(
                        "INSERT OR IGNORE INTO device_metadata(identity) VALUES (?)",
                        [(device_identity(device, row["network"]),) for device in devices],
                    )
                con.execute("PRAGMA user_version = 1")
            if version < 2:
                self._migrate_classification(con)
                con.execute("PRAGMA user_version = 2")

    @staticmethod
    def _migrate_classification(con: sqlite3.Connection) -> None:
        # SQLite CHECK constraints require rebuilding this current-metadata table.
        # The scans table is intentionally never updated by this migration.
        con.execute(
            """
            CREATE TABLE device_metadata_v2 (
                identity TEXT PRIMARY KEY,
                friendly_name TEXT NOT NULL DEFAULT '',
                device_type TEXT CHECK (
                    device_type IN (
                        'router', 'computer', 'phone', 'tablet', 'tv', 'printer',
                        'speaker', 'gaming_console', 'camera', 'smart_home', 'server', 'unknown'
                    )
                ),
                trust_status TEXT NOT NULL DEFAULT 'unreviewed'
                    CHECK (trust_status IN ('trusted', 'unreviewed', 'ignored'))
            )
            """
        )
        con.execute(
            """
            INSERT INTO device_metadata_v2(identity, friendly_name, device_type, trust_status)
            SELECT identity, friendly_name,
                CASE WHEN device_type = 'iot' THEN 'smart_home' ELSE device_type END,
                trust_status
            FROM device_metadata
            """
        )
        con.execute("DROP TABLE device_metadata")
        con.execute("ALTER TABLE device_metadata_v2 RENAME TO device_metadata")

    @staticmethod
    def _read_scan(row: sqlite3.Row) -> SavedScan:
        return SavedScan(
            id=row["id"],
            network=row["network"],
            local_ip=row["local_ip"],
            scanned_at=row["scanned_at"],
            scanner=row["scanner"],
            devices=[Device.model_validate(item) for item in json.loads(row["devices_json"])],
        )

    def recent_scans(self, network: str, limit: int = 10) -> list[SavedScan]:
        """Read saved observations unchanged; one extra row supplies vanished counts."""
        if not 1 <= limit <= 10:
            raise ValueError("Scan history limit must be between 1 and 10.")
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM scans WHERE network = ? ORDER BY id DESC LIMIT ?",
                (network, limit + 1),
            ).fetchall()
        scans = [self._read_scan(row) for row in rows]
        for current, previous in pairwise(scans):
            keys = {device_identity(device, network) for device in current.devices}
            current.vanished = [
                device.model_copy(update={"state": "vanished"})
                for device in previous.devices
                if device_identity(device, network) not in keys
            ]
        return scans[:limit]

    def previous_scan(self, scan: SavedScan) -> SavedScan | None:
        """Find the immediately preceding saved scan of this subnet, including empty scans."""
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM scans WHERE network = ? AND id < ? ORDER BY id DESC LIMIT 1",
                (scan.network, scan.id),
            ).fetchone()
        return self._read_scan(row) if row is not None else None

    def last_devices(self, network: str) -> dict[str, Device]:
        with self._connect() as con:
            row = con.execute(
                "SELECT devices_json FROM scans WHERE network = ? ORDER BY id DESC LIMIT 1",
                (network,),
            ).fetchone()

        if not row:
            return {}

        devices = [Device.model_validate(item) for item in json.loads(row["devices_json"])]
        return {device_identity(device, network): device for device in devices}

    def _metadata(self) -> dict[str, DeviceMetadata]:
        with self._connect() as con:
            rows = con.execute("SELECT * FROM device_metadata").fetchall()
        return {row["identity"]: DeviceMetadata.model_validate(dict(row)) for row in rows}

    def apply_metadata(self, devices: list[Device], network: str) -> list[Device]:
        metadata = self._metadata()
        refreshed = []
        for device in devices:
            device = classify_observation(device).model_copy(update={"device_type_override": None})
            saved = metadata.get(device_identity(device, network))
            if saved is not None:
                updates = saved.model_dump(exclude={"device_type"})
                updates["device_type_override"] = saved.device_type
                if saved.device_type is not None:
                    updates["device_type"] = saved.device_type
                device = device.model_copy(update=updates)
            refreshed.append(device)
        return refreshed

    def update_metadata(self, device: Device, network: str, metadata: DeviceMetadata) -> None:
        with self._connect() as con:
            con.execute(
                """
                INSERT INTO device_metadata(identity, friendly_name, device_type, trust_status)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(identity) DO UPDATE SET
                    friendly_name = excluded.friendly_name,
                    device_type = excluded.device_type,
                    trust_status = excluded.trust_status
                """,
                (
                    device_identity(device, network),
                    metadata.friendly_name.strip(),
                    metadata.device_type,
                    metadata.trust_status,
                ),
            )

    def annotate_states(
        self, devices: list[Device], network: str
    ) -> tuple[list[Device], list[Device]]:
        previous = self.last_devices(network)
        known_keys = self._metadata().keys()
        current_keys: set[str] = set()

        annotated: list[Device] = []
        for device in devices:
            key = device_identity(device, network)
            current_keys.add(key)
            device.state = "known" if key in known_keys else "new"
            annotated.append(device)

        vanished: list[Device] = []
        for key, old in previous.items():
            if key not in current_keys:
                vanished.append(old.model_copy(update={"state": "vanished"}))

        return self.apply_metadata(annotated, network), self.apply_metadata(vanished, network)

    def save(self, result: ScanResult) -> None:
        payload = [device.model_dump(mode="json") for device in result.devices]
        with self._connect() as con:
            con.executemany(
                "INSERT OR IGNORE INTO device_metadata(identity) VALUES (?)",
                [(device_identity(device, result.network),) for device in result.devices],
            )
            con.execute(
                """
                INSERT INTO scans(scanned_at, network, local_ip, scanner, devices_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    result.scanned_at.isoformat(),
                    result.network,
                    result.local_ip,
                    result.scanner,
                    json.dumps(payload),
                ),
            )
