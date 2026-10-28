from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import Device, ScanResult


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

    def last_devices(self) -> dict[str, Device]:
        with self._connect() as con:
            row = con.execute(
                "SELECT devices_json FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()

        if not row:
            return {}

        devices = [Device.model_validate(item) for item in json.loads(row["devices_json"])]
        return {device.mac or device.ip: device for device in devices}

    def annotate_states(self, devices: list[Device]) -> tuple[list[Device], list[Device]]:
        previous = self.last_devices()
        current_keys: set[str] = set()

        annotated: list[Device] = []
        for device in devices:
            key = device.mac or device.ip
            current_keys.add(key)
            device.state = "known" if key in previous else "new"
            annotated.append(device)

        vanished: list[Device] = []
        for key, old in previous.items():
            if key not in current_keys:
                vanished.append(old.model_copy(update={"state": "vanished"}))

        return annotated, vanished

    def save(self, result: ScanResult) -> None:
        payload = [device.model_dump(mode="json") for device in result.devices]
        with self._connect() as con:
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
