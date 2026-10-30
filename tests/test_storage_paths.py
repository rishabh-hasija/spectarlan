import getpass
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from platformdirs.windows import Windows

from specterlan import storage_paths
from specterlan.demo import DemoSession
from specterlan.models import Device, DeviceMetadata, ScanResult
from specterlan.store import SnapshotStore

NETWORK = "192.168.1.0/24"
DEVICE = Device(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01")


@pytest.fixture
def local_storage(tmp_path, monkeypatch):
    working = tmp_path / "checkout"
    working.mkdir()
    monkeypatch.chdir(working)
    directory = tmp_path / "local-app-data" / "SpecterLAN"

    def app_data(appname, *, appauthor, roaming):
        assert (appname, appauthor, roaming) == ("SpecterLAN", False, False)
        return directory

    monkeypatch.setattr(storage_paths, "user_data_path", app_data)
    return directory, working


def save_scan(store):
    devices, vanished = store.annotate_states([DEVICE.model_copy()], NETWORK)
    store.save(
        ScanResult(
            network=NETWORK,
            local_ip="192.168.1.1",
            scanner="test",
            devices=devices,
            vanished=vanished,
        )
    )


def test_default_storage_uses_os_app_data_without_identity_lookup(local_storage, monkeypatch):
    directory, working = local_storage

    def forbidden():
        pytest.fail("Storage must not look up an account name")

    monkeypatch.setattr(getpass, "getuser", forbidden)
    monkeypatch.setattr(os, "getlogin", forbidden)
    monkeypatch.delenv("USERNAME", raising=False)
    monkeypatch.delenv("USER", raising=False)
    store = SnapshotStore()
    save_scan(store)
    store.update_metadata(
        DEVICE,
        NETWORK,
        DeviceMetadata(friendly_name="Office", trust_status="trusted", device_type="server"),
    )
    store.save_model_preference("qwen3.5:4b")
    assert Path(store.path) == directory / "specterlan.db"
    assert not list(working.iterdir())

    # Changing the launch directory must not create a second live database.
    elsewhere = working / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    reopened = SnapshotStore()
    assert len(reopened.recent_scans(NETWORK)) == 1
    metadata = reopened.apply_metadata([DEVICE], NETWORK)[0]
    assert (metadata.friendly_name, metadata.trust_status, metadata.device_type) == (
        "Office",
        "trusted",
        "server",
    )
    assert reopened.model_preference() == "qwen3.5:4b"


def test_windows_resolver_selects_local_not_roaming_app_data(tmp_path, monkeypatch):
    from platformdirs import windows

    requested = []

    def shell_folder(name):
        requested.append(name)
        return str(tmp_path / "Local")

    monkeypatch.setattr(windows, "get_win_folder", shell_folder)
    directory = Windows("SpecterLAN", appauthor=False, roaming=False).user_data_path
    assert directory == tmp_path / "Local" / "SpecterLAN"
    assert requested == ["CSIDL_LOCAL_APPDATA"]


def test_two_devices_on_same_lan_keep_independent_history_and_labels(local_storage, monkeypatch):
    directory, _ = local_storage
    laptop_a = SnapshotStore()
    save_scan(laptop_a)
    laptop_a.update_metadata(DEVICE, NETWORK, DeviceMetadata(friendly_name="A only"))
    laptop_a.save_model_preference("qwen3.5:4b")
    monkeypatch.setattr(storage_paths, "user_data_path", lambda *a, **k: directory.parent / "B")
    laptop_b = SnapshotStore()
    assert laptop_b.recent_scans(NETWORK) == []
    assert laptop_b.model_preference() is None
    save_scan(laptop_b)
    assert laptop_b.apply_metadata([DEVICE], NETWORK)[0].friendly_name == ""
    assert laptop_a.apply_metadata([DEVICE], NETWORK)[0].friendly_name == "A only"
    assert len(laptop_a.recent_scans(NETWORK)) == 1
    assert laptop_a.path != laptop_b.path


def test_legacy_backup_preserves_history_metadata_preferences_and_committed_wal(local_storage):
    directory, working = local_storage
    legacy = SnapshotStore(working / ".specterlan.db")
    save_scan(legacy)
    legacy.update_metadata(
        DEVICE,
        NETWORK,
        DeviceMetadata(friendly_name="Preserved", trust_status="ignored", device_type="camera"),
    )
    with sqlite3.connect(legacy.path) as con:
        before = con.execute("SELECT * FROM scans").fetchall()
    # Keep this connection open so the latest write remains in WAL during import.
    con = sqlite3.connect(legacy.path)
    try:
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("INSERT INTO app_preferences VALUES ('ollama_model', 'qwen3.5:4b')")
        con.commit()
        migrated = SnapshotStore()
        assert migrated.model_preference() == "qwen3.5:4b"
        with sqlite3.connect(migrated.path) as new:
            assert new.execute("SELECT * FROM scans").fetchall() == before
            assert new.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert con.execute("SELECT * FROM scans").fetchall() == before
    finally:
        con.close()
    assert Path(legacy.path).exists()
    assert migrated.apply_metadata([DEVICE], NETWORK)[0].friendly_name == "Preserved"
    assert not list(directory.glob("migration-*"))
    # Subsequent starts must neither merge nor overwrite from the legacy file.
    save_scan(legacy)
    assert len(SnapshotStore().recent_scans(NETWORK)) == 1


def test_v2_legacy_migrates_preferences_without_changing_scan_rows(local_storage):
    _, working = local_storage
    legacy = SnapshotStore(working / ".specterlan.db")
    save_scan(legacy)
    with sqlite3.connect(legacy.path) as con:
        con.execute("DROP TABLE app_preferences")
        con.execute("PRAGMA user_version = 2")
        before = con.execute("SELECT * FROM scans").fetchall()
    migrated = SnapshotStore()
    assert migrated.model_preference() is None
    with sqlite3.connect(migrated.path) as con:
        assert con.execute("SELECT * FROM scans").fetchall() == before
        assert con.execute("PRAGMA user_version").fetchone()[0] == 3
    with sqlite3.connect(legacy.path) as con:
        assert con.execute("PRAGMA user_version").fetchone()[0] == 2


def test_existing_destination_wins_over_legacy(local_storage):
    _, working = local_storage
    live = SnapshotStore()
    live.save_model_preference("local-choice")
    legacy = SnapshotStore(working / ".specterlan.db")
    save_scan(legacy)
    assert SnapshotStore().model_preference() == "local-choice"
    assert SnapshotStore().recent_scans(NETWORK) == []


def test_failed_legacy_copy_leaves_source_and_no_partial_destination(local_storage):
    directory, working = local_storage
    legacy = working / ".specterlan.db"
    legacy.write_bytes(b"not a SQLite database")
    with pytest.raises(sqlite3.DatabaseError):
        SnapshotStore()
    assert legacy.read_bytes() == b"not a SQLite database"
    assert list(directory.iterdir()) == []


def test_permission_failure_never_falls_back_to_working_directory(local_storage, monkeypatch):
    _, working = local_storage

    def denied(*args, **kwargs):
        raise PermissionError("Local app-data access denied")

    monkeypatch.setattr(Path, "mkdir", denied)
    with pytest.raises(PermissionError):
        SnapshotStore()
    assert list(working.iterdir()) == []


def test_relative_app_data_is_rejected_without_writing(local_storage, monkeypatch):
    _, working = local_storage
    monkeypatch.setattr(storage_paths, "user_data_path", lambda *a, **k: Path("relative"))
    with pytest.raises(OSError, match="absolute"):
        SnapshotStore()
    assert list(working.iterdir()) == []


def test_remote_app_data_is_rejected_without_creating_database(local_storage, monkeypatch):
    directory, _ = local_storage
    monkeypatch.setattr(storage_paths, "_is_remote_drive", lambda path: True)
    with pytest.raises(OSError, match="local application-data"):
        SnapshotStore()
    assert not directory.exists()


def test_linked_database_is_rejected_without_touching_target(local_storage):
    directory, working = local_storage
    directory.mkdir(parents=True)
    target = working / "other.db"
    target.write_bytes(b"untouched")
    try:
        (directory / "specterlan.db").symlink_to(target)
    except OSError:
        pytest.skip("Creating symlinks requires OS permission")
    with pytest.raises(OSError, match="symbolic link"):
        SnapshotStore()
    assert target.read_bytes() == b"untouched"


def test_app_data_path_is_a_file_fails_without_fallback(local_storage):
    directory, working = local_storage
    directory.parent.mkdir(parents=True)
    directory.write_bytes(b"not a directory")
    with pytest.raises(FileExistsError):
        SnapshotStore()
    assert directory.read_bytes() == b"not a directory"
    assert not list(working.iterdir())


def test_concurrent_legacy_startups_do_not_duplicate_or_replace_data(local_storage):
    directory, working = local_storage
    legacy = SnapshotStore(working / ".specterlan.db")
    save_scan(legacy)
    with ThreadPoolExecutor(max_workers=3) as pool:
        stores = list(pool.map(lambda _: SnapshotStore(), range(3)))
    assert {store.path for store in stores} == {str(directory / "specterlan.db")}
    assert all(len(store.recent_scans(NETWORK)) == 1 for store in stores)
    assert not list(directory.glob("migration-*"))


def test_demo_never_resolves_or_migrates_live_storage(local_storage, monkeypatch):
    _, working = local_storage
    legacy = working / ".specterlan.db"
    legacy.write_bytes(b"untouched live file")

    def forbidden(*args, **kwargs):
        pytest.fail("Demo must not resolve live app data")

    monkeypatch.setattr(storage_paths, "user_data_path", forbidden)
    demo = DemoSession()
    try:
        demo.advance()
        demo.reset()
        assert legacy.read_bytes() == b"untouched live file"
    finally:
        path = Path(demo.store.path)
        demo.close()
    assert not path.exists()
