"""Resolve local storage without collecting or assigning an application identity."""

from __future__ import annotations

import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from tempfile import NamedTemporaryFile

from platformdirs import user_data_path


def local_database_path() -> Path:
    """Use OS local app data, never the roaming directory or a username lookup."""
    directory = user_data_path("SpecterLAN", appauthor=False, roaming=False)
    if not directory.is_absolute():
        raise OSError("Local application-data directory must be absolute.")
    resolved = directory.resolve()
    if resolved.drive.startswith("\\\\") or _is_remote_drive(resolved):
        raise OSError("SpecterLAN requires a local application-data directory.")
    if directory.is_symlink() or getattr(directory, "is_junction", lambda: False)():
        raise OSError("SpecterLAN application-data directory must not be a link.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = directory / "specterlan.db"
    if destination.is_symlink():
        raise OSError("SpecterLAN database must not be a symbolic link.")
    if not destination.exists():
        legacy = Path.cwd() / ".specterlan.db"
        if legacy.is_file():
            _copy_legacy_database(legacy, destination)
    return destination


def _is_remote_drive(path: Path) -> bool:
    if sys.platform != "win32":
        return False
    import ctypes

    # DRIVE_REMOTE also catches Windows mapped network drives.
    return ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(path.anchor)) == 4


def _copy_legacy_database(source: Path, destination: Path) -> None:
    """Publish a complete SQLite backup without overwriting data or deleting the source."""
    with NamedTemporaryFile(
        dir=destination.parent, prefix="migration-", suffix=".db", delete=False
    ) as f:
        temporary = Path(f.name)
    try:
        with (
            closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as old,
            closing(sqlite3.connect(temporary)) as new,
        ):
            old.backup(new)
            if new.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise sqlite3.DatabaseError("Legacy database integrity check failed.")
        try:
            # Same-directory hard link publishes atomically and refuses an existing target.
            os.link(temporary, destination)
        except FileExistsError:
            pass  # Another startup already initialized the local database.
    finally:
        temporary.unlink(missing_ok=True)
