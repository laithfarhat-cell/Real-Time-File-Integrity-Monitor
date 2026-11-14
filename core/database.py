"""SQLite cryptographic baseline state manager with tamper-evident manifest digest."""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from core.hasher import FileMetadata, normalize_path

logger = logging.getLogger("fim.database")

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class BaselineSummary:
    """Summary returned when initializing or inspecting a baseline database."""

    db_path: str
    file_count: int
    total_bytes: int
    initialized_at: str
    hostname: str
    manifest_sha256: str


def _compute_manifest_digest(records: List[FileMetadata]) -> str:
    """Compute a deterministic SHA-256 digest over all sorted baseline records."""
    hasher = hashlib.sha256()
    for rec in sorted(records, key=lambda r: r.path):
        line = (
            f"{rec.path}|{rec.sha256}|{rec.size}|"
            f"{rec.mode:04o}|{rec.uid}|{rec.gid}|{int(rec.is_symlink)}\n"
        )
        hasher.update(line.encode("utf-8", errors="surrogateescape"))
    return hasher.hexdigest()


class BaselineDatabase:
    """Thread-safe SQLite manager for FIM baseline records and metadata."""

    def __init__(self, db_path: str = "./baseline.db", read_only: bool = False) -> None:
        self.db_path = normalize_path(db_path) if db_path != ":memory:" else ":memory:"
        self.read_only = read_only
        self._lock = threading.RLock()
        self._conn = self._connect()
        if not self.read_only:
            self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            conn = sqlite3.connect(":memory:", check_same_thread=False)
            conn.row_factory = sqlite3.Row
            return conn

        if self.read_only:
            if not os.path.exists(self.db_path):
                raise FileNotFoundError(
                    f"Baseline database not found at {self.db_path}. "
                    "Run with --init first to establish a cryptographic baseline."
                )
            uri = f"file:{self.db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            return conn

        parent_dir = os.path.dirname(self.db_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        try:
            conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
            except sqlite3.OperationalError as exc:
                logger.debug("Could not set WAL mode on %s: %s", self.db_path, exc)
            return conn
        except sqlite3.OperationalError:
            # Fallback to read-only URI if database sits on a read-only mount
            if os.path.exists(self.db_path):
                logger.info(
                    "Opening baseline database %s in read-only mode", self.db_path
                )
                self.read_only = True
                uri = f"file:{self.db_path}?mode=ro"
                conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                return conn
            raise

    def _ensure_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS baseline_files (
                    path        TEXT PRIMARY KEY,
                    sha256      TEXT NOT NULL,
                    size        INTEGER NOT NULL,
                    mode        INTEGER NOT NULL,
                    uid         INTEGER NOT NULL,
                    gid         INTEGER NOT NULL,
                    mtime       REAL NOT NULL,
                    inode       INTEGER NOT NULL DEFAULT 0,
                    is_symlink  INTEGER NOT NULL DEFAULT 0,
                    captured_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS baseline_metadata (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def is_initialized(self) -> bool:
        """Return True if the database contains an initialized baseline schema."""
        with self._lock:
            try:
                row = self._conn.execute(
                    "SELECT value FROM baseline_metadata WHERE key = 'initialized_at'"
                ).fetchone()
                return row is not None
            except sqlite3.OperationalError:
                return False

    def initialize_baseline(self, records: Iterable[FileMetadata]) -> BaselineSummary:
        """Atomically replace baseline contents and store tamper-evident digest."""
        if self.read_only:
            raise PermissionError(
                f"Cannot initialize baseline: {self.db_path} is opened read-only"
            )

        materialized = list(records)
        now_iso = datetime.now(timezone.utc).isoformat()
        hostname = socket.gethostname()
        total_bytes = sum(r.size for r in materialized)
        manifest_sha256 = _compute_manifest_digest(materialized)

        with self._lock, self._conn:
            self._conn.execute("DELETE FROM baseline_files")
            self._conn.execute("DELETE FROM baseline_metadata")

            self._conn.executemany(
                """
                INSERT INTO baseline_files (
                    path, sha256, size, mode, uid, gid, mtime, inode, is_symlink, captured_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        r.path,
                        r.sha256,
                        r.size,
                        r.mode,
                        r.uid,
                        r.gid,
                        r.mtime,
                        r.inode,
                        int(r.is_symlink),
                        now_iso,
                    )
                    for r in materialized
                ],
            )

            meta_rows = [
                ("schema_version", SCHEMA_VERSION),
                ("initialized_at", now_iso),
                ("hostname", hostname),
                ("file_count", str(len(materialized))),
                ("total_bytes", str(total_bytes)),
                ("manifest_sha256", manifest_sha256),
            ]
            self._conn.executemany(
                "INSERT INTO baseline_metadata (key, value) VALUES (?, ?)",
                meta_rows,
            )

        # Restrict baseline database permissions on POSIX systems (owner rw only)
        if self.db_path != ":memory:" and os.name == "posix":
            for suffix in ("", "-wal", "-shm"):
                candidate = f"{self.db_path}{suffix}"
                if os.path.exists(candidate):
                    try:
                        os.chmod(candidate, 0o600)
                    except OSError:
                        pass

        logger.info(
            "Baseline initialized at %s (%d files, %d bytes, manifest=%s)",
            self.db_path,
            len(materialized),
            total_bytes,
            manifest_sha256[:16],
        )

        return BaselineSummary(
            db_path=self.db_path,
            file_count=len(materialized),
            total_bytes=total_bytes,
            initialized_at=now_iso,
            hostname=hostname,
            manifest_sha256=manifest_sha256,
        )

    @staticmethod
    def _row_to_metadata(row: sqlite3.Row) -> FileMetadata:
        return FileMetadata(
            path=row["path"],
            sha256=row["sha256"],
            size=int(row["size"]),
            mode=int(row["mode"]),
            uid=int(row["uid"]),
            gid=int(row["gid"]),
            mtime=float(row["mtime"]),
            inode=int(row["inode"]),
            is_symlink=bool(row["is_symlink"]),
        )

    def get_record(self, path: str) -> Optional[FileMetadata]:
        """Fetch baseline metadata for a single normalized path."""
        norm = normalize_path(path)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM baseline_files WHERE path = ?",
                (norm,),
            ).fetchone()
            return self._row_to_metadata(row) if row is not None else None

    def get_all_records(self) -> Dict[str, FileMetadata]:
        """Load all baseline records indexed by normalized file path."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM baseline_files ORDER BY path ASC"
            ).fetchall()
            return {row["path"]: self._row_to_metadata(row) for row in rows}

    def get_metadata(self) -> Dict[str, str]:
        """Return baseline metadata key-value dictionary."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, value FROM baseline_metadata"
            ).fetchall()
            return {row["key"]: row["value"] for row in rows}

    def count_records(self) -> int:
        """Return total number of tracked files in the baseline."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM baseline_files"
            ).fetchone()
            return int(row["cnt"]) if row is not None else 0

    def verify_database_integrity(self) -> Tuple[bool, str]:
        """Verify stored manifest SHA-256 against current SQLite rows."""
        with self._lock:
            meta = self.get_metadata()
            expected = meta.get("manifest_sha256")
            if not expected:
                return False, "Missing manifest_sha256 in baseline_metadata"
            records = list(self.get_all_records().values())
            actual = _compute_manifest_digest(records)
            if actual != expected:
                return (
                    False,
                    f"Baseline manifest mismatch (expected {expected[:16]}..., got {actual[:16]}...)",
                )
            return True, actual

    def get_protected_paths(self) -> List[str]:
        """Return filesystem paths associated with this SQLite database (main, WAL, SHM)."""
        if self.db_path == ":memory:":
            return []
        return [
            self.db_path,
            f"{self.db_path}-wal",
            f"{self.db_path}-shm",
            f"{self.db_path}-journal",
        ]

    def close(self) -> None:
        """Close the underlying SQLite connection safely."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "BaselineDatabase":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
