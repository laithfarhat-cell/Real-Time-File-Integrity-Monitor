"""Chunked cryptographic SHA-256 hashing and POSIX metadata extraction."""

from __future__ import annotations

import hashlib
import logging
import os
import stat
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple, Union

logger = logging.getLogger("fim.hasher")

DEFAULT_CHUNK_SIZE = 65536  # 64 KiB


def normalize_path(path: str) -> str:
    """Expand '~' and normalize path without dereferencing leaf symlinks."""
    return os.path.abspath(os.path.expanduser(path))


def format_mode(mode: int) -> str:
    """Format POSIX permission bits (including SUID/SGID/sticky) as 4-digit octal."""
    return f"{stat.S_IMODE(mode):04o}"


@dataclass(frozen=True)
class FileMetadata:
    """Immutable cryptographic & POSIX metadata snapshot for a single file."""

    path: str
    sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime: float
    inode: int = 0
    is_symlink: bool = False

    @property
    def mode_octal(self) -> str:
        """Return 4-digit octal mode string, e.g. '0644' or '4755'."""
        return format_mode(self.mode)

    def has_attribute_drift(self, other: "FileMetadata") -> bool:
        """Return True if permissions (mode) or ownership (UID/GID) differ."""
        return (
            self.mode != other.mode
            or self.uid != other.uid
            or self.gid != other.gid
        )


def compute_sha256(
    file_path: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    follow_symlinks: bool = False,
) -> str:
    """Compute SHA-256 digest of a regular file in memory-safe fixed-size chunks.

    If ``file_path`` is a symbolic link and ``follow_symlinks`` is False, hashes
    the raw symlink target bytes (prefixed with ``symlink:``) so symlink retargeting
    is cryptographically detected without following untrusted links.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")

    if not follow_symlinks and os.path.islink(file_path):
        target = os.readlink(file_path)
        digest = hashlib.sha256()
        digest.update(b"symlink:")
        digest.update(os.fsencode(target))
        return digest.hexdigest()

    digest = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def extract_file_metadata(
    file_path: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    follow_symlinks: bool = False,
) -> Optional[FileMetadata]:
    """Extract SHA-256 digest and POSIX metadata for ``file_path``.

    Safely skips directories, FIFOs, sockets, and block/character devices so the
    daemon never blocks on special files. Returns ``None`` if the file is missing,
    inaccessible, or not a regular file / tracked symlink.
    """
    norm_path = normalize_path(file_path)
    try:
        st = os.stat(norm_path, follow_symlinks=follow_symlinks)
    except FileNotFoundError:
        logger.debug("File vanished before stat: %s", norm_path)
        return None
    except PermissionError:
        logger.warning("Permission denied reading metadata: %s", norm_path)
        return None
    except OSError as exc:
        logger.warning("OS error stating %s: %s", norm_path, exc)
        return None

    file_type = st.st_mode
    is_link = stat.S_ISLNK(file_type)
    is_reg = stat.S_ISREG(file_type)

    if not (is_reg or (is_link and not follow_symlinks)):
        # Skip directories, FIFOs, sockets, and device nodes
        logger.debug("Skipping non-regular file: %s (mode=%o)", norm_path, file_type)
        return None

    try:
        sha256_hex = compute_sha256(
            norm_path,
            chunk_size=chunk_size,
            follow_symlinks=follow_symlinks,
        )
    except FileNotFoundError:
        logger.debug("File vanished during hashing: %s", norm_path)
        return None
    except PermissionError:
        logger.warning("Permission denied hashing file: %s", norm_path)
        return None
    except OSError as exc:
        logger.warning("OS error hashing %s: %s", norm_path, exc)
        return None

    return FileMetadata(
        path=norm_path,
        sha256=sha256_hex,
        size=st.st_size,
        mode=stat.S_IMODE(st.st_mode),
        uid=st.st_uid,
        gid=st.st_gid,
        mtime=st.st_mtime,
        inode=st.st_ino,
        is_symlink=is_link,
    )


@dataclass(frozen=True)
class MonitoredTarget:
    """Normalized representation of an entry in ``monitored_paths``."""

    path: str
    recursive: bool = True

    @classmethod
    def from_config(cls, entry: Union[str, Dict[str, object]]) -> "MonitoredTarget":
        if isinstance(entry, str):
            return cls(path=normalize_path(entry), recursive=True)
        if isinstance(entry, dict) and "path" in entry:
            raw_path = str(entry["path"])
            recursive = bool(entry.get("recursive", True))
            return cls(path=normalize_path(raw_path), recursive=recursive)
        raise ValueError(f"Invalid monitored_paths entry: {entry!r}")


def scan_paths(
    targets: List[Union[str, Dict[str, object], MonitoredTarget]],
    is_excluded: Optional[Callable[[str], bool]] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    follow_symlinks: bool = False,
) -> Iterator[FileMetadata]:
    """Recursively traverse configured targets and yield ``FileMetadata`` snapshots.

    Deduplicates overlapping paths, prunes excluded directories before descending,
    and protects against cyclic symlink loops when ``follow_symlinks=True``.
    """
    seen_files: Set[str] = set()
    visited_dirs: Set[Tuple[int, int]] = set()

    def excluded(candidate: str) -> bool:
        return bool(is_excluded and is_excluded(candidate))

    for raw_target in targets:
        target = (
            raw_target
            if isinstance(raw_target, MonitoredTarget)
            else MonitoredTarget.from_config(raw_target)
        )
        root_path = target.path

        if excluded(root_path):
            logger.debug("Skipping excluded target root: %s", root_path)
            continue

        try:
            st = os.stat(root_path, follow_symlinks=follow_symlinks)
        except FileNotFoundError:
            logger.warning("Monitored path does not exist (skipping): %s", root_path)
            continue
        except PermissionError:
            logger.warning("Permission denied accessing monitored path: %s", root_path)
            continue
        except OSError as exc:
            logger.warning("Cannot access monitored path %s: %s", root_path, exc)
            continue

        if not stat.S_ISDIR(st.st_mode):
            if root_path not in seen_files:
                seen_files.add(root_path)
                meta = extract_file_metadata(
                    root_path,
                    chunk_size=chunk_size,
                    follow_symlinks=follow_symlinks,
                )
                if meta is not None:
                    yield meta
            continue

        if not target.recursive:
            try:
                with os.scandir(root_path) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except (PermissionError, OSError) as exc:
                logger.warning("Unable to list directory %s: %s", root_path, exc)
                continue

            for entry in entries:
                full_path = normalize_path(entry.path)
                if full_path in seen_files or excluded(full_path):
                    continue
                try:
                    if entry.is_dir(follow_symlinks=follow_symlinks):
                        continue
                except OSError:
                    continue
                seen_files.add(full_path)
                meta = extract_file_metadata(
                    full_path,
                    chunk_size=chunk_size,
                    follow_symlinks=follow_symlinks,
                )
                if meta is not None:
                    yield meta
            continue

        def _on_walk_error(err: OSError) -> None:
            logger.warning("Directory traversal error: %s", err)

        for current_root, dirs, files in os.walk(
            root_path,
            topdown=True,
            onerror=_on_walk_error,
            followlinks=follow_symlinks,
        ):
            norm_root = normalize_path(current_root)
            if follow_symlinks:
                try:
                    dir_st = os.stat(norm_root, follow_symlinks=True)
                    dir_key = (dir_st.st_dev, dir_st.st_ino)
                    if dir_key in visited_dirs:
                        logger.warning(
                            "Detected symlink directory cycle, pruning: %s", norm_root
                        )
                        dirs[:] = []
                        continue
                    visited_dirs.add(dir_key)
                except OSError:
                    dirs[:] = []
                    continue

            # Prune excluded subdirectories in-place and traverse deterministically
            pruned_dirs: List[str] = []
            for d in sorted(dirs):
                dir_path = normalize_path(os.path.join(norm_root, d))
                if excluded(dir_path) or excluded(dir_path + "/"):
                    logger.debug("Pruning excluded directory: %s", dir_path)
                    continue
                pruned_dirs.append(d)
            dirs[:] = pruned_dirs

            for fname in sorted(files):
                full_path = normalize_path(os.path.join(norm_root, fname))
                if full_path in seen_files or excluded(full_path):
                    continue
                seen_files.add(full_path)
                meta = extract_file_metadata(
                    full_path,
                    chunk_size=chunk_size,
                    follow_symlinks=follow_symlinks,
                )
                if meta is not None:
                    yield meta
