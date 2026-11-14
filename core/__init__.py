"""Core cryptographic hashing, baseline persistence, and filesystem monitoring engine."""

from core.database import BaselineDatabase, BaselineSummary
from core.hasher import (
    FileMetadata,
    compute_sha256,
    extract_file_metadata,
    format_mode,
    normalize_path,
    scan_paths,
)
from core.watcher import (
    ExclusionFilter,
    FIMWatcher,
    SeverityClassifier,
    verify_filesystem_against_baseline,
)

__all__ = [
    "BaselineDatabase",
    "BaselineSummary",
    "ExclusionFilter",
    "FIMWatcher",
    "FileMetadata",
    "SeverityClassifier",
    "compute_sha256",
    "extract_file_metadata",
    "format_mode",
    "normalize_path",
    "scan_paths",
    "verify_filesystem_against_baseline",
]
