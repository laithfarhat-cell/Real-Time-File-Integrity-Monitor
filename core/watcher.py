"""Real-time OS-native filesystem watcher with debounce coalescing, exclusions, and severity rules."""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Pattern, Set, Tuple, Union

from watchdog.events import (
    FileSystemEvent,
    FileSystemEventHandler,
    FileSystemMovedEvent,
)
from watchdog.observers import Observer

from core.database import BaselineDatabase
from core.hasher import (
    DEFAULT_CHUNK_SIZE,
    FileMetadata,
    MonitoredTarget,
    extract_file_metadata,
    normalize_path,
    scan_paths,
)
from notifiers.alert_manager import SEVERITY_RANK, AlertManager, IntegrityAlert

logger = logging.getLogger("fim.watcher")


def _to_posix(path: str) -> str:
    return path.replace("\\", "/")


class ExclusionFilter:
    """Evaluates file/directory paths against glob patterns, regexes, and self-protected files."""

    def __init__(
        self,
        globs: Optional[Iterable[str]] = None,
        regexes: Optional[Iterable[str]] = None,
        protected_paths: Optional[Iterable[str]] = None,
    ) -> None:
        self.globs: List[str] = []
        for pattern in globs or []:
            pat = str(pattern).strip()
            if not pat:
                continue
            if pat.startswith("~"):
                pat = os.path.expanduser(pat)
            self.globs.append(_to_posix(pat))

        self.regexes: List[Pattern[str]] = []
        for raw_rx in regexes or []:
            rx_str = str(raw_rx).strip()
            if rx_str:
                self.regexes.append(re.compile(rx_str))

        self.protected_paths: Set[str] = {
            normalize_path(p) for p in (protected_paths or []) if p
        }

    def add_protected_paths(self, paths: Iterable[str]) -> None:
        for p in paths:
            if p:
                self.protected_paths.add(normalize_path(p))

    def is_excluded(self, path: str) -> bool:
        """Return True if ``path`` matches any protected path, glob, or regex rule."""
        norm = normalize_path(path)
        if norm in self.protected_paths:
            return True

        posix_path = _to_posix(norm)
        # Preserve trailing slash check for directories if caller passed one
        trimmed = posix_path.rstrip("/")
        basename = os.path.basename(trimmed)

        for rx in self.regexes:
            if rx.search(posix_path):
                return True

        for pat in self.globs:
            if "/" not in pat:
                if fnmatch.fnmatchcase(basename, pat) or fnmatch.fnmatchcase(
                    trimmed, pat
                ):
                    return True
                continue

            if pat.startswith("/"):
                if fnmatch.fnmatchcase(trimmed, pat):
                    return True
                if pat.endswith("/*") and trimmed == pat[:-2]:
                    return True
            else:
                # Relative segment glob such as '.git/*' or '__pycache__/*'
                if fnmatch.fnmatchcase(trimmed, pat) or fnmatch.fnmatchcase(
                    trimmed, f"*/{pat}"
                ):
                    return True
                if pat.endswith("/*"):
                    dir_token = pat[:-2].strip("/")
                    if dir_token and (
                        trimmed.endswith(f"/{dir_token}")
                        or f"/{dir_token}/" in f"{trimmed}/"
                    ):
                        return True

        return False


@dataclass(frozen=True)
class _CompiledSeverityRule:
    level: str
    pattern: Optional[str]
    regex: Optional[Pattern[str]]
    is_exact: bool
    specificity: int


class SeverityClassifier:
    """Maps file paths to CRITICAL / HIGH / MEDIUM / LOW based on configured path rules."""

    def __init__(
        self,
        rules: Optional[Iterable[Dict[str, object]]] = None,
        default_severity: str = "MEDIUM",
    ) -> None:
        default_up = default_severity.upper()
        self.default_severity = default_up if default_up in SEVERITY_RANK else "MEDIUM"
        self._rules: List[_CompiledSeverityRule] = []

        for raw in rules or []:
            level = str(raw.get("level", self.default_severity)).upper()
            if level not in SEVERITY_RANK:
                logger.warning("Ignoring unknown severity level %r in rule %r", level, raw)
                continue

            raw_regex = raw.get("regex")
            if raw_regex:
                rx_str = str(raw_regex)
                self._rules.append(
                    _CompiledSeverityRule(
                        level=level,
                        pattern=None,
                        regex=re.compile(rx_str),
                        is_exact=False,
                        specificity=len(rx_str),
                    )
                )
                continue

            raw_pat = raw.get("pattern") or raw.get("path")
            if not raw_pat:
                continue

            expanded = _to_posix(normalize_path(str(raw_pat)))
            has_wildcard = any(ch in expanded for ch in ("*", "?", "["))
            if has_wildcard:
                # Static prefix length before first wildcard character
                first_wild = min(
                    idx
                    for idx, ch in enumerate(expanded)
                    if ch in ("*", "?", "[")
                )
                spec = first_wild
            else:
                spec = len(expanded)

            self._rules.append(
                _CompiledSeverityRule(
                    level=level,
                    pattern=expanded,
                    regex=None,
                    is_exact=not has_wildcard,
                    specificity=spec,
                )
            )

    def classify(self, path: str) -> str:
        """Return highest-specificity (tie-broken by highest severity) level for ``path``."""
        posix_path = _to_posix(normalize_path(path))
        best_score: Optional[Tuple[int, int, int]] = None
        best_level = self.default_severity

        for rule in self._rules:
            matched = False
            match_kind = 1
            if rule.regex is not None:
                matched = bool(rule.regex.search(posix_path))
            elif rule.pattern is not None:
                if rule.is_exact:
                    if posix_path == rule.pattern:
                        matched = True
                        match_kind = 2
                    elif posix_path.startswith(rule.pattern.rstrip("/") + "/"):
                        # Directory path specified without trailing '/*'
                        matched = True
                        match_kind = 1
                else:
                    if fnmatch.fnmatchcase(posix_path, rule.pattern):
                        matched = True
                        match_kind = 1
                    elif rule.pattern.endswith("/*") and posix_path == rule.pattern[:-2]:
                        matched = True
                        match_kind = 1

            if matched:
                score = (
                    match_kind,
                    rule.specificity,
                    SEVERITY_RANK[rule.level],
                )
                if best_score is None or score > best_score:
                    best_score = score
                    best_level = rule.level

        return best_level


class _MonitoredScope:
    """Determines whether a filesystem event path belongs to configured targets."""

    def __init__(self) -> None:
        self.exact_files: Set[str] = set()
        self.flat_dirs: Set[str] = set()
        self.recursive_dirs: List[str] = []

    def add_exact_file(self, file_path: str) -> None:
        self.exact_files.add(normalize_path(file_path))

    def add_directory(self, dir_path: str, recursive: bool) -> None:
        norm = normalize_path(dir_path)
        if recursive:
            if norm not in self.recursive_dirs:
                self.recursive_dirs.append(norm)
        else:
            self.flat_dirs.add(norm)

    def contains(self, path: str) -> bool:
        norm = normalize_path(path)
        if norm in self.exact_files:
            return True
        parent = os.path.dirname(norm)
        if parent in self.flat_dirs:
            return True
        for rdir in self.recursive_dirs:
            prefix = "/" if rdir == "/" else rdir + os.sep
            if norm == rdir or norm.startswith(prefix):
                return True
        return False


@dataclass
class _PendingEntry:
    first_seen: float
    due_at: float


class _WatchdogBridge(FileSystemEventHandler):
    """Forwards relevant kernel filesystem events into FIMWatcher's debounce engine."""

    def __init__(self, watcher: "FIMWatcher") -> None:
        super().__init__()
        self._watcher = watcher

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._watcher.notify_path_event(os.fsdecode(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._watcher.notify_path_event(os.fsdecode(event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        src = os.fsdecode(event.src_path)
        if event.is_directory:
            self._watcher.notify_directory_deleted(src)
        else:
            self._watcher.notify_path_event(src)

    def on_moved(self, event: FileSystemMovedEvent) -> None:
        src = os.fsdecode(event.src_path)
        dst = os.fsdecode(event.dest_path)
        if event.is_directory:
            self._watcher.notify_directory_moved(src, dst)
        else:
            self._watcher.notify_move_event(src, dst)

    def on_attrib(self, event: FileSystemEvent) -> None:
        # Supported natively on watchdog >= 5.x/6.x/7.x for chmod/chown (IN_ATTRIB)
        if not event.is_directory:
            self._watcher.notify_path_event(os.fsdecode(event.src_path))


class FIMWatcher:
    """Real-time File Integrity Monitor combining OS kernel hooks, debouncing, and baseline diffing."""

    def __init__(
        self,
        targets: List[Union[str, Dict[str, object], MonitoredTarget]],
        database: BaselineDatabase,
        alert_manager: AlertManager,
        exclusion_filter: ExclusionFilter,
        severity_classifier: SeverityClassifier,
        debounce_ms: int = 500,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        follow_symlinks: bool = False,
    ) -> None:
        self.targets = [
            t if isinstance(t, MonitoredTarget) else MonitoredTarget.from_config(t)
            for t in targets
        ]
        self.database = database
        self.alert_manager = alert_manager
        self.exclusion_filter = exclusion_filter
        self.severity_classifier = severity_classifier
        self.debounce_sec = max(0.05, debounce_ms / 1000.0)
        self.max_coalesce_sec = max(0.25, self.debounce_sec * 4.0)
        self.chunk_size = chunk_size
        self.follow_symlinks = follow_symlinks

        # Ensure baseline DB and alert JSON output are always excluded
        self.exclusion_filter.add_protected_paths(self.database.get_protected_paths())
        self.exclusion_filter.add_protected_paths(
            self.alert_manager.get_protected_paths()
        )

        # Immutable cryptographic baseline + mutable live-observed state
        self._baseline: Dict[str, FileMetadata] = self.database.get_all_records()
        self._observed: Dict[str, FileMetadata] = dict(self._baseline)
        self._scope = _MonitoredScope()

        # Debounce state guarded by condition lock
        self._cond = threading.Condition()
        self._pending: Dict[str, _PendingEntry] = {}
        # Maps dest_path -> src_path for non-excluded in-scope file moves
        self._pending_moves: Dict[str, str] = {}
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._observer: Optional[Observer] = None

    def is_eligible_path(self, path: str) -> bool:
        """Return True if ``path`` falls inside monitored scope and is not excluded."""
        norm = normalize_path(path)
        return self._scope.contains(norm) and not self.exclusion_filter.is_excluded(norm)

    def _schedule_locked(self, norm_path: str, now: float) -> None:
        existing = self._pending.get(norm_path)
        if existing is None:
            self._pending[norm_path] = _PendingEntry(
                first_seen=now,
                due_at=now + self.debounce_sec,
            )
        else:
            # Extend deadline up to max_coalesce_sec so continuous writes still flush
            capped_due = min(
                now + self.debounce_sec,
                existing.first_seen + self.max_coalesce_sec,
            )
            existing.due_at = max(existing.due_at, capped_due)

    def notify_path_event(self, raw_path: str) -> None:
        """Record a create/modify/delete/attrib kernel event in the debounce buffer."""
        norm = normalize_path(raw_path)
        if not self.is_eligible_path(norm):
            return
        now = time.monotonic()
        with self._cond:
            self._schedule_locked(norm, now)
            self._cond.notify_all()

    def notify_move_event(self, raw_src: str, raw_dst: str) -> None:
        """Record a rename/relocate kernel event, handling atomic editor saves cleanly."""
        src = normalize_path(raw_src)
        dst = normalize_path(raw_dst)
        src_ok = self.is_eligible_path(src)
        dst_ok = self.is_eligible_path(dst)

        if not src_ok and not dst_ok:
            return

        now = time.monotonic()
        with self._cond:
            if src_ok and dst_ok:
                # Chain transitive moves if a -> b -> c happens within debounce window
                origin = self._pending_moves.pop(src, src)
                if origin != dst:
                    self._pending_moves[dst] = origin
                self._schedule_locked(src, now)
                self._schedule_locked(dst, now)
            elif src_ok:
                # Moved out of watched scope or moved to backup/swap file (e.g. vim foo -> foo~)
                self._schedule_locked(src, now)
            else:
                # Moved from excluded temp file onto tracked file (e.g. sed -i / vim atomic rename)
                self._schedule_locked(dst, now)
            self._cond.notify_all()

    def notify_directory_moved(self, raw_src_dir: str, raw_dst_dir: str) -> None:
        """Translate a directory rename into per-file move notifications for tracked children."""
        src_dir = normalize_path(raw_src_dir)
        dst_dir = normalize_path(raw_dst_dir)
        prefix = src_dir.rstrip(os.sep) + os.sep

        with self._cond:
            tracked_children = [
                p for p in self._observed if p == src_dir or p.startswith(prefix)
            ]

        for old_file in tracked_children:
            rel = os.path.relpath(old_file, src_dir)
            new_file = normalize_path(os.path.join(dst_dir, rel))
            self.notify_move_event(old_file, new_file)

        # Also catch any newly moved untracked files inside destination if in scope
        if os.path.isdir(dst_dir) and not self.exclusion_filter.is_excluded(dst_dir):
            for meta in scan_paths(
                [MonitoredTarget(path=dst_dir, recursive=True)],
                is_excluded=self.exclusion_filter.is_excluded,
                chunk_size=self.chunk_size,
                follow_symlinks=self.follow_symlinks,
            ):
                if meta.path not in self._pending_moves:
                    self.notify_path_event(meta.path)

    def notify_directory_deleted(self, raw_dir: str) -> None:
        """Schedule deletion checks for any tracked files under a removed directory."""
        norm_dir = normalize_path(raw_dir)
        prefix = norm_dir.rstrip(os.sep) + os.sep
        now = time.monotonic()
        with self._cond:
            for p in list(self._observed.keys()):
                if p.startswith(prefix):
                    self._schedule_locked(p, now)
            self._cond.notify_all()

    def _debounce_loop(self) -> None:
        while True:
            due_paths: List[str] = []
            due_moves: Dict[str, str] = {}

            with self._cond:
                while self._running and not self._pending:
                    self._cond.wait()

                if not self._running and not self._pending:
                    break

                now = time.monotonic()
                earliest_due = min(entry.due_at for entry in self._pending.values())
                if self._running and earliest_due > now:
                    self._cond.wait(timeout=earliest_due - now)
                    continue

                # Collect all paths whose debounce window has elapsed (or all on shutdown)
                cutoff = time.monotonic() if self._running else float("inf")
                ready = {
                    path
                    for path, entry in self._pending.items()
                    if entry.due_at <= cutoff
                }
                # Ensure move pairs flush atomically together once both endpoints settle
                for dst, src in list(self._pending_moves.items()):
                    if dst in ready or src in ready:
                        src_entry = self._pending.get(src)
                        dst_entry = self._pending.get(dst)
                        max_due = max(
                            src_entry.due_at if src_entry else 0.0,
                            dst_entry.due_at if dst_entry else 0.0,
                        )
                        if max_due <= cutoff:
                            ready.add(src)
                            ready.add(dst)
                            due_moves[dst] = self._pending_moves.pop(dst)
                        else:
                            ready.discard(src)
                            ready.discard(dst)

                for path in ready:
                    self._pending.pop(path, None)
                due_paths = sorted(ready)

            if due_paths or due_moves:
                self._process_settled_batch(due_paths, due_moves)

    def _path_exists_on_disk(self, norm_path: str) -> bool:
        try:
            os.stat(norm_path, follow_symlinks=self.follow_symlinks)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return True

    def _process_settled_batch(
        self,
        paths: List[str],
        moves: Dict[str, str],
    ) -> None:
        handled: Set[str] = set()

        # 1. Evaluate correlated FILE_MOVED pairs first
        for dst, src in sorted(moves.items()):
            dst_exists = self._path_exists_on_disk(dst)
            src_exists = self._path_exists_on_disk(src)

            if dst_exists and not src_exists:
                new_meta = extract_file_metadata(
                    dst,
                    chunk_size=self.chunk_size,
                    follow_symlinks=self.follow_symlinks,
                )
                old_meta = self._baseline.get(src) or self._observed.get(src)
                if new_meta is not None:
                    src_sev = self.severity_classifier.classify(src)
                    dst_sev = self.severity_classifier.classify(dst)
                    sev = (
                        src_sev
                        if SEVERITY_RANK[src_sev] >= SEVERITY_RANK[dst_sev]
                        else dst_sev
                    )
                    self._observed.pop(src, None)
                    self._observed[dst] = new_meta
                    handled.add(src)
                    handled.add(dst)
                    self.alert_manager.dispatch(
                        IntegrityAlert(
                            event_type="FILE_MOVED",
                            severity=sev,
                            file_path=dst,
                            source_path=src,
                            old_meta=old_meta,
                            new_meta=new_meta,
                        )
                    )

        # 2. Evaluate remaining individual paths
        for path in paths:
            if path in handled:
                continue
            self._evaluate_single_path(path)

    def _evaluate_single_path(self, norm_path: str) -> None:
        baseline_meta = self._baseline.get(norm_path)
        observed_meta = self._observed.get(norm_path)
        exists_now = self._path_exists_on_disk(norm_path)

        if not exists_now:
            if observed_meta is not None:
                ref_meta = baseline_meta or observed_meta
                self._observed.pop(norm_path, None)
                self.alert_manager.dispatch(
                    IntegrityAlert(
                        event_type="FILE_DELETED",
                        severity=self.severity_classifier.classify(norm_path),
                        file_path=norm_path,
                        old_meta=ref_meta,
                        new_meta=None,
                    )
                )
            return

        current_meta = extract_file_metadata(
            norm_path,
            chunk_size=self.chunk_size,
            follow_symlinks=self.follow_symlinks,
        )
        if current_meta is None:
            return

        # Brand new file never seen in baseline or prior runtime state
        if baseline_meta is None and observed_meta is None:
            self._observed[norm_path] = current_meta
            self.alert_manager.dispatch(
                IntegrityAlert(
                    event_type="FILE_CREATED",
                    severity=self.severity_classifier.classify(norm_path),
                    file_path=norm_path,
                    old_meta=None,
                    new_meta=current_meta,
                )
            )
            return

        # Suppress duplicate alerts if nothing changed since last processed state
        if (
            observed_meta is not None
            and current_meta.sha256 == observed_meta.sha256
            and not current_meta.has_attribute_drift(observed_meta)
        ):
            return

        ref_meta = baseline_meta or observed_meta
        assert ref_meta is not None

        # Compare content hash against authoritative reference (baseline if present)
        if current_meta.sha256 != ref_meta.sha256 and (
            observed_meta is None or current_meta.sha256 != observed_meta.sha256
        ):
            self._observed[norm_path] = current_meta
            self.alert_manager.dispatch(
                IntegrityAlert(
                    event_type="FILE_MODIFIED",
                    severity=self.severity_classifier.classify(norm_path),
                    file_path=norm_path,
                    old_meta=ref_meta,
                    new_meta=current_meta,
                )
            )
            return

        # Content hash matches prior state (or returned to baseline); check permission/owner drift
        compare_attr_meta = observed_meta or ref_meta
        if current_meta.has_attribute_drift(compare_attr_meta):
            # If content matches baseline and attributes drifted from baseline, report baseline attrs
            attr_old = (
                baseline_meta
                if (
                    baseline_meta is not None
                    and current_meta.has_attribute_drift(baseline_meta)
                )
                else compare_attr_meta
            )
            self._observed[norm_path] = current_meta
            self.alert_manager.dispatch(
                IntegrityAlert(
                    event_type="ATTRIBUTE_CHANGED",
                    severity=self.severity_classifier.classify(norm_path),
                    file_path=norm_path,
                    old_meta=attr_old,
                    new_meta=current_meta,
                )
            )
            return

        # File reverted cleanly to baseline state
        self._observed[norm_path] = current_meta

    def _prepare_schedules(self) -> List[Tuple[str, bool]]:
        """Build deduplicated ``(watch_dir, recursive)`` schedules for watchdog."""
        schedules: Dict[str, bool] = {}

        for target in self.targets:
            tpath = target.path
            if self.exclusion_filter.is_excluded(tpath):
                continue

            if os.path.isdir(tpath):
                self._scope.add_directory(tpath, recursive=target.recursive)
                schedules[tpath] = schedules.get(tpath, False) or target.recursive
            elif os.path.exists(tpath) or os.path.islink(tpath) or tpath in self._baseline:
                parent = os.path.dirname(tpath) or "."
                if os.path.isdir(parent):
                    self._scope.add_exact_file(tpath)
                    if parent not in schedules:
                        schedules[parent] = False
                else:
                    logger.warning(
                        "Parent directory does not exist for monitored file: %s", tpath
                    )
            else:
                logger.warning(
                    "Monitored path does not exist (skipping): %s", tpath
                )

        return sorted(schedules.items())

    def start(self) -> int:
        """Start OS-native watchdog observer and debounce worker. Returns scheduled watch count."""
        if self._running:
            return 0

        schedules = self._prepare_schedules()
        if not schedules:
            raise RuntimeError(
                "No accessible monitored_paths available to watch. Check config.yaml."
            )

        handler = _WatchdogBridge(self)
        observer = Observer()
        scheduled_count = 0
        for watch_dir, recursive in schedules:
            try:
                observer.schedule(handler, watch_dir, recursive=recursive)
                scheduled_count += 1
                logger.info(
                    "Registered kernel watch on %s (recursive=%s)",
                    watch_dir,
                    recursive,
                )
            except OSError as exc:
                logger.error("Failed to schedule watch on %s: %s", watch_dir, exc)

        if scheduled_count == 0:
            raise RuntimeError("Failed to register any OS kernel filesystem watches.")

        self._running = True
        self._worker_thread = threading.Thread(
            target=self._debounce_loop,
            name="fim-debounce",
            daemon=True,
        )
        self._worker_thread.start()
        observer.start()
        self._observer = observer
        return scheduled_count

    def stop(self) -> None:
        """Gracefully stop kernel observer and flush remaining debounced events."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5.0)
            self._observer = None

        with self._cond:
            self._running = False
            self._cond.notify_all()

        if self._worker_thread is not None:
            self._worker_thread.join(timeout=5.0)
            self._worker_thread = None


def verify_filesystem_against_baseline(
    targets: List[Union[str, Dict[str, object], MonitoredTarget]],
    database: BaselineDatabase,
    exclusion_filter: ExclusionFilter,
    severity_classifier: SeverityClassifier,
    alert_manager: Optional[AlertManager] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    follow_symlinks: bool = False,
) -> List[IntegrityAlert]:
    """Perform a full cryptographic audit comparing disk state against ``baseline.db``."""
    exclusion_filter.add_protected_paths(database.get_protected_paths())
    if alert_manager is not None:
        exclusion_filter.add_protected_paths(alert_manager.get_protected_paths())

    baseline_records = database.get_all_records()
    current_records: Dict[str, FileMetadata] = {
        meta.path: meta
        for meta in scan_paths(
            targets,
            is_excluded=exclusion_filter.is_excluded,
            chunk_size=chunk_size,
            follow_symlinks=follow_symlinks,
        )
    }

    alerts: List[IntegrityAlert] = []
    all_paths = sorted(set(baseline_records.keys()) | set(current_records.keys()))

    for path in all_paths:
        if exclusion_filter.is_excluded(path):
            continue
        old_meta = baseline_records.get(path)
        new_meta = current_records.get(path)

        alert: Optional[IntegrityAlert] = None
        if old_meta is None and new_meta is not None:
            alert = IntegrityAlert(
                event_type="FILE_CREATED",
                severity=severity_classifier.classify(path),
                file_path=path,
                old_meta=None,
                new_meta=new_meta,
            )
        elif old_meta is not None and new_meta is None:
            alert = IntegrityAlert(
                event_type="FILE_DELETED",
                severity=severity_classifier.classify(path),
                file_path=path,
                old_meta=old_meta,
                new_meta=None,
            )
        elif old_meta is not None and new_meta is not None:
            if old_meta.sha256 != new_meta.sha256:
                alert = IntegrityAlert(
                    event_type="FILE_MODIFIED",
                    severity=severity_classifier.classify(path),
                    file_path=path,
                    old_meta=old_meta,
                    new_meta=new_meta,
                )
            elif new_meta.has_attribute_drift(old_meta):
                alert = IntegrityAlert(
                    event_type="ATTRIBUTE_CHANGED",
                    severity=severity_classifier.classify(path),
                    file_path=path,
                    old_meta=old_meta,
                    new_meta=new_meta,
                )

        if alert is not None:
            alerts.append(alert)
            if alert_manager is not None:
                alert_manager.dispatch(alert)

    return alerts
