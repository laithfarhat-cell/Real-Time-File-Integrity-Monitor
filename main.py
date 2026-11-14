#!/usr/bin/env python3
"""CLI entrypoint and daemon lifecycle controller for Real-Time File Integrity Monitor."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from typing import Any, Dict, Optional

import yaml

from core.database import BaselineDatabase
from core.hasher import DEFAULT_CHUNK_SIZE, normalize_path, scan_paths
from core.watcher import (
    ExclusionFilter,
    FIMWatcher,
    SeverityClassifier,
    verify_filesystem_against_baseline,
)
from notifiers.alert_manager import AlertManager

logger = logging.getLogger("fim.main")


def configure_logging(verbose: bool = False) -> None:
    """Configure structured timestamped console logging for daemon/systemd output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def load_config(config_path: str) -> Dict[str, Any]:
    """Load and validate YAML configuration file."""
    resolved = normalize_path(config_path)
    if not os.path.isfile(resolved):
        raise FileNotFoundError(f"Configuration file not found: {resolved}")

    with open(resolved, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Top-level YAML configuration in {resolved} must be a mapping")
    return data


def _prefix_host_root(raw_path: str, host_root: str) -> str:
    """Optionally remap host paths (e.g. /etc/passwd -> /host/etc/passwd in containers)."""
    expanded = os.path.expanduser(raw_path)
    if not host_root or not expanded.startswith("/"):
        return expanded
    norm_root = host_root.rstrip("/")
    if not norm_root or expanded == norm_root or expanded.startswith(norm_root + "/"):
        return expanded
    return f"{norm_root}{expanded}"


def _build_components(
    config: Dict[str, Any],
    db_override: Optional[str] = None,
    alerts_override: Optional[str] = None,
) -> Dict[str, Any]:
    engine_cfg = config.get("engine") or {}
    db_path = db_override or str(engine_cfg.get("database_path", "./baseline.db"))
    chunk_size = int(engine_cfg.get("chunk_size", DEFAULT_CHUNK_SIZE))
    debounce_ms = int(engine_cfg.get("debounce_ms", 500))
    follow_symlinks = bool(engine_cfg.get("follow_symlinks", False))
    host_root = (
        os.environ.get("FIM_HOST_ROOT")
        or str(engine_cfg.get("host_root", ""))
    ).strip()

    raw_targets = config.get("monitored_paths") or []
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ValueError("config.yaml must define a non-empty 'monitored_paths' list")

    targets = []
    for entry in raw_targets:
        if isinstance(entry, str):
            targets.append(_prefix_host_root(entry, host_root))
        elif isinstance(entry, dict) and "path" in entry:
            remapped = dict(entry)
            remapped["path"] = _prefix_host_root(str(entry["path"]), host_root)
            targets.append(remapped)
        else:
            raise ValueError(f"Invalid monitored_paths entry: {entry!r}")

    excl_cfg = config.get("exclusions") or {}
    exclusion_filter = ExclusionFilter(
        globs=excl_cfg.get("globs") or [],
        regexes=excl_cfg.get("regex") or [],
    )

    sev_cfg = config.get("severity") or {}
    raw_rules = sev_cfg.get("rules") or []
    remapped_rules = []
    for rule in raw_rules:
        if isinstance(rule, dict) and ("pattern" in rule or "path" in rule):
            r_copy = dict(rule)
            key = "pattern" if "pattern" in r_copy else "path"
            r_copy[key] = _prefix_host_root(str(r_copy[key]), host_root)
            remapped_rules.append(r_copy)
        else:
            remapped_rules.append(rule)

    severity_classifier = SeverityClassifier(
        rules=remapped_rules,
        default_severity=str(sev_cfg.get("default_severity", "MEDIUM")),
    )

    alert_cfg = dict(config.get("alerting") or {})
    if alerts_override:
        alert_cfg["ecs_log_file"] = alerts_override

    return {
        "db_path": db_path,
        "chunk_size": chunk_size,
        "debounce_ms": debounce_ms,
        "follow_symlinks": follow_symlinks,
        "targets": targets,
        "exclusion_filter": exclusion_filter,
        "severity_classifier": severity_classifier,
        "alert_cfg": alert_cfg,
    }


def run_init(components: Dict[str, Any]) -> int:
    """Execute --init mode: compute SHA-256 + POSIX metadata baseline into SQLite."""
    db_path = components["db_path"]
    exclusion_filter: ExclusionFilter = components["exclusion_filter"]
    alert_file = normalize_path(
        str(components["alert_cfg"].get("ecs_log_file", "./fim_alerts.json"))
    )

    with BaselineDatabase(db_path=db_path, read_only=False) as db:
        exclusion_filter.add_protected_paths(db.get_protected_paths())
        exclusion_filter.add_protected_paths([alert_file])

        logger.info("Scanning monitored paths to build cryptographic baseline...")
        started = time.monotonic()
        records = list(
            scan_paths(
                targets=components["targets"],
                is_excluded=exclusion_filter.is_excluded,
                chunk_size=components["chunk_size"],
                follow_symlinks=components["follow_symlinks"],
            )
        )
        summary = db.initialize_baseline(records)
        elapsed = time.monotonic() - started

    logger.info(
        "Baseline complete in %.2fs | files=%d | bytes=%d | db=%s | manifest_sha256=%s",
        elapsed,
        summary.file_count,
        summary.total_bytes,
        summary.db_path,
        summary.manifest_sha256,
    )
    return 0


def run_verify(components: Dict[str, Any]) -> int:
    """Execute --verify mode: one-shot cryptographic audit against baseline.db."""
    db_path = components["db_path"]
    alert_manager = AlertManager(components["alert_cfg"])

    try:
        with BaselineDatabase(db_path=db_path, read_only=True) as db:
            if not db.is_initialized():
                logger.error(
                    "Baseline database %s is not initialized. Run '--init' first.",
                    db.db_path,
                )
                return 1

            db_ok, db_msg = db.verify_database_integrity()
            if not db_ok:
                logger.critical(
                    "TAMPER WARNING: Baseline database integrity check failed: %s",
                    db_msg,
                )

            violations = verify_filesystem_against_baseline(
                targets=components["targets"],
                database=db,
                exclusion_filter=components["exclusion_filter"],
                severity_classifier=components["severity_classifier"],
                alert_manager=alert_manager,
                chunk_size=components["chunk_size"],
                follow_symlinks=components["follow_symlinks"],
            )

            if not violations and db_ok:
                logger.info(
                    "Verification PASSED: all %d tracked paths match cryptographic baseline.",
                    db.count_records(),
                )
                return 0

            logger.warning(
                "Verification detected %d integrity violation(s) (logged to %s).",
                len(violations),
                alert_manager.ecs_log_file,
            )
            return 2
    finally:
        alert_manager.close(wait=True)


def run_monitor(components: Dict[str, Any], audit_on_start: bool = False) -> int:
    """Execute --monitor mode: real-time OS kernel filesystem watcher daemon."""
    db_path = components["db_path"]
    stop_event = threading.Event()

    def _signal_handler(signum: int, _frame: Any) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("Received %s — initiating graceful daemon shutdown...", sig_name)
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    alert_manager = AlertManager(components["alert_cfg"])
    try:
        with BaselineDatabase(db_path=db_path, read_only=True) as db:
            if not db.is_initialized():
                logger.error(
                    "Baseline database %s is not initialized. Run '--init' first.",
                    db.db_path,
                )
                return 1

            db_ok, db_msg = db.verify_database_integrity()
            if not db_ok:
                logger.critical(
                    "TAMPER WARNING: Baseline database manifest mismatch: %s",
                    db_msg,
                )

            if audit_on_start:
                logger.info("Running startup integrity audit against baseline...")
                drift = verify_filesystem_against_baseline(
                    targets=components["targets"],
                    database=db,
                    exclusion_filter=components["exclusion_filter"],
                    severity_classifier=components["severity_classifier"],
                    alert_manager=alert_manager,
                    chunk_size=components["chunk_size"],
                    follow_symlinks=components["follow_symlinks"],
                )
                if drift:
                    logger.warning(
                        "Startup audit found %d pre-existing drift violation(s).",
                        len(drift),
                    )

            watcher = FIMWatcher(
                targets=components["targets"],
                database=db,
                alert_manager=alert_manager,
                exclusion_filter=components["exclusion_filter"],
                severity_classifier=components["severity_classifier"],
                debounce_ms=components["debounce_ms"],
                chunk_size=components["chunk_size"],
                follow_symlinks=components["follow_symlinks"],
            )

            watch_count = watcher.start()
            logger.info(
                "Real-Time FIM active | baseline_files=%d | watches=%d | debounce=%dms | alerts=%s",
                db.count_records(),
                watch_count,
                components["debounce_ms"],
                alert_manager.ecs_log_file,
            )

            try:
                while not stop_event.is_set():
                    stop_event.wait(timeout=0.5)
            finally:
                logger.info("Stopping filesystem watcher and flushing debounce buffer...")
                watcher.stop()
    finally:
        logger.info("Draining pending webhook notifications...")
        alert_manager.close(wait=True)
        logger.info("FIM daemon stopped cleanly.")

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="Production-grade Real-Time File Integrity Monitor (HIDS)",
    )
    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="Override SQLite baseline database path from config.yaml",
    )
    parser.add_argument(
        "--alerts-file",
        default=None,
        help="Override ECS JSON alert output file path from config.yaml",
    )
    parser.add_argument(
        "--audit-on-start",
        action="store_true",
        help="Perform a baseline verification pass when starting --monitor",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose DEBUG logging",
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--init",
        action="store_true",
        help="Build or rebuild the cryptographic SHA-256 baseline in SQLite",
    )
    mode_group.add_argument(
        "--monitor",
        action="store_true",
        help="Run real-time OS-native filesystem integrity monitor daemon",
    )
    mode_group.add_argument(
        "--verify",
        action="store_true",
        help="Run a one-shot offline integrity check against the SQLite baseline",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    configure_logging(verbose=args.verbose)

    try:
        config = load_config(args.config)
        components = _build_components(
            config=config,
            db_override=args.db,
            alerts_override=args.alerts_file,
        )

        if args.init:
            return run_init(components)
        if args.verify:
            return run_verify(components)
        if args.monitor:
            return run_monitor(components, audit_on_start=args.audit_on_start)
        return 1
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    except Exception as exc:  # noqa: BLE001
        logger.exception("Fatal error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
