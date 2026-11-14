"""Comprehensive unit and end-to-end integration tests for Real-Time FIM."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
import yaml

from core.database import BaselineDatabase
from core.hasher import compute_sha256, extract_file_metadata, scan_paths
from core.watcher import (
    ExclusionFilter,
    FIMWatcher,
    SeverityClassifier,
    verify_filesystem_against_baseline,
)
from main import main
from notifiers.alert_manager import AlertManager, IntegrityAlert


def _wait_until(predicate, timeout: float = 4.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_chunked_sha256_and_metadata_extraction(tmp_path: Path) -> None:
    payload = os.urandom(150_000)  # Multiple chunks
    target = tmp_path / "large.bin"
    target.write_bytes(payload)
    os.chmod(target, 0o640)

    expected_sha = hashlib.sha256(payload).hexdigest()
    assert compute_sha256(str(target), chunk_size=4096) == expected_sha

    meta = extract_file_metadata(str(target), chunk_size=4096)
    assert meta is not None
    assert meta.sha256 == expected_sha
    assert meta.size == len(payload)
    assert meta.mode_octal == "0640"
    assert meta.uid == os.getuid()
    assert meta.gid == os.getgid()


def test_symlink_and_fifo_safety(tmp_path: Path) -> None:
    real_file = tmp_path / "target_a.txt"
    real_file.write_text("alpha", encoding="utf-8")
    real_file_b = tmp_path / "target_b.txt"
    real_file_b.write_text("alpha", encoding="utf-8")

    link_path = tmp_path / "config_link"
    os.symlink(real_file, link_path)

    meta1 = extract_file_metadata(str(link_path), follow_symlinks=False)
    assert meta1 is not None
    assert meta1.is_symlink is True

    # Retarget symlink to another file with identical contents: must change symlink hash
    os.unlink(link_path)
    os.symlink(real_file_b, link_path)
    meta2 = extract_file_metadata(str(link_path), follow_symlinks=False)
    assert meta2 is not None
    assert meta1.sha256 != meta2.sha256

    # Named pipe (FIFO) must be skipped immediately without blocking
    fifo_path = tmp_path / "test.fifo"
    os.mkfifo(fifo_path)
    assert extract_file_metadata(str(fifo_path)) is None


def test_database_baseline_and_tamper_manifest(tmp_path: Path) -> None:
    watched = tmp_path / "etc"
    watched.mkdir()
    f1 = watched / "passwd"
    f1.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")

    db_file = tmp_path / "baseline.db"
    records = list(scan_paths([str(watched)]))

    with BaselineDatabase(str(db_file)) as db:
        summary = db.initialize_baseline(records)
        assert summary.file_count == 1
        assert db.is_initialized() is True
        ok, _ = db.verify_database_integrity()
        assert ok is True
        assert stat.S_IMODE(os.stat(db_file).st_mode) == 0o600

    # Simulate direct SQLite tampering of a stored SHA-256 hash
    conn = sqlite3.connect(str(db_file))
    conn.execute("UPDATE baseline_files SET sha256 = '0000' WHERE path LIKE '%passwd'")
    conn.commit()
    conn.close()

    with BaselineDatabase(str(db_file), read_only=True) as db_ro:
        ok, reason = db_ro.verify_database_integrity()
        assert ok is False
        assert "mismatch" in reason


def test_exclusions_and_severity_classification() -> None:
    excl = ExclusionFilter(
        globs=["*.swp", "*.tmp", "__pycache__/*", ".git/*"],
        regexes=[r"^/proc(/|$)", r"\.#[^/]+$"],
        protected_paths=["/opt/fim/baseline.db"],
    )
    assert excl.is_excluded("/etc/.passwd.swp") is True
    assert excl.is_excluded("/app/__pycache__/mod.cpython-311.pyc") is True
    assert excl.is_excluded("/app/.git/HEAD") is True
    assert excl.is_excluded("/proc/cpuinfo") is True
    assert excl.is_excluded("/etc/.#sshd_config") is True
    assert excl.is_excluded("/opt/fim/baseline.db") is True
    assert excl.is_excluded("/etc/passwd") is False

    classifier = SeverityClassifier(
        default_severity="MEDIUM",
        rules=[
            {"pattern": "/etc/*", "level": "MEDIUM"},
            {"pattern": "/etc/passwd", "level": "CRITICAL"},
            {"pattern": "/etc/sudoers", "level": "CRITICAL"},
            {"pattern": "~/.ssh/authorized_keys", "level": "CRITICAL"},
            {"pattern": "/var/www/html/*", "level": "HIGH"},
        ],
    )
    assert classifier.classify("/etc/passwd") == "CRITICAL"
    assert classifier.classify("/etc/sudoers") == "CRITICAL"
    assert classifier.classify(os.path.expanduser("~/.ssh/authorized_keys")) == "CRITICAL"
    assert classifier.classify("/var/www/html/index.php") == "HIGH"
    assert classifier.classify("/etc/hosts") == "MEDIUM"
    assert classifier.classify("/opt/custom/app.conf") == "MEDIUM"


def test_ecs_logging_and_async_webhooks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "999:TEST_TOKEN")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-10042")
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/api/webhooks/1/abc")

    calls: List[Dict[str, Any]] = []

    def fake_post(url: str, json: Dict[str, Any], timeout: float):
        calls.append({"url": url, "json": json, "timeout": timeout})
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        return resp

    alerts_path = tmp_path / "fim_alerts.json"
    mgr = AlertManager(
        alert_config={
            "ecs_log_file": str(alerts_path),
            "console_alerts": False,
            "telegram": {
                "enabled": True,
                "bot_token": "${TELEGRAM_BOT_TOKEN}",
                "chat_id": "${TELEGRAM_CHAT_ID}",
                "min_severity": "HIGH",
            },
            "discord": {
                "enabled": True,
                "webhook_url": "${DISCORD_WEBHOOK_URL}",
                "min_severity": "MEDIUM",
            },
        },
        http_post=fake_post,
    )

    sample = tmp_path / "sudoers"
    sample.write_text("root ALL=(ALL:ALL) ALL\n", encoding="utf-8")
    old_m = extract_file_metadata(str(sample))
    sample.write_text("root ALL=(ALL:ALL) ALL\nevil ALL=(ALL) NOPASSWD:ALL\n", encoding="utf-8")
    new_m = extract_file_metadata(str(sample))

    futures = mgr.dispatch(
        IntegrityAlert(
            event_type="FILE_MODIFIED",
            severity="CRITICAL",
            file_path=str(sample),
            old_meta=old_m,
            new_meta=new_m,
        )
    )
    for fut in futures:
        fut.result(timeout=5)
    mgr.close(wait=True)

    # Validate ECS JSON record
    lines = alerts_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    doc = json.loads(lines[0])
    assert doc["ecs"]["version"] == "8.11.0"
    assert doc["event_type"] == "FILE_MODIFIED"
    assert doc["severity"] == "CRITICAL"
    assert doc["old_hash"] == old_m.sha256
    assert doc["new_hash"] == new_m.sha256
    assert doc["@timestamp"].endswith("Z")

    # Validate both Telegram and Discord received async payloads
    assert len(calls) == 2
    urls = {c["url"] for c in calls}
    assert "https://api.telegram.org/bot999:TEST_TOKEN/sendMessage" in urls
    assert "https://discord.example/api/webhooks/1/abc" in urls


def test_realtime_watcher_all_events_and_debounce(tmp_path: Path) -> None:
    watched_dir = tmp_path / "watched"
    watched_dir.mkdir()

    f_mod = watched_dir / "app.conf"
    f_mod.write_text("port=8080\n", encoding="utf-8")
    os.chmod(f_mod, 0o644)

    f_perm = watched_dir / "secret.key"
    f_perm.write_text("PRIVATE_KEY_MATERIAL\n", encoding="utf-8")
    os.chmod(f_perm, 0o640)

    f_move = watched_dir / "original.txt"
    f_move.write_text("move-me\n", encoding="utf-8")

    f_del = watched_dir / "obsolete.cfg"
    f_del.write_text("delete-me\n", encoding="utf-8")

    db_path = tmp_path / "baseline.db"
    alerts_file = tmp_path / "fim_alerts.json"

    excl = ExclusionFilter(globs=["*.swp", "*.tmp", "*~"])
    sev = SeverityClassifier(
        default_severity="MEDIUM",
        rules=[{"pattern": f"{watched_dir}/secret.key", "level": "CRITICAL"}],
    )

    with BaselineDatabase(str(db_path)) as db:
        db.initialize_baseline(scan_paths([str(watched_dir)], is_excluded=excl.is_excluded))

    alert_mgr = AlertManager(
        {"ecs_log_file": str(alerts_file), "console_alerts": False}
    )

    def read_alerts() -> List[Dict[str, Any]]:
        if not alerts_file.exists():
            return []
        return [
            json.loads(line)
            for line in alerts_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    with BaselineDatabase(str(db_path), read_only=True) as db:
        watcher = FIMWatcher(
            targets=[str(watched_dir)],
            database=db,
            alert_manager=alert_mgr,
            exclusion_filter=excl,
            severity_classifier=sev,
            debounce_ms=200,
        )
        watcher.start()
        try:
            # 1. Simulate noisy atomic editor save (swap file + backup + rapid multi-writes)
            swap = watched_dir / ".app.conf.swp"
            swap.write_text("swap", encoding="utf-8")
            backup = watched_dir / "app.conf~"
            os.rename(f_mod, backup)
            tmp_write = watched_dir / "app.conf.tmp"
            tmp_write.write_text("port=9090\n", encoding="utf-8")
            os.rename(tmp_write, f_mod)
            f_mod.write_text("port=9443\ntls=true\n", encoding="utf-8")
            os.chmod(f_mod, 0o644)
            swap.unlink()
            backup.unlink()

            assert _wait_until(lambda: len(read_alerts()) >= 1)
            time.sleep(0.35)  # Ensure no duplicate trailing alerts fire
            mod_alerts = [a for a in read_alerts() if a["file_path"] == str(f_mod)]
            assert len(mod_alerts) == 1
            assert mod_alerts[0]["event_type"] == "FILE_MODIFIED"

            # 2. Create unexpected file -> FILE_CREATED
            created = watched_dir / "webshell.php"
            created.write_text("<?php echo 'test'; ?>\n", encoding="utf-8")
            assert _wait_until(
                lambda: any(a["event_type"] == "FILE_CREATED" for a in read_alerts())
            )

            # 3. Change permissions only -> ATTRIBUTE_CHANGED with CRITICAL severity
            os.chmod(f_perm, 0o600)
            assert _wait_until(
                lambda: any(a["event_type"] == "ATTRIBUTE_CHANGED" for a in read_alerts())
            )
            attr_alert = next(
                a for a in read_alerts() if a["event_type"] == "ATTRIBUTE_CHANGED"
            )
            assert attr_alert["severity"] == "CRITICAL"
            assert attr_alert["old_hash"] == attr_alert["new_hash"]
            assert attr_alert["fim"]["old_mode"] == "0640"
            assert attr_alert["fim"]["new_mode"] == "0600"

            # 4. Rename file inside watched directory -> single FILE_MOVED
            dest_move = watched_dir / "relocated.txt"
            os.rename(f_move, dest_move)
            assert _wait_until(
                lambda: any(a["event_type"] == "FILE_MOVED" for a in read_alerts())
            )
            move_alerts = [
                a
                for a in read_alerts()
                if a["file_path"] in (str(f_move), str(dest_move))
            ]
            assert len(move_alerts) == 1
            assert move_alerts[0]["event_type"] == "FILE_MOVED"
            assert move_alerts[0]["source_path"] == str(f_move)
            assert move_alerts[0]["file_path"] == str(dest_move)

            # 5. Delete tracked file -> FILE_DELETED
            f_del.unlink()
            assert _wait_until(
                lambda: any(a["event_type"] == "FILE_DELETED" for a in read_alerts())
            )
        finally:
            watcher.stop()
            alert_mgr.close(wait=True)


def test_cli_init_verify_and_sigterm_monitor(tmp_path: Path) -> None:
    monitored = tmp_path / "target_etc"
    monitored.mkdir()
    critical_file = monitored / "passwd"
    critical_file.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")

    db_path = tmp_path / "baseline.db"
    alerts_path = tmp_path / "fim_alerts.json"
    cfg_path = tmp_path / "config.yaml"

    cfg = {
        "engine": {
            "database_path": str(db_path),
            "debounce_ms": 150,
            "chunk_size": 65536,
        },
        "monitored_paths": [{"path": str(monitored), "recursive": True}],
        "exclusions": {"globs": ["*.swp"], "regex": []},
        "severity": {
            "default_severity": "MEDIUM",
            "rules": [{"pattern": f"{monitored}/passwd", "level": "CRITICAL"}],
        },
        "alerting": {
            "ecs_log_file": str(alerts_path),
            "console_alerts": False,
        },
    }
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")

    # 1. --init builds baseline
    assert main(["--config", str(cfg_path), "--init"]) == 0
    assert db_path.exists()

    # 2. --verify exits 0 when clean
    assert main(["--config", str(cfg_path), "--verify"]) == 0

    # 3. Start --monitor as a real subprocess, tamper with file, then send SIGTERM
    repo_root = Path(__file__).resolve().parent.parent
    proc = subprocess.Popen(
        [sys.executable, str(repo_root / "main.py"), "--config", str(cfg_path), "--monitor"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # Wait briefly for daemon watch registration
        time.sleep(0.5)
        critical_file.write_text("root:x:0:0:root:/root:/bin/bash\nhacker:x:0:0::/:/bin/sh\n", encoding="utf-8")
        assert _wait_until(lambda: alerts_path.exists() and alerts_path.stat().st_size > 0)
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=5)
        assert rc == 0
    finally:
        if proc.poll() is None:
            proc.kill()

    # 4. --verify exits 2 when baseline drift exists
    assert main(["--config", str(cfg_path), "--verify"]) == 2
