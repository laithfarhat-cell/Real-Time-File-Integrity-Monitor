"""ECS-compliant SIEM JSON logger and asynchronous Discord/Telegram webhook dispatcher."""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import requests

from core.hasher import FileMetadata, format_mode, normalize_path

logger = logging.getLogger("fim.alerts")

SEVERITY_RANK: Dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

ECS_SEVERITY_NUMBER: Dict[str, int] = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 95,
}

DISCORD_EMBED_COLORS: Dict[str, int] = {
    "LOW": 0x3498DB,       # Blue
    "MEDIUM": 0xF1C40F,    # Amber
    "HIGH": 0xE67E22,      # Orange
    "CRITICAL": 0xE74C3C,  # Red
}

SEVERITY_BADGES: Dict[str, str] = {
    "LOW": "[LOW]",
    "MEDIUM": "[MEDIUM]",
    "HIGH": "[HIGH]",
    "CRITICAL": "[CRITICAL]",
}

EVENT_TYPES = frozenset(
    {
        "FILE_CREATED",
        "FILE_MODIFIED",
        "FILE_DELETED",
        "FILE_MOVED",
        "ATTRIBUTE_CHANGED",
    }
)

_ECS_EVENT_TYPE_MAP: Dict[str, List[str]] = {
    "FILE_CREATED": ["creation"],
    "FILE_MODIFIED": ["change"],
    "FILE_DELETED": ["deletion"],
    "FILE_MOVED": ["change"],
    "ATTRIBUTE_CHANGED": ["change"],
}

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def resolve_env_Placeholders(raw_value: Optional[str]) -> str:
    """Expand ${VAR_NAME} placeholders using process environment variables."""
    if not raw_value:
        return ""

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, "")

    return _ENV_PATTERN.sub(_replace, str(raw_value)).strip()


def _escape_code_span(text: str) -> str:
    """Escape backticks inside Markdown inline code spans."""
    return text.replace("`", "'")


@dataclass(frozen=True)
class IntegrityAlert:
    """Structured representation of a detected file integrity violation."""

    event_type: str
    severity: str
    file_path: str
    old_meta: Optional[FileMetadata] = None
    new_meta: Optional[FileMetadata] = None
    source_path: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    hostname: str = field(default_factory=socket.gethostname)
    details: Optional[str] = None

    @property
    def old_hash(self) -> Optional[str]:
        return self.old_meta.sha256 if self.old_meta else None

    @property
    def new_hash(self) -> Optional[str]:
        return self.new_meta.sha256 if self.new_meta else None

    def summary_message(self) -> str:
        """Build human-readable summary message for SIEM and console output."""
        if self.details:
            return self.details
        if self.event_type == "FILE_CREATED":
            return f"Unauthorized file created: {self.file_path}"
        if self.event_type == "FILE_DELETED":
            return f"Tracked file deleted: {self.file_path}"
        if self.event_type == "FILE_MOVED":
            return f"Tracked file moved from {self.source_path} to {self.file_path}"
        if self.event_type == "ATTRIBUTE_CHANGED":
            old_attr = (
                f"mode={self.old_meta.mode_octal} uid={self.old_meta.uid} gid={self.old_meta.gid}"
                if self.old_meta
                else "unknown"
            )
            new_attr = (
                f"mode={self.new_meta.mode_octal} uid={self.new_meta.uid} gid={self.new_meta.gid}"
                if self.new_meta
                else "unknown"
            )
            return f"File attributes altered on {self.file_path} ({old_attr} -> {new_attr})"
        return f"File content hash modified: {self.file_path}"

    def to_ecs_dict(self) -> Dict[str, Any]:
        """Serialize alert in Elastic Common Schema (ECS v8.11.0) structured JSON."""
        sev = self.severity.upper()
        active_meta = self.new_meta or self.old_meta

        file_obj: Dict[str, Any] = {
            "path": self.file_path,
            "name": os.path.basename(self.file_path),
            "directory": os.path.dirname(self.file_path),
        }
        if self.source_path:
            file_obj["source_path"] = self.source_path
        if active_meta is not None:
            file_obj["size"] = active_meta.size
            file_obj["mode"] = format_mode(active_meta.mode)
            file_obj["uid"] = str(active_meta.uid)
            file_obj["gid"] = str(active_meta.gid)
            file_obj["inode"] = str(active_meta.inode)
            file_obj["mtime"] = (
                datetime.fromtimestamp(active_meta.mtime, tz=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
        if self.new_hash or self.old_hash:
            file_obj["hash"] = {
                "sha256": self.new_hash or self.old_hash,
            }

        return {
            "@timestamp": self.timestamp,
            "timestamp": self.timestamp,
            "message": self.summary_message(),
            "event_type": self.event_type,
            "severity": sev,
            "file_path": self.file_path,
            "source_path": self.source_path,
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
            "ecs": {"version": "8.11.0"},
            "event": {
                "kind": "alert",
                "category": ["file", "intrusion_detection"],
                "type": _ECS_EVENT_TYPE_MAP.get(self.event_type, ["info"]),
                "action": self.event_type,
                "severity": ECS_SEVERITY_NUMBER.get(sev, 50),
                "severity_label": sev,
                "module": "fim",
            },
            "host": {
                "hostname": self.hostname,
                "name": self.hostname,
            },
            "file": file_obj,
            "fim": {
                "event_type": self.event_type,
                "severity": sev,
                "old_hash": self.old_hash,
                "new_hash": self.new_hash,
                "old_size": self.old_meta.size if self.old_meta else None,
                "new_size": self.new_meta.size if self.new_meta else None,
                "old_mode": self.old_meta.mode_octal if self.old_meta else None,
                "new_mode": self.new_meta.mode_octal if self.new_meta else None,
                "old_uid": self.old_meta.uid if self.old_meta else None,
                "new_uid": self.new_meta.uid if self.new_meta else None,
                "old_gid": self.old_meta.gid if self.old_meta else None,
                "new_gid": self.new_meta.gid if self.new_meta else None,
            },
        }

    def to_markdown(self) -> str:
        """Render safe Markdown notification suitable for Telegram & Discord."""
        badge = SEVERITY_BADGES.get(self.severity.upper(), f"[{self.severity}]")
        lines = [
            f"*{badge} FIM Alert — {self.event_type}*",
            f"• *Host:* `{_escape_code_span(self.hostname)}`",
            f"• *Severity:* `{self.severity.upper()}`",
            f"• *Time (UTC):* `{self.timestamp}`",
            f"• *File:* `{_escape_code_span(self.file_path)}`",
        ]
        if self.source_path:
            lines.append(f"• *Moved From:* `{_escape_code_span(self.source_path)}`")
        if self.old_hash:
            lines.append(f"• *Old SHA-256:* `{self.old_hash}`")
        if self.new_hash:
            lines.append(f"• *New SHA-256:* `{self.new_hash}`")

        if self.old_meta or self.new_meta:
            old_perm = (
                f"{self.old_meta.mode_octal} ({self.old_meta.uid}:{self.old_meta.gid})"
                if self.old_meta
                else "N/A"
            )
            new_perm = (
                f"{self.new_meta.mode_octal} ({self.new_meta.uid}:{self.new_meta.gid})"
                if self.new_meta
                else "N/A"
            )
            lines.append(f"• *Mode/Owner:* `{old_perm}` -> `{new_perm}`")

        return "\n".join(lines)


class AlertManager:
    """Thread-safe ECS JSON file writer and async webhook dispatcher."""

    def __init__(
        self,
        alert_config: Optional[Dict[str, Any]] = None,
        http_post: Optional[Callable[..., requests.Response]] = None,
        max_workers: int = 4,
    ) -> None:
        cfg = alert_config or {}
        raw_log_path = cfg.get("ecs_log_file", "./fim_alerts.json")
        self.ecs_log_file = normalize_path(str(raw_log_path))
        self.console_alerts = bool(cfg.get("console_alerts", True))
        self._file_lock = threading.Lock()
        self._http_post = http_post or requests.post
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="fim-webhook",
        )
        self._closed = False

        # Telegram configuration
        tg_cfg = cfg.get("telegram") or {}
        self.telegram_enabled = bool(tg_cfg.get("enabled", False))
        self.telegram_bot_token = resolve_env_Placeholders(
            tg_cfg.get("bot_token")
        ) or os.environ.get("FIM_TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = resolve_env_Placeholders(
            tg_cfg.get("chat_id")
        ) or os.environ.get("FIM_TELEGRAM_CHAT_ID", "")
        self.telegram_min_severity = str(
            tg_cfg.get("min_severity", "MEDIUM")
        ).upper()
        self.telegram_timeout = float(tg_cfg.get("timeout_seconds", 10))

        if self.telegram_enabled and (
            not self.telegram_bot_token or not self.telegram_chat_id
        ):
            logger.warning(
                "Telegram alerting enabled in config, but bot_token or chat_id is empty; disabling Telegram."
            )
            self.telegram_enabled = False

        # Discord configuration
        dc_cfg = cfg.get("discord") or {}
        self.discord_enabled = bool(dc_cfg.get("enabled", False))
        self.discord_webhook_url = resolve_env_Placeholders(
            dc_cfg.get("webhook_url")
        ) or os.environ.get("FIM_DISCORD_WEBHOOK_URL", "")
        self.discord_username = str(
            dc_cfg.get("username", "FIM Security Sentinel")
        )
        self.discord_min_severity = str(
            dc_cfg.get("min_severity", "MEDIUM")
        ).upper()
        self.discord_timeout = float(dc_cfg.get("timeout_seconds", 10))

        if self.discord_enabled and not self.discord_webhook_url:
            logger.warning(
                "Discord alerting enabled in config, but webhook_url is empty; disabling Discord."
            )
            self.discord_enabled = False

    def get_protected_paths(self) -> List[str]:
        """Return output alert file path so the watcher excludes it automatically."""
        return [self.ecs_log_file]

    def _meets_severity(self, alert_severity: str, threshold: str) -> bool:
        return SEVERITY_RANK.get(alert_severity.upper(), 2) >= SEVERITY_RANK.get(
            threshold.upper(), 2
        )

    def _append_ecs_json(self, ecs_payload: Dict[str, Any]) -> None:
        parent = os.path.dirname(self.ecs_log_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        serialized = json.dumps(ecs_payload, separators=(",", ":"), sort_keys=False)
        with self._file_lock:
            with open(self.ecs_log_file, "a", encoding="utf-8") as fh:
                fh.write(serialized + "\n")
                fh.flush()

    def _send_telegram(self, alert: IntegrityAlert) -> None:
        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": alert.to_markdown(),
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        try:
            resp = self._http_post(url, json=payload, timeout=self.telegram_timeout)
            if resp.status_code >= 400:
                logger.error(
                    "Telegram API returned HTTP %d: %s",
                    resp.status_code,
                    resp.text[:200],
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to dispatch Telegram alert: %s", exc)

    def _send_discord(self, alert: IntegrityAlert) -> None:
        sev = alert.severity.upper()
        fields: List[Dict[str, Any]] = [
            {"name": "Event", "value": f"`{alert.event_type}`", "inline": True},
            {"name": "Severity", "value": f"`{sev}`", "inline": True},
            {"name": "Host", "value": f"`{alert.hostname}`", "inline": True},
            {
                "name": "File Path",
                "value": f"`{_escape_code_span(alert.file_path)}`",
                "inline": False,
            },
        ]
        if alert.source_path:
            fields.append(
                {
                    "name": "Moved From",
                    "value": f"`{_escape_code_span(alert.source_path)}`",
                    "inline": False,
                }
            )
        if alert.old_hash:
            fields.append(
                {"name": "Old SHA-256", "value": f"`{alert.old_hash}`", "inline": False}
            )
        if alert.new_hash:
            fields.append(
                {"name": "New SHA-256", "value": f"`{alert.new_hash}`", "inline": False}
            )
        if alert.old_meta or alert.new_meta:
            old_attr = (
                f"{alert.old_meta.mode_octal} ({alert.old_meta.uid}:{alert.old_meta.gid})"
                if alert.old_meta
                else "N/A"
            )
            new_attr = (
                f"{alert.new_meta.mode_octal} ({alert.new_meta.uid}:{alert.new_meta.gid})"
                if alert.new_meta
                else "N/A"
            )
            fields.append(
                {
                    "name": "Permissions / Owner",
                    "value": f"`{old_attr}` → `{new_attr}`",
                    "inline": False,
                }
            )

        payload = {
            "username": self.discord_username,
            "content": f"**{SEVERITY_BADGES.get(sev, '[ALERT]')} {alert.event_type}** on `{alert.hostname}`",
            "embeds": [
                {
                    "title": f"Integrity Violation: {os.path.basename(alert.file_path) or alert.file_path}",
                    "description": alert.summary_message(),
                    "color": DISCORD_EMBED_COLORS.get(sev, 0xF1C40F),
                    "timestamp": alert.timestamp,
                    "fields": fields,
                }
            ],
        }
        try:
            resp = self._http_post(
                self.discord_webhook_url,
                json=payload,
                timeout=self.discord_timeout,
            )
            if resp.status_code >= 400:
                logger.error(
                    "Discord webhook returned HTTP %d: %s",
                    resp.status_code,
                    resp.text[:200],
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to dispatch Discord webhook alert: %s", exc)

    def dispatch(self, alert: IntegrityAlert) -> List[Future[None]]:
        """Persist alert to ECS JSON immediately and schedule non-blocking webhooks."""
        ecs_doc = alert.to_ecs_dict()
        try:
            self._append_ecs_json(ecs_doc)
        except OSError as exc:
            logger.error(
                "Failed writing ECS alert to %s: %s", self.ecs_log_file, exc
            )

        if self.console_alerts:
            log_fn = (
                logger.critical
                if alert.severity.upper() == "CRITICAL"
                else logger.warning
            )
            log_fn(
                "[%s] %s | path=%s | old_sha256=%s | new_sha256=%s",
                alert.severity.upper(),
                alert.event_type,
                alert.file_path,
                (alert.old_hash[:12] + "...") if alert.old_hash else "None",
                (alert.new_hash[:12] + "...") if alert.new_hash else "None",
            )

        futures: List[Future[None]] = []
        if self._closed:
            return futures

        if self.telegram_enabled and self._meets_severity(
            alert.severity, self.telegram_min_severity
        ):
            futures.append(self._executor.submit(self._send_telegram, alert))

        if self.discord_enabled and self._meets_severity(
            alert.severity, self.discord_min_severity
        ):
            futures.append(self._executor.submit(self._send_discord, alert))

        return futures

    def close(self, wait: bool = True) -> None:
        """Drain queued webhook notifications and shut down worker threads."""
        if not self._closed:
            self._closed = True
            self._executor.shutdown(wait=wait)
