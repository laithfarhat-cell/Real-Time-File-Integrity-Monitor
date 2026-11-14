# Real-Time File Integrity Monitor (FIM)

A production-grade, lightweight Host Intrusion Detection System (HIDS) component written in Python. It establishes a tamper-evident cryptographic `SHA-256` baseline of critical system files and directories in `SQLite` and hooks directly into OS-native filesystem event subsystems (`inotify` on Linux, `FSEvents` on macOS, `ReadDirectoryChangesW` on Windows) to detect unauthorized modifications, creations, deletions, moves, and permission/ownership changes in real time.

---

## Key Capabilities

- **Memory-Safe Cryptographic Baseline (`--init`)**: Streams files in fixed `64 KiB` chunks via `hashlib.sha256` alongside POSIX metadata (`size`, `mode` including SUID/SGID/sticky bits, `uid`, `gid`, `mtime`, `inode`), storing a deterministic manifest digest inside a `0600`-permissioned `SQLite` WAL store (`baseline.db`).
- **Real-Time Kernel Event Monitoring (`--monitor`)**: Classifies `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `FILE_MOVED`, and `ATTRIBUTE_CHANGED` events with a configurable **500ms debounce buffer** that coalesces multi-step atomic saves (`vim`, `nano`, `sed -i`, `rsync`) into single, noise-free alerts.
- **Offline Cryptographic Verification (`--verify`)**: Performs one-shot integrity audits suitable for cron jobs, CI pipelines, or incident triage, returning exit code `0` (clean) or `2` (integrity drift detected).
- **Exclusion Filtering & Path Severity Engine**: Supports glob and regex exclusion rules (`*.swp`, `*.tmp`, `__pycache__/*`, `.git/*`) plus specificity-aware severity rules (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **SIEM-Ready ECS Logging & Async Webhooks**: Writes Elastic Common Schema (`ECS v8.11.0`) JSON Lines to `fim_alerts.json` and dispatches non-blocking Markdown alerts to **Telegram Bot API** and **Discord Webhooks** via a bounded background thread pool.
- **Hardened Daemon Deployment**: Ships with a read-only container setup (`Dockerfile` + `docker-compose.yml` using `:ro` host mounts and `FIM_HOST_ROOT`) and a sandboxed `systemd` unit (`fim.service`).

---

## Architecture & Workflow Diagram

```text
                        +------------------------------+
                        |         config.yaml          |
                        |  - monitored_paths           |
                        |  - exclusions (glob / regex) |
                        |  - severity rules            |
                        |  - webhook & ECS settings    |
                        +--------------+---------------+
                                       |
               +-----------------------+-----------------------+
               |                                               |
               v (--init / --verify)                           v (--monitor)
+------------------------------+                +------------------------------+
|   Cryptographic Hasher       |                |   OS Kernel Event Hooks      |
|   (core/hasher.py)           |                |   (watchdog Observer)        |
|  - 64 KiB chunked SHA-256    |                |  - Linux:   inotify          |
|  - POSIX mode/UID/GID/mtime  |                |  - macOS:   FSEvents         |
|  - Safe symlink/FIFO guards  |                |  - Windows: ReadDirChangesW  |
+--------------+---------------+                +--------------+---------------+
               |                                               |
               v                                               v
+------------------------------+                +------------------------------+
|   SQLite Baseline Store      |<---------------+   Watcher & Debounce Engine  |
|   (core/database.py)         |  Read-Only     |   (core/watcher.py)          |
|  - baseline.db (WAL, 0600)   |  Baseline Ref  |  - Exclusion glob/regex      |
|  - Tamper-evident manifest   |                |  - 500ms atomic-save buffer  |
+------------------------------+                |  - Diff hash & POSIX attrs   |
                                                |  - Severity classification   |
                                                +--------------+---------------+
                                                               |
                                     IntegrityAlert            |
                      (CREATED | MODIFIED | DELETED | MOVED | ATTRIBUTE_CHANGED)
                                                               |
                                                               v
                                                +------------------------------+
                                                |        Alert Manager         |
                                                |  (notifiers/alert_manager.py)|
                                                +--------------+---------------+
                                                               |
                         +-------------------------------------+------------------------------------+
                         | (Synchronous, Locked)               | (Async ThreadPool)                 | (Async ThreadPool)
                         v                                     v                                    v
          +------------------------------+      +------------------------------+     +------------------------------+
          |       fim_alerts.json        |      |       Telegram Bot API       |     |       Discord Webhook        |
          |  Elastic Common Schema (ECS) |      |   Markdown Instant Alert     |     |   Rich Color-Coded Embed     |
          +------------------------------+      +------------------------------+     +------------------------------+
```

---

## Repository Structure

```text
Real-Time-File-Integrity-Monitor/
├── config.yaml                 # Monitored paths, exclusions, severity mappings & webhook config
├── requirements.txt            # Runtime Python dependencies (watchdog, PyYAML, requests)
├── main.py                     # CLI entrypoint (--init, --monitor, --verify) & signal handling
├── core/
│   ├── __init__.py
│   ├── hasher.py               # Chunked SHA-256 computation & POSIX metadata extraction
│   ├── database.py             # Thread-safe SQLite baseline manager & manifest verification
│   └── watcher.py              # Watchdog handler, 500ms debounce buffer, exclusions & severity
├── notifiers/
│   ├── __init__.py
│   └── alert_manager.py        # ECS v8.11.0 JSON logger + threaded Telegram/Discord webhooks
├── tests/                      # Unit & end-to-end integration test suite
├── Dockerfile                  # Minimal hardened Python 3.11 container image
├── docker-compose.yml          # Container deployment with read-only (:ro) host mounts
└── fim.service                 # Systemd service unit with filesystem sandboxing
```

---

## Installation

```bash
git clone https://github.com/laithfarhat-cell/Real-Time-File-Integrity-Monitor.git
cd Real-Time-File-Integrity-Monitor

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## CLI Usage Examples

### 1. Initialize the Cryptographic Baseline (`--init`)
Traverse all configured `monitored_paths` in `config.yaml`, compute chunked `SHA-256` hashes and POSIX metadata, and commit the baseline to `baseline.db`:

```bash
python main.py --config config.yaml --init
```

### 2. Start Real-Time Monitoring (`--monitor`)
Attach OS-native kernel filesystem watchers and monitor against `baseline.db` in real time. Adding `--audit-on-start` catches any offline modifications that occurred while the daemon was stopped:

```bash
python main.py --config config.yaml --audit-on-start --monitor
```

Stop cleanly at any time with `Ctrl+C` (`SIGINT`) or `kill -TERM <pid>` (`SIGTERM`); pending debounced events and queued webhook requests flush gracefully before exit.

### 3. One-Shot Integrity Audit (`--verify`)
Run a standalone integrity verification pass against `baseline.db` (exits `0` when clean, `2` when violations are detected):

```bash
python main.py --config config.yaml --verify
echo "Exit status: $?"
```

### Custom Database & Log Paths
```bash
python main.py \
  --config /etc/fim/config.yaml \
  --db /var/lib/fim/baseline.db \
  --alerts-file /var/log/fim/fim_alerts.json \
  --monitor
```

---

## Webhook Configuration (Telegram & Discord)

Webhook secrets use `${ENV_VAR}` interpolation in `config.yaml` so tokens never need to be stored in plaintext:

```bash
export TELEGRAM_BOT_TOKEN="123456789:AAExampleBotTokenValue"
export TELEGRAM_CHAT_ID="-1001234567890"
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/123456789/example-token"
```

Then enable the desired channels in `config.yaml`:

```yaml
alerting:
  ecs_log_file: "./fim_alerts.json"
  console_alerts: true
  telegram:
    enabled: true
    bot_token: "${TELEGRAM_BOT_TOKEN}"
    chat_id: "${TELEGRAM_CHAT_ID}"
    min_severity: "HIGH"
  discord:
    enabled: true
    webhook_url: "${DISCORD_WEBHOOK_URL}"
    min_severity: "MEDIUM"
```

---

## Sample ECS JSON Alert Output (`fim_alerts.json`)

Each violation is appended as a single-line Elastic Common Schema (`ECS v8.11.0`) JSON record ready for ingestion by Filebeat, Elastic Agent, Wazuh, Logstash, or Splunk (pretty-printed below for readability):

```json
{
  "@timestamp": "2026-11-14T10:42:19.518204Z",
  "timestamp": "2026-11-14T10:42:19.518204Z",
  "message": "File content hash modified: /etc/sudoers",
  "event_type": "FILE_MODIFIED",
  "severity": "CRITICAL",
  "file_path": "/etc/sudoers",
  "source_path": null,
  "old_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "new_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "ecs": {
    "version": "8.11.0"
  },
  "event": {
    "kind": "alert",
    "category": ["file", "intrusion_detection"],
    "type": ["change"],
    "action": "FILE_MODIFIED",
    "severity": 95,
    "severity_label": "CRITICAL",
    "module": "fim"
  },
  "host": {
    "hostname": "prod-web-01",
    "name": "prod-web-01"
  },
  "file": {
    "path": "/etc/sudoers",
    "name": "sudoers",
    "directory": "/etc",
    "size": 1742,
    "mode": "0440",
    "uid": "0",
    "gid": "0",
    "inode": "131094",
    "mtime": "2026-11-14T10:42:19.011482Z",
    "hash": {
      "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    }
  },
  "fim": {
    "event_type": "FILE_MODIFIED",
    "severity": "CRITICAL",
    "old_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "new_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "old_size": 1690,
    "new_size": 1742,
    "old_mode": "0440",
    "new_mode": "0440",
    "old_uid": 0,
    "new_uid": 0,
    "old_gid": 0,
    "new_gid": 0
  }
}
```

---

## Production Deployment

### Option A: Docker & Docker Compose (Read-Only Host Mounts)

`docker-compose.yml` mounts watched host paths strictly read-only (`:ro`) under `/host` and sets `FIM_HOST_ROOT=/host`, preventing container processes from modifying the host filesystem while keeping container TLS certificates intact.

```bash
# 1. Build image and initialize baseline against read-only host mounts
docker compose build
docker compose run --rm fim \
  --config /opt/fim/config.yaml \
  --db /var/lib/fim/baseline.db \
  --init

# 2. Launch real-time monitoring container in the background
docker compose up -d

# 3. Inspect logs and ECS alerts
docker compose logs -f fim
tail -f ./logs/fim_alerts.json
```

### Option B: Native Linux `systemd` Daemon (`fim.service`)

```bash
# 1. Install application and dependencies under /opt/fim
sudo mkdir -p /opt/fim /etc/fim /var/lib/fim /var/log/fim
sudo cp -r core notifiers main.py requirements.txt /opt/fim/
sudo cp config.yaml /etc/fim/config.yaml
sudo python3 -m venv /opt/fim/.venv
sudo /opt/fim/.venv/bin/pip install -r /opt/fim/requirements.txt

# 2. (Optional) Configure webhook secrets
sudo install -m 0600 /dev/null /etc/fim/fim.env
# Add TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID / DISCORD_WEBHOOK_URL to /etc/fim/fim.env

# 3. Initialize cryptographic baseline
sudo /opt/fim/.venv/bin/python /opt/fim/main.py \
  --config /etc/fim/config.yaml \
  --db /var/lib/fim/baseline.db \
  --init

# 4. Install and enable systemd service
sudo cp fim.service /etc/systemd/system/fim.service
sudo systemctl daemon-reload
sudo systemctl enable --now fim.service
sudo systemctl status fim.service
```

---

## Operational & Security Notes

1. **Linux `inotify` Watch Limits**: When recursively monitoring large trees (e.g., `/var/www`), ensure kernel watch limits are sized appropriately:
   ```bash
   sudo sysctl -w fs.inotify.max_user_watches=524288
   ```
2. **Baseline Protection**: Always initialize `baseline.db` from a known-clean golden state. Under `fim.service` and Docker `--monitor`, `baseline.db` is opened in SQLite read-only mode (`?mode=ro`) and its SHA-256 manifest is verified on startup to detect database tampering.
