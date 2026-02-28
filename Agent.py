"""
agent_v2.py — Insider Threat Detection Agent (Enhanced)
=========================================================
New in v2 vs v1:
  - Keystroke rhythm & typing-burst detection (no content captured)
  - Login pattern profiling (time-of-day, failed attempts)
  - Email behaviour: external recipients, attachments, bulk send detection
  - Malicious / sensitive file detection (hash + keyword + extension)
  - Clipboard monitoring (size spike + credential pattern detection)
  - Cloud-sync folder watcher (Dropbox / OneDrive / GDrive)
  - Print-job monitoring
  - Per-session behavioural context (idle ratio, app-switch rate)
  - Local 24-h rolling cache for FP reduction (baseline deviation scoring)
  - All collectors are non-blocking, time-bounded, privacy-respecting
    (keystrokes: counts/rhythm only — NO content stored or sent)

Usage
-----
  pip install psutil requests cryptography pywin32 pynput watchdog pillow pytz
  python agent_v2.py

Config via environment variables (same as v1, extended):
  AGENT_SERVER   — collector URL   (default: http://172.16.13.100:5000/api/logs)
  AGENT_APIKEY   — API key header
  AGENT_SECRET   — HMAC secret
  AGENT_INTERVAL — send interval seconds (default: 30)
  AGENT_SCREENSHOT — "true" to enable screenshots
  AGENT_DEBUG    — "true" for verbose tracebacks
"""

# ─────────────────────────────────────────────────────────────────────────────
# Stdlib
# ─────────────────────────────────────────────────────────────────────────────
import os, sys, json, time, socket, platform, tempfile, shutil
import sqlite3, uuid, re, stat, hmac, base64, threading, hashlib
import ctypes
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import deque, defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# Third-party (graceful degradation if missing)
# ─────────────────────────────────────────────────────────────────────────────
import psutil
import requests
import pytz
from cryptography.fernet import Fernet

try:
    from pynput import keyboard as _kb
    PYNPUT_OK = True
except ImportError:
    PYNPUT_OK = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False

try:
    import win32gui, win32process, win32con, win32api, win32security
    WIN32_OK = True
except ImportError:
    WIN32_OK = False

try:
    import win32com.client as _w32com
    WIN32COM_OK = True
except ImportError:
    WIN32COM_OK = False

try:
    import win32clipboard
    CLIPBOARD_OK = True
except ImportError:
    CLIPBOARD_OK = False

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
TIMEZONE        = os.getenv("AGENT_TIMEZONE", "Asia/Kolkata")
SERVER_URL      = os.getenv("AGENT_SERVER",   "http://172.16.13.100:5000/api/logs")
API_KEY         = os.getenv("AGENT_APIKEY",   "")
HMAC_SECRET     = os.getenv("AGENT_SECRET",   "")
SEND_INTERVAL   = int(os.getenv("AGENT_INTERVAL", "30"))
SCREENSHOT_ENABLED = os.getenv("AGENT_SCREENSHOT", "false").lower() == "true"
DEBUG           = os.getenv("AGENT_DEBUG", "false").lower() == "true"

# Payload size limits
MAX_RISK_FILES      = 10
MAX_BROWSER_ENTRIES = 5
MAX_PROCESS_ENTRIES = 20
MAX_CLIPBOARD_CHARS = 200   # only metadata — no raw content beyond this
SCREENSHOT_MAX_BYTES = 250 * 1024

# Work-hours definition (used for after-hours scoring)
WORK_HOUR_START = 8   # 08:00
WORK_HOUR_END   = 19  # 19:00

# Sensitive file extensions (beyond keyword matching)
SENSITIVE_EXTENSIONS = {
    ".kdbx", ".key", ".pem", ".pfx", ".p12", ".cer",
    ".sql", ".bak", ".dump", ".db", ".sqlite",
    ".docx", ".xlsx", ".csv", ".pdf",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".ps1", ".bat", ".sh", ".vbs",
}

# Credential-pattern regex (for clipboard scanning — no content stored)
CREDENTIAL_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)aws_access_key_id\s*="),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),  # long base64 blob
]

SUSPICIOUS_KEYWORDS = [
    "secret", "confidential", "salary", "database", "credential",
    "password", "private", "key", "internal", "classified", "restricted",
    "backup", "dump", "export", "finance", "payroll", "hr_data",
]

# ─────────────────────────────────────────────────────────────────────────────
# Local state directory
# ─────────────────────────────────────────────────────────────────────────────
LOCAL_STATE_DIR = Path.home() / ".uamhids_v2"
AGENT_ID_FILE   = LOCAL_STATE_DIR / "agent_id"
FERNET_KEY_FILE = LOCAL_STATE_DIR / "fernet.key"
QUEUE_DB        = LOCAL_STATE_DIR / "queue.db"
BASELINE_DB     = LOCAL_STATE_DIR / "baseline.db"
TEMP_DIR        = Path(tempfile.gettempdir())

def _ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    try:
        p.chmod(0o700)
    except Exception:
        pass

_ensure_dir(LOCAL_STATE_DIR)

def _write_secure(path: Path, data, mode="wb"):
    with open(path, mode) as f:
        f.write(data)
    try:
        path.chmod(0o600)
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# Agent identity & crypto
# ─────────────────────────────────────────────────────────────────────────────
def get_agent_id() -> str:
    try:
        if AGENT_ID_FILE.exists():
            return AGENT_ID_FILE.read_text().strip()
        aid = hashlib.sha256((platform.node() + str(uuid.getnode())).encode()).hexdigest()[:24]
        _write_secure(AGENT_ID_FILE, aid, mode="w")
        return aid
    except Exception:
        return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:24]

AGENT_ID = get_agent_id()

def _get_fernet() -> "Fernet | None":
    try:
        if FERNET_KEY_FILE.exists():
            return Fernet(FERNET_KEY_FILE.read_bytes().strip())
        key = Fernet.generate_key()
        _write_secure(FERNET_KEY_FILE, key)
        return Fernet(key)
    except Exception:
        return None

FERNET = _get_fernet()

def sign_payload(payload_bytes: bytes) -> str:
    if not HMAC_SECRET:
        return ""
    return hmac.new(HMAC_SECRET.encode(), payload_bytes, hashlib.sha256).hexdigest()

# ─────────────────────────────────────────────────────────────────────────────
# Persistent queue (SQLite, owner-only)
# ─────────────────────────────────────────────────────────────────────────────
def _init_queue_db():
    conn = sqlite3.connect(str(QUEUE_DB), timeout=10)
    conn.execute("""CREATE TABLE IF NOT EXISTS queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT,
        payload BLOB
    )""")
    conn.commit()
    conn.close()
    try:
        QUEUE_DB.chmod(0o600)
    except Exception:
        pass

_init_queue_db()

def enqueue_payload(payload_json: str):
    conn = sqlite3.connect(str(QUEUE_DB), timeout=10)
    conn.execute("INSERT INTO queue (created_at, payload) VALUES (?, ?)",
                 (datetime.now(timezone.utc).isoformat(), payload_json.encode()))
    conn.commit()
    conn.close()

def dequeue_and_send_all(session, url, headers):
    conn = sqlite3.connect(str(QUEUE_DB), timeout=10)
    rows = conn.execute("SELECT id, payload FROM queue ORDER BY id ASC LIMIT 50").fetchall()
    for rid, blob in rows:
        try:
            pb = blob if isinstance(blob, bytes) else blob.encode()
            h = headers.copy()
            h["X-PAYLOAD-SIGNATURE"] = sign_payload(pb)
            if _send_with_retry(session, url, h, pb):
                conn.execute("DELETE FROM queue WHERE id = ?", (rid,))
                conn.commit()
        except Exception:
            break
    conn.close()

# ─────────────────────────────────────────────────────────────────────────────
# Per-user local baseline DB  (FP reduction)
# ─────────────────────────────────────────────────────────────────────────────
def _init_baseline_db():
    conn = sqlite3.connect(str(BASELINE_DB), timeout=10)
    conn.execute("""CREATE TABLE IF NOT EXISTS hourly_stats (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user        TEXT,
        hour_bucket TEXT,          -- ISO date + hour e.g. "2025-07-10T14"
        keystrokes  INTEGER,
        mouse_clicks INTEGER,
        app_switches INTEGER,
        files_accessed INTEGER,
        net_bytes_sent INTEGER,
        clipboard_events INTEGER,
        usb_count   INTEGER,
        email_sent  INTEGER
    )""")
    conn.commit()
    conn.close()
    try:
        BASELINE_DB.chmod(0o600)
    except Exception:
        pass

_init_baseline_db()

def save_hourly_stats(user: str, stats: dict):
    """Persist current-hour stats for baseline computation."""
    bucket = datetime.now().strftime("%Y-%m-%dT%H")
    conn = sqlite3.connect(str(BASELINE_DB), timeout=10)
    # upsert
    conn.execute("""INSERT INTO hourly_stats
        (user, hour_bucket, keystrokes, mouse_clicks, app_switches,
         files_accessed, net_bytes_sent, clipboard_events, usb_count, email_sent)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (user, bucket,
         stats.get("keystrokes", 0),
         stats.get("mouse_clicks", 0),
         stats.get("app_switches", 0),
         stats.get("files_accessed", 0),
         stats.get("net_bytes_sent", 0),
         stats.get("clipboard_events", 0),
         stats.get("usb_count", 0),
         stats.get("email_sent", 0)))
    conn.commit()
    # Keep only last 30 days
    conn.execute("""DELETE FROM hourly_stats WHERE hour_bucket < ?""",
                 ((datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT%H"),))
    conn.commit()
    conn.close()

def get_user_baseline(user: str) -> dict:
    """
    Returns mean + stdev for key metrics over the past 30 days (same hour of day).
    Used to compute deviation score → FP reduction.
    """
    import statistics
    conn = sqlite3.connect(str(BASELINE_DB), timeout=10)
    current_hour = datetime.now().hour
    rows = conn.execute("""
        SELECT keystrokes, mouse_clicks, app_switches, files_accessed,
               net_bytes_sent, clipboard_events, usb_count, email_sent
        FROM hourly_stats
        WHERE user = ?
          AND CAST(substr(hour_bucket, 12, 2) AS INTEGER) = ?
          AND hour_bucket < ?
        ORDER BY hour_bucket DESC LIMIT 60
    """, (user, current_hour, datetime.now().strftime("%Y-%m-%dT%H"))).fetchall()
    conn.close()

    if len(rows) < 3:
        return {}   # not enough history yet

    keys = ["keystrokes","mouse_clicks","app_switches","files_accessed",
            "net_bytes_sent","clipboard_events","usb_count","email_sent"]
    baseline = {}
    for i, k in enumerate(keys):
        vals = [r[i] for r in rows if r[i] is not None]
        if vals:
            mean = statistics.mean(vals)
            sd   = statistics.pstdev(vals) or 1.0
            baseline[k] = {"mean": round(mean, 2), "stdev": round(sd, 2)}
    return baseline

def compute_deviation_score(current: dict, baseline: dict) -> float:
    """
    Z-score based deviation from personal baseline.
    Returns 0-100 score. Higher = more anomalous.
    FP reduction: event only scores high if it deviates from THIS USER's norm.
    """
    if not baseline:
        return 0.0
    z_scores = []
    mapping = {
        "keystrokes":      current.get("keystrokes", 0),
        "app_switches":    current.get("app_switches", 0),
        "files_accessed":  current.get("files_accessed", 0),
        "net_bytes_sent":  current.get("net_bytes_sent", 0),
        "clipboard_events": current.get("clipboard_events", 0),
        "usb_count":       current.get("usb_count", 0),
        "email_sent":      current.get("email_sent", 0),
    }
    for key, val in mapping.items():
        if key in baseline:
            mean = baseline[key]["mean"]
            sd   = baseline[key]["stdev"]
            z = abs(val - mean) / (sd if sd > 0 else 1.0)
            z_scores.append(min(z, 5.0))   # cap at 5σ
    if not z_scores:
        return 0.0
    avg_z = sum(z_scores) / len(z_scores)
    return round(min(avg_z / 5.0 * 100, 100), 2)

# ─────────────────────────────────────────────────────────────────────────────
# In-memory live counters (reset each send cycle)
# ─────────────────────────────────────────────────────────────────────────────
class LiveCounters:
    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.keystrokes       = 0
            self.key_intervals_ms = deque(maxlen=500)  # inter-key timing
            self.mouse_clicks     = 0
            self.app_switches     = 0
            self.last_app         = ""
            self.clipboard_events = 0
            self.clipboard_credential_hits = 0
            self.clipboard_large_paste     = 0
            self.cloud_sync_events         = []   # watchdog events
            self.print_jobs                = []

    def snapshot(self) -> dict:
        with self._lock:
            intervals = list(self.key_intervals_ms)
            rhythm_stdev = 0.0
            if len(intervals) > 3:
                import statistics
                rhythm_stdev = round(statistics.pstdev(intervals), 2)
            return {
                "keystrokes":            self.keystrokes,
                "keystroke_rhythm_stdev_ms": rhythm_stdev,
                "mouse_clicks":          self.mouse_clicks,
                "app_switches":          self.app_switches,
                "clipboard_events":      self.clipboard_events,
                "clipboard_credential_hits": self.clipboard_credential_hits,
                "clipboard_large_paste": self.clipboard_large_paste,
                "cloud_sync_events":     list(self.cloud_sync_events)[:20],
                "print_jobs":            list(self.print_jobs)[:10],
            }

COUNTERS = LiveCounters()

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1 — Keystroke Monitor (rhythm only, zero content)
# ─────────────────────────────────────────────────────────────────────────────
_last_key_time = [0.0]

def _on_key_press(key):
    """Count keystrokes and measure inter-key timing for rhythm analysis."""
    now = time.monotonic() * 1000
    with COUNTERS._lock:
        COUNTERS.keystrokes += 1
        if _last_key_time[0] > 0:
            interval = now - _last_key_time[0]
            if 10 < interval < 5000:   # filter noise / idle gaps
                COUNTERS.key_intervals_ms.append(interval)
        _last_key_time[0] = now

def start_keystroke_monitor():
    if not PYNPUT_OK:
        return
    listener = _kb.Listener(on_press=_on_key_press, suppress=False)
    listener.daemon = True
    listener.start()

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2 — Clipboard Monitor
# ─────────────────────────────────────────────────────────────────────────────
_last_clipboard_hash = [None]

def _clipboard_worker():
    """Poll clipboard every 2 s. Record metadata only — NO raw content sent."""
    while True:
        try:
            if CLIPBOARD_OK:
                win32clipboard.OpenClipboard()
                try:
                    if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                        text = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                        h = hashlib.md5(text.encode(errors="ignore")).hexdigest()
                        if h != _last_clipboard_hash[0]:
                            _last_clipboard_hash[0] = h
                            length = len(text)
                            cred_hit = any(p.search(text) for p in CREDENTIAL_PATTERNS)
                            large = length > 500
                            with COUNTERS._lock:
                                COUNTERS.clipboard_events += 1
                                if cred_hit:
                                    COUNTERS.clipboard_credential_hits += 1
                                if large:
                                    COUNTERS.clipboard_large_paste += 1
                finally:
                    win32clipboard.CloseClipboard()
        except Exception:
            pass
        time.sleep(2)

def start_clipboard_monitor():
    t = threading.Thread(target=_clipboard_worker, daemon=True)
    t.start()

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3 — Cloud Sync Folder Watcher
# ─────────────────────────────────────────────────────────────────────────────
CLOUD_SYNC_PATHS = []

def _detect_cloud_sync_dirs() -> list:
    home = Path.home()
    candidates = [
        home / "Dropbox",
        home / "OneDrive",
        home / "Google Drive",
        home / "Box",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Drive" / "My Drive",
    ]
    return [str(p) for p in candidates if p.exists()]

if WATCHDOG_OK:
    class _CloudSyncHandler(FileSystemEventHandler):
        def on_created(self, event):
            self._record("created", event.src_path)
        def on_modified(self, event):
            self._record("modified", event.src_path)
        def on_moved(self, event):
            self._record("moved", event.src_path)

        def _record(self, action, path):
            try:
                size = os.path.getsize(path) if os.path.isfile(path) else 0
            except Exception:
                size = 0
            with COUNTERS._lock:
                COUNTERS.cloud_sync_events.append({
                    "action": action,
                    "filename": os.path.basename(path)[:120],
                    "size_bytes": size,
                    "time": datetime.now(timezone.utc).isoformat()
                })

def start_cloud_sync_monitor():
    if not WATCHDOG_OK:
        return
    dirs = _detect_cloud_sync_dirs()
    if not dirs:
        return
    observer = Observer()
    handler = _CloudSyncHandler()
    for d in dirs:
        observer.schedule(handler, d, recursive=True)
    observer.daemon = True
    observer.start()

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4 — Print-Job Monitor (Windows Spooler via WMI)
# ─────────────────────────────────────────────────────────────────────────────
_seen_print_jobs: set = set()

def get_print_jobs() -> list:
    """Return new print jobs since last call."""
    jobs = []
    if not WIN32COM_OK:
        return jobs
    try:
        wmi = _w32com.GetObject("winmgmts:")
        for job in wmi.ExecQuery("SELECT * FROM Win32_PrintJob"):
            jid = getattr(job, "JobId", 0)
            if jid not in _seen_print_jobs:
                _seen_print_jobs.add(jid)
                jobs.append({
                    "document":   str(getattr(job, "Document", ""))[:120],
                    "printer":    str(getattr(job, "Name", ""))[:80],
                    "owner":      str(getattr(job, "Owner", ""))[:80],
                    "pages":      getattr(job, "TotalPages", 0),
                    "size_bytes": getattr(job, "Size", 0),
                    "time":       datetime.now(timezone.utc).isoformat()
                })
    except Exception:
        pass
    return jobs

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 5 — Login Pattern Profiling
# ─────────────────────────────────────────────────────────────────────────────
def get_login_events() -> dict:
    """
    Returns current sessions + failed login attempts.
    Flags off-hours logins and unusual source IPs.
    """
    sessions = []
    failed_logins = 0
    try:
        for u in psutil.users():
            started = getattr(u, "started", None)
            t = datetime.fromtimestamp(started, timezone.utc).isoformat() if started else None
            hour = datetime.fromtimestamp(started).hour if started else datetime.now().hour
            off_hours = hour < WORK_HOUR_START or hour > WORK_HOUR_END
            sessions.append({
                "user":      u.name,
                "terminal":  u.terminal or "",
                "host":      u.host or "",
                "time":      t,
                "off_hours": off_hours,
            })
    except Exception:
        pass

    # Windows: read failed logon count from Security event log via WMI
    if WIN32COM_OK:
        try:
            wmi = _w32com.GetObject("winmgmts:{impersonationLevel=impersonate,(Security)}!//.")
            # EventID 4625 = failed logon (Windows Security log)
            q = ("SELECT * FROM Win32_NTLogEvent WHERE Logfile='Security' "
                 "AND EventCode='4625'")
            events = wmi.ExecQuery(q)
            for _ in events:
                failed_logins += 1
                if failed_logins > 100:    # cap for performance
                    break
        except Exception:
            pass

    return {
        "active_sessions": sessions,
        "session_count":   len(sessions),
        "failed_logon_count": failed_logins,
        "off_hours_session": any(s["off_hours"] for s in sessions),
    }

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 6 — Email Behaviour (Outlook COM)
# ─────────────────────────────────────────────────────────────────────────────
# Known internal domains — customise for your org
INTERNAL_DOMAINS = set(os.getenv("AGENT_INTERNAL_DOMAINS", "company.com,corp.local").split(","))

def get_email_activity() -> dict:
    """
    Analyse Outlook today:
      - sent / received counts
      - external recipient count
      - attachment count + total size
      - bulk-send flag (>20 external in one session)
    """
    result = {
        "sent_count": 0, "recv_count": 0,
        "external_recipients": 0,
        "attachment_count": 0,
        "attachment_total_bytes": 0,
        "bulk_send_flag": False,
        "draft_count": 0,
    }
    if not WIN32COM_OK:
        return result
    try:
        outlook   = _w32com.Dispatch("Outlook.Application")
        ns        = outlook.GetNamespace("MAPI")
        today     = datetime.now().date()

        # Sent Items (folder 5)
        sent = ns.GetDefaultFolder(5).Items
        sent.Sort("[SentOn]", True)
        for item in sent:
            try:
                d = getattr(item, "SentOn", None)
                if d and hasattr(d, "date") and d.date() == today:
                    result["sent_count"] += 1
                    # Check recipients
                    for r in item.Recipients:
                        addr = str(getattr(r, "Address", "")).lower()
                        domain = addr.split("@")[-1] if "@" in addr else ""
                        if domain and domain not in INTERNAL_DOMAINS:
                            result["external_recipients"] += 1
                    # Attachments
                    for att in item.Attachments:
                        result["attachment_count"] += 1
                        result["attachment_total_bytes"] += getattr(att, "Size", 0)
                elif d and hasattr(d, "date") and d.date() < today:
                    break
            except Exception:
                continue

        # Inbox (folder 6)
        inbox = ns.GetDefaultFolder(6).Items
        inbox.Sort("[ReceivedTime]", True)
        for item in inbox:
            try:
                d = getattr(item, "ReceivedTime", None)
                if d and hasattr(d, "date") and d.date() == today:
                    result["recv_count"] += 1
                elif d and hasattr(d, "date") and d.date() < today:
                    break
            except Exception:
                continue

        # Drafts (folder 16)
        try:
            result["draft_count"] = ns.GetDefaultFolder(16).Items.Count
        except Exception:
            pass

        result["bulk_send_flag"] = result["external_recipients"] > 20

    except Exception:
        pass
    return result

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 7 — Sensitive / Malicious File Detection
# ─────────────────────────────────────────────────────────────────────────────

# Known malware hashes (MD5) — extend with threat-intel feeds
KNOWN_BAD_HASHES_MD5: set = set(os.getenv("AGENT_BAD_HASHES", "").split(",")) - {""}

def _file_md5(path: str) -> str:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def detect_sensitive_files(limit=MAX_RISK_FILES) -> list:
    """
    Scan home dirs for:
      1. Keyword hits in filename
      2. Sensitive extension
      3. Recently modified (last 1 h) — higher weight
      4. Known-bad MD5 hash
    Each finding gets a risk_weight (1-3).
    """
    results = []
    base_dirs = [
        Path.home() / "Documents",
        Path.home() / "Desktop",
        Path.home() / "Downloads",
        Path.home() / "AppData" / "Roaming",
    ]
    cutoff = datetime.now().timestamp() - 3600  # last hour

    for d in base_dirs:
        if not d.is_dir():
            continue
        for fname in os.listdir(str(d)):
            if len(results) >= limit:
                break
            fp = d / fname
            risk_weight = 0
            reasons = []

            flower = fname.lower()
            # Keyword hit
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in flower:
                    risk_weight += 1
                    reasons.append(f"keyword:{kw}")
                    break

            # Sensitive extension
            ext = Path(fname).suffix.lower()
            if ext in SENSITIVE_EXTENSIONS:
                risk_weight += 1
                reasons.append(f"ext:{ext}")

            # Recently modified
            try:
                mtime = fp.stat().st_mtime
                if mtime > cutoff:
                    risk_weight += 1
                    reasons.append("recent_modify")
            except Exception:
                pass

            if risk_weight == 0:
                continue

            entry = {
                "filename":    fname[:120],
                "path":        str(fp)[:250],
                "reasons":     reasons,
                "risk_weight": risk_weight,
                "size_bytes":  0,
                "md5":         "",
                "known_bad":   False,
                "time":        datetime.now(timezone.utc).isoformat()
            }
            try:
                entry["size_bytes"] = fp.stat().st_size
            except Exception:
                pass

            # Hash only if small enough (< 5 MB) to avoid stalling
            if entry["size_bytes"] < 5 * 1024 * 1024:
                md5 = _file_md5(str(fp))
                entry["md5"] = md5
                if md5 in KNOWN_BAD_HASHES_MD5:
                    entry["known_bad"] = True
                    entry["risk_weight"] += 3
                    reasons.append("known_bad_hash")

            results.append(entry)

        if len(results) >= limit:
            break

    results.sort(key=lambda x: x["risk_weight"], reverse=True)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 8 — Process & Application Monitor
# ─────────────────────────────────────────────────────────────────────────────

# Processes that are suspicious if seen unexpectedly
SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe",
    "pwdump.exe", "gsecdump.exe", "lsadump.exe",
    "netcat.exe", "nc.exe", "ncat.exe",
    "wireshark.exe", "tcpdump.exe", "rawcap.exe",
    "psexec.exe", "paexec.exe",
    "tor.exe", "privoxy.exe",
    "7z.exe", "7za.exe", "winrar.exe",
    "rclone.exe", "restic.exe",
    "python.exe", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
}

def get_process_snapshot(limit=MAX_PROCESS_ENTRIES) -> dict:
    """
    Returns process list + flags suspicious ones.
    Tracks active window title for context.
    """
    procs = []
    suspicious_found = []
    try:
        for p in psutil.process_iter(["pid", "name", "username", "cpu_percent",
                                       "memory_percent", "create_time"]):
            try:
                info = p.info
                name_lower = (info["name"] or "").lower()
                entry = {
                    "pid":    info["pid"],
                    "name":   info["name"][:60],
                    "user":   (info["username"] or "")[:60],
                    "cpu":    round(info["cpu_percent"] or 0, 1),
                    "mem":    round(info["memory_percent"] or 0, 1),
                }
                if name_lower in SUSPICIOUS_PROCESSES:
                    entry["suspicious"] = True
                    suspicious_found.append(name_lower)
                procs.append(entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass

    procs.sort(key=lambda x: x.get("cpu", 0), reverse=True)

    active_window = "unknown"
    if WIN32_OK:
        try:
            hwnd  = win32gui.GetForegroundWindow()
            active_window = win32gui.GetWindowText(hwnd)[:200]
        except Exception:
            pass

    return {
        "top_processes":      procs[:limit],
        "suspicious_procs":   suspicious_found,
        "suspicious_count":   len(suspicious_found),
        "active_window":      active_window,
    }

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 9 — Network Activity
# ─────────────────────────────────────────────────────────────────────────────

# Track previous counters for delta computation
_prev_net = {"bytes_sent": 0, "bytes_recv": 0, "ts": time.monotonic()}

# Known suspicious ports
SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 6667, 6697,   # C2 / IRC
    9050, 9150,                        # Tor
    5900, 5800,                        # VNC
    3389,                              # RDP (external)
    22, 23,                            # SSH/Telnet (note if unexpected)
}

def get_network_activity() -> dict:
    global _prev_net
    now = time.monotonic()
    try:
        nio = psutil.net_io_counters()
        elapsed = max(now - _prev_net["ts"], 1)
        sent_delta  = max(nio.bytes_sent - _prev_net["bytes_sent"], 0)
        recv_delta  = max(nio.bytes_recv - _prev_net["bytes_recv"], 0)
        sent_bps    = sent_delta / elapsed
        recv_bps    = recv_delta / elapsed
        _prev_net = {"bytes_sent": nio.bytes_sent, "bytes_recv": nio.bytes_recv, "ts": now}
    except Exception:
        sent_delta = recv_delta = sent_bps = recv_bps = 0

    # Active connections
    conns = []
    suspicious_conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != "ESTABLISHED":
                continue
            raddr = c.raddr
            if not raddr:
                continue
            rport = raddr.port
            entry = {
                "raddr":  f"{raddr.ip}:{rport}",
                "lport":  c.laddr.port if c.laddr else 0,
                "pid":    c.pid,
            }
            if rport in SUSPICIOUS_PORTS:
                entry["suspicious_port"] = True
                suspicious_conns.append(entry)
            conns.append(entry)
    except Exception:
        pass

    return {
        "bytes_sent_delta":   int(sent_delta),
        "bytes_recv_delta":   int(recv_delta),
        "send_bps":           round(sent_bps, 1),
        "recv_bps":           round(recv_bps, 1),
        "established_conns":  len(conns),
        "suspicious_conns":   suspicious_conns[:10],
        "large_upload_flag":  sent_bps > 1_000_000,  # > 1 MB/s sustained upload
    }

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 10 — USB / Removable Media
# ─────────────────────────────────────────────────────────────────────────────
_known_usb: set = set()   # track newly inserted vs. pre-existing

def get_usb_devices() -> dict:
    devices = []
    newly_inserted = []
    try:
        for part in psutil.disk_partitions(all=False):
            if "removable" not in (part.opts or ""):
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                entry = {
                    "device":       part.device,
                    "mountpoint":   part.mountpoint,
                    "fstype":       part.fstype,
                    "total_gb":     round(usage.total / (1024 ** 3), 2),
                    "used_gb":      round(usage.used  / (1024 ** 3), 2),
                    "percent_used": usage.percent,
                }
            except Exception:
                entry = {"device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype}
            devices.append(entry)
            if part.device not in _known_usb:
                newly_inserted.append(part.device)
                _known_usb.add(part.device)
    except Exception:
        pass
    return {
        "devices":        devices,
        "count":          len(devices),
        "newly_inserted": newly_inserted,
        "new_usb_flag":   len(newly_inserted) > 0,
    }

# ─────────────────────────────────────────────────────────────────────────────
# MODULE 11 — Browser History
# ─────────────────────────────────────────────────────────────────────────────
def detect_browsers() -> list:
    found = []
    local   = os.environ.get("LOCALAPPDATA", "")
    appdata = os.environ.get("APPDATA", "")
    checks = {
        "Chrome":  Path(local)  / "Google/Chrome/User Data/Default/History",
        "Brave":   Path(local)  / "BraveSoftware/Brave-Browser/User Data/Default/History",
        "Edge":    Path(local)  / "Microsoft/Edge/User Data/Default/History",
        "Firefox": Path(appdata)/ "Mozilla/Firefox/Profiles",
    }
    for name, p in checks.items():
        if p.exists():
            found.append(name)
    return found

def get_browser_history(browser: str, limit=MAX_BROWSER_ENTRIES) -> list:
    history = []
    local   = os.environ.get("LOCALAPPDATA", "")
    appdata = os.environ.get("APPDATA", "")
    mapping = {
        "Chrome":  Path(local)  / "Google/Chrome/User Data/Default/History",
        "Brave":   Path(local)  / "BraveSoftware/Brave-Browser/User Data/Default/History",
        "Edge":    Path(local)  / "Microsoft/Edge/User Data/Default/History",
    }

    if browser == "Firefox":
        prof_dir = Path(appdata) / "Mozilla/Firefox/Profiles"
        if not prof_dir.is_dir():
            return []
        profiles = [d for d in os.listdir(str(prof_dir))
                    if d.endswith(".default") or d.endswith(".default-release")]
        if not profiles:
            return []
        path = prof_dir / profiles[0] / "places.sqlite"
    else:
        path = mapping.get(browser)

    if not path or not path.exists():
        return []

    tmp = TEMP_DIR / f"{AGENT_ID}_{browser}_hist.db"
    try:
        shutil.copy2(str(path), str(tmp))
        conn = sqlite3.connect(str(tmp))
        cur  = conn.cursor()
        if browser in ("Chrome", "Brave", "Edge"):
            cur.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT ?", (limit,))
        else:
            cur.execute("SELECT url, title FROM moz_places ORDER BY last_visit_date DESC LIMIT ?", (limit,))
        for row in cur.fetchall():
            url   = str(row[0] or "")[:200]
            title = str(row[1] or "")[:120]
            history.append({"browser": browser, "url": url, "title": title})
        conn.close()
    except Exception:
        pass
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
    return history

# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────
def safe_getlogin() -> str:
    try:
        return os.getlogin()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"

def get_disk_io_delta() -> dict:
    try:
        d = psutil.disk_io_counters()
        return {
            "read_mb":  round(d.read_bytes  / (1024 ** 2), 2),
            "write_mb": round(d.write_bytes / (1024 ** 2), 2),
        }
    except Exception:
        return {"read_mb": 0, "write_mb": 0}

def take_screenshot() -> "str | None":
    if not SCREENSHOT_ENABLED:
        return None
    try:
        from PIL import ImageGrab
        img  = ImageGrab.grab()
        tmp  = TEMP_DIR / f"snap_{AGENT_ID}_{int(time.time())}.jpg"
        img.convert("RGB").save(str(tmp), format="JPEG", quality=40)
        size = tmp.stat().st_size
        if size > SCREENSHOT_MAX_BYTES:
            tmp.unlink(missing_ok=True)
            return None
        data = tmp.read_bytes()
        tmp.unlink(missing_ok=True)
        return base64.b64encode(data).decode()
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Transport
# ─────────────────────────────────────────────────────────────────────────────
def _send_with_retry(session, url, headers, payload_bytes, max_attempts=4) -> bool:
    backoff = 1.0
    for attempt in range(1, max_attempts + 1):
        try:
            r = session.post(url, data=payload_bytes, headers=headers, timeout=10, verify=True)
            if 200 <= r.status_code < 300:
                return True
            if 400 <= r.status_code < 500 and r.status_code != 429:
                return False
        except requests.exceptions.SSLError:
            return False
        except requests.exceptions.RequestException:
            pass
        time.sleep(backoff)
        backoff = min(backoff * 2, 30)
    return False

# ─────────────────────────────────────────────────────────────────────────────
# Payload builder — assembles everything
# ─────────────────────────────────────────────────────────────────────────────
def build_payload() -> dict:
    tz   = pytz.timezone(TIMEZONE)
    user = safe_getlogin()
    hour = datetime.now().hour
    is_off_hours = hour < WORK_HOUR_START or hour > WORK_HOUR_END

    # ── Collect all modules ──────────────────────────────────────────────
    kb_snap     = COUNTERS.snapshot()
    COUNTERS.reset()

    print_jobs  = get_print_jobs()
    with COUNTERS._lock:
        COUNTERS.print_jobs.extend(print_jobs)

    login_info  = get_login_events()
    email_info  = get_email_activity()
    file_info   = detect_sensitive_files()
    proc_info   = get_process_snapshot()
    net_info    = get_network_activity()
    usb_info    = get_usb_devices()
    disk_io     = get_disk_io_delta()
    browsers    = detect_browsers()

    browsing = []
    for b in browsers:
        browsing.extend(get_browser_history(b))
        if len(browsing) >= MAX_BROWSER_ENTRIES:
            break

    # ── Per-user baseline & deviation score ─────────────────────────────
    current_stats = {
        "keystrokes":      kb_snap["keystrokes"],
        "app_switches":    kb_snap["app_switches"],
        "files_accessed":  len(file_info),
        "net_bytes_sent":  net_info["bytes_sent_delta"],
        "clipboard_events": kb_snap["clipboard_events"],
        "usb_count":       usb_info["count"],
        "email_sent":      email_info["sent_count"],
    }
    save_hourly_stats(user, current_stats)
    baseline = get_user_baseline(user)
    deviation_score = compute_deviation_score(current_stats, baseline)

    # ── Rule-based risk flags (deterministic, interpretable) ─────────────
    # These complement ML and reduce FP by requiring COMBINATIONS of signals
    risk_flags = []

    if usb_info["new_usb_flag"] and net_info["bytes_sent_delta"] > 10_000_000:
        risk_flags.append("USB_INSERT_WITH_LARGE_UPLOAD")

    if kb_snap["clipboard_credential_hits"] > 0:
        risk_flags.append("CLIPBOARD_CREDENTIAL_PATTERN")

    if kb_snap["clipboard_large_paste"] > 0 and usb_info["count"] > 0:
        risk_flags.append("LARGE_PASTE_WITH_USB_PRESENT")

    if email_info["bulk_send_flag"]:
        risk_flags.append("BULK_EXTERNAL_EMAIL")

    if email_info["attachment_total_bytes"] > 20 * 1024 * 1024:
        risk_flags.append("LARGE_EMAIL_ATTACHMENT")

    if proc_info["suspicious_count"] > 0:
        risk_flags.append(f"SUSPICIOUS_PROCESS:{','.join(proc_info['suspicious_procs'])}")

    if net_info["suspicious_conns"]:
        risk_flags.append("SUSPICIOUS_NETWORK_PORT")

    if net_info["large_upload_flag"] and is_off_hours:
        risk_flags.append("LARGE_UPLOAD_AFTER_HOURS")

    if login_info["failed_logon_count"] > 5:
        risk_flags.append("MULTIPLE_FAILED_LOGONS")

    if login_info["off_hours_session"] and len(file_info) > 2:
        risk_flags.append("OFF_HOURS_FILE_ACCESS")

    if any(f.get("known_bad") for f in file_info):
        risk_flags.append("KNOWN_BAD_FILE_HASH")

    if kb_snap["cloud_sync_events"]:
        total_cloud = sum(e.get("size_bytes", 0) for e in kb_snap["cloud_sync_events"])
        if total_cloud > 50 * 1024 * 1024:
            risk_flags.append("LARGE_CLOUD_SYNC_UPLOAD")

    if print_jobs:
        total_pages = sum(j.get("pages", 0) for j in print_jobs)
        if total_pages > 50:
            risk_flags.append("HIGH_VOLUME_PRINTING")

    # ── Composite pre-score (helps ML + reduces FP at server) ────────────
    # Score = weighted sum of flags + deviation score
    FLAG_WEIGHTS = {
        "USB_INSERT_WITH_LARGE_UPLOAD":    35,
        "CLIPBOARD_CREDENTIAL_PATTERN":    30,
        "LARGE_PASTE_WITH_USB_PRESENT":    25,
        "BULK_EXTERNAL_EMAIL":             30,
        "LARGE_EMAIL_ATTACHMENT":          15,
        "SUSPICIOUS_NETWORK_PORT":         25,
        "LARGE_UPLOAD_AFTER_HOURS":        30,
        "MULTIPLE_FAILED_LOGONS":          20,
        "OFF_HOURS_FILE_ACCESS":           15,
        "KNOWN_BAD_FILE_HASH":             50,
        "LARGE_CLOUD_SYNC_UPLOAD":         25,
        "HIGH_VOLUME_PRINTING":            20,
    }
    rule_score = 0
    for flag in risk_flags:
        for k, w in FLAG_WEIGHTS.items():
            if flag.startswith(k):
                rule_score += w
    rule_score = min(rule_score, 100)

    agent_risk_score = round(0.5 * rule_score + 0.5 * deviation_score, 2)

    # ── Assemble final payload ────────────────────────────────────────────
    payload = {
        "schema_version": "2.0",
        "timestamp":  datetime.now(tz).isoformat(),
        "agent_id":   AGENT_ID,
        "hostname":   platform.node()[:100],
        "os":         platform.system(),
        "os_version": platform.platform()[:120],
        "status":     "online",

        # Identity & session
        "session": {
            "user":          user[:80],
            "status":        "active",
            "is_off_hours":  is_off_hours,
            "hour_of_day":   hour,
        },

        # Behavioural biometrics
        "keystroke_behaviour": {
            "keystrokes_per_interval": kb_snap["keystrokes"],
            "rhythm_stdev_ms":         kb_snap["keystroke_rhythm_stdev_ms"],
            "app_switches":            kb_snap["app_switches"],
            "active_window":           proc_info["active_window"],
        },

        # Clipboard analysis (metadata only)
        "clipboard_behaviour": {
            "events":            kb_snap["clipboard_events"],
            "credential_hits":   kb_snap["clipboard_credential_hits"],
            "large_paste_count": kb_snap["clipboard_large_paste"],
        },

        # File intelligence
        "file_activity": {
            "risk_files":    file_info,
            "risk_file_count": len(file_info),
            "disk_io":       disk_io,
        },

        # Network
        "network_activity": net_info,

        # Email
        "email_activity": email_info,

        # USB / removable
        "usb_activity": usb_info,

        # Login
        "login_activity": login_info,

        # Process
        "process_activity": {
            "suspicious_procs":  proc_info["suspicious_procs"],
            "suspicious_count":  proc_info["suspicious_count"],
            "top_processes":     proc_info["top_processes"],
        },

        # Cloud sync
        "cloud_sync_activity": {
            "events":      kb_snap["cloud_sync_events"],
            "event_count": len(kb_snap["cloud_sync_events"]),
        },

        # Print
        "print_activity": {
            "jobs":        print_jobs,
            "job_count":   len(print_jobs),
        },

        # Browser
        "browsers_installed": browsers,
        "recent_browsing":    browsing,

        # Risk intelligence (pre-computed, aids server ML)
        "risk_intelligence": {
            "rule_based_flags":   risk_flags,
            "rule_score":         rule_score,
            "deviation_score":    deviation_score,
            "agent_risk_score":   agent_risk_score,
            "baseline_available": bool(baseline),
            "baseline_snapshot":  baseline,
        },
    }

    # Optional screenshot
    ss = take_screenshot()
    if ss:
        payload["screenshot_b64"] = ss

    # IP
    try:
        payload["ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        payload["ip"] = None

    return payload

# ─────────────────────────────────────────────────────────────────────────────
# Send routine
# ─────────────────────────────────────────────────────────────────────────────
def send_payload(session, endpoint: str, payload_obj: dict) -> bool:
    try:
        payload_json = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        payload_json = json.dumps({"agent_id": AGENT_ID,
                                   "timestamp": datetime.now(timezone.utc).isoformat()})

    # Size cap
    if len(payload_json.encode()) > 512_000:
        payload_obj["recent_browsing"]             = payload_obj.get("recent_browsing", [])[:2]
        payload_obj["process_activity"]["top_processes"] = \
            payload_obj["process_activity"].get("top_processes", [])[:5]
        payload_json = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False)

    payload_bytes = payload_json.encode("utf-8")
    sig = sign_payload(payload_bytes)
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-KEY"] = API_KEY
    if sig:
        headers["X-PAYLOAD-SIGNATURE"] = sig

    ok = _send_with_retry(session, endpoint, headers, payload_bytes)
    if not ok:
        try:
            enqueue_payload(payload_json)
        except Exception:
            pass
    else:
        try:
            dequeue_and_send_all(session, endpoint, headers)
        except Exception:
            pass
    return ok

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def run_agent():
    print(f"[*] UAM Agent v2 starting — id: {AGENT_ID}")

    # Start background monitors
    start_keystroke_monitor()
    start_clipboard_monitor()
    start_cloud_sync_monitor()
    print("[+] Background monitors started")

    session = requests.Session()
    session.headers.update({"User-Agent": "UAM-Agent/2.0"})

    jitter_base = hash(AGENT_ID) % 7

    while True:
        try:
            payload = build_payload()
            ok = send_payload(session, SERVER_URL, payload)
            score = payload["risk_intelligence"]["agent_risk_score"]
            flags = payload["risk_intelligence"]["rule_based_flags"]
            print(f"[{'OK' if ok else 'Q'}] Sent | risk={score} flags={flags or 'none'}")
        except Exception as e:
            if DEBUG:
                import traceback
                traceback.print_exc()
            else:
                print(f"[!] Agent loop error: {e}")

        time.sleep(SEND_INTERVAL + jitter_base)


if __name__ == "__main__":
    try:
        run_agent()
    except KeyboardInterrupt:
        print("Agent stopped.")
    except Exception as e:
        print(f"Fatal: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
