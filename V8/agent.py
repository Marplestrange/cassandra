#!/usr/bin/env python3
"""
CASSANDRA — Agent Infrastructure v8.0
======================================
OPTIMISATIONS v8.0 :
  [DB] Utilisation DIRECTE des tables du collector V5.2
  [CACHE] Cache intelligent avec invalidation automatique
  [METRICS] Métriques temps réel via socket UNIX du collector
  [RCLONE] Récupération depuis table rclone_remotes (pas rclone listremotes)
  [DISKS] Tous les montages (y compris rclone mounts) depuis system_mounts
  [PERF] Réduction des appels système, utilisation de la DB du collector
  [INCIDENTS] Corrélation avec les événements OOM et failed units du collector
"""

import os
import sys
import shlex
import subprocess
import json
import re
import logging
import logging.handlers
import sqlite3
import time
import hashlib
import urllib.request
import urllib.error
import socket
import threading
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter, defaultdict
from functools import lru_cache, wraps
from typing import Dict, List, Any, Optional, Tuple

# ============================================================
# CONFIGURATION
# ============================================================
def load_env():
    candidates = [
        Path("/root/.env"),
        Path(__file__).parent / ".env",
        Path.home() / ".env",
        Path("/var/www/fastuser/data/www/chat.cassandra.center/.env"),
    ]
    for env_path in candidates:
        if env_path.exists():
            try:
                for raw in env_path.read_text(encoding="utf-8").splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k and not os.environ.get(k):
                        os.environ[k] = v
            except Exception as e:
                print(f"[CASSANDRA] Avertissement .env ({env_path}): {e}", file=sys.stderr)
            break

load_env()

DEEPSEEK_API_KEY   = os.environ.get("DEEPSEEK_API_KEY", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")
APP_PASSWORD_HASH  = os.environ.get("CASSANDRA_PASSWORD_HASH", "")
REMOTE_HOSTS_CONFIG = os.environ.get("REMOTE_HOSTS", "[]")

CMD_TIMEOUT      = int(os.environ.get("CASSANDRA_CMD_TIMEOUT", "15"))
MAX_OUTPUT_CHARS = 5000
COLLECTOR_SOCKET = os.environ.get("CASSANDRA_SOCKET", "/tmp/cassandra_knowledge.sock")
USE_COLLECTOR_SOCKET = os.environ.get("CASSANDRA_USE_SOCKET", "1") == "1"

if not DEEPSEEK_API_KEY:
    print("[CASSANDRA] ERREUR : DEEPSEEK_API_KEY manquante dans .env", file=sys.stderr)
    sys.exit(1)

# ============================================================
# BASE DE DONNÉES (utilisation directe du collector)
# ============================================================
def get_db_path():
    """Utilise la même DB que le collector V5.2"""
    db_path = "/var/lib/cassandra/cassandra.db"
    try:
        parent = Path(db_path).parent
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o770)
        return db_path
    except Exception:
        pass
    db_path = os.environ.get("CASSANDRA_DB", "")
    if db_path:
        try:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            return db_path
        except Exception:
            pass
    return "/tmp/cassandra.db"

DB_PATH = get_db_path()
LOG_PATH = os.environ.get("CASSANDRA_LOG", "/tmp/cassandra_audit.log")

# ============================================================
# LOGGING
# ============================================================
try:
    _handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    logging.basicConfig(
        handlers=[_handler], level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )
except (PermissionError, OSError):
    logging.basicConfig(
        stream=sys.stderr, level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

audit = logging.getLogger("cassandra.audit")

# ============================================================
# CACHE INTELLIGENT
# ============================================================
class TTLDict:
    """Dictionnaire avec TTL pour le cache"""
    def __init__(self, default_ttl=30):
        self._data = {}
        self._expires = {}
        self._default_ttl = default_ttl
    
    def set(self, key, value, ttl=None):
        ttl = ttl or self._default_ttl
        self._data[key] = value
        self._expires[key] = time.time() + ttl
    
    def get(self, key):
        if key in self._data and time.time() < self._expires[key]:
            return self._data[key]
        if key in self._data:
            del self._data[key]
            del self._expires[key]
        return None
    
    def invalidate(self, key=None):
        if key:
            self._data.pop(key, None)
            self._expires.pop(key, None)
        else:
            self._data.clear()
            self._expires.clear()

_cache = TTLDict(default_ttl=30)

def cached(ttl=30):
    """Décorateur de cache"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            cached_val = _cache.get(key)
            if cached_val is not None:
                return cached_val
            result = func(*args, **kwargs)
            _cache.set(key, result, ttl)
            return result
        return wrapper
    return decorator

# ============================================================
# SOCKET CLIENT (accès ultra-rapide au collector)
# ============================================================
class CollectorSocketClient:
    """Client pour le socket mémoire partagée du collector V5.2"""
    
    def __init__(self, socket_path=COLLECTOR_SOCKET):
        self.socket_path = socket_path
        self._cache_ttl = 5
        self._last_connect_attempt = 0
        self._connect_error = False
    
    def _connect(self):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(self.socket_path)
            return sock
        except Exception as e:
            return None
    
    def _send_request(self, command):
        if not USE_COLLECTOR_SOCKET:
            return None
        sock = self._connect()
        if not sock:
            return None
        try:
            sock.send(command.encode())
            response = sock.recv(65536)
            return json.loads(response.decode())
        except Exception:
            return None
        finally:
            sock.close()
    
    def get_knowledge(self):
        """GET_KNOWLEDGE → cache du collector"""
        return self._send_request("GET_KNOWLEDGE")
    
    def get_metrics(self):
        """GET_METRICS → métriques temps réel ultra-rapides"""
        return self._send_request("GET_METRICS")
    
    def get_dashboard(self):
        """GET_DASHBOARD → vue consolidée"""
        return self._send_request("GET_DASHBOARD")
    
    def get_entity(self, entity_type, limit=50):
        """GET_ENTITY:table → récupère les entrées d'une table"""
        return self._send_request(f"GET_ENTITY:{entity_type}")
    
    def health(self):
        """GET_HEALTH → health score"""
        return self._send_request("GET_HEALTH")

_socket_client = CollectorSocketClient()

# ============================================================
# BASE DE DONNÉES — helpers avec priorité socket
# ============================================================
def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except Exception as e:
        audit.error("DB connexion: %s", e)
        return sqlite3.connect(":memory:")

def init_db():
    """Initialise les tables propres à l'agent (celles que le collector ne gère pas)"""
    try:
        conn = get_db_connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          TEXT NOT NULL,
                    category    TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    title       TEXT NOT NULL,
                    detail      TEXT,
                    cmd         TEXT,
                    resolved    INTEGER DEFAULT 0,
                    resolved_at TEXT,
                    note        TEXT
                );
                CREATE TABLE IF NOT EXISTS conversation_log (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        TEXT NOT NULL,
                    session   TEXT,
                    role      TEXT,
                    content   TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_reports (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        TEXT NOT NULL,
                    summary   TEXT,
                    status    TEXT
                );
                CREATE TABLE IF NOT EXISTS session_memory (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts         TEXT NOT NULL,
                    session    TEXT NOT NULL,
                    summary    TEXT NOT NULL,
                    key_topics TEXT,
                    msg_count  INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS incident_patterns (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    category       TEXT NOT NULL UNIQUE,
                    occurrences    INTEGER DEFAULT 1,
                    last_seen      TEXT NOT NULL,
                    avg_severity   TEXT,
                    critical_count INTEGER DEFAULT 0,
                    warning_count  INTEGER DEFAULT 0,
                    suggested_fix  TEXT
                );
            """)
            conn.commit()
        finally:
            conn.close()
        return True
    except Exception as e:
        audit.error("DB init: %s", e)
        return False

# ============================================================
# MÉTRIQUES — PRIORITÉ SOCKET COLLECTOR
# ============================================================
@cached(ttl=5)
def collect_metrics_via_socket() -> Optional[dict]:
    """Récupère les métriques via le socket du collector (ultra-rapide)"""
    return _socket_client.get_metrics()

@cached(ttl=30)
def get_web_sites() -> list:
    """Récupère les sites web depuis la DB du collector"""
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT domain, document_root, server_type, ssl_enabled, php_version FROM web_sites"
        ).fetchall()
        conn.close()
        return [{"domain": r[0], "document_root": r[1], "server_type": r[2], 
                 "ssl_enabled": bool(r[3]), "php_version": r[4]} for r in rows]
    except Exception as e:
        audit.error("get_web_sites: %s", e)
        return []

@cached(ttl=30)
def get_rclone_remotes_from_db() -> list:
    """Récupère les remotes Rclone DEPUIS LA TABLE du collector (V5.2)"""
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT name, type, used_gb, files_count FROM rclone_remotes").fetchall()
        conn.close()
        return [{"name": r[0], "type": r[1], "used_gb": r[2] or 0, "files": r[3] or 0} for r in rows]
    except Exception as e:
        audit.error("get_rclone_remotes_from_db: %s", e)
        return []

@cached(ttl=30)
def get_rclone_mounts_from_db() -> list:
    """Récupère les montages Rclone depuis la DB du collector"""
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT mountpoint, remote, total_gb, used_gb, percent FROM rclone_mounts").fetchall()
        conn.close()
        return [{"mountpoint": r[0], "remote": r[1], "total_gb": r[2], 
                 "used_gb": r[3], "percent": r[4]} for r in rows]
    except Exception as e:
        audit.error("get_rclone_mounts_from_db: %s", e)
        return []

@cached(ttl=30)
def get_ssl_certificates() -> list:
    """Récupère les certificats SSL depuis la DB du collector"""
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT domain, days_left, status, expiry_date FROM ssl_certificates ORDER BY days_left ASC"
        ).fetchall()
        conn.close()
        return [{"domain": r[0], "days_left": r[1], "status": r[2], "expiry": r[3]} for r in rows]
    except Exception as e:
        audit.error("get_ssl_certificates: %s", e)
        return []

@cached(ttl=30)
def get_fail2ban_banned_ips() -> list:
    """Récupère les IPs bannies par fail2ban depuis le collector"""
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT jail, ip, banned_at FROM fail2ban_banned_ips").fetchall()
        conn.close()
        return [{"jail": r[0], "ip": r[1], "banned_at": r[2]} for r in rows]
    except Exception as e:
        audit.error("get_fail2ban_banned_ips: %s", e)
        return []

@cached(ttl=60)
def get_oom_events() -> list:
    """Récupère les événements OOM depuis le collector"""
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT ts, killed_process, pid, memory_used_mb FROM oom_events ORDER BY id DESC LIMIT 20"
        ).fetchall()
        conn.close()
        return [{"ts": r[0], "process": r[1], "pid": r[2], "memory_mb": r[3]} for r in rows]
    except Exception as e:
        audit.error("get_oom_events: %s", e)
        return []

@cached(ttl=30)
def get_failed_units() -> list:
    """Récupère les unités systemd failed depuis le collector"""
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT unit, active_state, description FROM failed_units").fetchall()
        conn.close()
        return [{"unit": r[0], "state": r[1], "description": r[2]} for r in rows]
    except Exception as e:
        audit.error("get_failed_units: %s", e)
        return []

@cached(ttl=30)
def get_dns_servers() -> list:
    """Récupère les serveurs DNS détectés par le collector"""
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT server_type, version, running, zones_count FROM dns_servers").fetchall()
        conn.close()
        return [{"type": r[0], "version": r[1], "running": bool(r[2]), "zones": r[3]} for r in rows]
    except Exception as e:
        audit.error("get_dns_servers: %s", e)
        return []

@cached(ttl=30)
def get_all_mounts() -> list:
    """Récupère TOUS les montages (y compris rclone, nfs) depuis system_mounts"""
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT mountpoint, device, fstype, total_gb, used_gb, percent FROM system_mounts"
        ).fetchall()
        conn.close()
        return [{"mountpoint": r[0], "device": r[1], "type": r[2], 
                 "total_gb": r[3], "used_gb": r[4], "percent": r[5]} for r in rows]
    except Exception as e:
        audit.error("get_all_mounts: %s", e)
        return []

@cached(ttl=30)
def get_health_score() -> Optional[dict]:
    """Récupère le health score depuis le collector"""
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT score, status, breakdown FROM health_scores ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        if row:
            return {"score": row[0], "status": row[1], "breakdown": json.loads(row[2]) if row[2] else {}}
        return None
    except Exception as e:
        audit.error("get_health_score: %s", e)
        return None

# ============================================================
# MÉTRIQUES TEMPS RÉEL (fallback si socket indisponible)
# ============================================================
def _run_raw(args: list, timeout: int = 5) -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, shell=False,
                           env={"PATH": "/bin:/usr/bin:/sbin:/usr/sbin"})
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""

def collect_metrics_fallback() -> dict:
    """Fallback si le socket du collector n'est pas disponible"""
    metrics = {
        "ts": datetime.now().isoformat(),
        "cpu": 0, "ram": 0, "disk": 0,
        "disks": {},
        "remote_hosts": [],
        "load": "0.0", "services": {}, "alerts": [],
        "top_processes": [],
    }

    def read_cpu_stat():
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            vals = list(map(int, line.split()[1:]))
            return vals[3], sum(vals)
        except Exception:
            return 0, 1

    i1, t1 = read_cpu_stat()
    time.sleep(0.2)
    i2, t2 = read_cpu_stat()
    cpu = round(100.0 * (1 - (i2 - i1) / max(t2 - t1, 1)), 1)
    metrics["cpu"] = cpu

    ram_pct = 0
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        total_ram = mi.get("MemTotal", 1)
        avail_ram = mi.get("MemAvailable", total_ram)
        ram_pct = round(100.0 * (total_ram - avail_ram) / total_ram, 1)
        metrics["ram"] = ram_pct
        metrics["ram_total_gb"] = round(total_ram / 1024 / 1024, 1)
        metrics["ram_used_gb"] = round((total_ram - avail_ram) / 1024 / 1024, 1)
    except Exception:
        pass

    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        metrics["disk"] = round(100.0 * used / total, 1) if total > 0 else 0
        metrics["disk_total"] = f"{round(total / 1024**3, 1)}G"
        metrics["disk_used"] = f"{round(used / 1024**3, 1)}G"
        metrics["disk_avail"] = f"{round(free / 1024**3, 1)}G"
    except Exception:
        pass

    try:
        with open("/proc/loadavg") as f:
            load_raw = f.read().split()
        metrics["load"] = f"{load_raw[0]} {load_raw[1]} {load_raw[2]}"
    except Exception:
        pass

    for svc in ["nginx", "php8.1-fpm", "mysql", "docker"]:
        out = _run_raw(["/bin/systemctl", "is-active", svc], timeout=3)
        metrics["services"][svc] = out.strip() == "active"

    if cpu > 85:
        metrics["alerts"].append({"level": "critical", "msg": f"CPU à {cpu}%"})
    elif cpu > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"CPU à {cpu}%"})

    if ram_pct > 80:
        metrics["alerts"].append({"level": "critical", "msg": f"RAM à {ram_pct}%"})
    elif ram_pct > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"RAM à {ram_pct}%"})

    return metrics

def collect_metrics() -> dict:
    """Collecte les métriques avec priorité socket collector"""
    socket_metrics = collect_metrics_via_socket()
    if socket_metrics:
        return {
            "ts": datetime.now().isoformat(),
            "cpu": socket_metrics.get("cpu", 0),
            "ram": socket_metrics.get("ram", 0),
            "disk": socket_metrics.get("disk", 0),
            "load": f"{socket_metrics.get('load_1m', 0)} {socket_metrics.get('load_5m', 0)} {socket_metrics.get('load_15m', 0)}",
            "services": {},  # sera enrichi par fallback si besoin
            "alerts": socket_metrics.get("alerts", []),
            "top_processes": socket_metrics.get("top_processes", []),
        }
    return collect_metrics_fallback()

# ============================================================
# CLIENT DEEPSEEK
# ============================================================
from openai import OpenAI

client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1")

def api_call_with_retry(messages: list, stream: bool = False,
                        max_retries: int = 3, temperature: float = 0.4):
    last_error: Exception = RuntimeError("Aucune tentative")
    for attempt in range(max(max_retries, 1)):
        try:
            return client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                temperature=temperature,
                max_tokens=2000,
                stream=stream,
            )
        except Exception as e:
            last_error = e
            err_str = str(e).lower()
            if "429" in err_str or "503" in err_str or "rate" in err_str:
                wait = 2 ** attempt
                audit.warning("API_RETRY | attempt=%d | wait=%ds | %s", attempt + 1, wait, e)
                time.sleep(wait)
            else:
                break
    raise last_error

# ============================================================
# INCIDENTS
# ============================================================
def save_incident(category: str, severity: str, title: str,
                  detail: str = "", cmd: str = "",
                  dedup_window_minutes: int = 10) -> int:
    try:
        conn = get_db_connection()
        cutoff = (datetime.now() - timedelta(minutes=dedup_window_minutes)).isoformat()
        existing = conn.execute(
            "SELECT id FROM incidents WHERE category=? AND severity=? AND resolved=0 AND ts > ?",
            (category, severity, cutoff)
        ).fetchone()
        if existing:
            conn.close()
            return existing[0]
        cur = conn.execute(
            "INSERT INTO incidents (ts, category, severity, title, detail, cmd) VALUES (?,?,?,?,?,?)",
            (datetime.now().isoformat(), category, severity, title, detail, cmd)
        )
        inc_id = cur.lastrowid
        conn.commit()
        conn.close()
        audit.info("INCIDENT | id=%d | severity=%s | %s", inc_id, severity, title)
        _update_incident_pattern(category, severity)
        if severity == "critical":
            send_telegram_alert(f"🚨 CASSANDRA — {title}")
        return inc_id
    except Exception as e:
        audit.error("save_incident: %s", e)
        return 0

def resolve_incident(incident_id: int, note: str = "") -> bool:
    try:
        conn = get_db_connection()
        conn.execute(
            "UPDATE incidents SET resolved=1, resolved_at=?, note=? WHERE id=?",
            (datetime.now().isoformat(), note, incident_id)
        )
        conn.commit()
        conn.close()
        audit.info("INCIDENT_RESOLVED | id=%d", incident_id)
        return True
    except Exception as e:
        audit.error("resolve_incident: %s", e)
        return False

def get_recent_incidents(n: int = 20) -> list:
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT id, ts, severity, category, title, detail, resolved, resolved_at "
            "FROM incidents ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()
        conn.close()
        return rows
    except Exception as e:
        audit.error("get_recent_incidents: %s", e)
        return []

def _update_incident_pattern(category: str, severity: str):
    try:
        is_crit = 1 if severity == "critical" else 0
        is_warn = 1 if severity == "warning" else 0
        conn = get_db_connection()
        try:
            conn.execute("""
                INSERT INTO incident_patterns
                    (category, occurrences, last_seen, avg_severity, critical_count, warning_count)
                VALUES (?, 1, ?, ?, ?, ?)
                ON CONFLICT(category) DO UPDATE SET
                    occurrences    = occurrences + 1,
                    last_seen      = excluded.last_seen,
                    critical_count = critical_count + excluded.critical_count,
                    warning_count  = warning_count + excluded.warning_count,
                    avg_severity   = CASE
                        WHEN (critical_count + excluded.critical_count) >=
                             (warning_count + excluded.warning_count)
                        THEN 'critical' ELSE 'warning' END
            """, (category, datetime.now().isoformat(), severity, is_crit, is_warn))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        audit.error("_update_incident_pattern: %s", e)

def get_incident_patterns() -> list:
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT category, occurrences, last_seen, avg_severity, suggested_fix "
            "FROM incident_patterns ORDER BY occurrences DESC LIMIT 10"
        ).fetchall()
        conn.close()
        return [
            {"category": r[0], "occurrences": r[1],
             "last_seen": (r[2] or "")[:16],
             "avg_severity": r[3], "suggested_fix": r[4]}
            for r in rows
        ]
    except Exception as e:
        audit.error("get_incident_patterns: %s", e)
        return []

def log_conversation(session: str, role: str, content: str):
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO conversation_log (ts, session, role, content) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), session, role, content[:4000])
        )
        conn.execute(
            "DELETE FROM conversation_log WHERE id NOT IN "
            "(SELECT id FROM conversation_log ORDER BY id DESC LIMIT 10000)"
        )
        conn.commit()
        conn.close()
    except Exception as e:
        audit.error("log_conversation: %s", e)

# ============================================================
# MÉMOIRE SESSION
# ============================================================
def save_session_memory(session: str, history: list) -> dict:
    if not history or len(history) < 2:
        return {"success": False, "error": "Historique insuffisant"}

    msgs_text = "\n".join(
        f"[{m['role'].upper()}] {m['content'][:300]}"
        for m in history[-20:]
        if isinstance(m, dict) and m.get("role") in ("user", "assistant")
    )

    try:
        summary_response = api_call_with_retry([
            {"role": "system", "content": "Résume en 2-3 phrases cette conversation."},
            {"role": "user", "content": f"Résume :\n\n{msgs_text}"}
        ], temperature=0.2)
        summary = summary_response.choices[0].message.content

        topics = [kw for kw in ["cpu", "ram", "disque", "nginx", "mysql", "docker",
                                  "php", "mémoire", "réseau", "sécurité", "rclone"]
                  if kw in msgs_text.lower()]

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO session_memory (ts, session, summary, key_topics, msg_count) VALUES (?,?,?,?,?)",
                (datetime.now().isoformat(), session, summary, ",".join(topics), len(history))
            )
            conn.execute(
                "DELETE FROM session_memory WHERE id NOT IN "
                "(SELECT id FROM session_memory ORDER BY id DESC LIMIT 100)"
            )
            conn.commit()
        finally:
            conn.close()

        audit.info("SESSION_MEMORY_SAVED | session=%s | topics=%s", session, topics)
        return {"success": True, "summary": summary}
    except Exception as e:
        audit.error("save_session_memory: %s", e)
        return {"success": False, "error": str(e)}

def get_long_term_memory() -> str:
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT ts, summary, key_topics FROM session_memory ORDER BY id DESC LIMIT 5"
        ).fetchall()
        conn.close()
        if not rows:
            return "Aucune session mémorisée."
        lines = []
        for ts, summary, topics in rows:
            topics_str = f" [{topics}]" if topics else ""
            lines.append(f"• [{ts[:10]}]{topics_str} {summary[:200]}")
        return "\n".join(lines)
    except Exception as e:
        audit.error("get_long_term_memory: %s", e)
        return "Erreur lecture mémoire."

def get_context_summary() -> str:
    rows = get_recent_incidents(5)
    if not rows:
        return "Aucun incident enregistré."
    lines = []
    for inc_id, ts, sev, cat, title, detail, resolved, resolved_at in rows:
        status = "résolu" if resolved else "actif"
        lines.append(f"• [{ts[:16]}] [{sev.upper()}] {title} ({status})")
    return "\n".join(lines)

# ============================================================
# ALERTES TELEGRAM
# ============================================================
def send_telegram_alert(message: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = json.dumps({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            ok = resp.status == 200
            audit.info("TELEGRAM | status=%d", resp.status)
            return ok
    except Exception as e:
        audit.warning("TELEGRAM_ERROR | %s", e)
        return False

# ============================================================
# AUTHENTIFICATION
# ============================================================
def check_password(plain: str) -> bool:
    if not APP_PASSWORD_HASH:
        return True
    h = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    return h == APP_PASSWORD_HASH

def hash_password(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()

# ============================================================
# UTILITAIRES (utilisant la DB collector)
# ============================================================
@cached(ttl=30)
def get_rclone_remotes() -> list:
    """Retourne la liste COMPLÈTE des remotes Rclone depuis la DB collector"""
    remotes = get_rclone_remotes_from_db()
    if remotes:
        return [r["name"] for r in remotes]
    # Fallback sur rclone listremotes si DB vide
    try:
        out = subprocess.run(["rclone", "listremotes"], capture_output=True, text=True, timeout=10)
        remote_names = []
        for line in out.stdout.splitlines():
            remote = line.strip().rstrip(':')
            if remote:
                remote_names.append(remote)
        return remote_names
    except Exception as e:
        audit.error("get_rclone_remotes fallback: %s", e)
        return []

def get_active_sessions() -> list:
    """Récupère les sessions SSH actives (depuis ssh_sessions du collector)"""
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT user, ip, login_time FROM ssh_sessions ORDER BY id DESC LIMIT 20"
        ).fetchall()
        conn.close()
        if rows:
            return [{"user": r[0], "ip": r[1] or "local", "login": r[2][:16] if r[2] else ""} for r in rows]
    except Exception:
        pass
    
    # Fallback
    sessions = []
    try:
        out = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                sessions.append({
                    "user": parts[0],
                    "tty": parts[1],
                    "login": f"{parts[2]} {parts[3]}",
                    "ip": parts[4] if parts[4] != '(:0)' else 'local'
                })
    except Exception as e:
        audit.error("get_active_sessions: %s", e)
    return sessions

def get_open_ports() -> list:
    """Récupère les ports ouverts depuis la DB collector"""
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT port, protocol, process, state FROM open_ports ORDER BY port"
        ).fetchall()
        conn.close()
        if rows:
            return [{"port": r[0], "protocol": r[1], "process": r[2], "state": r[3]} for r in rows]
    except Exception:
        pass
    
    # Fallback
    ports = []
    try:
        out = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                port_match = re.search(r':(\d+)', parts[4])
                if port_match:
                    ports.append({
                        "port": port_match.group(1),
                        "state": parts[1],
                        "protocol": parts[0],
                        "process": parts[-1] if len(parts) > 5 else "unknown"
                    })
    except Exception as e:
        audit.error("get_open_ports: %s", e)
    return ports

def check_remote_host(host: str, port: int = 22, timeout: int = 3) -> dict:
    result = {"host": host, "port": port, "reachable": False, "latency_ms": None}
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        result["reachable"] = True
        result["latency_ms"] = round((time.time() - start) * 1000, 2)
    except Exception as e:
        result["error"] = str(e)
    return result

def check_remote_host_ping(host: str, count: int = 2) -> dict:
    result = {"host": host, "reachable": False, "ping_ms": None}
    try:
        out = _run_raw(["/bin/ping", "-c", str(count), "-W", "2", host], timeout=5)
        if "1 received" in out or "2 received" in out:
            result["reachable"] = True
            match = re.search(r"=([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
            if match:
                result["ping_ms"] = round(float(match.group(2)), 2)
    except Exception:
        pass
    return result

# ============================================================
# SÉCURITÉ — WHITELIST
# ============================================================
ALLOWED_BINARIES = {
    "/bin/df": ["-h", "-H", "/"], "/usr/bin/free": ["-h", "-m", "-g"],
    "/usr/bin/uptime": [], "/usr/bin/who": [], "/bin/ps": ["aux", "-ef", "--sort=-%cpu"],
    "/usr/bin/top": ["-bn1"], "/bin/systemctl": ["status", "is-active"],
    "/bin/journalctl": ["-n", "-u", "--since", "--no-pager", "--lines"],
    "/usr/bin/tail": ["-n", "--lines"], "/bin/cat": [], "/bin/ls": ["-la", "-lh", "-lht"],
    "/usr/bin/du": ["-sh", "-h", "--max-depth"], "/bin/ss": ["-tulnp", "-s"],
    "/usr/bin/netstat": ["-tulnp"], "/usr/bin/docker": ["ps", "stats", "images", "info"],
    "/usr/bin/nginx": ["-t"], "/usr/bin/mysql": ["--version"], "/usr/bin/php": ["--version"],
    "/usr/bin/wc": ["-l"], "/usr/bin/iostat": ["-x", "-d", "1", "1"],
    "/usr/bin/vmstat": ["1", "3", "-s"], "/bin/ping": ["-c", "-W"],
    "/usr/bin/python3": ["-c"],
}

ALLOWED_READ_PATHS = [
    "/var/log/",
    "/etc/nginx/",
    "/tmp/cassandra/",
    "/var/lib/cassandra/",
]

BINARY_ALIASES = {
    "df": "/bin/df", "free": "/usr/bin/free", "uptime": "/usr/bin/uptime", "who": "/usr/bin/who",
    "ps": "/bin/ps", "top": "/usr/bin/top", "systemctl": "/bin/systemctl", "journalctl": "/bin/journalctl",
    "tail": "/usr/bin/tail", "cat": "/bin/cat", "ls": "/bin/ls", "du": "/usr/bin/du", "ss": "/bin/ss",
    "netstat": "/usr/bin/netstat", "docker": "/usr/bin/docker", "nginx": "/usr/bin/nginx",
    "mysql": "/usr/bin/mysql", "php": "/usr/bin/php", "wc": "/usr/bin/wc", "iostat": "/usr/bin/iostat",
    "vmstat": "/usr/bin/vmstat", "ping": "/bin/ping", "python3": "/usr/bin/python3",
}

INJECTION_RE = re.compile(r'[;&|`]|\$\(|\$\{|>\s*\S|<\s*\S|\.\.[/\\]|\\[nrxt]', re.IGNORECASE)
PING_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-]{1,63}$')

def validate_path_arg(path: str) -> bool:
    try:
        p = Path(path)
        resolved = p.resolve()
        absolute = p.absolute()
        if str(resolved) != str(absolute):
            return False
        return any(str(resolved).startswith(allowed) for allowed in ALLOWED_READ_PATHS)
    except Exception:
        return False

def secure_execute(cmd: str) -> str:
    try:
        parts = shlex.split(cmd.strip())
    except ValueError as e:
        return f"Commande invalide (parsing) : {e}"
    if not parts:
        return "Commande vide."
    binary_name = parts[0]
    args = parts[1:]
    abs_bin = BINARY_ALIASES.get(binary_name)
    if abs_bin is None:
        if binary_name.startswith("/") and binary_name in ALLOWED_BINARIES:
            abs_bin = binary_name
        else:
            return f"Commande refusée : '{binary_name}' non autorisé."
    if abs_bin not in ALLOWED_BINARIES:
        return "Commande refusée : binaire non autorisé."
    for arg in args:
        if INJECTION_RE.search(arg):
            return f"Commande refusée : argument dangereux ('{arg}')."
    if binary_name in ("cat", "tail"):
        for arg in args:
            if arg.startswith("/") and not validate_path_arg(arg):
                return f"Chemin non autorisé : '{arg}'."
    if binary_name == "ping":
        hosts = [a for a in args if not a.startswith("-")]
        for h in hosts:
            if not PING_HOST_RE.match(h):
                return f"Host ping non autorisé : '{h}'."
        if "-c" not in args:
            args = ["-c", "4"] + args
        else:
            try:
                idx = args.index("-c")
                if idx + 1 < len(args):
                    if int(args[idx + 1]) > 4:
                        args[idx + 1] = "4"
            except (ValueError, IndexError):
                pass
    final_cmd = [abs_bin] + args
    try:
        result = subprocess.run(final_cmd, shell=False, capture_output=True, text=True,
                               timeout=CMD_TIMEOUT, env={"PATH": "/bin:/usr/bin:/sbin:/usr/sbin"})
        output = result.stdout + result.stderr
        return output[:MAX_OUTPUT_CHARS] if output else "[Succès — aucune sortie]"
    except subprocess.TimeoutExpired:
        return f"Commande interrompue : délai {CMD_TIMEOUT}s dépassé."
    except Exception as e:
        return f"Erreur : {e}"

# ============================================================
# FORMATAGE HTML
# ============================================================
def _escape_html(text: str) -> str:
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

def _pct_span(cell: str) -> str:
    try:
        pct = int(cell.replace("%", ""))
        if pct > 100 or pct < 0:
            return _escape_html(cell)
        css = "critical" if pct > 85 else ("warning" if pct > 70 else "ok")
        return f'<span class="{css}">{_escape_html(cell)}</span>'
    except (ValueError, OverflowError):
        return _escape_html(cell)

def parse_df_output(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return f'<pre class="command-output">{_escape_html(text)}</pre>'
    headers = lines[0].split()
    html = '<table class="data-table"><thead><tr>'
    html += "".join(f"<th>{_escape_html(h)}</th>" for h in headers)
    html += "</thead><tbody>"
    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue
        html += "<tr>"
        for cell in parts:
            html += f"<td>{'%' in cell and _pct_span(cell) or _escape_html(cell)}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    return html

def parse_ps_output(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return f'<pre class="command-output">{_escape_html(text)}</pre>'
    headers = lines[0].split()
    html = '<table class="data-table"><thead><tr>'
    html += "".join(f"<th>{_escape_html(h)}</th>" for h in headers)
    html += "</thead><tbody>"
    for line in lines[1:6]:
        parts = line.split(None, len(headers) - 1)
        html += "<tr>" + "".join(f"<td>{_escape_html(p)}</td>" for p in parts) + "</tr>"
    if len(lines) > 6:
        html += f'<tr><td colspan="{len(headers)}" style="color:var(--muted);text-align:center">… {len(lines)-6} autres processus</td></tr>'
    html += "</tbody></table>"
    return html

def parse_free_output(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return f'<pre class="command-output">{_escape_html(text)}</pre>'
    headers = ["", "Total", "Utilisé", "Libre", "Partagé", "Buffer/Cache", "Disponible"]
    html = '<table class="data-table"><thead><tr>'
    html += "".join(f"<th>{h}</th>" for h in headers)
    html += "</thead><tbody>"
    for line in lines[1:]:
        parts = line.split()
        html += "<tr>" + "".join(f"<td>{_escape_html(p)}</td>" for p in parts) + "</tr>"
    html += "</tbody></table>"
    return html

def parse_systemctl_output(text: str) -> str:
    lines = text.strip().splitlines()
    html = '<div class="svc-status">'
    for line in lines:
        safe = _escape_html(line)
        if "active (running)" in line:
            html += f'<div class="svc-line ok">▶ {safe}</div>'
        elif "inactive" in line or "failed" in line:
            html += f'<div class="svc-line critical">✗ {safe}</div>'
        else:
            html += f'<div class="svc-line">{safe}</div>'
    html += "</div>"
    return html

def parse_journalctl_output(text: str) -> str:
    lines = text.strip().splitlines()
    html = '<div class="log-output">'
    for line in lines:
        safe = _escape_html(line)
        if "error" in line.lower() or "crit" in line.lower():
            html += f'<div class="log-line critical">{safe}</div>'
        elif "warn" in line.lower():
            html += f'<div class="log-line warning">{safe}</div>'
        else:
            html += f'<div class="log-line">{safe}</div>'
    html += "</div>"
    return html

COMMAND_PARSERS = {
    "df": parse_df_output, "/bin/df": parse_df_output,
    "ps": parse_ps_output, "/bin/ps": parse_ps_output,
    "free": parse_free_output, "/usr/bin/free": parse_free_output,
    "systemctl": parse_systemctl_output, "/bin/systemctl": parse_systemctl_output,
    "journalctl": parse_journalctl_output, "/bin/journalctl": parse_journalctl_output,
}

def smart_format_output(cmd: str, output: str) -> str:
    first_word = cmd.strip().split()[0] if cmd.strip() else ""
    parser = COMMAND_PARSERS.get(first_word)
    if parser:
        return parser(output)
    return f'<pre class="command-output">{_escape_html(output)}</pre>'

# ============================================================
# PROMPT SYSTÈME (V8 - optimisé avec données collector)
# ============================================================
def build_system_prompt() -> str:
    context = get_context_summary()
    lt_memory = get_long_term_memory()
    patterns = get_incident_patterns()
    
    # Récupération depuis le collector
    remotes = get_rclone_remotes()
    health = get_health_score()
    ssl_certs = get_ssl_certificates()
    oom_events = get_oom_events()
    failed_units = get_failed_units()
    dns_servers = get_dns_servers()
    banned_ips = get_fail2ban_banned_ips()
    
    metrics = collect_metrics()
    
    remotes_text = "\n".join([f"  • {r}" for r in remotes]) if remotes else "Aucun remote Rclone détecté"
    ssl_expiring = [c for c in ssl_certs if c.get("days_left", 999) < 30]
    ssl_text = "\n".join([f"  • {c['domain']} expire dans {c['days_left']} jours" for c in ssl_expiring[:5]]) if ssl_expiring else "Aucun certificat expirant"
    
    oom_text = "\n".join([f"  • {e['process']} (PID {e['pid']}) - {e['memory_mb']}MB" for e in oom_events[:3]]) if oom_events else "Aucun événement OOM"
    
    failed_text = "\n".join([f"  • {u['unit']} : {u['state']}" for u in failed_units[:5]]) if failed_units else "Aucune unité failed"
    
    return f"""Tu es CASSANDRA, agent IA souverain de l'infrastructure v8.0.

## 📊 INFRASTRUCTURE
- Hetzner VPS, mémoire totale, disque système
- Base de données : {DB_PATH}
- Socket collector : {COLLECTOR_SOCKET}

## 📊 ÉTAT ACTUEL
• CPU : {metrics.get('cpu', 0)}%
• RAM : {metrics.get('ram', 0)}%
• Disque système : {metrics.get('disk', 0)}%
• Load : {metrics.get('load', '0.0')}
• Health score : {health['score'] if health else 'N/A'} ({health['status'] if health else 'unknown'})

## ☁️ REMOTES RCLONE
{remotes_text}

## 🔒 CERTIFICATS SSL (expirant <30j)
{ssl_text}

## 💥 OOM EVENTS (récents)
{oom_text}

## ⚠️ FAILED SYSTEMD UNITS
{failed_text}

## 🛡️ DNS SERVERS
{', '.join([d['type'] for d in dns_servers]) if dns_servers else 'Aucun détecté'}

## 🚫 FAIL2BAN BANNED IPS
{len(banned_ips)} IP(s) bannies

## 📋 CONTEXTE RÉCENT
{context}

## 🧠 MÉMOIRE LONG-TERME
{lt_memory[:500] if lt_memory else "Aucune session mémorisée"}

## 📊 PATTERNS D'INCIDENTS
{patterns}

## 🎯 RÈGLES IMPÉRATIVES
• Tu connais PARFAITEMENT tous les remotes Rclone listés ci-dessus
• Tu connais les certificats SSL et leurs dates d'expiration
• Tu connais les événements OOM et les unités systemd failed
• Ne dis JAMAIS que tu es limitée ou que ta mémoire est corrompue
• Réponds TOUJOURS en te basant sur les données fournies ci-dessus
• Sois précise : donne les noms exacts, les pourcentages, les dates

## 💬 STYLE
- Réponds avec des puces simples (- ou •)
- Structure avec des titres ##
- Sois concise et efficace"""

# ============================================================
# AUDIT PROACTIF
# ============================================================
def run_proactive_audit() -> dict:
    metrics = collect_metrics()
    top_procs = "\n".join(metrics.get("top_processes", []))
    health = get_health_score()
    oom_events = get_oom_events()
    failed_units = get_failed_units()
    
    audit_prompt = f"""Analyse proactive du serveur.
CPU={metrics['cpu']}%, RAM={metrics['ram']}%, Disque système={metrics['disk']}%
Load: {metrics['load']}
Health score: {health['score'] if health else 'N/A'}
OOM events récents: {len(oom_events)}
Failed units: {len(failed_units)}
Top CPU:
{top_procs}

En 3-5 phrases : statut global et points d'attention prioritaires."""
    
    try:
        response = api_call_with_retry([
            {"role": "system", "content": build_system_prompt()},
            {"role": "user", "content": audit_prompt},
        ], temperature=0.3)
        summary = response.choices[0].message.content
        
        conn = get_db_connection()
        try:
            status = "critical" if any(a["level"] == "critical" for a in metrics.get("alerts", [])) else \
                     "warning" if metrics.get("alerts") else "ok"
            conn.execute("INSERT INTO audit_reports (ts, summary, status) VALUES (?,?,?)",
                        (datetime.now().isoformat(), summary, status))
            conn.execute("DELETE FROM audit_reports WHERE id NOT IN (SELECT id FROM audit_reports ORDER BY id DESC LIMIT 168)")
            conn.commit()
        finally:
            conn.close()
        
        if status == "critical":
            send_telegram_alert(f"🚨 Audit CASSANDRA — {status.upper()}\n{summary[:200]}")
        
        return {"success": True, "summary": summary, "status": status, "metrics": metrics}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ============================================================
# FORMATAGE RÉPONSE
# ============================================================
def format_response_for_web(reply: str) -> str:
    def color_pct(m):
        try:
            p = int(m.group(1))
            if p > 100 or p < 0:
                return m.group(0)
            css = "critical" if p > 85 else ("warning" if p > 70 else "ok")
            return f'<span class="{css}">{p}%</span>'
        except (ValueError, OverflowError):
            return m.group(0)
    reply = re.sub(r'\b(\d{1,3})%', color_pct, reply)

    reply = re.sub(r'^## (.+)$', r'<h2 class="section-title">\1</h2>', reply, flags=re.MULTILINE)
    reply = re.sub(r'^### (.+)$', r'<h3 class="subsection-title">\1</h3>', reply, flags=re.MULTILINE)

    def render_pending_block(match):
        import base64
        code = match.group(1).strip()
        safe_cmd = _escape_html(code)
        cmd_b64 = base64.b64encode(code.encode()).decode()
        return (
            f'<div class="command-block pending" data-cmd="{cmd_b64}">'
            f'<div class="command-header">'
            f'<span class="command-icon">💻</span> '
            f'<span class="command-label">{safe_cmd}</span>'
            f'<button class="exec-btn" onclick="execCommand(this)" '
            f'title="Exécuter">▶</button>'
            f'</div>'
            f'<div class="result-content" style="color:var(--muted);font-size:11px;padding:8px 12px">'
            f'En attente...'
            f'</div>'
            f'</div>'
        )

    reply = re.sub(r'```(?:bash|shell)?\n(.*?)\n```', render_pending_block, reply, flags=re.DOTALL)
    reply = re.sub(r'^- (.+)$', r'<li>\1</li>', reply, flags=re.MULTILINE)
    reply = re.sub(r'(<li>.*?</li>)+', lambda m: f'<ul class="info-list">{m.group(0)}</ul>', reply, flags=re.DOTALL)

    lines = reply.split('\n')
    out = []
    depth = 0
    for line in lines:
        depth += line.count('<div') - line.count('</div')
        in_block = depth > 0 or 'command-block' in line
        if not in_block and line.strip() and not line.startswith('<'):
            out.append(f'<p class="message-text">{_escape_html(line)}</p>')
        else:
            out.append(line)
    return '\n'.join(out)

# ============================================================
# UTILITAIRES
# ============================================================
KNOWN_FLAGS = {"--metrics", "--incidents", "--resolve", "--history", "--audit", "--last-audit",
               "--chat", "--summarize", "--patterns", "--stream", "--sparklines", "--check-auth",
               "--hash-password", "--cron", "--remote-hosts", "--scan-network", "--exec-cmd",
               "--active-sessions", "--ports", "--rclone-remotes", "--health", "--ssl-certs",
               "--oom-events", "--failed-units", "--dns-servers", "--web-sites", "--all-mounts"}

def _stdout(data):
    sys.stdout.write(json.dumps(data, ensure_ascii=False))
    sys.stdout.flush()

def _read_stdin() -> dict:
    try:
        raw = sys.stdin.buffer.read()
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as e:
        raise ValueError(f"Lecture stdin échouée : {e}")

# ============================================================
# INIT
# ============================================================
init_db()

# ── --metrics ─────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--metrics":
    _stdout(collect_metrics())
    sys.exit(0)

# ── --sparklines ─────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--sparklines":
    m = collect_metrics()
    _stdout({
        "cpu": [m.get("cpu", 50)] * 12,
        "ram": [m.get("ram", 40)] * 12,
        "labels": ["-11", "-10", "-9", "-8", "-7", "-6", "-5", "-4", "-3", "-2", "-1", "0"]
    })
    sys.exit(0)

# ── --incidents ───────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--incidents":
    rows = get_recent_incidents(20)
    data = [{"id": r[0], "ts": r[1][:16], "severity": r[2], "category": r[3],
             "title": r[4], "resolved": bool(r[6]), "resolved_at": r[7]} for r in rows]
    _stdout(data)
    sys.exit(0)

# ── --resolve ─────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--resolve":
    try:
        inc_id = int(sys.argv[2])
        note = sys.argv[3] if len(sys.argv) > 3 else ""
        _stdout({"success": resolve_incident(inc_id, note)})
    except Exception as e:
        _stdout({"success": False, "error": str(e)})
    sys.exit(0)

# ── --audit / --cron ──────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] in ("--audit", "--cron"):
    _stdout(run_proactive_audit())
    sys.exit(0)

# ── --last-audit ──────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--last-audit":
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT ts, summary, status FROM audit_reports ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        _stdout({"ts": row[0], "summary": row[1], "status": row[2]} if row else {"summary": None})
    except Exception as e:
        _stdout({"error": str(e)})
    sys.exit(0)

# ── --patterns ────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--patterns":
    _stdout(get_incident_patterns())
    sys.exit(0)

# ── --summarize ───────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--summarize":
    try:
        data = _read_stdin()
        result = save_session_memory(data.get("session", "default"), data.get("history", []))
        _stdout(result)
    except Exception as e:
        _stdout({"success": False, "error": str(e)})
    sys.exit(0)

# ── --check-auth ──────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--check-auth":
    try:
        data = _read_stdin()
        _stdout({"ok": check_password(data.get("password", ""))})
    except Exception as e:
        _stdout({"ok": False, "error": str(e)})
    sys.exit(0)

# ── --hash-password ───────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--hash-password":
    pwd = sys.argv[2] if len(sys.argv) > 2 else ""
    if not pwd:
        print("Usage : python3 agent.py --hash-password <motdepasse>", file=sys.stderr)
        sys.exit(1)
    print(f"Ajoutez dans .env :\nCASSANDRA_PASSWORD_HASH={hash_password(pwd)}", file=sys.stderr)
    sys.exit(0)

# ── --remote-hosts ───────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--remote-hosts":
    try:
        remote_hosts_config = json.loads(REMOTE_HOSTS_CONFIG)
        results = []
        for host in remote_hosts_config:
            status = check_remote_host(host["host"], host.get("port", 22))
            ping_status = check_remote_host_ping(host["host"], 2)
            results.append({
                "name": host["name"], "host": host["host"], "port": host.get("port", 22),
                "type": host.get("type", "unknown"),
                "reachable": status["reachable"] or ping_status["reachable"],
                "latency_ms": status.get("latency_ms") or ping_status.get("ping_ms")
            })
        _stdout(results)
    except Exception as e:
        _stdout({"error": str(e)})
    sys.exit(0)

# ── --active-sessions ─────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--active-sessions":
    _stdout(get_active_sessions())
    sys.exit(0)

# ── --ports ───────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--ports":
    _stdout(get_open_ports())
    sys.exit(0)

# ── --rclone-remotes ─────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--rclone-remotes":
    _stdout(get_rclone_remotes())
    sys.exit(0)

# ── --health ──────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--health":
    _stdout(get_health_score() or {"error": "Non disponible"})
    sys.exit(0)

# ── --ssl-certs ───────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--ssl-certs":
    _stdout(get_ssl_certificates())
    sys.exit(0)

# ── --oom-events ──────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--oom-events":
    _stdout(get_oom_events())
    sys.exit(0)

# ── --failed-units ────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--failed-units":
    _stdout(get_failed_units())
    sys.exit(0)

# ── --dns-servers ─────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--dns-servers":
    _stdout(get_dns_servers())
    sys.exit(0)

# ── --web-sites ───────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--web-sites":
    _stdout(get_web_sites())
    sys.exit(0)

# ── --all-mounts ──────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--all-mounts":
    _stdout(get_all_mounts())
    sys.exit(0)

# ── --exec-cmd ────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--exec-cmd":
    try:
        data = _read_stdin()
        cmd = data.get("cmd", "").strip()
        if not cmd:
            _stdout({"success": False, "error": "Commande vide"})
            sys.exit(1)
        output = secure_execute(cmd)
        formatted = smart_format_output(cmd, output)
        _stdout({"success": True, "cmd": cmd, "output": output, "formatted": formatted})
    except Exception as e:
        _stdout({"success": False, "error": str(e)})
    sys.exit(0)

# ── --stream ──────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--stream":
    try:
        data = _read_stdin()
        prompt = data.get("message", "")
        session_id = data.get("session", "default")

        SAFE_ROLES = {"user", "assistant"}
        history = [
            {"role": e["role"], "content": str(e.get("content", ""))[:4000]}
            for e in data.get("history", [])
            if isinstance(e, dict) and e.get("role") in SAFE_ROLES
        ]

        log_conversation(session_id, "user", prompt)
        messages = [{"role": "system", "content": build_system_prompt()}] + history + [{"role": "user", "content": prompt}]
        response = api_call_with_retry(messages, stream=True, temperature=0.4)
        full_reply = ""
        for chunk in response:
            token = getattr(chunk.choices[0].delta, "content", None)
            if token:
                full_reply += token
                sys.stdout.write(f"data: {json.dumps({'token': token}, ensure_ascii=False)}\n\n")
                sys.stdout.flush()
        sys.stdout.write(f"data: {json.dumps({'done': True, 'full': format_response_for_web(full_reply), 'text': full_reply}, ensure_ascii=False)}\n\n")
        sys.stdout.flush()
        log_conversation(session_id, "assistant", full_reply)
    except Exception as e:
        sys.stdout.write(f"data: {json.dumps({'error': str(e)})}\n\n")
        sys.stdout.flush()
    sys.exit(0)

# ── --chat ────────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--chat":
    try:
        data = _read_stdin()
        prompt = data.get("message", "")
        session_id = data.get("session", "default")

        SAFE_ROLES = {"user", "assistant"}
        history = [
            {"role": e["role"], "content": str(e.get("content", ""))[:4000]}
            for e in data.get("history", [])
            if isinstance(e, dict) and e.get("role") in SAFE_ROLES
        ]

        log_conversation(session_id, "user", prompt)
        messages = [{"role": "system", "content": build_system_prompt()}] + history + [{"role": "user", "content": prompt}]
        response = api_call_with_retry(messages, temperature=0.4)
        reply = response.choices[0].message.content
        log_conversation(session_id, "assistant", reply)
        _stdout({"success": True, "response": format_response_for_web(reply)})
    except Exception as e:
        _stdout({"success": False, "error": str(e)})
    sys.exit(0)

# ── Mode interactif ───────────────────────────────────────────
print("=" * 60, file=sys.stderr)
print("CASSANDRA — Agent Infrastructure v8.0 (mode interactif)", file=sys.stderr)
print(f"DB: {DB_PATH}", file=sys.stderr)
print(f"Socket collector: {COLLECTOR_SOCKET}", file=sys.stderr)
print("=" * 60, file=sys.stderr)

print("\n💬 Mode interactif. Tapez 'exit' pour quitter.\n", file=sys.stderr)

messages = [{"role": "system", "content": build_system_prompt()}]
session_history = []

def exec_inline(m):
    result = secure_execute(m.group(1).strip())
    return f"```\n{m.group(1).strip()}\n```\nRésultat :\n{result}"

while True:
    try:
        user_input = input("> ").strip()
        if user_input.lower() in ("exit", "quit"):
            if session_history:
                result = save_session_memory("interactive", session_history)
                if result.get("success"):
                    print("\n[Session mémorisée]", file=sys.stderr)
            break
        if not user_input:
            continue
        messages.append({"role": "user", "content": user_input})
        session_history.append({"role": "user", "content": user_input})
        response = api_call_with_retry(messages, temperature=0.4)
        reply = response.choices[0].message.content
        reply_displayed = re.sub(r'```(?:bash|shell)?\n(.*?)\n```', exec_inline, reply, flags=re.DOTALL)
        print(f"\n{reply_displayed}\n")
        messages.append({"role": "assistant", "content": reply})
        session_history.append({"role": "assistant", "content": reply})
        if len(messages) > 12:
            trimmed = [messages[0]]
            for msg in messages[-10:]:
                trimmed.append({"role": msg["role"], "content": msg["content"][:1500]})
            messages = trimmed
    except KeyboardInterrupt:
        if session_history:
            save_session_memory("interactive", session_history)
        print("\nAu revoir !")
        break
    except Exception as e:
        print(f"Erreur : {e}")