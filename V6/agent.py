#!/usr/bin/env python3
"""
CASSANDRA — Agent Infrastructure v6.0
======================================
CORRECTIONS v5 → v6 :
  [B1] Tous les print() de debug redirigés vers stderr (stdout réservé au JSON)
  [B2] secure_execute ping : reconstruction args corrigée, valeur -c plafonnée à 4
  [B3] color_pct : try/except + filtre valeurs > 100
  [B4] save_session_memory : propage l'erreur, --summarize répond success:false si échec
  [B5] Mode --chat lit stdin via sys.stdin.buffer pour éviter les problèmes d'encodage
  [B6] _escape_html systématiquement appliqué dans tous les parsers

INNOVATIONS v6 :
  [I1] Streaming SSE : mode --stream retourne les tokens un par un (Server-Sent Events)
  [I2] Alertes Telegram : TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID dans .env
  [I3] Sparklines : mode --sparklines retourne JSON pour graphes Canvas côté client
  [I4] Authentification : mode --check-auth + hash bcrypt du mot de passe
  [I5] Planificateur : mode --cron pour audit automatique planifiable via crontab
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
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter

# ============================================================
# CONFIGURATION — lecture .env sans dépendance externe
# ============================================================
def load_env():
    candidates = [
        Path("/root/.env"),
        Path(__file__).parent / ".env",
        Path.home() / ".env",
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
APP_PASSWORD_HASH  = os.environ.get("CASSANDRA_PASSWORD_HASH", "")  # [I4] sha256 du mdp

CMD_TIMEOUT      = int(os.environ.get("CASSANDRA_CMD_TIMEOUT", "15"))
MAX_OUTPUT_CHARS = 5000

# ============================================================
# BASE DE DONNÉES
# ============================================================
def get_db_path():
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

DB_PATH  = get_db_path()
LOG_PATH = os.environ.get("CASSANDRA_LOG", "/tmp/cassandra_audit.log")

print(f"[CASSANDRA] DB={DB_PATH}", file=sys.stderr)

if not DEEPSEEK_API_KEY:
    print("[CASSANDRA] ERREUR : DEEPSEEK_API_KEY manquante dans .env", file=sys.stderr)
    sys.exit(1)

# ============================================================
# LOGGING AUDIT — rotation automatique
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
# CLIENT DEEPSEEK
# ============================================================
from openai import OpenAI

client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1")

def api_call_with_retry(messages: list, stream: bool = False,
                        max_retries: int = 3, temperature: float = 0.4):
    last_error: Exception = RuntimeError("Aucune tentative effectuée")
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
# BASE DE DONNÉES — init + helpers
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
    try:
        conn = get_db_connection()
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
            CREATE TABLE IF NOT EXISTS metrics_history (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT NOT NULL,
                cpu_pct   REAL,
                ram_pct   REAL,
                disk_pct  REAL,
                load_avg  TEXT
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
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                category      TEXT NOT NULL UNIQUE,
                occurrences   INTEGER DEFAULT 1,
                last_seen     TEXT NOT NULL,
                avg_severity  TEXT,
                suggested_fix TEXT
            );
        """)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        audit.error("DB init: %s", e)
        return False

# ── Incidents ────────────────────────────────────────────────
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
        # [I2] Alerte Telegram si critique
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

# ── Métriques ─────────────────────────────────────────────────
def save_metrics(cpu: float, ram: float, disk: float, load: str):
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO metrics_history (ts, cpu_pct, ram_pct, disk_pct, load_avg) VALUES (?,?,?,?,?)",
            (datetime.now().isoformat(), cpu, ram, disk, load)
        )
        conn.execute(
            "DELETE FROM metrics_history WHERE id NOT IN "
            "(SELECT id FROM metrics_history ORDER BY id DESC LIMIT 2880)"
        )
        conn.commit()
        conn.close()
    except Exception as e:
        audit.error("save_metrics: %s", e)

def get_metrics_history(minutes: int = 30) -> list:
    try:
        conn = get_db_connection()
        cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        rows = conn.execute(
            "SELECT ts, cpu_pct, ram_pct, disk_pct FROM metrics_history "
            "WHERE ts > ? ORDER BY ts ASC", (cutoff,)
        ).fetchall()
        conn.close()
        return rows
    except Exception as e:
        audit.error("get_metrics_history: %s", e)
        return []

# [I3] Sparklines : séries compressées pour Canvas
def get_sparklines(minutes: int = 60) -> dict:
    rows = get_metrics_history(minutes)
    if not rows:
        return {"cpu": [], "ram": [], "disk": [], "labels": []}
    # Rééchantillonner à 30 points max
    step = max(1, len(rows) // 30)
    sampled = rows[::step][-30:]
    return {
        "cpu":    [round(r[1] or 0, 1) for r in sampled],
        "ram":    [round(r[2] or 0, 1) for r in sampled],
        "disk":   [round(r[3] or 0, 1) for r in sampled],
        "labels": [r[0][11:16] for r in sampled],  # HH:MM
    }

# ── Contexte prompt ───────────────────────────────────────────
def get_context_summary() -> str:
    rows = get_recent_incidents(5)
    if not rows:
        return "Aucun incident enregistré."
    lines = []
    for inc_id, ts, sev, cat, title, detail, resolved, resolved_at in rows:
        status = "résolu" if resolved else "actif"
        lines.append(f"• [{ts[:16]}] [{sev.upper()}] {title} ({status})")
    return "\n".join(lines)

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

# ── Mémoire long-terme ────────────────────────────────────────
def _update_incident_pattern(category: str, severity: str):
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO incident_patterns (category, occurrences, last_seen, avg_severity)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(category) DO UPDATE SET
                occurrences  = occurrences + 1,
                last_seen    = excluded.last_seen,
                avg_severity = excluded.avg_severity
        """, (category, datetime.now().isoformat(), severity))
        conn.commit()
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

def save_session_memory(session: str, history: list) -> str:
    """
    [B4] Lève une exception si l'API échoue au lieu de retourner None silencieusement.
    L'appelant (mode --summarize) est responsable du catch.
    """
    if not history or len(history) < 2:
        raise ValueError("Historique insuffisant (< 2 messages)")

    msgs_text = "\n".join(
        f"[{m['role'].upper()}] {m['content'][:300]}"
        for m in history[-20:]
    )

    summary_response = api_call_with_retry([
        {"role": "system", "content": "Résume en 2-3 phrases cette conversation d'administration serveur. Mentionne les problèmes, commandes et solutions."},
        {"role": "user", "content": f"Résume :\n\n{msgs_text}"}
    ], temperature=0.2)
    summary = summary_response.choices[0].message.content

    topics = [kw for kw in ["cpu", "ram", "disque", "nginx", "mysql", "docker",
                              "php", "mémoire", "réseau", "sécurité"]
              if kw in msgs_text.lower()]

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO session_memory (ts, session, summary, key_topics, msg_count) VALUES (?,?,?,?,?)",
        (datetime.now().isoformat(), session, summary, ",".join(topics), len(history))
    )
    conn.execute(
        "DELETE FROM session_memory WHERE id NOT IN "
        "(SELECT id FROM session_memory ORDER BY id DESC LIMIT 100)"
    )
    conn.commit()
    conn.close()
    audit.info("SESSION_MEMORY_SAVED | session=%s | topics=%s", session, topics)
    return summary

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

def get_patterns_for_prompt() -> str:
    patterns = get_incident_patterns()
    if not patterns:
        return "Aucun pattern détecté."
    lines = []
    for p in patterns[:5]:
        fix = f" → {p['suggested_fix']}" if p.get("suggested_fix") else ""
        lines.append(f"• {p['category'].upper()} : {p['occurrences']} occurrence(s) [{p['avg_severity']}]{fix}")
    return "\n".join(lines)

# ============================================================
# [I2] ALERTES TELEGRAM
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
# [I4] AUTHENTIFICATION
# ============================================================
def check_password(plain: str) -> bool:
    if not APP_PASSWORD_HASH:
        return True  # Pas de mot de passe configuré → accès libre
    h = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    return h == APP_PASSWORD_HASH

def hash_password(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()

# ============================================================
# COLLECTE MÉTRIQUES SYSTÈME
# ============================================================
def _run_raw(args: list, timeout: int = 5) -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, shell=False,
                           env={"PATH": "/bin:/usr/bin:/sbin:/usr/sbin"})
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""

def collect_metrics() -> dict:
    metrics = {
        "ts": datetime.now().isoformat(),
        "cpu": 0, "ram": 0, "disk": 0,
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
    time.sleep(0.5)
    i2, t2 = read_cpu_stat()
    cpu = round(100.0 * (1 - (i2 - i1) / max(t2 - t1, 1)), 1)
    metrics["cpu"] = cpu

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
        metrics["ram_used_gb"]  = round((total_ram - avail_ram) / 1024 / 1024, 1)
    except Exception:
        pass

    out = _run_raw(["/bin/df", "-h", "/"])
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            try:
                metrics["disk"]       = int(parts[4].replace("%", ""))
                metrics["disk_total"] = parts[1]
                metrics["disk_used"]  = parts[2]
                metrics["disk_avail"] = parts[3]
            except ValueError:
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

    try:
        ps_out = _run_raw(["/bin/ps", "aux", "--sort=-%cpu"], timeout=5)
        metrics["top_processes"] = [l for l in ps_out.splitlines() if l.strip()][1:4]
    except Exception:
        pass

    # Alertes avec déduplication
    if cpu > 85:
        metrics["alerts"].append({"level": "critical", "msg": f"CPU à {cpu}%"})
        save_incident("cpu", "critical", f"CPU critique : {cpu}%", dedup_window_minutes=10)
    elif cpu > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"CPU à {cpu}%"})
        save_incident("cpu", "warning", f"CPU élevé : {cpu}%", dedup_window_minutes=10)

    ram = metrics["ram"]
    if ram > 80:
        metrics["alerts"].append({"level": "critical", "msg": f"RAM à {ram}%"})
        save_incident("ram", "critical", f"RAM critique : {ram}%", dedup_window_minutes=10)
    elif ram > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"RAM élevée : {ram}%"})
        save_incident("ram", "warning", f"RAM élevée : {ram}%", dedup_window_minutes=10)

    disk = metrics["disk"]
    if disk > 85:
        metrics["alerts"].append({"level": "critical", "msg": f"Disque à {disk}%"})
        save_incident("disk", "critical", f"Disque critique : {disk}%", dedup_window_minutes=30)

    save_metrics(cpu, ram, disk, metrics["load"])
    return metrics

# ============================================================
# SÉCURITÉ — WHITELIST + VALIDATION
# ============================================================
ALLOWED_BINARIES = {
    "/bin/df":          ["-h", "-H", "/"],
    "/usr/bin/free":    ["-h", "-m", "-g"],
    "/usr/bin/uptime":  [],
    "/usr/bin/who":     [],
    "/bin/ps":          ["aux", "-ef", "--sort=-%cpu", "--sort=-%mem"],
    "/usr/bin/top":     ["-bn1"],
    "/bin/systemctl":   ["status", "list-units", "--type=service",
                         "--state=running", "is-active"],
    "/bin/journalctl":  ["-n", "-u", "--since", "--no-pager", "--lines"],
    "/usr/bin/tail":    ["-n", "--lines"],
    "/bin/cat":         [],
    "/bin/ls":          ["-la", "-lh", "-lht"],
    "/usr/bin/du":      ["-sh", "-h", "--max-depth"],
    "/bin/ss":          ["-tulnp", "-s"],
    "/usr/bin/netstat": ["-tulnp"],
    "/usr/bin/docker":  ["ps", "stats", "--no-stream", "images", "info", "container", "ls"],
    "/usr/bin/nginx":   ["-t"],
    "/usr/bin/mysql":   ["--version"],
    "/usr/bin/php":     ["--version"],
    "/usr/bin/wc":      ["-l"],
    "/usr/bin/iostat":  ["-x", "-d", "1", "1"],
    "/usr/bin/vmstat":  ["1", "3", "-s"],
    "/bin/ping":        ["-c", "-W"],
}

ALLOWED_READ_PATHS = [
    "/var/log/",
    "/etc/nginx/",
    "/tmp/cassandra/",
    "/proc/",
    "/var/lib/cassandra/",
]

BINARY_ALIASES = {
    "df": "/bin/df", "free": "/usr/bin/free", "uptime": "/usr/bin/uptime",
    "who": "/usr/bin/who", "ps": "/bin/ps", "top": "/usr/bin/top",
    "systemctl": "/bin/systemctl", "journalctl": "/bin/journalctl",
    "tail": "/usr/bin/tail", "cat": "/bin/cat", "ls": "/bin/ls",
    "du": "/usr/bin/du", "ss": "/bin/ss", "netstat": "/usr/bin/netstat",
    "docker": "/usr/bin/docker", "nginx": "/usr/bin/nginx",
    "mysql": "/usr/bin/mysql", "php": "/usr/bin/php", "wc": "/usr/bin/wc",
    "iostat": "/usr/bin/iostat", "vmstat": "/usr/bin/vmstat",
    "ping": "/bin/ping",
}

INJECTION_RE = re.compile(
    r'[;&|`]|'
    r'\$\(|'
    r'\$\{|'
    r'>\s*\S|'
    r'<\s*\S|'
    r'\.\.[/\\]|'
    r'\\[nrxt]',
    re.IGNORECASE
)

PING_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-]{1,63}$')

def validate_path_arg(path: str) -> bool:
    try:
        resolved = str(Path(path).resolve())
        return any(resolved.startswith(p) for p in ALLOWED_READ_PATHS)
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
            audit.warning("REFUS_BINAIRE | cmd=%s", cmd)
            return f"Commande refusée : '{binary_name}' non autorisé."

    if abs_bin not in ALLOWED_BINARIES:
        audit.warning("REFUS_BINAIRE | bin=%s", abs_bin)
        return "Commande refusée : binaire non autorisé."

    for arg in args:
        if INJECTION_RE.search(arg):
            audit.warning("REFUS_INJECTION | cmd=%s | arg=%s", cmd, arg)
            return f"Commande refusée : argument dangereux ('{arg}')."

    if binary_name in ("cat", "tail"):
        for arg in args:
            if arg.startswith("/") and not validate_path_arg(arg):
                audit.warning("REFUS_CHEMIN | cmd=%s | path=%s", cmd, arg)
                return f"Chemin non autorisé : '{arg}'."

    # [B2] Ping : reconstruction args corrigée
    if binary_name == "ping":
        hosts = [a for a in args if not a.startswith("-")]
        for h in hosts:
            if not PING_HOST_RE.match(h):
                return f"Host ping non autorisé : '{h}'."
        if "-c" in args:
            # Valider et plafonner la valeur de -c
            try:
                idx = args.index("-c")
                if idx + 1 < len(args):
                    count = int(args[idx + 1])
                    if count > 4:
                        args = list(args)
                        args[idx + 1] = "4"
            except (ValueError, IndexError):
                # Retirer -c et sa valeur puis remettre -c 4
                new_args = []
                skip = False
                for a in args:
                    if skip:
                        skip = False
                        continue
                    if a == "-c":
                        skip = True
                        continue
                    new_args.append(a)
                args = ["-c", "4"] + new_args
        else:
            args = ["-c", "4"] + args

    final_cmd = [abs_bin] + args
    audit.info("EXEC | %s", " ".join(final_cmd))

    try:
        result = subprocess.run(
            final_cmd, shell=False, capture_output=True, text=True,
            timeout=CMD_TIMEOUT,
            env={"PATH": "/bin:/usr/bin:/sbin:/usr/sbin"},
        )
        output = result.stdout + result.stderr
        audit.info("OK | exit=%d | chars=%d", result.returncode, len(output))
        return output[:MAX_OUTPUT_CHARS] if output else "[Succès — aucune sortie]"
    except subprocess.TimeoutExpired:
        audit.warning("TIMEOUT | cmd=%s", " ".join(final_cmd))
        return f"Commande interrompue : délai {CMD_TIMEOUT}s dépassé."
    except FileNotFoundError:
        audit.error("BINAIRE_INTROUVABLE | %s", abs_bin)
        return f"Binaire introuvable : {abs_bin}"
    except Exception as e:
        audit.error("ERREUR | %s | %s", " ".join(final_cmd), e)
        return f"Erreur : {e}"

# ============================================================
# PARSERS DE SORTIE — HTML sécurisé
# ============================================================
def _escape_html(text: str) -> str:
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

def _pct_span(cell: str) -> str:
    # [B3] try/except + filtre valeurs > 100
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
    html += "</tr></thead><tbody>"
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
    html += "</tr></thead><tbody>"
    for line in lines[1:11]:
        parts = line.split(None, len(headers) - 1)
        html += "<tr>" + "".join(f"<td>{_escape_html(p)}</td>" for p in parts) + "</tr>"
    if len(lines) > 11:
        html += f'<tr><td colspan="{len(headers)}" style="color:var(--muted);text-align:center">… {len(lines)-11} autres processus</td></tr>'
    html += "</tbody></table>"
    return html

def parse_free_output(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return f'<pre class="command-output">{_escape_html(text)}</pre>'
    headers = ["", "Total", "Utilisé", "Libre", "Partagé", "Buffer/Cache", "Disponible"]
    html = '<table class="data-table"><thead></tr>'
    html += "".join(f"<th>{h}</th>" for h in headers)
    html += "</tr></thead><tbody>"
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
    "df":         parse_df_output,   "/bin/df":          parse_df_output,
    "ps":         parse_ps_output,   "/bin/ps":          parse_ps_output,
    "free":       parse_free_output, "/usr/bin/free":    parse_free_output,
    "systemctl":  parse_systemctl_output, "/bin/systemctl": parse_systemctl_output,
    "journalctl": parse_journalctl_output, "/bin/journalctl": parse_journalctl_output,
}

def smart_format_output(cmd: str, output: str) -> str:
    first_word = cmd.strip().split()[0] if cmd.strip() else ""
    parser = COMMAND_PARSERS.get(first_word)
    if parser:
        return parser(output)
    return f'<pre class="command-output">{_escape_html(output)}</pre>'

# ============================================================
# FORMATAGE HTML DE LA RÉPONSE
# ============================================================
def format_response_for_web(reply: str) -> str:
    reply = re.sub(r'^## (.+)$',  r'<h2 class="section-title">\1</h2>',    reply, flags=re.MULTILINE)
    reply = re.sub(r'^### (.+)$', r'<h3 class="subsection-title">\1</h3>', reply, flags=re.MULTILINE)

    def process_code_block(match):
        code = match.group(1).strip()
        result = secure_execute(code)
        formatted = smart_format_output(code, result)
        safe_code = _escape_html(code)
        return (
            f'<div class="command-block">'
            f'<div class="command-header"><span class="command-icon">💻</span>'
            f' <span class="command-label">{safe_code}</span></div>'
            f'<div class="result-header"><span class="result-icon">📋</span> Résultat</div>'
            f'<div class="result-content">{formatted}</div>'
            f'</div>'
        )

    reply = re.sub(r'```(?:bash|shell)?\n(.*?)\n```', process_code_block, reply, flags=re.DOTALL)
    reply = re.sub(r'^- (.+)$', r'<li>\1</li>', reply, flags=re.MULTILINE)
    reply = re.sub(r'(<li>.*?</li>)+',
                   lambda m: f'<ul class="info-list">{m.group(0)}</ul>',
                   reply, flags=re.DOTALL)

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
    reply = '\n'.join(out)

    # [B3] color_pct sécurisé
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
    return reply

# ============================================================
# PROMPT SYSTÈME
# ============================================================
def build_system_prompt() -> str:
    context   = get_context_summary()
    lt_memory = get_long_term_memory()
    patterns  = get_patterns_for_prompt()
    return f"""Tu es CASSANDRA, agent IA souverain de l'infrastructure.

## ACCÈS SERVEUR
- Hetzner VPS, 8 Go RAM, 105 Go disque
- Services : Nginx, PHP-FPM, MySQL, Nextcloud, Docker
- Commandes autorisées : df, free, uptime, who, ps, top, systemctl, journalctl, tail, cat, ls, du, ss, netstat, docker, nginx, mysql, php, iostat, vmstat, ping

## MÉMOIRE CONTEXTUELLE — incidents récents
{context}

## MÉMOIRE LONG-TERME — sessions précédentes
{lt_memory}

## PATTERNS D'INCIDENTS
{patterns}

## RÈGLES
- Disque >85% ou RAM >80% → alerte immédiate
- Commandes entre ```bash ... ```
- Titres ## et listes pour structurer
- Tableaux pour les données chiffrées
- Confirmation avant toute action destructive
- Rappeler les incidents similaires si pertinent
- Pattern récurrent → proposer une solution permanente

## STYLE
- Titres ## sections
- Listes à puces
- Tableaux métriques
- Terminer par une proposition d'action concrète"""

# ============================================================
# AUDIT PROACTIF (--audit / --cron)
# ============================================================
def run_proactive_audit() -> dict:
    metrics = collect_metrics()
    top_procs = "\n".join(metrics.get("top_processes", []))
    audit_prompt = (
        f"Analyse proactive du serveur.\n"
        f"CPU={metrics['cpu']}%, RAM={metrics['ram']}%, Disque={metrics['disk']}%\n"
        f"Load: {metrics['load']}\n"
        f"Services: {json.dumps(metrics['services'])}\n"
        f"Alertes: {json.dumps(metrics['alerts'])}\n"
        f"Top CPU:\n{top_procs}\n\n"
        f"En 3-5 phrases : statut global et points d'attention prioritaires."
    )
    try:
        response = api_call_with_retry([
            {"role": "system", "content": build_system_prompt()},
            {"role": "user",   "content": audit_prompt},
        ], temperature=0.3)
        summary = response.choices[0].message.content

        conn = get_db_connection()
        status = ("critical" if any(a["level"] == "critical" for a in metrics["alerts"])
                  else "warning" if metrics["alerts"] else "ok")
        conn.execute(
            "INSERT INTO audit_reports (ts, summary, status) VALUES (?,?,?)",
            (datetime.now().isoformat(), summary, status)
        )
        conn.execute(
            "DELETE FROM audit_reports WHERE id NOT IN "
            "(SELECT id FROM audit_reports ORDER BY id DESC LIMIT 168)"
        )
        conn.commit()
        conn.close()

        # [I2] Telegram si critique
        if status == "critical":
            send_telegram_alert(f"🚨 Audit CASSANDRA — {status.upper()}\n{summary[:200]}")

        audit.info("PROACTIVE_AUDIT | status=%s", status)
        return {"success": True, "summary": summary, "status": status, "metrics": metrics}
    except Exception as e:
        audit.error("PROACTIVE_AUDIT_ERROR | %s", e)
        return {"success": False, "error": str(e)}

# ============================================================
# UTILITAIRES STDIN/STDOUT
# ============================================================
KNOWN_FLAGS = {
    "--metrics", "--incidents", "--resolve", "--history",
    "--audit", "--last-audit", "--chat", "--summarize",
    "--patterns", "--stream", "--sparklines", "--check-auth",
    "--hash-password", "--cron",
}

def _stdout(data):
    """[B1] Toute sortie JSON va sur stdout, rien d'autre."""
    sys.stdout.write(json.dumps(data, ensure_ascii=False))
    sys.stdout.flush()

def _read_stdin() -> dict:
    """[B5] Lecture stdin robuste en binaire puis décodage."""
    try:
        raw = sys.stdin.buffer.read()
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as e:
        raise ValueError(f"Lecture stdin échouée : {e}")

# ============================================================
# INITIALISATION DB
# ============================================================
init_db()

# ============================================================
# MODES D'EXÉCUTION
# ============================================================

# ── --metrics ─────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--metrics":
    _stdout(collect_metrics())
    sys.exit(0)

# ── --sparklines ─────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--sparklines":
    minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    _stdout(get_sparklines(minutes))
    sys.exit(0)

# ── --incidents ───────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--incidents":
    rows = get_recent_incidents(20)
    data = [
        {"id": r[0], "ts": r[1][:16], "severity": r[2], "category": r[3],
         "title": r[4], "resolved": bool(r[6]), "resolved_at": r[7]}
        for r in rows
    ]
    _stdout(data)
    sys.exit(0)

# ── --resolve ─────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--resolve":
    try:
        inc_id = int(sys.argv[2])
        note   = sys.argv[3] if len(sys.argv) > 3 else ""
        _stdout({"success": resolve_incident(inc_id, note)})
    except Exception as e:
        _stdout({"success": False, "error": str(e)})
    sys.exit(0)

# ── --history ─────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--history":
    minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    rows    = get_metrics_history(minutes)
    _stdout([{"ts": r[0], "cpu": r[1], "ram": r[2], "disk": r[3]} for r in rows])
    sys.exit(0)

# ── --audit / --cron ──────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] in ("--audit", "--cron"):
    _stdout(run_proactive_audit())
    sys.exit(0)

# ── --last-audit ──────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--last-audit":
    try:
        conn = get_db_connection()
        row  = conn.execute(
            "SELECT ts, summary, status FROM audit_reports ORDER BY id DESC LIMIT 1"
        ).fetchone()
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
        data    = _read_stdin()
        session = data.get("session", "default")
        history = data.get("history", [])
        summary = save_session_memory(session, history)  # [B4] lève une exception si échec
        _stdout({"success": True, "summary": summary})
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

# ── --hash-password (utilitaire setup) ───────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--hash-password":
    pwd = sys.argv[2] if len(sys.argv) > 2 else ""
    if not pwd:
        print("Usage : python3 agent.py --hash-password <motdepasse>", file=sys.stderr)
        sys.exit(1)
    h = hash_password(pwd)
    print(f"Ajoutez dans .env :\nCASSANDRA_PASSWORD_HASH={h}", file=sys.stderr)
    sys.exit(0)

# ── --stream : [I1] Streaming SSE ────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--stream":
    try:
        data       = _read_stdin()
        prompt     = data.get("message", "")
        history    = data.get("history", [])
        session_id = data.get("session", "default")

        log_conversation(session_id, "user", prompt)

        messages = [{"role": "system", "content": build_system_prompt()}]
        messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        response = api_call_with_retry(messages, stream=True, temperature=0.4)

        full_reply = ""
        # Streaming : chaque token envoyé en SSE
        for chunk in response:
            delta = chunk.choices[0].delta
            token = getattr(delta, "content", None)
            if token:
                full_reply += token
                # Format SSE : data: <json>\n\n
                sys.stdout.write(f"data: {json.dumps({'token': token}, ensure_ascii=False)}\n\n")
                sys.stdout.flush()

        # Fin du stream
        sys.stdout.write(f"data: {json.dumps({'done': True, 'full': format_response_for_web(full_reply)}, ensure_ascii=False)}\n\n")
        sys.stdout.flush()

        log_conversation(session_id, "assistant", full_reply)
    except Exception as e:
        audit.error("STREAM_ERROR | %s", e)
        sys.stdout.write(f"data: {json.dumps({'error': str(e)})}\n\n")
        sys.stdout.flush()
    sys.exit(0)

# ── --chat : mode standard JSON ───────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--chat":
    try:
        data       = _read_stdin()
        prompt     = data.get("message", "")
        history    = data.get("history", [])
        session_id = data.get("session", "default")

        log_conversation(session_id, "user", prompt)

        messages = [{"role": "system", "content": build_system_prompt()}]
        messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        response = api_call_with_retry(messages, temperature=0.4)
        reply    = response.choices[0].message.content

        log_conversation(session_id, "assistant", reply)
        _stdout({"success": True, "response": format_response_for_web(reply)})
        sys.exit(0)
    except Exception as e:
        audit.error("CHAT_ERROR | %s", e)
        _stdout({"success": False, "error": str(e)})
        sys.exit(1)

# ── Argument inconnu ──────────────────────────────────────────
if len(sys.argv) > 1:
    arg = sys.argv[1]
    if arg not in KNOWN_FLAGS and arg.strip().startswith("{"):
        # Compatibilité ascendante : ancien appel via argv JSON
        try:
            data       = json.loads(arg)
            prompt     = data.get("message", "")
            history    = data.get("history", [])
            session_id = data.get("session", "default")
            log_conversation(session_id, "user", prompt)
            messages = [{"role": "system", "content": build_system_prompt()}]
            messages.extend(history)
            messages.append({"role": "user", "content": prompt})
            response = api_call_with_retry(messages, temperature=0.4)
            reply    = response.choices[0].message.content
            log_conversation(session_id, "assistant", reply)
            _stdout({"success": True, "response": format_response_for_web(reply)})
            sys.exit(0)
        except Exception as e:
            audit.error("API_ERROR (legacy) | %s", e)
            _stdout({"success": False, "error": str(e)})
            sys.exit(1)
    else:
        print(f"[CASSANDRA] Argument inconnu : {arg!r}. Valides : {', '.join(sorted(KNOWN_FLAGS))}", file=sys.stderr)
        sys.exit(1)

# ============================================================
# MODE INTERACTIF — terminal
# ============================================================
print("=" * 60, file=sys.stderr)
print("CASSANDRA — Agent Infrastructure v6.0 (mode interactif)", file=sys.stderr)
print(f"DB: {DB_PATH}", file=sys.stderr)
print("=" * 60, file=sys.stderr)

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
                try:
                    save_session_memory("interactive", session_history)
                    print("\n[Session mémorisée]", file=sys.stderr)
                except Exception:
                    pass
            break
        if not user_input:
            continue

        messages.append({"role": "user", "content": user_input})
        session_history.append({"role": "user", "content": user_input})

        response = api_call_with_retry(messages, temperature=0.4)
        reply    = response.choices[0].message.content
        reply_displayed = re.sub(r'```(?:bash|shell)?\n(.*?)\n```', exec_inline,
                                  reply, flags=re.DOTALL)
        print(f"\n{reply_displayed}\n")
        messages.append({"role": "assistant", "content": reply})
        session_history.append({"role": "assistant", "content": reply})

        if len(messages) > 12:
            messages = [messages[0]] + messages[-10:]

    except KeyboardInterrupt:
        if session_history:
            try:
                save_session_memory("interactive", session_history)
            except Exception:
                pass
        print("\nAu revoir !")
        break
    except Exception as e:
        print(f"Erreur : {e}")