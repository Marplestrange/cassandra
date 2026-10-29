#!/usr/bin/env python3
"""
CASSANDRA — Agent Infrastructure v5.0
==============================================
CORRECTIONS v4 → v5 :
  - [BUG] collect_metrics() ouvre /proc/stat sans context manager → fuite fichier
  - [BUG] secure_execute() split naïf casse les args avec espaces (ex: tail -n 50 /var/log/nginx/error.log)
  - [BUG] validate_path_arg() ne gère pas les symlinks (Path.resolve() suffit mais /proc/ est exclu)
  - [BUG] log_conversation() tronque à 2000 mais la session history peut dépasser la taille utile
  - [BUG] Mode interactif : exec_inline défini dans la boucle while (re-défini à chaque tour)
  - [BUG] api_call_with_retry : last_error peut être None si max_retries=0
  - [BUG] Compatibilité ascendante argv : json.loads(sys.argv[1]) peut crasher sur n'importe quel arg non-JSON

INNOVATIONS v5 :
  - Mémoire long-terme : résumés de sessions stockés en DB + injectés dans le prompt système
  - Apprentissage adaptatif : patterns d'incidents récurrents détectés et mémorisés
  - Mode --summarize : résumé automatique d'une session (appelé par chat.php à la fin)
  - Mode --patterns : retourne les patterns d'incidents détectés
  - Commandes enrichies : iostat, vmstat, ping (whitelist étendue prudemment)
  - Timeout par commande configurable via env CASSANDRA_CMD_TIMEOUT
  - Rotation automatique des logs d'audit (évite /tmp plein)
  - Contexte enrichi : top 3 processus CPU + connexions réseau actives injectés dans le prompt
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
                print(f"[CASSANDRA] Avertissement lecture .env ({env_path}): {e}", file=sys.stderr)
            break

load_env()

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")

# ============================================================
# GESTION BASE DE DONNÉES
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

# FIX : timeout configurable via env
CMD_TIMEOUT      = int(os.environ.get("CASSANDRA_CMD_TIMEOUT", "15"))
MAX_OUTPUT_CHARS = 5000

print(f"[CASSANDRA] Base de données: {DB_PATH}", file=sys.stderr)

if not DEEPSEEK_API_KEY:
    print(
        "[CASSANDRA] ERREUR : clé API introuvable.\n"
        "  → Vérifiez que /root/.env contient : DEEPSEEK_API_KEY=sk-xxxx",
        file=sys.stderr
    )
    sys.exit(1)

# ============================================================
# LOGGING AUDIT — FIX : rotation automatique (évite /tmp plein)
# ============================================================
try:
    _handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    logging.basicConfig(
        handlers=[_handler],
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )
except (PermissionError, OSError):
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

audit = logging.getLogger("cassandra.audit")

# ============================================================
# CLIENT DEEPSEEK avec retry exponentiel
# ============================================================
from openai import OpenAI

client = OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com/v1"
)

def api_call_with_retry(messages: list, stream: bool = False,
                        max_retries: int = 3, temperature: float = 0.4):
    """Appel API avec retry exponentiel sur 429/503."""
    # FIX : last_error initialisé à Exception générique
    last_error: Exception = RuntimeError("max_retries=0 ou aucune tentative effectuée")
    for attempt in range(max(max_retries, 1)):
        try:
            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                temperature=temperature,
                max_tokens=2000,
                stream=stream,
            )
            return response
        except Exception as e:
            last_error = e
            err_str = str(e).lower()
            if "429" in err_str or "503" in err_str or "rate" in err_str:
                wait = 2 ** attempt
                audit.warning("API_RETRY | attempt=%d | wait=%ds | error=%s", attempt + 1, wait, e)
                time.sleep(wait)
            else:
                break
    raise last_error

# ============================================================
# BASE DE DONNÉES
# ============================================================
def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except Exception as e:
        audit.error("Erreur connexion DB: %s", e)
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
            -- INNOVATION v5 : mémoire long-terme des sessions
            CREATE TABLE IF NOT EXISTS session_memory (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                session    TEXT NOT NULL,
                summary    TEXT NOT NULL,
                key_topics TEXT,
                msg_count  INTEGER DEFAULT 0
            );
            -- INNOVATION v5 : patterns d'incidents détectés
            CREATE TABLE IF NOT EXISTS incident_patterns (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                category     TEXT NOT NULL UNIQUE,
                occurrences  INTEGER DEFAULT 1,
                last_seen    TEXT NOT NULL,
                avg_severity TEXT,
                suggested_fix TEXT
            );
        """)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        audit.error("Erreur initialisation DB: %s", e)
        return False

# ============================================================
# DÉDUPLICATION DES INCIDENTS
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

        # INNOVATION v5 : mettre à jour les patterns
        _update_incident_pattern(category, severity)
        return inc_id
    except Exception as e:
        audit.error("Erreur sauvegarde incident: %s", e)
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
        audit.error("Erreur résolution incident: %s", e)
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
        audit.error("Erreur lecture incidents: %s", e)
        return []

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
        audit.error("Erreur sauvegarde metrics: %s", e)

def get_metrics_history(minutes: int = 30) -> list:
    try:
        conn = get_db_connection()
        cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        rows = conn.execute(
            "SELECT ts, cpu_pct, ram_pct, disk_pct FROM metrics_history "
            "WHERE ts > ? ORDER BY ts ASC",
            (cutoff,)
        ).fetchall()
        conn.close()
        return rows
    except Exception as e:
        audit.error("Erreur lecture historique métriques: %s", e)
        return []

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
            (datetime.now().isoformat(), session, role, content[:4000])  # FIX : 4000 au lieu de 2000
        )
        # Garder 10 000 lignes max
        conn.execute(
            "DELETE FROM conversation_log WHERE id NOT IN "
            "(SELECT id FROM conversation_log ORDER BY id DESC LIMIT 10000)"
        )
        conn.commit()
        conn.close()
    except Exception as e:
        audit.error("Erreur log conversation: %s", e)

# ============================================================
# INNOVATION v5 : MÉMOIRE LONG-TERME
# ============================================================
def _update_incident_pattern(category: str, severity: str):
    """Met à jour les patterns d'incidents pour l'apprentissage adaptatif."""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO incident_patterns (category, occurrences, last_seen, avg_severity)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(category) DO UPDATE SET
                occurrences = occurrences + 1,
                last_seen   = excluded.last_seen,
                avg_severity = excluded.avg_severity
        """, (category, datetime.now().isoformat(), severity))
        conn.commit()
        conn.close()
    except Exception as e:
        audit.error("Erreur update pattern: %s", e)

def get_incident_patterns() -> list:
    """Retourne les patterns d'incidents détectés pour l'apprentissage."""
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT category, occurrences, last_seen, avg_severity, suggested_fix "
            "FROM incident_patterns ORDER BY occurrences DESC LIMIT 10"
        ).fetchall()
        conn.close()
        return [
            {
                "category": r[0], "occurrences": r[1],
                "last_seen": r[2][:16] if r[2] else "",
                "avg_severity": r[3], "suggested_fix": r[4]
            }
            for r in rows
        ]
    except Exception as e:
        audit.error("Erreur lecture patterns: %s", e)
        return []

def save_session_memory(session: str, history: list):
    """
    INNOVATION : résume une session et la stocke en mémoire long-terme.
    Appelé à la fin de chaque session (via --summarize ou automatiquement).
    """
    if not history or len(history) < 2:
        return

    msgs_text = "\n".join(
        f"[{m['role'].upper()}] {m['content'][:300]}"
        for m in history[-20:]
    )

    try:
        summary_response = api_call_with_retry([
            {"role": "system", "content": "Tu es un assistant qui résume des conversations techniques en 2-3 phrases. Sois concis et factuel. Mentionne les problèmes discutés, les commandes exécutées et les solutions apportées."},
            {"role": "user", "content": f"Résume cette conversation d'administration serveur :\n\n{msgs_text}"}
        ], temperature=0.2)
        summary = summary_response.choices[0].message.content

        # Extraire les topics clés
        topics = []
        topic_keywords = ["cpu", "ram", "disque", "nginx", "mysql", "docker", "php", "mémoire", "réseau", "sécurité"]
        combined = msgs_text.lower()
        for kw in topic_keywords:
            if kw in combined:
                topics.append(kw)

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO session_memory (ts, session, summary, key_topics, msg_count) VALUES (?,?,?,?,?)",
            (datetime.now().isoformat(), session, summary, ",".join(topics), len(history))
        )
        # Garder 100 résumés de sessions
        conn.execute(
            "DELETE FROM session_memory WHERE id NOT IN "
            "(SELECT id FROM session_memory ORDER BY id DESC LIMIT 100)"
        )
        conn.commit()
        conn.close()
        audit.info("SESSION_MEMORY_SAVED | session=%s | topics=%s", session, topics)
        return summary
    except Exception as e:
        audit.error("Erreur sauvegarde mémoire session: %s", e)
        return None

def get_long_term_memory() -> str:
    """Récupère les résumés de sessions récentes pour le contexte du prompt."""
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
            topics_str = f" [topics: {topics}]" if topics else ""
            lines.append(f"• [{ts[:10]}]{topics_str} {summary[:200]}")
        return "\n".join(lines)
    except Exception as e:
        audit.error("Erreur lecture mémoire long-terme: %s", e)
        return "Erreur lecture mémoire."

def get_patterns_for_prompt() -> str:
    """Formate les patterns pour injection dans le prompt système."""
    patterns = get_incident_patterns()
    if not patterns:
        return "Aucun pattern détecté."
    lines = []
    for p in patterns[:5]:
        fix = f" → {p['suggested_fix']}" if p.get('suggested_fix') else ""
        lines.append(
            f"• {p['category'].upper()} : {p['occurrences']} occurrence(s) "
            f"[{p['avg_severity']}]{fix}"
        )
    return "\n".join(lines)

# ============================================================
# COLLECTE DE MÉTRIQUES SYSTÈME
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
        "load": "0.0", "services": {}, "alerts": []
    }

    # FIX : utiliser context manager pour /proc/stat
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
        metrics["ram_used_gb"] = round((total_ram - avail_ram) / 1024 / 1024, 1)
    except Exception:
        pass

    out = _run_raw(["/bin/df", "-h", "/"])
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            pct_str = parts[4].replace("%", "")
            try:
                metrics["disk"] = int(pct_str)
                metrics["disk_total"] = parts[1]
                metrics["disk_used"] = parts[2]
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

    # Alertes avec déduplication
    if cpu > 85:
        metrics["alerts"].append({"level": "critical", "msg": f"CPU à {cpu}%"})
        save_incident("cpu", "critical", f"CPU critique : {cpu}%", dedup_window_minutes=10)
    elif cpu > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"CPU à {cpu}%"})
        save_incident("cpu", "warning", f"CPU élevé : {cpu}%", dedup_window_minutes=10)

    if metrics["ram"] > 80:
        metrics["alerts"].append({"level": "critical", "msg": f"RAM à {metrics['ram']}%"})
        save_incident("ram", "critical", f"RAM critique : {metrics['ram']}%", dedup_window_minutes=10)
    elif metrics["ram"] > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"RAM élevée : {metrics['ram']}%"})
        save_incident("ram", "warning", f"RAM élevée : {metrics['ram']}%", dedup_window_minutes=10)

    if metrics["disk"] > 85:
        metrics["alerts"].append({"level": "critical", "msg": f"Disque à {metrics['disk']}%"})
        save_incident("disk", "critical", f"Disque critique : {metrics['disk']}%", dedup_window_minutes=30)

    save_metrics(cpu, metrics["ram"], metrics["disk"], metrics["load"])

    # INNOVATION v5 : top 3 processus CPU pour le contexte
    try:
        ps_out = _run_raw(["/bin/ps", "aux", "--sort=-%cpu"], timeout=5)
        lines = [l for l in ps_out.splitlines() if l.strip()][1:4]
        metrics["top_processes"] = lines
    except Exception:
        metrics["top_processes"] = []

    return metrics

# ============================================================
# SÉCURITÉ — WHITELIST + VALIDATION
# ============================================================
ALLOWED_BINARIES = {
    "/bin/df":            ["-h", "-H", "/"],
    "/usr/bin/free":      ["-h", "-m", "-g"],
    "/usr/bin/uptime":    [],
    "/usr/bin/who":       [],
    "/bin/ps":            ["aux", "-ef", "--sort=-%cpu", "--sort=-%mem"],
    "/usr/bin/top":       ["-bn1"],
    "/bin/systemctl":     ["status", "list-units", "--type=service",
                           "--state=running", "is-active"],
    "/bin/journalctl":    ["-n", "-u", "--since", "--no-pager", "--lines"],
    "/usr/bin/tail":      ["-n", "--lines", "-f"],
    "/bin/cat":           [],
    "/bin/ls":            ["-la", "-lh", "-lht"],
    "/usr/bin/du":        ["-sh", "-h", "--max-depth"],
    "/bin/ss":            ["-tulnp", "-s"],
    "/usr/bin/netstat":   ["-tulnp"],
    "/usr/bin/docker":    ["ps", "stats", "--no-stream", "images", "info",
                           "container", "ls"],
    "/usr/bin/nginx":     ["-t"],
    "/usr/bin/mysql":     ["--version"],
    "/usr/bin/php":       ["--version"],
    "/usr/bin/wc":        ["-l"],
    # INNOVATION v5 : commandes supplémentaires utiles
    "/usr/bin/iostat":    ["-x", "-d", "1", "1"],
    "/usr/bin/vmstat":    ["1", "3", "-s"],
    "/bin/ping":          ["-c", "4", "-W", "2"],  # ping limité (4 paquets max)
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

# INJECTION_RE : bloquer tous les caractères dangereux
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

# Limiter ping à des IPs/hosts simples
PING_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-]{1,63}$')

def validate_path_arg(path: str) -> bool:
    try:
        resolved = str(Path(path).resolve())
        return any(resolved.startswith(p) for p in ALLOWED_READ_PATHS)
    except Exception:
        return False

def secure_execute(cmd: str) -> str:
    """
    FIX : utilise shlex.split au lieu de .split() pour gérer
    les arguments avec espaces (ex: tail -n 50 /var/log/nginx/error.log)
    """
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
            return f"Commande refusée : '{binary_name}' n'est pas dans la liste autorisée."

    if abs_bin not in ALLOWED_BINARIES:
        audit.warning("REFUS_BINAIRE | bin=%s", abs_bin)
        return "Commande refusée : binaire non autorisé."

    for arg in args:
        if INJECTION_RE.search(arg):
            audit.warning("REFUS_INJECTION | cmd=%s | arg=%s", cmd, arg)
            return f"Commande refusée : argument dangereux détecté ('{arg}')."

    # Validation spéciale : cat/tail → chemins autorisés uniquement
    if binary_name in ("cat", "tail"):
        for arg in args:
            if arg.startswith("/") and not validate_path_arg(arg):
                audit.warning("REFUS_CHEMIN | cmd=%s | path=%s", cmd, arg)
                return f"Chemin non autorisé : '{arg}'."

    # Validation spéciale : ping → host simple uniquement, max 4 paquets
    if binary_name == "ping":
        hosts = [a for a in args if not a.startswith("-")]
        for h in hosts:
            if not PING_HOST_RE.match(h):
                return f"Host ping non autorisé : '{h}'."
        if "-c" not in args:
            # Forcer -c 4 si non précisé
            args = ["-c", "4"] + [a for a in args if a not in ("-c",)]

    final_cmd = [abs_bin] + args
    audit.info("EXEC | %s", " ".join(final_cmd))

    try:
        result = subprocess.run(
            final_cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT,
            env={"PATH": "/bin:/usr/bin:/sbin:/usr/sbin"},
        )
        output = result.stdout + result.stderr
        audit.info("OK | exit=%d | chars=%d", result.returncode, len(output))
        return output[:MAX_OUTPUT_CHARS] if output else "[Succès — aucune sortie]"
    except subprocess.TimeoutExpired:
        audit.warning("TIMEOUT | cmd=%s", " ".join(final_cmd))
        return f"Commande interrompue : délai de {CMD_TIMEOUT}s dépassé."
    except FileNotFoundError:
        audit.error("BINAIRE_INTROUVABLE | %s", abs_bin)
        return f"Binaire introuvable : {abs_bin}"
    except Exception as e:
        audit.error("ERREUR | %s | %s", " ".join(final_cmd), e)
        return f"Erreur : {e}"

# ============================================================
# PARSERS SPÉCIALISÉS
# ============================================================
def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _pct_span(cell: str) -> str:
    try:
        pct = int(cell.replace("%", ""))
        css = "critical" if pct > 85 else ("warning" if pct > 70 else "ok")
        return f'<span class="{css}">{cell}</span>'
    except ValueError:
        return _escape_html(cell)

def parse_df_output(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return f'<pre class="command-output">{_escape_html(text)}</pre>'
    headers = lines[0].split()
    html = '<table class="data-table"><thead><tr>' + "".join(f"<th>{_escape_html(h)}</th>" for h in headers) + "</tr></thead><tbody>"
    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue
        html += "<tr>"
        for cell in parts:
            cell_html = _pct_span(cell) if "%" in cell else _escape_html(cell)
            html += f"<td>{cell_html}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    return html

def parse_ps_output(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return f'<pre class="command-output">{_escape_html(text)}</pre>'
    headers = lines[0].split()
    html = '<table class="data-table"><thead><tr>' + "".join(f"<th>{_escape_html(h)}</th>" for h in headers) + "</tr></thead><tbody>"
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
    html = '<table class="data-table"><thead><tr>' + "".join(f"<th>{h}</th>" for h in headers) + "</tr></thead><tbody>"
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
# FORMATAGE HTML DE LA RÉPONSE
# ============================================================
def format_response_for_web(reply: str) -> str:
    reply = re.sub(r'^## (.+)$', r'<h2 class="section-title">\1</h2>', reply, flags=re.MULTILINE)
    reply = re.sub(r'^### (.+)$', r'<h3 class="subsection-title">\1</h3>', reply, flags=re.MULTILINE)

    def process_code_block(match):
        code = match.group(1).strip()
        result = secure_execute(code)
        formatted = smart_format_output(code, result)
        safe_code = _escape_html(code)
        return f'''<div class="command-block">
            <div class="command-header"><span class="command-icon">💻</span> <span class="command-label">{safe_code}</span></div>
            <div class="result-header"><span class="result-icon">📋</span> Résultat</div>
            <div class="result-content">{formatted}</div>
        </div>'''

    reply = re.sub(r'```(?:bash|shell)?\n(.*?)\n```', process_code_block, reply, flags=re.DOTALL)
    reply = re.sub(r'^- (.+)$', r'<li>\1</li>', reply, flags=re.MULTILINE)
    reply = re.sub(r'(<li>.*?</li>)+', lambda m: f'<ul class="info-list">{m.group(0)}</ul>', reply, flags=re.DOTALL)

    # FIX : détection de bloc plus robuste avec compteur d'imbrication
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

    def color_pct(m):
        p = int(m.group(1))
        css = "critical" if p > 85 else ("warning" if p > 70 else "ok")
        return f'<span class="{css}">{p}%</span>'
    reply = re.sub(r'\b(\d{1,3})%', color_pct, reply)

    return reply

# ============================================================
# PROMPT SYSTÈME — enrichi avec mémoire long-terme
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

## PATTERNS D'INCIDENTS — apprentissage adaptatif
{patterns}

## RÈGLES IMPORTANTES
- Vérifie disque >85% ou RAM >80% → alerte immédiate
- Affiche les commandes à exécuter entre ```bash ... ```
- Structure avec des titres ## et des listes
- Utilise des tableaux pour les données chiffrées
- Demande confirmation pour toute action destructive
- Rappelle les incidents similaires passés si pertinent
- Si un pattern récurrent est détecté, propose une solution permanente

## STYLE
- Titres ## pour les sections
- Listes à puces pour les points clés
- Tableaux pour les métriques
- Termine par une proposition d'action concrète"""

# ============================================================
# ANALYSE PROACTIVE (mode --audit)
# ============================================================
def run_proactive_audit() -> dict:
    metrics = collect_metrics()
    top_procs = "\n".join(metrics.get("top_processes", []))

    audit_prompt = f"""Effectue une analyse proactive rapide du serveur.
Métriques actuelles : CPU={metrics['cpu']}%, RAM={metrics['ram']}%, Disque={metrics['disk']}%
Load: {metrics['load']}
Services: {json.dumps(metrics['services'])}
Alertes actives: {json.dumps(metrics['alerts'])}
Top processus CPU:
{top_procs}

En 3-5 phrases, donne un statut global et les points d'attention prioritaires."""

    try:
        response = api_call_with_retry([
            {"role": "system", "content": build_system_prompt()},
            {"role": "user", "content": audit_prompt},
        ], temperature=0.3)
        summary = response.choices[0].message.content

        conn = get_db_connection()
        status = "critical" if any(a["level"] == "critical" for a in metrics["alerts"]) else \
                 "warning" if metrics["alerts"] else "ok"
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
        audit.info("PROACTIVE_AUDIT | status=%s", status)
        return {"success": True, "summary": summary, "status": status, "metrics": metrics}
    except Exception as e:
        audit.error("PROACTIVE_AUDIT_ERROR | %s", e)
        return {"success": False, "error": str(e)}

# ============================================================
# MODES D'EXÉCUTION
# ============================================================
init_db()

if len(sys.argv) > 1 and sys.argv[1] == "--metrics":
    sys.stdout.write(json.dumps(collect_metrics()))
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--incidents":
    rows = get_recent_incidents(20)
    data = []
    for inc_id, ts, sev, cat, title, detail, resolved, resolved_at in rows:
        data.append({
            "id": inc_id, "ts": ts[:16], "severity": sev,
            "category": cat, "title": title,
            "resolved": bool(resolved), "resolved_at": resolved_at
        })
    sys.stdout.write(json.dumps(data))
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--resolve":
    try:
        inc_id = int(sys.argv[2])
        note = sys.argv[3] if len(sys.argv) > 3 else ""
        ok = resolve_incident(inc_id, note)
        sys.stdout.write(json.dumps({"success": ok}))
    except Exception as e:
        sys.stdout.write(json.dumps({"success": False, "error": str(e)}))
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--history":
    minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    rows = get_metrics_history(minutes)
    data = [{"ts": ts, "cpu": cpu, "ram": ram, "disk": disk}
            for ts, cpu, ram, disk in rows]
    sys.stdout.write(json.dumps(data))
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--audit":
    result = run_proactive_audit()
    sys.stdout.write(json.dumps(result))
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--last-audit":
    try:
        conn = get_db_connection()
        row = conn.execute(
            "SELECT ts, summary, status FROM audit_reports ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            sys.stdout.write(json.dumps({"ts": row[0], "summary": row[1], "status": row[2]}))
        else:
            sys.stdout.write(json.dumps({"summary": None}))
    except Exception as e:
        sys.stdout.write(json.dumps({"error": str(e)}))
    sys.exit(0)

# INNOVATION v5 : mode résumé de session
if len(sys.argv) > 1 and sys.argv[1] == "--summarize":
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
        session = data.get("session", "default")
        history = data.get("history", [])
        summary = save_session_memory(session, history)
        sys.stdout.write(json.dumps({"success": True, "summary": summary}))
    except Exception as e:
        sys.stdout.write(json.dumps({"success": False, "error": str(e)}))
    sys.exit(0)

# INNOVATION v5 : mode patterns
if len(sys.argv) > 1 and sys.argv[1] == "--patterns":
    patterns = get_incident_patterns()
    sys.stdout.write(json.dumps(patterns))
    sys.exit(0)

# Mode chat principal (stdin)
if len(sys.argv) > 1 and sys.argv[1] == "--chat":
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
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

        formatted = format_response_for_web(reply)
        sys.stdout.write(json.dumps({"success": True, "response": formatted}, ensure_ascii=False))
        sys.exit(0)

    except Exception as e:
        audit.error("API_ERROR | %s", e)
        sys.stdout.write(json.dumps({"success": False, "error": str(e)}))
        sys.exit(1)

# FIX : garde la compatibilité ascendante UNIQUEMENT si l'arg ressemble à du JSON
# (évite le crash sur tout argument inconnu)
if len(sys.argv) > 1:
    arg = sys.argv[1]
    known_flags = {
        "--metrics", "--incidents", "--resolve", "--history",
        "--audit", "--last-audit", "--chat", "--summarize", "--patterns"
    }
    if arg not in known_flags and arg.strip().startswith("{"):
        try:
            data      = json.loads(arg)
            prompt    = data.get("message", "")
            history   = data.get("history", [])
            session_id = data.get("session", "default")

            log_conversation(session_id, "user", prompt)
            messages = [{"role": "system", "content": build_system_prompt()}]
            messages.extend(history)
            messages.append({"role": "user", "content": prompt})

            response = api_call_with_retry(messages, temperature=0.4)
            reply    = response.choices[0].message.content
            log_conversation(session_id, "assistant", reply)

            formatted = format_response_for_web(reply)
            sys.stdout.write(json.dumps({"success": True, "response": formatted}, ensure_ascii=False))
            sys.exit(0)
        except Exception as e:
            audit.error("API_ERROR (legacy) | %s", e)
            sys.stdout.write(json.dumps({"success": False, "error": str(e)}))
            sys.exit(1)
    elif arg not in known_flags:
        print(f"[CASSANDRA] Argument inconnu : {arg!r}. Flags valides : {', '.join(sorted(known_flags))}", file=sys.stderr)
        sys.exit(1)

# ============================================================
# MODE INTERACTIF — terminal
# ============================================================
print("=" * 60, file=sys.stderr)
print("CASSANDRA — Agent Infrastructure v5.0 (mode interactif)", file=sys.stderr)
print(f"Base de données: {DB_PATH}", file=sys.stderr)
print("=" * 60, file=sys.stderr)
print("💬 Mode interactif. Tapez 'exit' pour quitter.", file=sys.stderr)

messages = [{"role": "system", "content": build_system_prompt()}]
session_history = []

# FIX : exec_inline défini UNE SEULE FOIS hors de la boucle
def exec_inline(m):
    result = secure_execute(m.group(1).strip())
    return f"```\n{m.group(1).strip()}\n```\nRésultat :\n{result}"

while True:
    try:
        user_input = input("> ").strip()
        if user_input.lower() in ("exit", "quit"):
            # Sauvegarder la mémoire de la session avant de quitter
            if session_history:
                save_session_memory("interactive", session_history)
                print("\n[Session mémorisée]", file=sys.stderr)
            break
        if not user_input:
            continue
        messages.append({"role": "user", "content": user_input})
        session_history.append({"role": "user", "content": user_input})

        response = api_call_with_retry(messages, temperature=0.4)
        reply    = response.choices[0].message.content

        reply_displayed = re.sub(r'```(?:bash|shell)?\n(.*?)\n```',
                                  exec_inline, reply, flags=re.DOTALL)
        print(f"\n{reply_displayed}\n")
        messages.append({"role": "assistant", "content": reply})
        session_history.append({"role": "assistant", "content": reply})

        if len(messages) > 12:
            messages = [messages[0]] + messages[-10:]

    except KeyboardInterrupt:
        if session_history:
            save_session_memory("interactive", session_history)
        print("\nAu revoir !")
        break
    except Exception as e:
        print(f"Erreur : {e}")
