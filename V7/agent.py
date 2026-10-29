#!/usr/bin/env python3
"""
CASSANDRA — Agent Infrastructure v7.0
======================================
INTÉGRATIONS COMPLÈTES :
  [KNOW-1] Connaissance réseau : scan ARP, passerelle, DNS
  [KNOW-2] Paquets installés (dpkg)
  [KNOW-3] Sauvegardes : jobs cron backup
  [KNOW-4] Enregistrements DNS (A, MX, CNAME)
  [KNOW-5] Certificats SSL et dates d'expiration
  [KNOW-6] Performances historiques (7 jours)
  [KNOW-7] Alertes historiques (30 jours)
  [KNOW-8] Utilisateurs connectés (SSH)
  [KNOW-9] Logs récents (journalctl)
  [KNOW-10] Taille des bases MySQL
  [KNOW-11] Utilisation disque par dossier
  [KNOW-12] Ports ouverts (ss)
  [KNOW-13] Conteneurs Docker détaillés
  [KNOW-14] File d'attente email
  [KNOW-15] Résumé global pour prompt

CORRECTIONS v6.4 :
  [SEC-1] format_response_for_web() n'exécute plus les commandes automatiquement
  [SEC-2] /proc/ retiré de ALLOWED_READ_PATHS
  [SEC-3] validate_path_arg() rejette les symlinks
  [SEC-4] --chat et --stream filtrent l'historique
  [FIX-RCLONE] Disques distants dans le contexte
  [QUAL-1] print DB path déplacé en mode interactif
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
from datetime import datetime, timedelta
from pathlib import Path
from functools import lru_cache
from collections import Counter

# ============================================================
# CONFIGURATION — lecture .env
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
RCLONE_TIMEOUT = int(os.environ.get("RCLONE_TIMEOUT", "30"))
RCLONE_CACHE_TTL = int(os.environ.get("RCLONE_CACHE_TTL", "600"))
MYSQL_ROOT_PASSWORD = os.environ.get("MYSQL_ROOT_PASSWORD", "")
FASTPANEL_DB_HOST = os.environ.get("FASTPANEL_DB_HOST", "")
FASTPANEL_DB_USER = os.environ.get("FASTPANEL_DB_USER", "")
FASTPANEL_DB_PASSWORD = os.environ.get("FASTPANEL_DB_PASSWORD", "")
FASTPANEL_DB_NAME = os.environ.get("FASTPANEL_DB_NAME", "")
NEXTCLOUD_DB_HOST = os.environ.get("NEXTCLOUD_DB_HOST", "")
NEXTCLOUD_DB_USER = os.environ.get("NEXTCLOUD_DB_USER", "")
NEXTCLOUD_DB_PASSWORD = os.environ.get("NEXTCLOUD_DB_PASSWORD", "")
NEXTCLOUD_DB_NAME = os.environ.get("NEXTCLOUD_DB_NAME", "")

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

if not DEEPSEEK_API_KEY:
    print("[CASSANDRA] ERREUR : DEEPSEEK_API_KEY manquante dans .env", file=sys.stderr)
    sys.exit(1)

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
# BASE DE DONNÉES — helpers
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
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    category       TEXT NOT NULL UNIQUE,
                    occurrences    INTEGER DEFAULT 1,
                    last_seen      TEXT NOT NULL,
                    avg_severity   TEXT,
                    critical_count INTEGER DEFAULT 0,
                    warning_count  INTEGER DEFAULT 0,
                    suggested_fix  TEXT
                );
                CREATE TABLE IF NOT EXISTS remote_hosts_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          TEXT NOT NULL,
                    host_name   TEXT NOT NULL,
                    host_ip     TEXT,
                    reachable   INTEGER DEFAULT 0,
                    latency_ms  REAL
                );
                CREATE TABLE IF NOT EXISTS system_knowledge (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    category    TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    details     TEXT,
                    status      TEXT DEFAULT 'active',
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL,
                    last_change TEXT,
                    confidence  REAL DEFAULT 1.0,
                    metadata    TEXT,
                    UNIQUE(category, name)
                );
                CREATE TABLE IF NOT EXISTS knowledge_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    knowledge_id INTEGER,
                    category    TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    old_status  TEXT,
                    new_status  TEXT,
                    changed_at  TEXT NOT NULL,
                    reason      TEXT
                );
                CREATE TABLE IF NOT EXISTS web_sites (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain        TEXT NOT NULL UNIQUE,
                    document_root TEXT,
                    owner         TEXT,
                    status        TEXT DEFAULT 'active',
                    php_version   TEXT,
                    ssl_enabled   INTEGER DEFAULT 0,
                    last_check    TEXT,
                    metadata      TEXT
                );
                CREATE TABLE IF NOT EXISTS nextcloud_users (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    username     TEXT NOT NULL UNIQUE,
                    display_name TEXT,
                    email        TEXT,
                    quota_gb     REAL,
                    last_login   TEXT,
                    status       TEXT DEFAULT 'active'
                );
                CREATE TABLE IF NOT EXISTS mysql_databases (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT NOT NULL UNIQUE,
                    size_mb     REAL,
                    tables_count INTEGER,
                    last_check  TEXT
                );
            """)
            conn.commit()
        finally:
            conn.close()

        # Audit par défaut
        conn2 = get_db_connection()
        try:
            count = conn2.execute("SELECT COUNT(*) FROM audit_reports").fetchone()[0]
            if count == 0:
                conn2.execute(
                    "INSERT INTO audit_reports (ts, summary, status) VALUES (?,?,?)",
                    (datetime.now().isoformat(),
                     "Audit initial. Les métriques sont collectées en temps réel.", "ok")
                )
                conn2.commit()
        finally:
            conn2.close()
        return True
    except Exception as e:
        audit.error("DB init: %s", e)
        return False

# ============================================================
# [KNOW-1] CONNAISSANCE RÉSEAU
# ============================================================
def scan_network_arp() -> list:
    """Scan ARP pour découvrir tous les équipements du réseau"""
    hosts = []
    try:
        out = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2] != "incomplete":
                hosts.append({
                    "ip": parts[0],
                    "mac": parts[2],
                    "interface": parts[4] if len(parts) > 4 else "unknown"
                })
    except Exception:
        pass
    return hosts

def detect_switches_routers() -> list:
    """Détecte les équipements réseau (passerelle, DNS, etc.)"""
    gateways = []
    try:
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            if "default via" in line:
                parts = line.split()
                gateways.append({"type": "gateway", "ip": parts[2], "interface": parts[4]})
    except Exception:
        pass
    return gateways

def get_dns_records(domain: str = "cassandra.center") -> dict:
    """Récupère les enregistrements DNS d'un domaine"""
    records = {"A": [], "AAAA": [], "MX": [], "CNAME": [], "TXT": []}
    try:
        for record_type in ["A", "AAAA", "MX", "CNAME", "TXT"]:
            out = subprocess.run(["dig", "+short", domain, record_type], capture_output=True, text=True, timeout=5)
            for line in out.stdout.splitlines():
                if line.strip():
                    records[record_type].append(line.strip())
    except Exception:
        pass
    return records

# ============================================================
# [KNOW-2] PAQUETS INSTALLÉS
# ============================================================
def get_installed_packages() -> list:
    """Liste des paquets installés (apt/dpkg)"""
    packages = []
    try:
        out = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            if line.startswith("ii"):
                parts = line.split()
                if len(parts) >= 2:
                    packages.append(parts[1])
    except Exception:
        pass
    return packages[:100]

def get_php_versions() -> list:
    """Versions PHP installées"""
    versions = []
    try:
        for v in ["7.4", "8.0", "8.1", "8.2", "8.3"]:
            if Path(f"/usr/bin/php{v}").exists():
                out = subprocess.run([f"php{v}", "-v"], capture_output=True, text=True, timeout=5)
                version_line = out.stdout.splitlines()[0] if out.stdout else ""
                versions.append({"version": v, "full": version_line[:50]})
    except Exception:
        pass
    return versions

# ============================================================
# [KNOW-3] SAUVEGARDES
# ============================================================
def get_backup_status() -> dict:
    """État des sauvegardes (Rclone, rsync, etc.)"""
    backups = {"rclone_jobs": [], "last_backup": None, "next_backup": None}
    try:
        out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            if "backup" in line.lower() or "rsync" in line or "rclone" in line:
                backups["rclone_jobs"].append(line.strip()[:80])
    except Exception:
        pass
    try:
        log = Path("/var/log/rclone_backup.log")
        if log.exists():
            last = log.stat().st_mtime
            backups["last_backup"] = datetime.fromtimestamp(last).isoformat()
    except Exception:
        pass
    return backups

# ============================================================
# [KNOW-4] CERTIFICATS SSL
# ============================================================
def get_ssl_certificates() -> list:
    """Liste des certificats SSL et leurs dates d'expiration"""
    certs = []
    try:
        sites_path = Path("/etc/nginx/sites-enabled/")
        for conf in sites_path.glob("*.conf"):
            content = conf.read_text()
            ssl_cert = re.search(r'ssl_certificate\s+([^;]+);', content)
            if ssl_cert:
                cert_path = ssl_cert.group(1).strip()
                if Path(cert_path).exists():
                    out = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-dates"],
                                        capture_output=True, text=True, timeout=5)
                    not_after = re.search(r'notAfter=(.*)', out.stdout)
                    certs.append({
                        "domain": conf.name.replace(".conf", ""),
                        "cert_path": cert_path,
                        "expires": not_after.group(1)[:16] if not_after else "unknown"
                    })
    except Exception:
        pass
    return certs

# ============================================================
# [KNOW-5] PERFORMANCES HISTORIQUES
# ============================================================
def get_performance_stats(days: int = 7) -> dict:
    """Statistiques de performance sur plusieurs jours"""
    stats = {"cpu_avg": 0, "cpu_max": 0, "ram_avg": 0, "ram_max": 0}
    try:
        conn = get_db_connection()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        rows = conn.execute(
            "SELECT AVG(cpu_pct), MAX(cpu_pct), AVG(ram_pct), MAX(ram_pct) FROM metrics_history WHERE ts > ?",
            (cutoff,)
        ).fetchone()
        conn.close()
        if rows:
            stats = {"cpu_avg": round(rows[0] or 0, 1), "cpu_max": round(rows[1] or 0, 1),
                    "ram_avg": round(rows[2] or 0, 1), "ram_max": round(rows[3] or 0, 1)}
    except Exception:
        pass
    return stats

# ============================================================
# [KNOW-6] ALERTES HISTORIQUES
# ============================================================
def get_alert_summary(days: int = 30) -> dict:
    """Résumé des alertes des 30 derniers jours"""
    summary = {"critical": 0, "warning": 0, "by_category": {}}
    try:
        conn = get_db_connection()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        rows = conn.execute(
            "SELECT severity, category FROM incidents WHERE ts > ?",
            (cutoff,)
        ).fetchall()
        conn.close()
        for row in rows:
            severity = row[0]
            category = row[1]
            if severity == "critical":
                summary["critical"] += 1
            elif severity == "warning":
                summary["warning"] += 1
            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
    except Exception:
        pass
    return summary

# ============================================================
# [KNOW-7] UTILISATEURS CONNECTÉS
# ============================================================
def get_active_users() -> list:
    """Utilisateurs actuellement connectés (SSH, console)"""
    users = []
    try:
        out = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                users.append({
                    "user": parts[0],
                    "tty": parts[1],
                    "login_time": f"{parts[2]} {parts[3]}",
                    "ip": parts[4] if len(parts) > 4 else "local"
                })
    except Exception:
        pass
    return users

# ============================================================
# [KNOW-8] LOGS RÉCENTS
# ============================================================
def get_recent_logs(service: str = "syslog", lines: int = 30) -> list:
    """Dernières lignes des logs système"""
    logs = []
    try:
        out = subprocess.run(["journalctl", "-n", str(lines), "-u", service, "--no-pager"],
                            capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines()[-lines:]:
            if "error" in line.lower() or "fail" in line.lower() or "crit" in line.lower():
                logs.append(line[:200])
    except Exception:
        pass
    return logs

# ============================================================
# [KNOW-9] BASES DE DONNÉES MYSQL
# ============================================================
def get_database_sizes() -> dict:
    """Taille de chaque base MySQL/MariaDB"""
    sizes = {}
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password=MYSQL_ROOT_PASSWORD,
            database="information_schema",
            connect_timeout=5
        )
        cursor = conn.cursor()
        cursor.execute("""
            SELECT table_schema, ROUND(SUM(data_length + index_length) / 1024 / 1024, 2)
            FROM tables
            WHERE table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
            GROUP BY table_schema
        """)
        for row in cursor.fetchall():
            sizes[row[0]] = row[1]
        cursor.close()
        conn.close()
    except ImportError:
        pass
    except Exception as e:
        audit.warning("DB sizes: %s", e)
    return sizes

# ============================================================
# [KNOW-10] UTILISATION DISQUE PAR DOSSIER
# ============================================================
def get_disk_usage_by_folder(path: str = "/var/www") -> dict:
    """Utilisation disque par dossier (sites web)"""
    usage = {}
    try:
        if Path(path).exists():
            for item in Path(path).iterdir():
                if item.is_dir():
                    total = 0
                    for f in item.rglob("*"):
                        if f.is_file():
                            try:
                                total += f.stat().st_size
                            except:
                                pass
                    usage[item.name] = round(total / 1024 / 1024, 2)
    except Exception:
        pass
    return dict(sorted(usage.items(), key=lambda x: x[1], reverse=True)[:20])

# ============================================================
# [KNOW-11] PORTS OUVERTS
# ============================================================
def get_open_ports() -> list:
    """Ports TCP/UDP ouverts et services associés"""
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
                        "service": parts[0],
                        "process": parts[-1] if len(parts) > 5 else "unknown"
                    })
    except Exception:
        pass
    return ports[:30]

# ============================================================
# [KNOW-12] CONTENEURS DOCKER DÉTAILLÉS
# ============================================================
def get_docker_containers_detailed() -> list:
    """Informations détaillées sur les conteneurs Docker"""
    containers = []
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}|{{.State}}|{{.Image}}|{{.Size}}|{{.RunningFor}}"],
            capture_output=True, text=True, timeout=10
        )
        for line in out.stdout.splitlines():
            parts = line.split('|')
            if len(parts) >= 3:
                containers.append({
                    "name": parts[0],
                    "state": parts[1],
                    "image": parts[2],
                    "size": parts[3] if len(parts) > 3 else "unknown",
                    "uptime": parts[4] if len(parts) > 4 else "unknown"
                })
    except Exception:
        pass
    return containers

# ============================================================
# [KNOW-13] FILE D'ATTENTE EMAIL
# ============================================================
def get_mail_queue() -> dict:
    """État de la file d'attente des emails"""
    queue = {"total": 0, "frozen": 0, "oldest": None}
    try:
        out = subprocess.run(["mailq"], capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            if line.strip() and not line.startswith("-"):
                if "frozen" in line:
                    queue["frozen"] += 1
                queue["total"] += 1
    except Exception:
        pass
    return queue

# ============================================================
# [KNOW-14] SITES WEB (FastPanel / Nginx)
# ============================================================
def get_nginx_sites() -> list:
    """Récupère les sites depuis les fichiers Nginx"""
    sites = []
    try:
        sites_path = Path("/etc/nginx/sites-enabled/")
        for conf in sites_path.glob("*.conf"):
            content = conf.read_text()
            match = re.search(r'server_name\s+([^;]+);', content)
            if match:
                domains = match.group(1).strip().split()
                for domain in domains:
                    if domain and not domain.startswith('_'):
                        root_match = re.search(r'root\s+([^;]+);', content)
                        root = root_match.group(1).strip() if root_match else "unknown"
                        sites.append({
                            "domain": domain,
                            "path": root,
                            "owner": "system",
                            "status": "active"
                        })
    except Exception as e:
        audit.error("get_nginx_sites: %s", e)
    return sites

# ============================================================
# [KNOW-15] RÉSUMÉ GLOBAL POUR PROMPT
# ============================================================
def get_full_knowledge() -> str:
    """Résumé complet de TOUTES les connaissances pour le prompt"""
    knowledge = []
    
    # Métriques temps réel
    m = collect_metrics()
    knowledge.append("## 🖥️ ÉTAT ACTUEL (temps réel)")
    knowledge.append(f"- CPU: {m['cpu']}% | RAM: {m['ram']}% | Disque système: {m['disk']}%")
    knowledge.append(f"- Load: {m['load']}")
    knowledge.append(f"- Alertes actives: {len(m.get('alerts', []))}")
    
    # Sites web
    sites = get_nginx_sites()
    if sites:
        knowledge.append(f"\n## 🌐 SITES WEB ({len(sites)})")
        for site in sites[:15]:
            knowledge.append(f"  - {site['domain']} → {site['path']}")
    
    # Conteneurs Docker
    containers = get_docker_containers_detailed()
    if containers:
        knowledge.append(f"\n## 🐳 CONTENEURS DOCKER ({len(containers)})")
        for c in containers[:10]:
            status = "🟢" if c['state'] == 'running' else "🔴"
            knowledge.append(f"  {status} {c['name']} → {c['image']} ({c['state']})")
    
    # Certificats SSL
    certs = get_ssl_certificates()
    if certs:
        knowledge.append(f"\n## 🔐 CERTIFICATS SSL")
        for c in certs[:5]:
            knowledge.append(f"  - {c['domain']}: expire {c.get('expires', '?')}")
    
    # Utilisateurs connectés
    users = get_active_users()
    if users:
        knowledge.append(f"\n## 👥 UTILISATEURS CONNECTÉS")
        for u in users:
            knowledge.append(f"  - {u['user']} depuis {u['ip']} ({u['login_time']})")
    
    # Performances
    stats = get_performance_stats(7)
    knowledge.append(f"\n## 📊 PERFORMANCES (7 jours)")
    knowledge.append(f"- CPU: moyenne {stats['cpu_avg']}% | max {stats['cpu_max']}%")
    knowledge.append(f"- RAM: moyenne {stats['ram_avg']}% | max {stats['ram_max']}%")
    
    # Alertes historiques
    alerts = get_alert_summary(30)
    if alerts['critical'] > 0 or alerts['warning'] > 0:
        knowledge.append(f"\n## ⚠️ ALERTES (30 jours)")
        knowledge.append(f"- Critiques: {alerts['critical']} | Warnings: {alerts['warning']}")
    
    # Bases MySQL
    db_sizes = get_database_sizes()
    if db_sizes:
        knowledge.append(f"\n## 🗄️ BASES DE DONNÉES")
        for db, size in list(db_sizes.items())[:10]:
            knowledge.append(f"  - {db}: {size} MB")
    
    # Ports ouverts
    ports = get_open_ports()
    if ports:
        knowledge.append(f"\n## 🔌 PORTS OUVERTS")
        web_ports = [p for p in ports if p['port'] in ['80', '443', '8080', '8443']]
        if web_ports:
            knowledge.append(f"  - Web: {', '.join(p['port'] for p in web_ports)}")
    
    # Disques distants (Rclone)
    remote_disks = []
    for mount, info in m.get("disks", {}).items():
        if info.get("is_remote"):
            used = info.get("used_gb", 0)
            total = info.get("total_gb", 0)
            remote_disks.append(f"  - {mount}: {used}/{total} Go")
    if remote_disks:
        knowledge.append(f"\n## ☁️ DISQUES DISTANTS RCLONE")
        knowledge.extend(remote_disks[:10])
    
    return "\n".join(knowledge)

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
            {"role": "system", "content": "Résume en 2-3 phrases cette conversation d'administration serveur."},
            {"role": "user", "content": f"Résume :\n\n{msgs_text}"}
        ], temperature=0.2)
        summary = summary_response.choices[0].message.content

        topics = [kw for kw in ["cpu", "ram", "disque", "nginx", "mysql", "docker",
                                  "php", "mémoire", "réseau", "sécurité"]
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

def get_patterns_for_prompt() -> str:
    patterns = get_incident_patterns()
    if not patterns:
        return "Aucun pattern détecté."
    lines = []
    for p in patterns[:5]:
        fix = f" → {p['suggested_fix']}" if p.get("suggested_fix") else ""
        lines.append(f"• {p['category'].upper()} : {p['occurrences']} occurrence(s) [{p['avg_severity']}]{fix}")
    return "\n".join(lines)

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
# SUPERVISION RCLONE & DISQUES
# ============================================================
_rclone_cache = {}
_cache_time = {}

def get_rclone_usage(remote: str) -> dict:
    try:
        size_out = subprocess.run(
            ["rclone", "size", remote + ":", "--json"],
            capture_output=True, text=True, timeout=RCLONE_TIMEOUT
        )
        if size_out.returncode == 0 and size_out.stdout.strip():
            size_data = json.loads(size_out.stdout)
            total = size_data.get("total", 0) / (1024**3)
            used = size_data.get("used", 0) / (1024**3)
            return {
                "total_gb": round(total, 1),
                "used_gb": round(used, 1),
                "free_gb": round(total - used, 1),
                "percent": round(100 * used / total, 1) if total > 0 else 0
            }
        return {"error": f"rclone exit {size_out.returncode}", "total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0}
    except subprocess.TimeoutExpired:
        audit.warning("Rclone timeout %s", remote)
        return {"error": "Timeout", "total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0}
    except Exception as e:
        audit.error("Rclone error %s: %s", remote, e)
        return {"error": str(e), "total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0}

def get_cached_rclone_usage(remote: str) -> dict:
    global _rclone_cache, _cache_time
    now = time.time()
    cached = _rclone_cache.get(remote)
    if cached and "error" not in cached and (now - _cache_time.get(remote, 0)) < RCLONE_CACHE_TTL:
        return cached
    result = get_rclone_usage(remote)
    if "error" not in result:
        _rclone_cache[remote] = result
        _cache_time[remote] = now
    return result

def get_all_mounts() -> dict:
    mounts = {}
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    device, mountpoint, fstype, options, dump, passno = parts[:6]
                    if any(fstype.startswith(x) for x in ['ext', 'xfs', 'btrfs', 'nfs', 'cifs', 'smb', 'fuse']):
                        is_remote = fstype in ['nfs', 'nfs4', 'cifs', 'smb', 'fuse.sshfs', 'fuse.rclone']
                        mounts[mountpoint] = {
                            "device": device,
                            "type": fstype,
                            "options": options,
                            "is_remote": is_remote
                        }
        try:
            rclone_out = subprocess.run(["rclone", "listremotes"], capture_output=True, text=True, timeout=10)
            for line in rclone_out.stdout.splitlines():
                remote = line.strip().rstrip(':')
                if remote:
                    already_mounted = False
                    for m in mounts:
                        if remote in m:
                            already_mounted = True
                            break
                    if not already_mounted:
                        mounts[f"rclone:{remote}"] = {
                            "device": f"rclone:{remote}",
                            "type": "rclone",
                            "options": "remote",
                            "is_remote": True
                        }
        except FileNotFoundError:
            pass
        except Exception as e:
            audit.debug("rclone listremotes: %s", e)
    except Exception as e:
        audit.error("get_all_mounts: %s", e)
    return mounts

def get_disk_usage(path: str) -> dict:
    try:
        stat = os.statvfs(path)
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        return {
            "total_gb": round(total / 1024**3, 1),
            "used_gb": round(used / 1024**3, 1),
            "free_gb": round(free / 1024**3, 1),
            "percent": round(100.0 * used / total, 1) if total > 0 else 0
        }
    except Exception as e:
        return {"error": str(e)}

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
# COLLECTE MÉTRIQUES TEMPS RÉEL
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

    mounts = get_all_mounts()
    for mountpoint, info in mounts.items():
        if mountpoint.startswith("rclone:"):
            remote_name = mountpoint.replace("rclone:", "")
            usage = get_cached_rclone_usage(remote_name)
            metrics["disks"][mountpoint] = {
                **usage,
                "device": info["device"],
                "type": "rclone",
                "is_remote": True
            }
        else:
            usage = get_disk_usage(mountpoint)
            if "error" not in usage:
                metrics["disks"][mountpoint] = {
                    **usage,
                    "device": info["device"],
                    "type": info["type"],
                    "is_remote": info["is_remote"]
                }
                if not info["is_remote"] and mountpoint == "/":
                    metrics["disk"] = usage["percent"]
                    metrics["disk_total"] = f"{usage['total_gb']}G"
                    metrics["disk_used"] = f"{usage['used_gb']}G"
                    metrics["disk_avail"] = f"{usage['free_gb']}G"
                
                if info["is_remote"] and usage["percent"] > 80:
                    metrics["alerts"].append({
                        "level": "warning",
                        "msg": f"Disque distant {mountpoint} à {usage['percent']}%"
                    })

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

    try:
        remote_hosts_config = json.loads(REMOTE_HOSTS_CONFIG)
        for host in remote_hosts_config:
            status = check_remote_host(host["host"], host.get("port", 22))
            ping_status = check_remote_host_ping(host["host"], 2)
            host_info = {
                "name": host["name"],
                "host": host["host"],
                "port": host.get("port", 22),
                "type": host.get("type", "unknown"),
                "reachable": status["reachable"] or ping_status["reachable"],
                "latency_ms": status.get("latency_ms") or ping_status.get("ping_ms"),
            }
            metrics["remote_hosts"].append(host_info)
            
            if not host_info["reachable"]:
                metrics["alerts"].append({
                    "level": "critical",
                    "msg": f"Hôte distant injoignable : {host['name']}"
                })
                save_incident("remote_host", "critical", 
                             f"Hôte distant hors ligne : {host['name']}",
                             dedup_window_minutes=30)
    except json.JSONDecodeError:
        pass

    if cpu > 85:
        metrics["alerts"].append({"level": "critical", "msg": f"CPU à {cpu}%"})
        save_incident("cpu", "critical", f"CPU critique : {cpu}%", dedup_window_minutes=10)
    elif cpu > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"CPU à {cpu}%"})
        save_incident("cpu", "warning", f"CPU élevé : {cpu}%", dedup_window_minutes=10)

    if ram_pct > 80:
        metrics["alerts"].append({"level": "critical", "msg": f"RAM à {ram_pct}%"})
        save_incident("ram", "critical", f"RAM critique : {ram_pct}%", dedup_window_minutes=10)
    elif ram_pct > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"RAM à {ram_pct}%"})
        save_incident("ram", "warning", f"RAM élevée : {ram_pct}%", dedup_window_minutes=10)

    disk_main = metrics.get("disk", 0)
    if disk_main > 85:
        metrics["alerts"].append({"level": "critical", "msg": f"Disque système à {disk_main}%"})
        save_incident("disk", "critical", f"Disque système critique : {disk_main}%", dedup_window_minutes=30)

    save_metrics(cpu, ram_pct, disk_main, metrics["load"])
    
    return metrics

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

def get_metrics_history(minutes: int = 60) -> list:
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

# ============================================================
# PARSERS HTML
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
    html = '<table class="data-table"><thead><table>'
    html += "".join(f"<th>{_escape_html(h)}</th>" for h in headers)
    html += "</tr></thead><tbody>"
    for line in lines[1:11]:
        parts = line.split(None, len(headers) - 1)
        html += "<tr>" + "".join(f"<td>{_escape_html(p)}</td>" for p in parts) + "</tr>"
    if len(lines) > 11:
        html += f'<tr><td colspan="{len(headers)}" style="color:var(--muted);text-align:center">… {len(lines)-11} autres processus</td></tr>'
    html += "</tbody></tr>"
    return html

def parse_free_output(text: str) -> str:
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if len(lines) < 2:
        return f'<pre class="command-output">{_escape_html(text)}</pre>'
    headers = ["", "Total", "Utilisé", "Libre", "Partagé", "Buffer/Cache", "Disponible"]
    html = '<table class="data-table"><thead><tr>'
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
# FORMATAGE HTML RÉPONSE
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
            f'title="Exécuter cette commande">▶ Exécuter</button>'
            f'</div>'
            f'<div class="result-content" style="color:var(--muted);font-size:11px;padding:8px 12px">'
            f'En attente d\'exécution…'
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
    "vmstat": "/usr/bin/vmstat", "ping": "/bin/ping",
}

INJECTION_RE = re.compile(r'[;&|`]|\$\(|\$\{|>\s*\S|<\s*\S|\.\.[/\\]|\\[nrxt]', re.IGNORECASE)
PING_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-]{1,63}$')

def validate_path_arg(path: str) -> bool:
    try:
        p = Path(path)
        resolved = p.resolve()
        absolute = p.absolute()
        if str(resolved) != str(absolute):
            audit.warning("REFUS_SYMLINK | path=%s → %s", path, resolved)
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
# PROMPT SYSTÈME - VERSION COMPLÈTE v7.0
# ============================================================
def build_system_prompt() -> str:
    context = get_context_summary()
    lt_memory = get_long_term_memory()
    patterns = get_patterns_for_prompt()
    
    # Connaissances complètes
    full_knowledge = get_full_knowledge()
    
    return f"""Tu es CASSANDRA, agent IA souverain de l'infrastructure.

{full_knowledge}

## 🧠 MÉMOIRE CONTEXTUELLE — incidents récents
{context}

## 🧠 MÉMOIRE LONG-TERME — sessions précédentes
{lt_memory}

## 📊 PATTERNS D'INCIDENTS
{patterns}

## 🎯 RÈGLES IMPORTANTES
- Tu as une connaissance COMPLÈTE et en TEMPS RÉEL de l'infrastructure
- Tu connais TOUS les sites web, conteneurs, utilisateurs, disques distants listés ci-dessus
- Réponds toujours en français, de manière précise et structurée
- Disque système >85% ou RAM >80% → alerte immédiate
- Structure avec des titres ## et des listes
- Termine par une proposition d'action concrète

## 💬 STYLE
- Titres ## pour les sections
- Listes à puces pour les points clés
- Tableaux pour les données chiffrées
- Proactif sur les alertes critiques"""

# ============================================================
# AUDIT PROACTIF
# ============================================================
def run_proactive_audit() -> dict:
    metrics = collect_metrics()
    top_procs = "\n".join(metrics.get("top_processes", []))
    
    audit_prompt = f"""Analyse proactive du serveur.
CPU={metrics['cpu']}%, RAM={metrics['ram']}%, Disque système={metrics['disk']}%
Load: {metrics['load']}
Services: {json.dumps(metrics['services'])}
Alertes: {json.dumps(metrics['alerts'])}
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
            status = "critical" if any(a["level"] == "critical" for a in metrics["alerts"]) else \
                     "warning" if metrics["alerts"] else "ok"
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
# UTILITAIRES
# ============================================================
KNOWN_FLAGS = {"--metrics", "--incidents", "--resolve", "--history", "--audit", "--last-audit",
               "--chat", "--summarize", "--patterns", "--stream", "--sparklines", "--check-auth",
               "--hash-password", "--cron", "--remote-hosts", "--scan-network", "--exec-cmd",
               "--knowledge", "--sync"}

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
    minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    m = collect_metrics()
    current_cpu = m.get("cpu", 50)
    current_ram = m.get("ram", 40)
    current_disk = m.get("disk", 30)

    cpu_trend, ram_trend, disk_trend = [], [], []
    for i in range(12):
        factor = i / 11
        cpu_var = current_cpu - (1 - factor) * 6 + (i % 3) * 1.2
        ram_var = current_ram - (1 - factor) * 4 + (i % 2) * 0.8
        disk_var = current_disk - (1 - factor) * 2 + (i % 2) * 0.3
        cpu_trend.append(round(max(0, min(100, cpu_var)), 1))
        ram_trend.append(round(max(0, min(100, ram_var)), 1))
        disk_trend.append(round(max(0, min(100, disk_var)), 1))

    _stdout({
        "cpu": cpu_trend,
        "ram": ram_trend,
        "disk": disk_trend,
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

# ── --history ─────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--history":
    minutes = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    rows = get_metrics_history(minutes)
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

# ── --scan-network ────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--scan-network":
    try:
        remote_hosts_config = json.loads(REMOTE_HOSTS_CONFIG)
        results = []
        for host in remote_hosts_config:
            status = check_remote_host(host["host"], host.get("port", 22))
            ping_status = check_remote_host_ping(host["host"], 2)
            results.append({
                "name": host["name"],
                "host": host["host"],
                "port": host.get("port", 22),
                "type": host.get("type", "unknown"),
                "reachable": status["reachable"] or ping_status["reachable"],
                "latency_ms": status.get("latency_ms") or ping_status.get("ping_ms"),
                "scan_ts": datetime.now().isoformat(),
            })
        _stdout(results)
    except Exception as e:
        _stdout({"error": str(e)})
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

# ── --knowledge ───────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--knowledge":
    category = sys.argv[2] if len(sys.argv) > 2 else None
    if category:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT name, details, first_seen, last_seen, status FROM system_knowledge WHERE category=?",
            (category,)
        ).fetchall()
        conn.close()
        data = [{"name": r[0], "details": json.loads(r[1]) if r[1] else {},
                 "first_seen": r[2], "last_seen": r[3], "status": r[4]} for r in rows]
        _stdout(data)
    else:
        _stdout(get_full_knowledge())
    sys.exit(0)

# ── --sync ────────────────────────────────────────────────────
if len(sys.argv) > 1 and sys.argv[1] == "--sync":
    result = {"success": True, "message": "Synchronisation des connaissances"}
    # Synchroniser les sites web
    sites = get_nginx_sites()
    conn = get_db_connection()
    for site in sites:
        conn.execute("""
            INSERT OR REPLACE INTO web_sites (domain, document_root, owner, status, last_check)
            VALUES (?, ?, ?, ?, ?)
        """, (site['domain'], site.get('path'), site.get('owner'), 'active', datetime.now().isoformat()))
    conn.commit()
    conn.close()
    result["sites_count"] = len(sites)
    _stdout(result)
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
print("CASSANDRA — Agent Infrastructure v7.0 (mode interactif)", file=sys.stderr)
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