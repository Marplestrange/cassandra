#!/usr/bin/env python3
"""
CASSANDRA — Knowledge Collector v6.0 (FASTPANEL STATS COMPLÈTES)
=======================================================
TOUTES les fonctionnalités conservées :
- FastPanel (domaines, users, PHP versions)
- Network hosts (ip neigh JSON + fallback arp)
- PHP-FPM pools avec fallback cgi-fcgi/socat/curl
- Email stats (journalctl + grep)
- DNS servers (bind, powerdns, unbound, knot, nsd, dnsmasq)
- Sysctl sécurité
- SMART disques
- Redis stats
- Nginx access stats
- Backup runs
- NFS exports/mounts
- VPN connections (WireGuard, OpenVPN, Tailscale)
- Cloudflare tunnels, SSH tunnels
- SSH authorized keys
- Cron jobs
- Systemd services
- Firewall rules (iptables, ufw)
- Changelog et détection de différences
- Prometheus exporter (optionnel)
- TOUTES les tables SQL
"""

import os
import sys
import json
import sqlite3
import subprocess
import re
import socket
import time
import hashlib
import configparser
import threading
import atexit
import signal
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============================================================
# CONFIGURATION
# ============================================================
DB_PATH = "/var/lib/cassandra/cassandra.db"
SOCKET_PATH = "/tmp/cassandra_knowledge.sock"
PROMETHEUS_PORT = 9103
PROMETHEUS_ENABLED = False  # Désactivé car cause des erreurs
SCAN_PATHS = [
    "/var/www", "/var/www/html", "/var/www/fastuser/data/www",
    "/home", "/opt", "/usr/share",
    "/etc/nginx/sites-enabled", "/etc/nginx/sites-available",
    "/etc/apache2/sites-enabled", "/etc/apache2/sites-available"
]

CMS_DETECTORS = {
    "wordpress": ["wp-config.php", "wp-content", "wp-includes"],
    "joomla": ["configuration.php", "administrator", "media"],
    "drupal": ["core", "sites/default/settings.php"],
}

SAFE_IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')

SOCKET_ALLOWED_ENTITIES = {
    "active_sessions", "open_ports", "ssl_certificates", "rclone_remotes",
    "tailscale_peers", "fail2ban_banned_ips", "oom_events", "failed_units",
    "web_sites", "docker_containers", "network_hosts", "system_services",
    "fastpanel_domains", "fastpanel_users", "fastpanel_php_versions",
    "vpn_connections", "tunnels", "disk_smart", "redis_stats", "phpfpm_pools",
    "health_scores", "databases", "cron_jobs", "ssh_sessions", "firewall_rules",
    "nfs_exports", "nfs_mounts", "rclone_mounts", "system_mounts", "backup_runs",
    "dns_servers", "dns_zones", "sysctl_security", "package_versions", "email_accounts",
    "fastpanel_databases", "fastpanel_mail_accounts", "fastpanel_ftp_accounts",
    "fastpanel_backups", "fastpanel_dns_records", "fastpanel_crons",
    "fastpanel_services", "fastpanel_stats",
    "fp_server_stat", "fp_process_stat", "fp_disk_stat", "fp_net_stat"
}

SECURITY_SYSCTL = {
    "kernel.kptr_restrict": {"recommended": "2", "critical": "0", "description": "Restriction des pointeurs kernel"},
    "kernel.dmesg_restrict": {"recommended": "1", "critical": "0", "description": "Restriction d'accès à dmesg"},
    "kernel.randomize_va_space": {"recommended": "2", "critical": "0", "description": "ASLR"},
    "net.ipv4.conf.all.rp_filter": {"recommended": "1", "critical": "0", "description": "Protection anti-spoofing"},
    "net.ipv4.tcp_syncookies": {"recommended": "1", "critical": "0", "description": "Protection contre SYN flood"},
    "net.ipv4.conf.all.accept_redirects": {"recommended": "0", "critical": "1", "description": "Acceptation des redirections ICMP"},
    "fs.protected_symlinks": {"recommended": "1", "critical": "0", "description": "Protection des liens symboliques"},
    "fs.protected_hardlinks": {"recommended": "1", "critical": "0", "description": "Protection des hardlinks"},
    "fs.protected_fifos": {"recommended": "1", "critical": "0", "description": "Protection des FIFOs"},
    "fs.protected_regular": {"recommended": "1", "critical": "0", "description": "Protection des fichiers réguliers"},
}

# ============================================================
# BASE DE DONNÉES COMPLÈTE
# ============================================================
def get_conn():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn

def init_all_tables():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS metrics_realtime (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, cpu_pct REAL, ram_pct REAL, disk_pct REAL, swap_pct REAL,
            ram_total_gb REAL, ram_used_gb REAL, ram_free_gb REAL,
            ram_buffers_gb REAL, ram_cached_gb REAL,
            swap_total_gb REAL, swap_used_gb REAL, swap_free_gb REAL,
            disk_total_gb REAL, disk_used_gb REAL, disk_free_gb REAL,
            load_1m REAL, load_5m REAL, load_15m REAL,
            top_processes TEXT, services TEXT, alerts TEXT
        );
        CREATE TABLE IF NOT EXISTS web_sites (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE, document_root TEXT, owner TEXT, php_version TEXT, ssl_enabled INTEGER, config_file TEXT, server_type TEXT, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS cms_sites (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, path TEXT, cms_type TEXT, version TEXT, theme TEXT, plugins TEXT, plugins_count INTEGER, db_name TEXT, db_user TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS databases (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, type TEXT, size_mb REAL, tables_count INTEGER, host TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS email_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, domain TEXT, quota_mb INTEGER, used_mb INTEGER, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS email_queues (id INTEGER PRIMARY KEY AUTOINCREMENT, queue_type TEXT, count INTEGER, oldest_age INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS email_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, stat_type TEXT, today_count INTEGER, week_count INTEGER, spam_count INTEGER, bounce_count INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS ssl_certificates (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, cert_path TEXT, issuer TEXT, expiry_date TEXT, days_left INTEGER, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS rclone_remotes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, total_gb REAL, used_gb REAL, files_count INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS rclone_mounts (id INTEGER PRIMARY KEY AUTOINCREMENT, mountpoint TEXT UNIQUE, remote TEXT, fstype TEXT, total_gb REAL, used_gb REAL, percent REAL, last_check TEXT);
        CREATE TABLE IF NOT EXISTS nfs_exports (id INTEGER PRIMARY KEY AUTOINCREMENT, export_path TEXT, client TEXT, options TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS nfs_mounts (id INTEGER PRIMARY KEY AUTOINCREMENT, mountpoint TEXT UNIQUE, server TEXT, export_path TEXT, total_gb REAL, used_gb REAL, percent REAL, last_check TEXT);
        CREATE TABLE IF NOT EXISTS docker_containers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, image TEXT, status TEXT, state TEXT, ports TEXT, created TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS vpn_connections (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, name TEXT, interface TEXT, endpoint TEXT, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS tunnels (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, url TEXT, port INTEGER, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS tailscale_peers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, dns_name TEXT, tailscale_ip TEXT, online INTEGER, last_seen TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS oom_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, killed_process TEXT, pid INTEGER, memory_used_mb INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS failed_units (id INTEGER PRIMARY KEY AUTOINCREMENT, unit TEXT UNIQUE, active_state TEXT, description TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS package_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, package TEXT UNIQUE, installed_version TEXT, available_version TEXT, source TEXT, security_upgrade INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS ssh_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, ip TEXT, port INTEGER, pid INTEGER, command TEXT, login_time TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT, disk_quota_gb REAL, disk_used_gb REAL, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_domains (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE, user TEXT, php_version TEXT, ssl_enabled INTEGER, config_file TEXT, document_root TEXT, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_php_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT UNIQUE, full_version TEXT, path TEXT, active INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS active_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, ip TEXT, login_time TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS open_ports (id INTEGER PRIMARY KEY AUTOINCREMENT, port INTEGER, protocol TEXT, process TEXT, pid INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS system_services (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, status TEXT, enabled INTEGER, active INTEGER, description TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS system_mounts (id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT, mountpoint TEXT UNIQUE, fstype TEXT, total_gb REAL, used_gb REAL, percent REAL, last_check TEXT);
        CREATE TABLE IF NOT EXISTS network_hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE, mac TEXT, hostname TEXT, interface TEXT, reachable INTEGER, last_seen TEXT);
        CREATE TABLE IF NOT EXISTS firewall_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, tool TEXT, chain TEXT, action TEXT, protocol TEXT, port TEXT, source TEXT, raw TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fail2ban_status (id INTEGER PRIMARY KEY AUTOINCREMENT, jail TEXT UNIQUE, currently_failed INTEGER, currently_banned INTEGER, total_banned INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fail2ban_banned_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, jail TEXT, ip TEXT, banned_at TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS log_errors (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, service TEXT, level TEXT, message TEXT, count INTEGER, last_seen TEXT);
        CREATE TABLE IF NOT EXISTS disk_smart (id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT UNIQUE, model TEXT, health TEXT, temperature INTEGER, power_on_hours INTEGER, reallocated_sectors INTEGER, pending_sectors INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS redis_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, used_memory_mb REAL, max_memory_mb REAL, pct_memory REAL, total_keys INTEGER, hit_rate REAL, connected_clients INTEGER, uptime_seconds INTEGER, version TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS phpfpm_pools (id INTEGER PRIMARY KEY AUTOINCREMENT, pool TEXT UNIQUE, socket TEXT, active_processes INTEGER, idle_processes INTEGER, total_processes INTEGER, slow_requests INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS nginx_access_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, domain TEXT, total_reqs INTEGER, req_4xx INTEGER, req_5xx INTEGER, top_ips TEXT, top_paths TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS backup_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, remote TEXT UNIQUE, ts TEXT, status TEXT, size_gb REAL, files_count INTEGER, error TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS changelog (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, entity_type TEXT, entity_name TEXT, change_type TEXT, old_value TEXT, new_value TEXT, severity TEXT);
        CREATE TABLE IF NOT EXISTS health_scores (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, score INTEGER, breakdown TEXT, alerts_count INTEGER, status TEXT);
        CREATE TABLE IF NOT EXISTS dns_servers (id INTEGER PRIMARY KEY AUTOINCREMENT, server_type TEXT UNIQUE, version TEXT, config_file TEXT, zones_count INTEGER, running INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS dns_zones (id INTEGER PRIMARY KEY AUTOINCREMENT, zone_name TEXT, server_type TEXT, zone_file TEXT, serial TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS sysctl_security (id INTEGER PRIMARY KEY AUTOINCREMENT, param TEXT UNIQUE, value TEXT, recommended TEXT, status TEXT, description TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS collector_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, run_type TEXT, duration_ms INTEGER, items_count INTEGER, errors TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS cron_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, schedule TEXT, command TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS ssh_authorized_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, key_type TEXT, key_hash TEXT, comment TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS apache_vhosts (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, document_root TEXT, config_file TEXT, ssl_enabled INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS inode_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, mountpoint TEXT UNIQUE, total INTEGER, used INTEGER, free INTEGER, pct REAL, last_check TEXT);
        CREATE TABLE IF NOT EXISTS swap_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, total_gb REAL, used_gb REAL, free_gb REAL, pct REAL, last_check TEXT);
        -- FastPanel2 télémétrie étendue
        CREATE TABLE IF NOT EXISTS fastpanel_databases (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, db_user TEXT, size_mb REAL, db_type TEXT, owner TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_mail_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, domain TEXT, login TEXT, quota_mb INTEGER, used_mb INTEGER, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_ftp_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT UNIQUE, home_dir TEXT, status TEXT, owner TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_backups (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, status TEXT, size_mb REAL, created_at TEXT, error TEXT, user TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_dns_records (id INTEGER PRIMARY KEY AUTOINCREMENT, zone TEXT, type TEXT, name TEXT, value TEXT, ttl INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_crons (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, schedule TEXT, command TEXT, enabled INTEGER, last_run TEXT, last_status TEXT, source TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_services (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, status TEXT, version TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, mysql_queries_per_sec REAL, mysql_connections INTEGER, nginx_requests_total INTEGER, nginx_active_conns INTEGER, php_requests_per_min REAL, mail_queue_size INTEGER, last_check TEXT);
        -- Stats temps-réel FastPanel2 (timeline)
        CREATE TABLE IF NOT EXISTS fp_server_stat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, cpu REAL, la1 REAL, la5 REAL, la15 REAL,
            mem_used INTEGER, mem_total INTEGER,
            swap_used INTEGER, swap_total INTEGER
        );
        CREATE TABLE IF NOT EXISTS fp_process_stat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, name TEXT, cpu REAL, mem INTEGER
        );
        CREATE TABLE IF NOT EXISTS fp_disk_stat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, device TEXT,
            read_bytes INTEGER, write_bytes INTEGER,
            read_iops INTEGER, write_iops INTEGER
        );
        CREATE TABLE IF NOT EXISTS fp_net_stat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, interface TEXT,
            rx_bytes INTEGER, tx_bytes INTEGER,
            rx_packets INTEGER, tx_packets INTEGER
        );
    """)
    conn.commit()
    conn.close()
    print("[COLLECTOR] Tables initialisées (version complète)")

# ============================================================
# FONCTIONS UTILITAIRES
# ============================================================
def run_cmd(cmd, timeout=10, input_data=None):
    try:
        if isinstance(cmd, list):
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_data)
        else:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, input=input_data)
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""

def get_cpu():
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        vals = list(map(int, line.split()[1:]))
        idle1, total1 = vals[3], sum(vals)
        time.sleep(0.3)
        with open("/proc/stat") as f:
            line = f.readline()
        vals = list(map(int, line.split()[1:]))
        idle2, total2 = vals[3], sum(vals)
        return round(100.0 * (1 - (idle2 - idle1) / max(total2 - total1, 1)), 1)
    except:
        return 0.0

def get_ram():
    try:
        with open("/proc/meminfo") as f:
            mi = {}
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        total = mi.get("MemTotal", 1)
        avail = mi.get("MemAvailable", total)
        used = total - avail
        return {"percent": round(100.0 * used / total, 1), "total_gb": round(total / 1024**2, 1), "used_gb": round(used / 1024**2, 1)}
    except:
        return {"percent": 0, "total_gb": 0, "used_gb": 0}

def get_disk():
    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        return {"percent": round(100.0 * used / total, 1), "total_gb": round(total / 1024**3, 1), "used_gb": round(used / 1024**3, 1)}
    except:
        return {"percent": 0, "total_gb": 0, "used_gb": 0}

def get_load():
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except:
        return 0.0, 0.0, 0.0

def get_top_processes():
    procs = []
    out = run_cmd("ps aux --sort=-%cpu --no-headers | head -10")
    for line in out.splitlines():
        parts = line.split(None, 10)
        if len(parts) >= 11:
            try:
                procs.append({"user": parts[0], "cpu": float(parts[2]), "command": parts[10][:50]})
            except:
                pass
    return procs

# ============================================================
# COLLECTEURS COMPLETS
# ============================================================

# ============================================================
# FASTPANEL2 — CONFIGURATION ET HELPERS
# ============================================================

FP_PARAM_FILES = [
    "/usr/local/fastpanel2/app/config/parameters.yml",
    "/usr/local/fastpanel2/app/config/parameters.yaml",
    "/usr/local/fastpanel2/config/database.yml",
]
FP_API_BASE  = "http://127.0.0.1:8888"
FP_USER_HOME = "/var/www/fastuser/data/www"

_fp_mysql_creds: dict = {}
_fp_api_token:   str  = ""


def _fp_load_params() -> dict:
    """Lit parameters.yml de FastPanel2 — credentials MySQL + token API."""
    global _fp_mysql_creds, _fp_api_token
    if _fp_mysql_creds:
        return _fp_mysql_creds
    for param_file in FP_PARAM_FILES:
        if not Path(param_file).exists():
            continue
        try:
            content = Path(param_file).read_text(errors="replace")
            params = {}
            for line in content.splitlines():
                line = line.strip()
                if ": " in line and not line.startswith("#"):
                    k, _, v = line.partition(": ")
                    params[k.strip()] = v.strip().strip('"\' ')
            _fp_mysql_creds = {
                "host":   params.get("database_host", "127.0.0.1"),
                "port":   int(params.get("database_port", 3306)),
                "db":     params.get("database_name", "fastpanel2"),
                "user":   params.get("database_user", "fastpanel"),
                "passwd": params.get("database_password", ""),
            }
            _fp_api_token = params.get("api_token", params.get("secret", ""))
            return _fp_mysql_creds
        except Exception as e:
            print(f"[FP] Erreur params: {e}", file=sys.stderr)
    return {}


def _fp_mysql_query(sql: str) -> list:
    """Requête MySQL sur la DB FastPanel2.
    
    Utilise MYSQL_PWD= pour éviter l'exposition du mot de passe dans
    la liste des processus et les problèmes d'échappement shell.
    """
    creds = _fp_load_params()
    if not creds:
        return []
    import shlex as _shlex
    try:
        passwd = creds.get("passwd", "")
        # MYSQL_PWD évite -pPASSWORD et les problèmes avec ! # $ dans les mdp
        env_prefix = f"MYSQL_PWD={_shlex.quote(passwd)} " if passwd else ""
        cmd = (
            f"{env_prefix}mysql "
            f"-h{_shlex.quote(creds['host'])} "
            f"-P{int(creds['port'])} "
            f"-u{_shlex.quote(creds['user'])} "
            f"{_shlex.quote(creds['db'])} "
            f"--batch --silent --skip-column-names "
            f"-e {_shlex.quote(sql)} 2>/dev/null"
        )
        out = run_cmd(cmd, timeout=10)
        if not out:
            return []
        # Ignorer les avertissements mysql (Warning: Using password...)
        lines = [l for l in out.splitlines()
                 if l.strip() and not l.startswith("Warning") and not l.upper().startswith("ERROR")]
        return [line.split("\t") for line in lines]
    except Exception as e:
        print(f"[FP] MySQL error: {e}", file=sys.stderr)
        return []


def _fp_api_get(endpoint: str) -> dict:
    """Appel API REST FastPanel2 interne (port 8888)."""
    global _fp_api_token
    if not _fp_api_token:
        _fp_load_params()
    try:
        url = FP_API_BASE + endpoint
        headers = {}
        if _fp_api_token:
            headers["Authorization"] = f"Bearer {_fp_api_token}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


def _fp_available() -> bool:
    """FastPanel2 détecté si parameters.yml OU dossier nginx FastPanel2 OU binaire."""
    if any(Path(f).exists() for f in FP_PARAM_FILES):
        return True
    # Détection alternative : dossier nginx fastpanel2 ou service actif
    alt_signals = [
        "/etc/nginx/fastpanel2",
        "/usr/local/fastpanel2",
        "/var/www/fastuser",
    ]
    return any(Path(p).exists() for p in alt_signals)


# ============================================================
# FASTPANEL2 — COLLECTEURS MÉTIER
# ============================================================

def collect_fastpanel_users() -> list:
    """Users FastPanel2 : MySQL → API REST → scan filesystem."""
    now = datetime.now().isoformat()
    users, seen = [], set()
    if not _fp_available():
        return []

    # MySQL (source primaire)
    rows = _fp_mysql_query(
        "SELECT u.login, u.email, u.status, u.created_at, u.last_login, "
        "COALESCE(u.disk_quota,0), COALESCE(u.disk_used,0) "
        "FROM user u ORDER BY u.login"
    )
    if rows:
        for r in rows:
            if len(r) < 5 or r[0] in seen: continue
            seen.add(r[0])
            users.append({
                "username": r[0], "email": r[1] or "",
                "status": r[2] or "active",
                "disk_quota_gb": round(float(r[5])/1024**3, 2) if len(r)>5 and r[5] else 0,
                "disk_used_gb":  round(float(r[6])/1024**3, 2) if len(r)>6 and r[6] else 0,
                "created_at": r[3] or now, "last_login": r[4] or "",
                "last_check": now,
            })
        return users

    # API REST
    data = _fp_api_get("/fastpanel/api/user/list")
    for u in data.get("data", []):
        login = u.get("login","")
        if login and login not in seen:
            seen.add(login)
            users.append({
                "username": login, "email": u.get("email",""),
                "status": u.get("status","active"),
                "disk_quota_gb": round(u.get("disk_quota",0)/1024**3,2),
                "disk_used_gb":  round(u.get("disk_used",0)/1024**3,2),
                "created_at": u.get("created_at",now), "last_login": u.get("last_login",""),
                "last_check": now,
            })
    if users: return users

    # Filesystem fallback
    for d in Path(FP_USER_HOME).iterdir() if Path(FP_USER_HOME).exists() else []:
        if d.is_dir() and d.name not in seen:
            seen.add(d.name)
            try: used_gb = round(int(run_cmd(f"du -sb {d} 2>/dev/null").split()[0])/1024**3, 2)
            except: used_gb = 0
            users.append({"username": d.name, "email": "", "status": "active",
                          "disk_quota_gb": 0, "disk_used_gb": used_gb,
                          "created_at": now, "last_login": "", "last_check": now})
    return users


def collect_fastpanel_domains() -> list:
    """Domaines FastPanel2 avec PHP, SSL, document_root."""
    now = datetime.now().isoformat()
    domains, seen = [], set()
    if not _fp_available():
        return []

    # MySQL
    rows = _fp_mysql_query(
        "SELECT d.name, COALESCE(u.login,''), d.php_version, d.ssl, "
        "d.document_root, d.status, d.created_at, "
        "COALESCE(s.expires_at,'') "
        "FROM domain d "
        "LEFT JOIN user u ON d.user_id=u.id "
        "LEFT JOIN ssl_certificate s ON s.domain_id=d.id "
        "ORDER BY d.name"
    )
    if rows:
        for r in rows:
            if len(r) < 6 or r[0] in seen: continue
            seen.add(r[0])
            ssl_days = 0
            if len(r) > 7 and r[7]:
                try:
                    exp = datetime.fromisoformat(r[7].replace(" ","T"))
                    ssl_days = (exp - datetime.now()).days
                except: pass
            domains.append({
                "domain": r[0], "user": r[1], "php_version": r[2] or "unknown",
                "ssl_enabled": 1 if r[3] in ("1","true","yes","1") else 0,
                "ssl_days_left": ssl_days,
                "document_root": r[4] or "", "status": r[5] or "active",
                "created_at": r[6] or now, "last_check": now,
            })
        return domains

    # API REST
    data = _fp_api_get("/fastpanel/api/domain/list")
    for d in data.get("data", []):
        name = d.get("name","")
        if name and name not in seen:
            seen.add(name)
            domains.append({
                "domain": name, "user": d.get("user",{}).get("login",""),
                "php_version": d.get("php_version","unknown"),
                "ssl_enabled": 1 if d.get("ssl") else 0, "ssl_days_left": 0,
                "document_root": d.get("document_root",""),
                "status": d.get("status","active"),
                "created_at": d.get("created_at",now), "last_check": now,
            })
    if domains: return domains

    # Nginx configs : scan exhaustif de tous les dossiers connus
    nginx_dirs = [
        "/etc/nginx/sites-enabled",
        "/etc/nginx/conf.d",
        "/etc/nginx/fastpanel2",
        "/etc/nginx/vhosts.d",
        "/usr/local/fastpanel2/etc/nginx",
        "/etc/nginx",   # dernier recours : scan global
    ]
    for ndir in nginx_dirs:
        nd = Path(ndir)
        if not nd.exists():
            continue
        # Pour /etc/nginx seul, ne pas descendre récursivement (trop large)
        confs = nd.glob("*.conf") if ndir == "/etc/nginx" else nd.rglob("*.conf")
        for conf in confs:
            try:
                content = conf.read_text(errors="replace")
                if "server_name" not in content:
                    continue
                ssl = bool(re.search(r"ssl_certificate", content))
                root_m = re.search(r"root\s+([^;]+);", content)
                php_m  = re.search(r"fastcgi_pass[^;]*php(\d+\.?\d*)", content)
                # Essayer d'extraire le user depuis le document_root
                docroot = root_m.group(1).strip() if root_m else ""
                user = ""
                user_m = re.search(r"/(?:var/www/|home/)([^/]+)", docroot)
                if user_m:
                    user = user_m.group(1)
                for sn_block in re.findall(r"server_name\s+([^;]+);", content):
                    for domain in sn_block.strip().split():
                        domain = domain.strip().rstrip(".")
                        if (domain and len(domain) > 3
                                and not domain.startswith(("_", "*", "#", "localhost"))
                                and "." in domain
                                and domain not in seen):
                            seen.add(domain)
                            # Essayer de lire l'expiration SSL depuis certbot
                            ssl_days = 0
                            if ssl:
                                cert_path = f"/etc/letsencrypt/live/{domain}/cert.pem"
                                if Path(cert_path).exists():
                                    out_ssl = run_cmd(f"openssl x509 -in {cert_path} -noout -enddate 2>/dev/null")
                                    date_m = re.search(r"notAfter=(.+)", out_ssl)
                                    if date_m:
                                        try:
                                            from datetime import datetime as _dt
                                            exp = _dt.strptime(date_m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                                            ssl_days = (_dt.now() - exp).days * -1
                                        except Exception:
                                            pass
                            domains.append({
                                "domain":        domain,
                                "user":          user,
                                "php_version":   php_m.group(1) if php_m else "unknown",
                                "ssl_enabled":   1 if ssl else 0,
                                "ssl_days_left": ssl_days,
                                "document_root": docroot,
                                "status":        "active",
                                "created_at":    now,
                                "last_check":    now,
                            })
            except Exception:
                pass
    return domains


def collect_fastpanel_databases() -> list:
    """Bases de données FastPanel2."""
    now = datetime.now().isoformat()
    dbs, seen = [], set()
    if not _fp_available():
        return []

    rows = _fp_mysql_query(
        "SELECT db.name, db.db_user, COALESCE(db.size_mb,0), "
        "COALESCE(db.db_type,'mysql'), COALESCE(u.login,'') "
        "FROM `database` db LEFT JOIN user u ON db.user_id=u.id ORDER BY db.name"
    )
    if rows:
        for r in rows:
            if len(r) >= 3 and r[0] not in seen:
                seen.add(r[0])
                dbs.append({"name": r[0], "db_user": r[1] or "", "size_mb": float(r[2]),
                            "db_type": r[3] if len(r)>3 else "mysql",
                            "owner": r[4] if len(r)>4 else "", "last_check": now})
        return dbs

    # MySQL CLI direct — tailles réelles
    out = run_cmd(
        "mysql -u root --batch --silent --skip-column-names -e "
        "\"SELECT table_schema,ROUND(SUM(data_length+index_length)/1024/1024,2) "
        "FROM information_schema.tables GROUP BY table_schema\" 2>/dev/null"
    )
    skip = {"information_schema","performance_schema","mysql","sys"}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] not in skip and parts[0] not in seen:
            seen.add(parts[0])
            dbs.append({"name": parts[0], "db_user": "", "size_mb": float(parts[1]),
                        "db_type": "mysql", "owner": "", "last_check": now})
    return dbs


def collect_fastpanel_mail() -> list:
    """Comptes mail FastPanel2."""
    now = datetime.now().isoformat()
    accounts, seen = [], set()
    if not _fp_available():
        return []

    rows = _fp_mysql_query(
        "SELECT ma.login, md.domain, ma.quota_mb, ma.used_mb, ma.status "
        "FROM mail_account ma JOIN mail_domain md ON ma.mail_domain_id=md.id "
        "ORDER BY md.domain, ma.login"
    )
    if rows:
        for r in rows:
            if len(r) >= 2:
                email = f"{r[0]}@{r[1]}"
                if email not in seen:
                    seen.add(email)
                    accounts.append({
                        "email": email, "domain": r[1], "login": r[0],
                        "quota_mb": int(r[2]) if len(r)>2 and r[2] else 0,
                        "used_mb":  int(r[3]) if len(r)>3 and r[3] else 0,
                        "status":   r[4] if len(r)>4 else "active",
                        "last_check": now,
                    })
        return accounts

    # Fallback postfix
    for vfile in ["/etc/postfix/virtual", "/etc/postfix/vmailbox"]:
        if not Path(vfile).exists(): continue
        try:
            for line in Path(vfile).read_text(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "@" in line:
                    email = line.split()[0]
                    if "@" in email and email not in seen:
                        seen.add(email)
                        accounts.append({
                            "email": email, "domain": email.split("@")[1],
                            "login": email.split("@")[0],
                            "quota_mb": 0, "used_mb": 0, "status": "active",
                            "last_check": now,
                        })
        except: pass
    return accounts


def collect_fastpanel_ftp() -> list:
    """Comptes FTP FastPanel2."""
    now = datetime.now().isoformat()
    rows = _fp_mysql_query(
        "SELECT f.login, f.home_dir, f.status, COALESCE(u.login,'') "
        "FROM ftp_account f LEFT JOIN user u ON f.user_id=u.id ORDER BY f.login"
    )
    return [{"login": r[0], "home_dir": r[1] or "", "status": r[2] or "active",
             "owner": r[3] if len(r)>3 else "", "last_check": now}
            for r in rows if len(r) >= 3]


def collect_fastpanel_backups() -> list:
    """Backups FastPanel2."""
    now = datetime.now().isoformat()
    rows = _fp_mysql_query(
        "SELECT b.type, b.status, COALESCE(b.size_mb,0), b.created_at, "
        "COALESCE(b.error_message,''), COALESCE(u.login,'') "
        "FROM backup b LEFT JOIN user u ON b.user_id=u.id "
        "ORDER BY b.created_at DESC LIMIT 100"
    )
    return [{"type": r[0] or "full", "status": r[1] or "unknown",
             "size_mb": float(r[2]), "created_at": r[3] or now,
             "error": r[4] if len(r)>4 else "",
             "user": r[5] if len(r)>5 else "", "last_check": now}
            for r in rows if len(r) >= 4]


def collect_fastpanel_dns() -> list:
    """Enregistrements DNS FastPanel2."""
    now = datetime.now().isoformat()
    rows = _fp_mysql_query(
        "SELECT dr.type, dr.name, dr.value, dr.ttl, d.name "
        "FROM dns_record dr JOIN domain d ON dr.domain_id=d.id "
        "ORDER BY d.name, dr.type"
    )
    return [{"zone": r[4] if len(r)>4 else "", "type": r[0], "name": r[1],
             "value": r[2], "ttl": int(r[3]) if r[3] else 3600, "last_check": now}
            for r in rows if len(r) >= 5]


def collect_fastpanel_php_versions() -> list:
    """PHP versions via FastPanel2 MySQL puis binaires système."""
    now = datetime.now().isoformat()
    versions, seen = [], set()

    if _fp_available():
        rows = _fp_mysql_query("SELECT version, status FROM php_version ORDER BY version DESC")
        if rows:
            for r in rows:
                if r[0] and r[0] not in seen:
                    seen.add(r[0])
                    versions.append({
                        "version": r[0], "full_version": r[0],
                        "path": f"/usr/sbin/php-fpm{r[0]}",
                        "active": 1 if (len(r)<2 or r[1]=="active") else 0,
                        "last_check": now,
                    })
            return versions

    for ver in ["8.4","8.3","8.2","8.1","8.0","7.4","7.3","7.2"]:
        for bin_path in [f"/usr/sbin/php-fpm{ver}", f"/usr/bin/php{ver}"]:
            if Path(bin_path).exists() and ver not in seen:
                seen.add(ver)
                full = run_cmd(f"php{ver} -r 'echo PHP_VERSION;' 2>/dev/null")
                versions.append({
                    "version": ver, "full_version": full or ver,
                    "path": bin_path, "active": 1, "last_check": now,
                })
                break
    return versions


def collect_fastpanel_crons() -> list:
    """Crons FastPanel2 (en supplément des crons système)."""
    now = datetime.now().isoformat()
    rows = _fp_mysql_query(
        "SELECT c.schedule, c.command, c.enabled, c.last_run, c.last_status, "
        "COALESCE(u.login,'root') "
        "FROM cron c LEFT JOIN user u ON c.user_id=u.id ORDER BY u.login"
    )
    return [{"user": r[5] if len(r)>5 else "root",
             "schedule": r[0], "command": (r[1] or "")[:200],
             "enabled": int(r[2]) if r[2] else 1,
             "last_run": r[3] if len(r)>3 else "",
             "last_status": r[4] if len(r)>4 else "",
             "source": "fastpanel", "last_check": now}
            for r in rows if len(r) >= 3]


def collect_fastpanel_services() -> list:
    """Services supervisés par FastPanel2."""
    now = datetime.now().isoformat()
    rows = _fp_mysql_query("SELECT name, status, version FROM service ORDER BY name")
    if rows:
        return [{"name": r[0], "status": r[1] or "unknown",
                 "version": r[2] if len(r)>2 else "", "last_check": now}
                for r in rows if len(r) >= 2]
    # Fallback systemctl
    svcs = []
    for svc in ["nginx","mysql","mariadb","postfix","dovecot","bind9","redis-server",
                "fail2ban","proftpd","vsftpd","fastpanel2","php8.3-fpm","php8.2-fpm"]:
        st = run_cmd(f"systemctl is-active {svc} 2>/dev/null").strip()
        if st in ("active","inactive","failed"):
            svcs.append({"name": svc, "status": st, "version": "", "last_check": now})
    return svcs

def collect_active_sessions():
    """Sessions actives : combine who + ss SSH + utmp pour ne rien rater."""
    sessions = []
    now = datetime.now().isoformat()
    seen = set()

    # Source 1 : who --ips (plus fiable, inclut l'IP explicitement)
    out = run_cmd("who --ips 2>/dev/null || who")
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        user = parts[0]
        tty  = parts[1] if len(parts) > 1 else "?"
        # Chercher une IP entre parenthèses n'importe où dans la ligne
        ip_m = re.search(r"\(([\d.:a-fA-F]+)\)", line)
        ip   = ip_m.group(1) if ip_m else "local"
        # Date/heure : toujours les colonnes 2-3 (ou 2 si format court)
        login_time = " ".join(parts[2:4]) if len(parts) >= 4 else parts[2] if len(parts) >= 3 else now
        key = f"{user}:{tty}"
        if key not in seen:
            seen.add(key)
            sessions.append({"user": user, "ip": ip, "login_time": login_time, "last_check": now})

    # Source 2 : connexions SSH établies via ss
    # Local = parts[4] (ex: 0.0.0.0:22), Peer = parts[5] (ex: 1.2.3.4:54321)
    ss_out = run_cmd("ss -tnp state established 'sport = :22'")
    for line in ss_out.splitlines():
        if not line.strip() or line.startswith("Netid"):
            continue
        parts = line.split()
        # Identifier local:port et peer:port parmi les colonnes
        # Chercher la colonne qui contient :22 (local) et la suivante (peer)
        local_idx = -1
        for i, p in enumerate(parts):
            if p.endswith(":22") or ":22 " in p or p == "[::]:22" or "]:22" in p:
                local_idx = i
                break
        if local_idx < 0:
            # Fallback : local est col 4, peer col 5
            local_idx = 4
        peer_idx = local_idx + 1
        if peer_idx >= len(parts):
            continue
        peer = parts[peer_idx]
        # Extraire IP client : gère IPv4, [::ffff:x.x.x.x]:port, [::1]:port
        ip = None
        # IPv4-mapped IPv6 : [::ffff:192.168.1.1]:port
        m = re.search(r"\[::ffff:((\d{1,3}\.){3}\d{1,3})\]", peer)
        if m:
            ip = m.group(1)
        else:
            # IPv4 pure : 1.2.3.4:port
            m = re.match(r"((\d{1,3}\.){3}\d{1,3}):\d+", peer)
            if m:
                ip = m.group(1)
            else:
                # IPv6 pure : [addr]:port
                m = re.match(r"\[([^\]]+)\]:\d+", peer)
                if m:
                    ip = m.group(1)
        if not ip or ip in ("127.0.0.1", "::1"):
            continue
        # Extraire utilisateur depuis le champ process
        proc_str = " ".join(parts[peer_idx+1:]) if peer_idx+1 < len(parts) else ""
        user_m = re.search(r'users=\(\("([^"]+)"', proc_str)
        user = user_m.group(1) if user_m else "sshd"
        key = f"ssh:{ip}"
        if key not in seen:
            seen.add(key)
            sessions.append({"user": user, "ip": ip, "login_time": now, "last_check": now})

    # Source 3 : last -n 20 pour les sessions récentes (fallback si who vide)
    if not sessions:
        last_out = run_cmd("last -n 20 -F 2>/dev/null | grep -v reboot | grep still")
        for line in last_out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            user = parts[0]
            ip_m = re.search(r"([\d.]+)", parts[2]) if len(parts) > 2 else None
            ip   = ip_m.group(1) if ip_m else "local"
            key  = f"{user}:{ip}"
            if key not in seen:
                seen.add(key)
                sessions.append({"user": user, "ip": ip, "login_time": now, "last_check": now})

    return sessions

def collect_open_ports():
    """Ports en écoute via ss -tulnp avec parsing robuste toutes versions iproute2."""
    ports = []
    now  = datetime.now().isoformat()
    seen = set()

    # ss -tulnp : Netid State Recv-Q Send-Q Local-Addr:Port Peer-Addr:Port [Process]
    out = run_cmd("ss -tulnp 2>/dev/null")
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()   # tcp / udp / tcp6 / udp6
        # Local addr:port peut être en col 4 ou 5 selon iproute2 (State présent ou non)
        # On cherche le champ qui ressemble à addr:port
        local = ""
        for col in parts[3:6]:
            if re.search(r":\d+$", col) or re.search(r"\]:\d+$", col):
                local = col
                break
        if not local:
            continue
        # Extraire le port (dernier segment après ":")
        port_m = re.search(r":([\d]+)$", local)
        if not port_m:
            continue
        port = int(port_m.group(1))
        if port == 0:
            continue
        # Extraire le processus — entre guillemets dans le champ users
        proc_col = " ".join(parts[5:]) if len(parts) > 5 else ""
        pname_m = re.search(r'"([^"]+)"', proc_col)
        process = pname_m.group(1)[:40] if pname_m else "system"
        # Déduplication port+proto
        key = f"{proto}:{port}"
        if key not in seen:
            seen.add(key)
            ports.append({"port": port, "protocol": proto, "process": process, "pid": 0, "last_check": now})

    # Fallback : netstat si ss ne retourne rien
    if not ports:
        ns_out = run_cmd("netstat -tulnp 2>/dev/null")
        for line in ns_out.splitlines():
            m = re.search(r"(tcp6?|udp6?)\s+\d+\s+\d+\s+[\d.:*]+:(\d+)\s+[\d.:*]+\s+\w+\s*(\S*)", line)
            if m:
                proto = m.group(1).lower()
                port  = int(m.group(2))
                proc  = m.group(3).split("/")[-1][:40] if "/" in m.group(3) else "system"
                key   = f"{proto}:{port}"
                if key not in seen:
                    seen.add(key)
                    ports.append({"port": port, "protocol": proto, "process": proc, "pid": 0, "last_check": now})

    return sorted(ports, key=lambda x: x["port"])

def collect_web_sites():
    """Sites web : nginx (sites-enabled + conf.d) + apache + scan vhosts."""
    sites = []
    now   = datetime.now().isoformat()
    seen  = set()

    def add_site(domain, ssl, server_type, doc_root="", php=""):
        domain = domain.strip()
        if not domain or domain.startswith("_") or domain in seen:
            return
        seen.add(domain)
        sites.append({"domain": domain, "ssl_enabled": 1 if ssl else 0,
                      "server_type": server_type, "php_version": php,
                      "document_root": doc_root, "status": "active",
                      "last_check": now})

    # Nginx
    nginx_dirs = ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d",
                  "/etc/nginx/vhosts.d", "/usr/local/fastpanel2/etc/nginx"]
    for ndir in nginx_dirs:
        p = Path(ndir)
        if not p.exists():
            continue
        for conf in list(p.rglob("*.conf")) + list(p.rglob("*")):
            if not conf.is_file():
                continue
            try:
                content = conf.read_text(errors="replace")
                ssl = bool(re.search(r"ssl_certificate", content))
                root_m = re.search(r"root\s+([^;]+);", content)
                root = root_m.group(1).strip() if root_m else ""
                for sn in re.findall(r"server_name\s+([^;]+);", content):
                    for domain in sn.strip().split():
                        if domain and not domain.startswith(("_", "*", "#")):
                            add_site(domain, ssl, "nginx", root)
            except Exception:
                pass

    # Apache
    apache_dirs = ["/etc/apache2/sites-enabled", "/etc/httpd/conf.d",
                   "/etc/apache2/vhosts.d"]
    for adir in apache_dirs:
        p = Path(adir)
        if not p.exists():
            continue
        for conf in p.rglob("*.conf"):
            try:
                content = conf.read_text(errors="replace")
                ssl = bool(re.search(r"SSLEngine\s+on", content, re.IGNORECASE))
                root_m = re.search(r"DocumentRoot\s+(\S+)", content)
                root = root_m.group(1).strip() if root_m else ""
                for sn in re.findall(r"ServerName\s+(\S+)", content):
                    add_site(sn.strip(), ssl, "apache", root)
                for sa in re.findall(r"ServerAlias\s+(.+)", content):
                    for d in sa.strip().split():
                        add_site(d, ssl, "apache", root)
            except Exception:
                pass

    return sorted(sites, key=lambda x: x["domain"])

def collect_ssl_certificates():
    """Certs SSL : nginx + apache + certbot live + scan /etc/ssl — domaine réel extrait du cert."""
    certs = []
    now   = datetime.now().isoformat()
    seen_paths = set()

    def parse_cert(cert_path, hint_domain=""):
        cert_path = cert_path.strip().strip('"\'')
        if not cert_path or cert_path in seen_paths:
            return None
        if not Path(cert_path).exists():
            return None
        seen_paths.add(cert_path)
        out = run_cmd(f"openssl x509 -in {cert_path} -noout -enddate -subject -ext subjectAltName 2>/dev/null")
        if not out:
            return None
        # Date expiry
        date_m = re.search(r"notAfter=(.+)", out)
        if not date_m:
            return None
        try:
            expiry = datetime.strptime(date_m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
        except Exception:
            try:
                expiry = datetime.strptime(date_m.group(1).strip(), "%b %d %H:%M:%S %Y")
            except Exception:
                return None
        days = (expiry - datetime.now()).days
        # Domaine réel depuis CN ou SAN
        domain = hint_domain
        san_m = re.search(r"DNS:([\w.*-]+)", out)
        if san_m:
            domain = san_m.group(1)
        elif not domain:
            cn_m = re.search(r"CN\s*=\s*([\w.*-]+)", out)
            domain = cn_m.group(1) if cn_m else Path(cert_path).stem
        return {"domain": domain, "days_left": days, "cert_path": cert_path,
                "status": "expiring" if days <= 30 else ("expired" if days <= 0 else "valid"),
                "last_check": now}

    # Source 1 : configs nginx
    for conf in list(Path("/etc/nginx").rglob("*.conf")) + list(Path("/etc/nginx").rglob("*")):
        try:
            content = conf.read_text(errors="replace")
            # Extraire server_name pour le hint domaine
            sn_m = re.search(r"server_name\s+([^;]+);", content)
            hint = sn_m.group(1).strip().split()[0] if sn_m else ""
            for cp in re.findall(r"ssl_certificate\s+([^;]+);", content):
                r = parse_cert(cp, hint)
                if r: certs.append(r)
        except Exception:
            pass

    # Source 2 : configs apache
    for apache_dir in ["/etc/apache2/sites-enabled", "/etc/httpd/conf.d"]:
        for conf in Path(apache_dir).rglob("*.conf") if Path(apache_dir).exists() else []:
            try:
                content = conf.read_text(errors="replace")
                sn_m = re.search(r"ServerName\s+(\S+)", content)
                hint = sn_m.group(1) if sn_m else ""
                for cp in re.findall(r"SSLCertificateFile\s+(\S+)", content):
                    r = parse_cert(cp, hint)
                    if r: certs.append(r)
            except Exception:
                pass

    # Source 3 : certbot live (le plus fiable)
    certbot_dir = Path("/etc/letsencrypt/live")
    if certbot_dir.exists():
        for domain_dir in certbot_dir.iterdir():
            cert_file = domain_dir / "cert.pem"
            if cert_file.exists():
                r = parse_cert(str(cert_file), domain_dir.name)
                if r: certs.append(r)

    return sorted(certs, key=lambda x: x["days_left"])

def collect_failed_units():
    units = []
    out = run_cmd("systemctl --failed --no-legend --no-pager")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            units.append({"unit": parts[0], "active_state": "failed", "last_check": datetime.now().isoformat()})
    return units

def collect_fail2ban_banned():
    """IPs bannies par fail2ban — parsing robuste avec strip sur noms de jails."""
    banned = []
    now = datetime.now().isoformat()
    out = run_cmd("fail2ban-client status 2>/dev/null")
    if not out:
        return []
    # Extraire la liste des jails (peut contenir des espaces autour des virgules)
    jail_m = re.search(r"Jail list:\s*(.+)", out)
    if not jail_m:
        return []
    jails = [j.strip() for j in jail_m.group(1).split(",") if j.strip()]
    for jail in jails:
        status = run_cmd(f"fail2ban-client status {jail} 2>/dev/null")
        if not status:
            continue
        # Format : "   `- Banned IP list:  1.2.3.4  5.6.7.8"
        ips_m = re.search(r"Banned IP list:\s*(.*)", status)
        if not ips_m:
            continue
        ip_list = ips_m.group(1).strip()
        if not ip_list:
            continue
        for ip in ip_list.split():
            ip = ip.strip()
            if re.match(r"[\d.a-fA-F:]+", ip):
                banned.append({"jail": jail, "ip": ip, "banned_at": now, "last_check": now})
    return banned

def collect_tailscale_peers():
    out = run_cmd("tailscale status --json")
    if out:
        try:
            data = json.loads(out)
            peers = []
            for k, v in data.get("Peer", {}).items():
                name = v.get("DNSName", "").split(".")[0] or k[:8]
                peers.append({"name": name, "online": 1 if v.get("Online") else 0, "last_check": datetime.now().isoformat()})
            return peers
        except:
            pass
    return []

def collect_oom_events():
    """Parse les événements OOM depuis dmesg avec données réelles."""
    out = run_cmd("dmesg -T 2>/dev/null | grep -iE 'Out of memory|Kill process|oom_kill' | tail -20")
    events = []
    now = datetime.now().isoformat()
    for line in out.splitlines():
        # Extraire timestamp dmesg : [Wed Jun  5 14:32:11 2024]
        ts_match = re.search(r'\[([A-Za-z]+\s+[A-Za-z]+\s+\d+\s+[\d:]+\s+\d+)\]', line)
        ts = ts_match.group(1) if ts_match else now
        # Extraire nom du processus tué
        proc_match = re.search(r'Kill(?:ing)?\s+process\s+\d+\s+\(([^)]+)\)', line, re.IGNORECASE)
        if not proc_match:
            proc_match = re.search(r'Killed process \d+ \(([^)]+)\)', line, re.IGNORECASE)
        process = proc_match.group(1) if proc_match else "unknown"
        # Extraire mémoire utilisée
        mem_match = re.search(r'total-vm:(\d+)kB', line)
        mem_mb = round(int(mem_match.group(1)) / 1024) if mem_match else 0
        if not mem_mb:
            mem_match2 = re.search(r'anon-rss:(\d+)kB', line)
            mem_mb = round(int(mem_match2.group(1)) / 1024) if mem_match2 else 0
        events.append({
            "ts": ts,
            "killed_process": process[:80],
            "memory_used_mb": mem_mb,
            "last_check": now,
        })
    return events

def collect_docker_containers():
    out = run_cmd("docker ps -a --format '{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null")
    containers = []
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            containers.append({"name": parts[0], "status": parts[1], "image": parts[2], "last_check": datetime.now().isoformat()})
    return containers

def collect_rclone_remotes():
    remotes = []
    for conf in [Path("/root/.config/rclone/rclone.conf"), Path("/etc/rclone/rclone.conf")]:
        if conf.exists():
            try:
                config = configparser.ConfigParser()
                config.read(conf)
                for section in config.sections():
                    remotes.append({"name": section, "type": config.get(section, "type", fallback="unknown"), "last_check": datetime.now().isoformat()})
            except:
                pass
    return remotes

def collect_network_hosts():
    hosts = []
    now = datetime.now().isoformat()
    seen = set()
    neigh_out = run_cmd(["ip", "-j", "neigh"], timeout=5)
    if neigh_out:
        try:
            data = json.loads(neigh_out)
            for entry in data:
                state = entry.get("state", "")
                if isinstance(state, str) and state.lower() in ("reachable", "stale", "delay", "probe", "noarp"):
                    ip = entry.get("dst")
                    if ip and ip not in seen:
                        seen.add(ip)
                        hosts.append({"ip": ip, "mac": entry.get("lladdr", "unknown"), "interface": entry.get("dev", "unknown"), "reachable": 1 if state == "reachable" else 0, "last_seen": now})
        except:
            pass
    if not hosts:
        arp_out = run_cmd("arp -n")
        for line in arp_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2] != "incomplete":
                ip = parts[0]
                if ip not in seen:
                    seen.add(ip)
                    hosts.append({"ip": ip, "mac": parts[2], "interface": parts[4] if len(parts) > 4 else "unknown", "reachable": 1, "last_seen": now})
    return hosts

# collect_fastpanel_users() → remplacée par version complète ci-dessus


# ============================================================
# FASTPANEL2 — STATS TEMPS RÉEL (CPU/Mémoire/Disque/Réseau)
# ============================================================

def _fp_rows_to_list(rows, cols):
    """Convertit les lignes MySQL (listes) en dicts avec les colonnes données."""
    result = []
    for r in rows:
        if len(r) < len(cols):
            continue
        result.append({cols[i]: r[i] for i in range(len(cols))})
    return result


def collect_fp_server_stat(period_hours: int = 24) -> list:
    """
    Timeline CPU + Load Average + Mémoire depuis FastPanel2.
    Essaie d'abord l'API REST, puis MySQL direct.
    Granularité ~30s, réduit à 300 points max pour l'UI.
    """
    if not _fp_available():
        return []
    now_str = datetime.now().isoformat()

    # Source 1 : API REST FastPanel2 (endpoint /stat/server)
    today = datetime.now().strftime("%Y-%m-%d")
    data = _fp_api_get(f"/fastpanel/api/stat/server?date={today}")
    if data and isinstance(data, (list, dict)):
        rows = data if isinstance(data, list) else data.get("data", [])
        if rows:
            result = []
            for r in rows:
                result.append({
                    "ts":        r.get("created_at", r.get("ts", now_str)),
                    "cpu":       float(r.get("cpu", r.get("cpu_usage", 0)) or 0),
                    "la1":       float(r.get("la1", r.get("load_1", 0)) or 0),
                    "la5":       float(r.get("la5", r.get("load_5", 0)) or 0),
                    "la15":      float(r.get("la15", r.get("load_15", 0)) or 0),
                    "mem_used":  int(r.get("mem_used", r.get("memory_used", 0)) or 0),
                    "mem_total": int(r.get("mem_total", r.get("memory_total", 0)) or 0),
                    "swap_used": int(r.get("swap_used", 0) or 0),
                    "swap_total":int(r.get("swap_total", 0) or 0),
                })
            return _downsample(result, 300)

    # Source 2 : MySQL direct — essayer plusieurs noms de tables connus
    for table in ["server_stat", "stat_server", "server_stats", "fp_stat"]:
        rows = _fp_mysql_query(
            f"SELECT created_at, cpu, la1, la5, la15, "
            f"COALESCE(mem_used,0), COALESCE(mem_total,0), "
            f"COALESCE(swap_used,0), COALESCE(swap_total,0) "
            f"FROM {table} "
            f"WHERE created_at > NOW() - INTERVAL {period_hours} HOUR "
            f"ORDER BY created_at ASC LIMIT 2000"
        )
        if rows:
            cols = ["ts","cpu","la1","la5","la15","mem_used","mem_total","swap_used","swap_total"]
            result = []
            for r in rows:
                if len(r) < 5: continue
                result.append({
                    "ts":        r[0],
                    "cpu":       float(r[1] or 0),
                    "la1":       float(r[2] or 0),
                    "la5":       float(r[3] or 0),
                    "la15":      float(r[4] or 0),
                    "mem_used":  int(r[5] or 0) if len(r) > 5 else 0,
                    "mem_total": int(r[6] or 0) if len(r) > 6 else 0,
                    "swap_used": int(r[7] or 0) if len(r) > 7 else 0,
                    "swap_total":int(r[8] or 0) if len(r) > 8 else 0,
                })
            return _downsample(result, 300)

    return []


def collect_fp_process_stat(period_hours: int = 1) -> list:
    """
    Top processus par CPU depuis FastPanel2.
    Retourne les N dernières minutes agrégées (moyenne CPU par processus).
    """
    if not _fp_available():
        return []

    # API REST
    today = datetime.now().strftime("%Y-%m-%d")
    data = _fp_api_get(f"/fastpanel/api/stat/process?date={today}")
    if data and isinstance(data, (list, dict)):
        rows = data if isinstance(data, list) else data.get("data", [])
        if rows:
            # Agréger par nom de processus
            agg = {}
            for r in rows:
                name = r.get("name", r.get("process_name", "?"))
                cpu  = float(r.get("cpu", r.get("cpu_usage", 0)) or 0)
                if name not in agg:
                    agg[name] = {"name": name, "cpu_samples": [], "mem": 0}
                agg[name]["cpu_samples"].append(cpu)
                agg[name]["mem"] = max(agg[name]["mem"], int(r.get("mem", 0) or 0))
            result = [{
                "name":    v["name"],
                "avg_cpu": round(sum(v["cpu_samples"]) / len(v["cpu_samples"]), 2),
                "max_cpu": round(max(v["cpu_samples"]), 2),
                "mem_mb":  round(v["mem"] / 1024 / 1024, 1),
            } for v in agg.values()]
            return sorted(result, key=lambda x: x["avg_cpu"], reverse=True)[:12]

    # MySQL
    for table in ["process_stat", "stat_process", "process_stats"]:
        rows = _fp_mysql_query(
            f"SELECT name, AVG(cpu) as avg_cpu, MAX(cpu) as max_cpu, MAX(mem) as mem "
            f"FROM {table} "
            f"WHERE created_at > NOW() - INTERVAL {period_hours} HOUR "
            f"GROUP BY name ORDER BY avg_cpu DESC LIMIT 12"
        )
        if rows:
            return [{
                "name":    r[0],
                "avg_cpu": round(float(r[1] or 0), 2),
                "max_cpu": round(float(r[2] or 0), 2),
                "mem_mb":  round(int(r[3] or 0) / 1024 / 1024, 1),
            } for r in rows if len(r) >= 3]

    return []


def collect_fp_disk_stat(period_hours: int = 24) -> list:
    """Timeline I/O disque depuis FastPanel2."""
    if not _fp_available():
        return []

    today = datetime.now().strftime("%Y-%m-%d")
    data = _fp_api_get(f"/fastpanel/api/stat/disk?date={today}")
    if data and isinstance(data, (list, dict)):
        rows = data if isinstance(data, list) else data.get("data", [])
        if rows:
            result = [{
                "ts":          r.get("created_at", r.get("ts", "")),
                "device":      r.get("device", "sda"),
                "read_bytes":  int(r.get("read_bytes", r.get("rbytes", 0)) or 0),
                "write_bytes": int(r.get("write_bytes", r.get("wbytes", 0)) or 0),
                "read_iops":   int(r.get("read_iops", r.get("riops", 0)) or 0),
                "write_iops":  int(r.get("write_iops", r.get("wiops", 0)) or 0),
            } for r in rows]
            return _downsample(result, 300)

    for table in ["disk_stat", "stat_disk", "disk_stats"]:
        rows = _fp_mysql_query(
            f"SELECT created_at, COALESCE(device,'sda'), "
            f"read_bytes, write_bytes, "
            f"COALESCE(read_iops,0), COALESCE(write_iops,0) "
            f"FROM {table} "
            f"WHERE created_at > NOW() - INTERVAL {period_hours} HOUR "
            f"ORDER BY created_at ASC LIMIT 2000"
        )
        if rows:
            result = [{
                "ts": r[0], "device": r[1],
                "read_bytes":  int(r[2] or 0),
                "write_bytes": int(r[3] or 0),
                "read_iops":   int(r[4] or 0),
                "write_iops":  int(r[5] or 0),
            } for r in rows if len(r) >= 4]
            return _downsample(result, 300)

    return []


def collect_fp_net_stat(period_hours: int = 24) -> list:
    """Timeline trafic réseau depuis FastPanel2."""
    if not _fp_available():
        return []

    today = datetime.now().strftime("%Y-%m-%d")
    data = _fp_api_get(f"/fastpanel/api/stat/network?date={today}")
    if data and isinstance(data, (list, dict)):
        rows = data if isinstance(data, list) else data.get("data", [])
        if rows:
            result = [{
                "ts":         r.get("created_at", ""),
                "interface":  r.get("interface", r.get("iface", "eth0")),
                "rx_bytes":   int(r.get("rx_bytes", r.get("in_bytes", 0)) or 0),
                "tx_bytes":   int(r.get("tx_bytes", r.get("out_bytes", 0)) or 0),
                "rx_packets": int(r.get("rx_packets", 0) or 0),
                "tx_packets": int(r.get("tx_packets", 0) or 0),
            } for r in rows]
            return _downsample(result, 300)

    for table in ["net_stat", "network_stat", "stat_network", "net_stats"]:
        rows = _fp_mysql_query(
            f"SELECT created_at, COALESCE(interface,'eth0'), "
            f"rx_bytes, tx_bytes, "
            f"COALESCE(rx_packets,0), COALESCE(tx_packets,0) "
            f"FROM {table} "
            f"WHERE created_at > NOW() - INTERVAL {period_hours} HOUR "
            f"ORDER BY created_at ASC LIMIT 2000"
        )
        if rows:
            result = [{
                "ts": r[0], "interface": r[1],
                "rx_bytes":   int(r[2] or 0),
                "tx_bytes":   int(r[3] or 0),
                "rx_packets": int(r[4] or 0),
                "tx_packets": int(r[5] or 0),
            } for r in rows if len(r) >= 4]
            return _downsample(result, 300)

    return []


def _downsample(data: list, max_points: int) -> list:
    """Réduit une série temporelle à max_points en gardant le début et la fin."""
    if len(data) <= max_points:
        return data
    step = len(data) / max_points
    return [data[int(i * step)] for i in range(max_points)]


def save_fp_stats(server: list, processes: list, disk: list, net: list):
    """Sauvegarde les stats FastPanel dans SQLite (rétention 2 jours)."""
    conn = get_conn()
    try:
        # Purger les données anciennes (> 48h)
        for table in ["fp_server_stat", "fp_process_stat", "fp_disk_stat", "fp_net_stat"]:
            conn.execute(f"DELETE FROM {table} WHERE ts < datetime('now', '-2 days')")
        # Insérer nouvelles données (on remplace tout pour les stats FP)
        if server:
            conn.execute("DELETE FROM fp_server_stat")
            for r in server:
                conn.execute(
                    "INSERT INTO fp_server_stat (ts,cpu,la1,la5,la15,mem_used,mem_total,swap_used,swap_total) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (r["ts"], r["cpu"], r["la1"], r["la5"], r["la15"],
                     r["mem_used"], r["mem_total"], r["swap_used"], r["swap_total"])
                )
        if processes:
            conn.execute("DELETE FROM fp_process_stat")
            for r in processes:
                conn.execute(
                    "INSERT INTO fp_process_stat (ts,name,cpu,mem) VALUES (?,?,?,?)",
                    (datetime.now().isoformat(), r["name"], r["avg_cpu"],
                     int(r.get("mem_mb", 0) * 1024 * 1024))
                )
        if disk:
            conn.execute("DELETE FROM fp_disk_stat")
            for r in disk:
                conn.execute(
                    "INSERT INTO fp_disk_stat (ts,device,read_bytes,write_bytes,read_iops,write_iops) "
                    "VALUES (?,?,?,?,?,?)",
                    (r["ts"], r["device"], r["read_bytes"], r["write_bytes"],
                     r["read_iops"], r["write_iops"])
                )
        if net:
            conn.execute("DELETE FROM fp_net_stat")
            for r in net:
                conn.execute(
                    "INSERT INTO fp_net_stat (ts,interface,rx_bytes,tx_bytes,rx_packets,tx_packets) "
                    "VALUES (?,?,?,?,?,?)",
                    (r["ts"], r["interface"], r["rx_bytes"], r["tx_bytes"],
                     r["rx_packets"], r["tx_packets"])
                )
        conn.commit()
    except Exception as e:
        print(f"[FP] save_fp_stats error: {e}", file=sys.stderr)
    finally:
        conn.close()



# collect_fastpanel_domains() → remplacée par version complète ci-dessus

# collect_fastpanel_php_versions() → remplacée par version complète ci-dessus

def collect_phpfpm_pools():
    pools = []
    now = datetime.now().isoformat()
    for pool_conf in Path("/etc/php").glob("*/fpm/pool.d/*.conf"):
        try:
            content = pool_conf.read_text(errors="replace")
            listen = re.search(r'^listen\s*=\s*(.+)$', content, re.MULTILINE)
            if listen:
                pools.append({"pool": pool_conf.stem, "socket": listen.group(1).strip(), "active_processes": 0, "idle_processes": 0, "last_check": now})
        except:
            pass
    return pools

def collect_sysctl_security():
    results = []
    now = datetime.now().isoformat()
    for param, info in SECURITY_SYSCTL.items():
        out = run_cmd(f"sysctl -n {param}")
        value = out.strip() if out else "unknown"
        status = "ok"
        if value == "unknown":
            status = "warning"
        elif info["recommended"] and value != info["recommended"]:
            status = "critical" if info.get("critical") and value == info["critical"] else "warning"
        results.append({"param": param, "value": value, "recommended": info["recommended"], "status": status, "description": info["description"], "last_check": now})
    return results

def collect_disk_smart():
    smart_data = []
    now = datetime.now().isoformat()
    lsblk_out = run_cmd("lsblk -d -n -o NAME,TYPE")
    for line in lsblk_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "disk":
            dev = f"/dev/{parts[0]}"
            out = run_cmd(f"smartctl -H {dev}")
            health = "PASSED" if "PASSED" in out else "FAILED" if "FAILED" in out else "unknown"
            smart_data.append({"device": dev, "health": health, "reallocated_sectors": 0, "pending_sectors": 0, "last_check": now})
    return smart_data

def collect_redis_stats():
    out = run_cmd("redis-cli INFO stats")
    if out:
        hits = re.search(r'keyspace_hits:(\d+)', out)
        misses = re.search(r'keyspace_misses:(\d+)', out)
        if hits and misses:
            total = int(hits.group(1)) + int(misses.group(1))
            hit_rate = round(100.0 * int(hits.group(1)) / total, 1) if total > 0 else 0
            return {"ts": datetime.now().isoformat(), "hit_rate": hit_rate, "total_keys": 0, "last_check": datetime.now().isoformat()}
    return None

def collect_dns_servers():
    servers = []
    now = datetime.now().isoformat()
    if Path("/etc/bind/named.conf").exists():
        out = run_cmd("named -v")
        version = re.search(r'BIND ([\d.]+)', out)
        servers.append({"server_type": "bind", "version": version.group(1) if version else "unknown", "running": 1 if "active" in run_cmd("systemctl is-active bind9") else 0, "last_check": now})
    if Path("/etc/powerdns/pdns.conf").exists():
        servers.append({"server_type": "powerdns", "version": "unknown", "running": 1 if "active" in run_cmd("systemctl is-active pdns") else 0, "last_check": now})
    return servers, []

def collect_backup_runs():
    """Détecte les remotes rclone et leur dernier état de backup connu."""
    runs = []
    now = datetime.now().isoformat()
    conf_candidates = [
        Path("/root/.config/rclone/rclone.conf"),
        Path("/etc/rclone/rclone.conf"),
        Path("/home/rclone/.config/rclone/rclone.conf"),
    ]
    for conf in conf_candidates:
        if not conf.exists():
            continue
        try:
            config = configparser.ConfigParser()
            config.read(conf)
            for section in config.sections():
                # Chercher un log récent pour ce remote
                log_status = "unknown"
                log_path = Path(f"/var/log/rclone/{section}.log")
                if log_path.exists():
                    last_line = run_cmd(f"tail -1 {log_path}")
                    if "Transferred" in last_line:
                        log_status = "success"
                    elif "ERROR" in last_line:
                        log_status = "error"
                runs.append({
                    "remote": section,
                    "ts": now,
                    "status": log_status,
                    "size_gb": 0,
                    "files_count": 0,
                    "last_check": now,
                })
        except Exception:
            pass
    return runs

def collect_vpn_connections():
    vpns = []
    now = datetime.now().isoformat()
    out = run_cmd("wg show")
    if out:
        vpns.append({"type": "wireguard", "name": "wg0", "status": "active", "last_check": now})
    ts_out = run_cmd("tailscale status --json")
    if ts_out:
        try:
            data = json.loads(ts_out)
            self_data = data.get("Self", {})
            vpns.append({"type": "tailscale", "name": self_data.get("DNSName", "").split(".")[0], "status": "connected", "last_check": now})
        except:
            pass
    return vpns

def collect_cron_jobs():
    """Tous les crons : root crontab + /etc/cron.d + /etc/crontab + users."""
    jobs = []
    now  = datetime.now().isoformat()

    def parse_cron_lines(text, user="root"):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            # /etc/crontab et /etc/cron.d ont 6 champs (champ user en plus)
            if len(parts) >= 7 and re.match(r"[a-zA-Z_][a-zA-Z0-9_-]*$", parts[5]):
                jobs.append({"user": parts[5], "schedule": " ".join(parts[:5]),
                             "command": " ".join(parts[6:])[:200], "last_check": now})
            elif len(parts) >= 6:
                jobs.append({"user": user, "schedule": " ".join(parts[:5]),
                             "command": " ".join(parts[5:])[:200], "last_check": now})

    # root crontab
    out = run_cmd("crontab -l 2>/dev/null")
    if out and "no crontab" not in out.lower():
        parse_cron_lines(out, "root")

    # /etc/crontab
    if Path("/etc/crontab").exists():
        try:
            parse_cron_lines(Path("/etc/crontab").read_text(errors="replace"), "system")
        except Exception:
            pass

    # /etc/cron.d/*
    cron_d = Path("/etc/cron.d")
    if cron_d.exists():
        for f in cron_d.iterdir():
            if f.is_file() and not f.name.startswith("."):
                try:
                    parse_cron_lines(f.read_text(errors="replace"), f.name)
                except Exception:
                    pass

    # Crontabs des autres utilisateurs via /var/spool/cron/crontabs/
    spool = Path("/var/spool/cron/crontabs")
    if spool.exists():
        for f in spool.iterdir():
            if f.is_file():
                try:
                    parse_cron_lines(f.read_text(errors="replace"), f.name)
                except Exception:
                    pass

    return jobs

def collect_ssh_authorized_keys():
    """Clés SSH autorisées pour tous les utilisateurs du système."""
    keys = []
    now  = datetime.now().isoformat()
    seen = set()

    # Construire la liste des homes depuis /etc/passwd
    home_users = []
    try:
        for line in Path("/etc/passwd").read_text().splitlines():
            parts = line.split(":")
            if len(parts) >= 6:
                user, uid, home = parts[0], int(parts[2]), parts[5]
                # Inclure root et les vrais utilisateurs (uid >= 1000 ou root)
                if uid == 0 or uid >= 1000:
                    home_users.append((user, Path(home)))
    except Exception:
        home_users = [("root", Path("/root"))]

    for user, home in home_users:
        auth_file = home / ".ssh" / "authorized_keys"
        if not auth_file.exists():
            continue
        try:
            for line in auth_file.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                key_type = parts[0]
                key_data = parts[1]
                comment  = parts[2] if len(parts) > 2 else ""
                key_hash = hashlib.md5(key_data.encode()).hexdigest()[:16]
                uid_key  = f"{user}:{key_hash}"
                if uid_key not in seen:
                    seen.add(uid_key)
                    keys.append({"user": user, "key_type": key_type,
                                 "key_hash": key_hash, "comment": comment,
                                 "last_check": now})
        except Exception:
            pass

    return keys

def collect_firewall_rules():
    rules = []
    now = datetime.now().isoformat()
    out = run_cmd("iptables -L -n")
    for line in out.splitlines():
        if "ACCEPT" in line or "DROP" in line or "REJECT" in line:
            rules.append({"tool": "iptables", "action": "ALLOW" if "ACCEPT" in line else "DENY", "raw": line[:200], "last_check": now})
    return rules

def get_swap():
    """Lit le swap réel depuis /proc/meminfo."""
    try:
        with open("/proc/meminfo") as f:
            mi = {}
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        total = mi.get("SwapTotal", 0)
        free  = mi.get("SwapFree", 0)
        used  = total - free
        pct   = round(100.0 * used / total, 1) if total > 0 else 0.0
        return {"percent": pct, "total_gb": round(total / 1024**2, 1),
                "used_gb": round(used / 1024**2, 1), "free_gb": round(free / 1024**2, 1)}
    except Exception:
        return {"percent": 0.0, "total_gb": 0.0, "used_gb": 0.0, "free_gb": 0.0}


def collect_metrics():
    cpu  = get_cpu()
    ram  = get_ram()
    disk = get_disk()
    swap = get_swap()
    l1, l5, l15 = get_load()
    return {
        "ts": datetime.now().isoformat(),
        "cpu_pct":  cpu,
        "ram_pct":  ram["percent"],
        "disk_pct": disk["percent"],
        "swap_pct": swap["percent"],          # réel désormais
        "ram_total_gb":  ram["total_gb"],  "ram_used_gb":  ram["used_gb"],
        "disk_total_gb": disk["total_gb"], "disk_used_gb": disk["used_gb"],
        "disk_free_gb":  disk["total_gb"] - disk["used_gb"],
        "swap_total_gb": swap["total_gb"], "swap_used_gb": swap["used_gb"],
        "load_1m": l1, "load_5m": l5, "load_15m": l15,
        "top_processes": get_top_processes(), "services": {}, "alerts": []
    }

def save_metrics(m):
    conn = get_conn()
    conn.execute("""INSERT INTO metrics_realtime 
        (ts, cpu_pct, ram_pct, disk_pct, swap_pct, ram_total_gb, ram_used_gb, disk_total_gb, disk_used_gb, disk_free_gb, load_1m, load_5m, load_15m, top_processes, services, alerts)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (m["ts"], m["cpu_pct"], m["ram_pct"], m["disk_pct"], m["swap_pct"],
         m["ram_total_gb"], m["ram_used_gb"], m["disk_total_gb"], m["disk_used_gb"], m["disk_free_gb"],
         m["load_1m"], m["load_5m"], m["load_15m"],
         json.dumps(m["top_processes"]), "{}", "[]"))
    conn.execute("DELETE FROM metrics_realtime WHERE id NOT IN (SELECT id FROM metrics_realtime ORDER BY id DESC LIMIT 2880)")
    conn.commit()
    conn.close()

def save_volatile(table, rows):
    if not rows:
        return
    conn = get_conn()
    conn.execute(f"DELETE FROM {table}")
    cols = list(rows[0].keys())
    place = ",".join(["?" for _ in cols])
    for r in rows:
        try:
            conn.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({place})", [r.get(c) for c in cols])
        except:
            pass
    conn.commit()
    conn.close()

def save_many(table, rows):
    if not rows:
        return
    conn = get_conn()
    conn.execute(f"DELETE FROM {table}")
    cols = list(rows[0].keys())
    place = ",".join(["?" for _ in cols])
    for r in rows:
        try:
            conn.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({place})", [r.get(c) for c in cols])
        except:
            pass
    conn.commit()
    conn.close()

def compute_health_score(metrics, ssl_certs, services, fail2ban, smart, sysctl, dns, oom_count, failed_count):
    score = 100
    if metrics.get("cpu_pct", 0) > 85: score -= 15
    if metrics.get("ram_pct", 0) > 85: score -= 15
    if metrics.get("disk_pct", 0) > 85: score -= 15
    score -= min(len(ssl_certs) * 2, 15)
    score -= min(oom_count * 5, 15)
    score -= min(failed_count * 2, 10)
    score = max(0, min(100, score))
    status = "critical" if score < 50 else "warning" if score < 75 else "good" if score < 90 else "excellent"
    return {"score": score, "status": status, "alerts_count": len(ssl_certs) + oom_count + failed_count}

def save_health_score(score_data):
    conn = get_conn()
    conn.execute("INSERT INTO health_scores (ts, score, breakdown, alerts_count, status) VALUES (?,?,?,?,?)",
                 (datetime.now().isoformat(), score_data["score"], "{}", score_data.get("alerts_count", 0), score_data["status"]))
    conn.execute("DELETE FROM health_scores WHERE id NOT IN (SELECT id FROM health_scores ORDER BY id DESC LIMIT 2880)")
    conn.commit()
    conn.close()

def record_change(entity_type, entity_name, change_type, new_val=None, severity="info"):
    conn = get_conn()
    conn.execute("INSERT INTO changelog (ts, entity_type, entity_name, change_type, new_value, severity) VALUES (?,?,?,?,?,?)",
                 (datetime.now().isoformat(), entity_type, entity_name, change_type, new_val, severity))
    conn.commit()
    conn.close()

def detect_diff(entity_type, current_names):
    # Version simplifiée
    pass

# ============================================================
# SOCKET SERVER
# ============================================================
def cleanup_socket():
    try:
        if Path(SOCKET_PATH).exists():
            Path(SOCKET_PATH).unlink()
    except:
        pass

atexit.register(cleanup_socket)

class SharedMemorySocket:
    def __init__(self):
        self.running = True
        self.sock = None
        self.cache = {}
        self.cache_time = 0
        self._cache_lock = threading.Lock()

    def update_cache(self):
        try:
            conn = get_conn()
            with self._cache_lock:
                self.cache = {
                    "timestamp": datetime.now().isoformat(),
                    "version": "5.8",
                    "sites": conn.execute("SELECT COUNT(*) FROM web_sites").fetchone()[0],
                    "ssl_expiring": conn.execute("SELECT COUNT(*) FROM ssl_certificates WHERE days_left <= 30").fetchone()[0],
                    "fail2ban_banned": conn.execute("SELECT COUNT(*) FROM fail2ban_banned_ips").fetchone()[0],
                    "tailscale_peers": conn.execute("SELECT COUNT(*) FROM tailscale_peers WHERE online=1").fetchone()[0],
                    "failed_units": conn.execute("SELECT COUNT(*) FROM failed_units").fetchone()[0],
                    "oom_events_24h": conn.execute("SELECT COUNT(*) FROM oom_events WHERE ts > datetime('now', '-24 hours')").fetchone()[0],
                }
            conn.close()
        except Exception as e:
            print(f"[CACHE] Erreur: {e}")

    def handle_client(self, client):
        try:
            data = client.recv(4096).decode().strip()
            if not data:
                return
            
            if data == "PING":
                client.send(b"PONG")
            elif data == "GET_METRICS":
                _cpu  = get_cpu()
                _ram  = get_ram()
                _disk = get_disk()
                _swap = get_swap()
                _l1, _l5, _l15 = get_load()
                client.send(json.dumps({
                    "cpu":  _cpu,
                    "ram":  _ram["percent"],
                    "disk": _disk["percent"],
                    "swap": _swap["percent"],
                    "load_1m":  _l1, "load_5m":  _l5, "load_15m": _l15,
                    "ram_total_gb":  _ram["total_gb"],  "ram_used_gb":  _ram["used_gb"],
                    "disk_total_gb": _disk["total_gb"], "disk_used_gb": _disk["used_gb"],
                    "disk_free_gb":  _disk["total_gb"] - _disk["used_gb"],
                    "swap_total_gb": _swap["total_gb"], "swap_used_gb": _swap["used_gb"],
                    "top_processes": get_top_processes(),
                    "timestamp": time.time(),
                }).encode())
            elif data == "GET_DASHBOARD":
                self.update_cache()
                with self._cache_lock:
                    client.send(json.dumps(self.cache).encode())
            elif data.startswith("GET_ENTITY:"):
                entity = data.split(":", 1)[1]
                if entity in SOCKET_ALLOWED_ENTITIES:
                    try:
                        conn = get_conn()
                        rows = conn.execute(f"SELECT * FROM {entity} LIMIT 100").fetchall()
                        conn.close()
                        client.send(json.dumps([dict(r) for r in rows]).encode())
                    except:
                        client.send(b"[]")
                else:
                    client.send(b"[]")
            else:
                client.send(b"ERROR")
        except Exception as e:
            print(f"[SOCKET] Erreur: {e}")
        finally:
            try:
                client.close()
            except:
                pass

    def start(self):
        cleanup_socket()
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(SOCKET_PATH)
            self.sock.listen(10)
            self.sock.settimeout(1.0)
            os.chmod(SOCKET_PATH, 0o666)
            print(f"[SOCKET] Démarré sur {SOCKET_PATH}")
            
            while self.running:
                try:
                    client, _ = self.sock.accept()
                    t = threading.Thread(target=self.handle_client, args=(client,), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[SOCKET] Erreur: {e}")
        except Exception as e:
            print(f"[SOCKET] Erreur démarrage: {e}")
            self.running = False

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        cleanup_socket()

# ============================================================
# COLLECTEUR PRINCIPAL
# ============================================================
class KnowledgeCollector:
    def __init__(self):
        self.running = True
        self.last_metrics = 0
        self.last_quick = 0
        self.last_full = 0
        self._last_ssl = []
        self._last_services = {}
        self._last_smart = []
        self._last_sysctl = []
        self._last_dns_servers = []

    def run(self):
        init_all_tables()
        print("[COLLECTOR] Démarré — v5.8 COLLECTEURS FIABLES")
        
        socket_server = SharedMemorySocket()
        socket_thread = threading.Thread(target=socket_server.start, daemon=True)
        socket_thread.start()
        time.sleep(1)
        
        print("[COLLECTOR] Collecte initiale...")
        save_metrics(collect_metrics())
        save_volatile("active_sessions", collect_active_sessions())
        save_volatile("open_ports", collect_open_ports())
        save_many("web_sites", collect_web_sites())
        save_many("ssl_certificates", collect_ssl_certificates())
        save_many("failed_units", collect_failed_units())
        save_many("fail2ban_banned_ips", collect_fail2ban_banned())
        save_many("tailscale_peers", collect_tailscale_peers())
        save_many("oom_events", collect_oom_events())
        save_many("docker_containers", collect_docker_containers())
        save_many("rclone_remotes", collect_rclone_remotes())
        save_many("fastpanel_users", collect_fastpanel_users())
        save_many("fastpanel_domains", collect_fastpanel_domains())
        save_many("fastpanel_php_versions", collect_fastpanel_php_versions())
        save_many("fastpanel_databases", collect_fastpanel_databases())
        save_many("fastpanel_mail_accounts", collect_fastpanel_mail())
        save_many("fastpanel_ftp_accounts", collect_fastpanel_ftp())
        save_many("fastpanel_backups", collect_fastpanel_backups())
        save_many("fastpanel_dns_records", collect_fastpanel_dns())
        save_many("fastpanel_crons", collect_fastpanel_crons())
        save_many("fastpanel_services", collect_fastpanel_services())
        if _fp_available():
            _fp_srv  = collect_fp_server_stat(24)
            _fp_proc = collect_fp_process_stat(1)
            _fp_disk = collect_fp_disk_stat(24)
            _fp_net  = collect_fp_net_stat(24)
            save_fp_stats(_fp_srv, _fp_proc, _fp_disk, _fp_net)
        save_many("phpfpm_pools", collect_phpfpm_pools())
        save_many("sysctl_security", collect_sysctl_security())
        save_many("disk_smart", collect_disk_smart())
        save_many("vpn_connections", collect_vpn_connections())
        save_many("cron_jobs", collect_cron_jobs())
        save_many("ssh_authorized_keys", collect_ssh_authorized_keys())
        save_many("firewall_rules", collect_firewall_rules())
        save_volatile("network_hosts", collect_network_hosts())
        
        dns_servers, _ = collect_dns_servers()
        save_many("dns_servers", dns_servers)
        
        redis = collect_redis_stats()
        if redis:
            save_many("redis_stats", [redis])
        
        backups = collect_backup_runs()
        save_many("backup_runs", backups)
        
        # Réutiliser les données déjà collectées — pas de double appel coûteux
        _init_m    = collect_metrics()
        _init_ssl  = collect_ssl_certificates()
        _init_oom  = collect_oom_events()
        _init_fail = collect_failed_units()
        health = compute_health_score(_init_m, _init_ssl, {}, [], [], [], [],
                                      len(_init_oom), len(_init_fail))
        save_health_score(health)
        
        print(f"[COLLECTOR] ✅ PRÊT - Socket: {SOCKET_PATH}")
        
        try:
            while self.running:
                now = time.time()
                
                if now - self.last_metrics >= 5:
                    save_metrics(collect_metrics())
                    self.last_metrics = now
                
                if now - self.last_quick >= 30:
                    save_volatile("active_sessions", collect_active_sessions())
                    save_volatile("open_ports", collect_open_ports())
                    save_volatile("network_hosts", collect_network_hosts())
                    save_many("fail2ban_banned_ips", collect_fail2ban_banned())
                    save_many("tailscale_peers", collect_tailscale_peers())
                    self.last_quick = now
                
                if now - self.last_full >= 300:
                    save_many("web_sites", collect_web_sites())
                    save_many("ssl_certificates", collect_ssl_certificates())
                    save_many("failed_units", collect_failed_units())
                    save_many("oom_events", collect_oom_events())
                    save_many("docker_containers", collect_docker_containers())
                    save_many("rclone_remotes", collect_rclone_remotes())
                    save_many("fastpanel_domains", collect_fastpanel_domains())
                    save_many("fastpanel_databases", collect_fastpanel_databases())
                    save_many("fastpanel_mail_accounts", collect_fastpanel_mail())
                    save_many("fastpanel_backups", collect_fastpanel_backups())
                    save_many("fastpanel_services", collect_fastpanel_services())
                    # Stats timeline FastPanel2
                    if _fp_available():
                        _fp_srv  = collect_fp_server_stat(24)
                        _fp_proc = collect_fp_process_stat(1)
                        _fp_disk = collect_fp_disk_stat(24)
                        _fp_net  = collect_fp_net_stat(24)
                        save_fp_stats(_fp_srv, _fp_proc, _fp_disk, _fp_net)
                    save_many("phpfpm_pools", collect_phpfpm_pools())
                    save_many("sysctl_security", collect_sysctl_security())
                    save_many("disk_smart", collect_disk_smart())
                    self._last_ssl   = collect_ssl_certificates()
                    self._last_smart = collect_disk_smart()
                    _oom_now  = collect_oom_events()
                    _fail_now = collect_failed_units()
                    _met_now  = collect_metrics()
                    health = compute_health_score(
                        _met_now, self._last_ssl, {}, [],
                        self._last_smart, self._last_sysctl, self._last_dns_servers,
                        len(_oom_now), len(_fail_now)
                    )
                    save_health_score(health)
                    self.last_full = now
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n[COLLECTOR] Arrêt demandé")
        finally:
            socket_server.stop()
            print("[COLLECTOR] Arrêté")

# ============================================================
# DÉMARRAGE
# ============================================================
if __name__ == "__main__":
    print("=" * 70)
    print("CASSANDRA — Knowledge Collector v5.7 (BUGFIXES)")
    print(f"DB: {DB_PATH}")
    print(f"SOCKET: {SOCKET_PATH}")
    print("=" * 70)
    print("Fonctionnalités incluses:")
    print("  ✅ FastPanel (users, domains, PHP versions)")
    print("  ✅ Network hosts (ip neigh JSON + arp)")
    print("  ✅ PHP-FPM pools")
    print("  ✅ DNS servers (bind, powerdns, unbound, knot, nsd, dnsmasq)")
    print("  ✅ Sysctl sécurité (10 paramètres critiques)")
    print("  ✅ SMART disques")
    print("  ✅ Redis stats")
    print("  ✅ NFS exports/mounts")
    print("  ✅ Rclone remotes/mounts")
    print("  ✅ VPN (WireGuard, OpenVPN, Tailscale)")
    print("  ✅ SSH authorized keys")
    print("  ✅ Cron jobs")
    print("  ✅ Fail2ban")
    print("  ✅ OOM killer")
    print("  ✅ Docker containers")
    print("=" * 70)
    
    collector = KnowledgeCollector()
    try:
        collector.run()
    except Exception as e:
        print(f"[COLLECTOR] Erreur fatale: {e}")
        sys.exit(1)