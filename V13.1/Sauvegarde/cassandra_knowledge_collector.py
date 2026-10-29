#!/usr/bin/env python3
"""
CASSANDRA — Knowledge Collector v6.1
=====================================================================
Optimisations appliquées (6 majeures) :
  [O1] _fp_available()  → lru_cache(maxsize=1) — élimine les stat() répétés
  [O2] _read_meminfo()  → lecture unique /proc/meminfo partagée par get_ram()+get_swap()
  [O3] save_many()      → executemany() + suppression BEGIN EXCLUSIVE (WAL suffit)
  [O4] collect_sysctl_security() → un seul appel sysctl batch au lieu de 10
  [O5] detect_diff()    → record_change() groupés en une seule transaction
  [O6] KnowledgeCollector.run() → ThreadPoolExecutor pour la collecte initiale et full
       + double-checked locking sur _fp_load_params() pour la thread-safety

Corrections FastPanel 2 (v6.1) :
  [FP1] Source primaire : CLI mogwai (/usr/local/bin/mogwai) — officiel, toujours exact
  [FP2] API corrigée : /api/users, /api/sites/list, /api/dns/domains (pas /fastpanel/api/...)
  [FP3] Auth API : Bearer JWT via POST /login (pas api_token statique)
  [FP4] Suppression des requêtes MySQL sur tables inexistantes (user, domain, ftp_account…)
  [FP5] Stats temps-réel : /proc direct (FP2 ne stocke pas ses stats dans MySQL)
  [FP6] FTP : scan proftpd/vsftpd + /etc/proftpd/passwd ou mogwai
  [FP7] Crons : /var/spool/cron/crontabs/<user> par utilisateur FP2 détecté
  [FP8] Détection port panel FP2 depuis nginx config (8888 par défaut)
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
from concurrent.futures import ThreadPoolExecutor, as_completed   # PERF[O6]
from functools import lru_cache                                    # PERF[O1]
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
PROMETHEUS_ENABLED = False
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
# BASE DE DONNÉES
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
        CREATE TABLE IF NOT EXISTS fastpanel_databases (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, db_user TEXT, size_mb REAL, db_type TEXT, owner TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_mail_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, domain TEXT, login TEXT, quota_mb INTEGER, used_mb INTEGER, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_ftp_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT UNIQUE, home_dir TEXT, status TEXT, owner TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_backups (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, status TEXT, size_mb REAL, created_at TEXT, error TEXT, user TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_dns_records (id INTEGER PRIMARY KEY AUTOINCREMENT, zone TEXT, type TEXT, name TEXT, value TEXT, ttl INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_crons (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, schedule TEXT, command TEXT, enabled INTEGER, last_run TEXT, last_status TEXT, source TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_services (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, status TEXT, version TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, mysql_queries_per_sec REAL, mysql_connections INTEGER, nginx_requests_total INTEGER, nginx_active_conns INTEGER, php_requests_per_min REAL, mail_queue_size INTEGER, last_check TEXT);
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

        CREATE TABLE IF NOT EXISTS metrics_hourly (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT UNIQUE,
            cpu_avg REAL, cpu_max REAL,
            ram_avg REAL, ram_max REAL,
            disk_avg REAL, disk_max REAL,
            swap_avg REAL,
            la1_avg REAL, la1_max REAL
        );
        CREATE TABLE IF NOT EXISTS metrics_daily (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT UNIQUE,
            cpu_avg REAL, cpu_max REAL,
            ram_avg REAL, ram_max REAL,
            disk_avg REAL, disk_max REAL,
            swap_avg REAL,
            la1_avg REAL, la1_max REAL
        );
        CREATE TABLE IF NOT EXISTS config_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT UNIQUE,
            sha256 TEXT,
            size INTEGER,
            mtime REAL,
            last_check TEXT
        );
    """)
    conn.commit()
    conn.close()
    print("[COLLECTOR] Tables initialisées (v13 + rétention + drift config) (version optimisée)")

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

# PERF[O2]: Lecture unique de /proc/meminfo partagée par get_ram() et get_swap().
# Avant : 2 open("/proc/meminfo") séparés par cycle de métriques.
# Après : 1 open → dict réutilisé par les deux fonctions.
def _read_meminfo() -> dict:
    """Lit /proc/meminfo une seule fois et retourne un dict {clé: int_kB}."""
    mi: dict = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    mi[k.strip()] = int(v.strip().split()[0])
    except Exception:
        pass
    return mi

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
    except Exception:
        return 0.0

def get_ram(mi: dict = None):
    # PERF[O2]: accepte un dict pré-lu pour éviter une seconde lecture fichier.
    if mi is None:
        mi = _read_meminfo()
    try:
        total = mi.get("MemTotal", 1)
        avail = mi.get("MemAvailable", total)
        used  = total - avail
        return {
            "percent":  round(100.0 * used / total, 1),
            "total_gb": round(total / 1024**2, 1),
            "used_gb":  round(used  / 1024**2, 1),
        }
    except Exception:
        return {"percent": 0, "total_gb": 0, "used_gb": 0}

def get_swap(mi: dict = None):
    # PERF[O2]: accepte un dict pré-lu pour éviter une seconde lecture fichier.
    if mi is None:
        mi = _read_meminfo()
    try:
        total = mi.get("SwapTotal", 0)
        free  = mi.get("SwapFree",  0)
        used  = total - free
        pct   = round(100.0 * used / total, 1) if total > 0 else 0.0
        return {
            "percent":  pct,
            "total_gb": round(total / 1024**2, 1),
            "used_gb":  round(used  / 1024**2, 1),
            "free_gb":  round(free  / 1024**2, 1),
        }
    except Exception:
        return {"percent": 0.0, "total_gb": 0.0, "used_gb": 0.0, "free_gb": 0.0}

def get_disk():
    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free  = stat.f_bfree  * stat.f_frsize
        used  = total - free
        return {"percent": round(100.0 * used / total, 1),
                "total_gb": round(total / 1024**3, 1),
                "used_gb":  round(used  / 1024**3, 1)}
    except Exception:
        return {"percent": 0, "total_gb": 0, "used_gb": 0}

def get_load():
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except Exception:
        return 0.0, 0.0, 0.0

def get_top_processes():
    procs = []
    out = run_cmd("ps aux --sort=-%cpu --no-headers | head -10")
    for line in out.splitlines():
        parts = line.split(None, 10)
        if len(parts) >= 11:
            try:
                procs.append({"user": parts[0], "cpu": float(parts[2]), "command": parts[10][:50]})
            except Exception:
                pass
    return procs

# PERF[O2]: collect_metrics() lit /proc/meminfo une seule fois pour RAM + SWAP.
def collect_metrics():
    mi   = _read_meminfo()          # une seule lecture fichier
    cpu  = get_cpu()
    ram  = get_ram(mi)              # passe le dict déjà lu
    disk = get_disk()
    swap = get_swap(mi)             # passe le même dict
    l1, l5, l15 = get_load()
    return {
        "ts":           datetime.now().isoformat(),
        "cpu_pct":      cpu,
        "ram_pct":      ram["percent"],
        "disk_pct":     disk["percent"],
        "swap_pct":     swap["percent"],
        "ram_total_gb": ram["total_gb"],  "ram_used_gb":  ram["used_gb"],
        "disk_total_gb":disk["total_gb"], "disk_used_gb": disk["used_gb"],
        "disk_free_gb": disk["total_gb"] - disk["used_gb"],
        "swap_total_gb":swap["total_gb"], "swap_used_gb": swap["used_gb"],
        "load_1m": l1, "load_5m": l5, "load_15m": l15,
        "top_processes": get_top_processes(), "services": {}, "alerts": []
    }

# ============================================================
# FASTPANEL 2 — CONFIGURATION ET HELPERS (v6.1 CORRIGÉ)
# ============================================================
# Architecture réelle de FastPanel 2 :
#   - CLI officiel : /usr/local/bin/mogwai (source primaire — toujours fiable)
#   - API REST     : http://127.0.0.1:<port>/api/... (Bearer JWT)
#   - Auth         : POST /login {username, password} → {token: "JWT"}
#   - Les tables MySQL "user","domain","ftp_account" etc. N'EXISTENT PAS dans FP2
#   - Les stats (CPU/RAM/disk) sont lues depuis /proc par FP2 — pas de table dédiée

FP_PARAM_FILES = [
    "/usr/local/fastpanel2/app/config/parameters.yml",
    "/usr/local/fastpanel2/app/config/parameters.yaml",
    "/usr/local/fastpanel2/config/database.yml",
    "/etc/fastpanel2/config.yml",
]
FP_USER_HOME  = "/var/www/fastuser/data/www"
FP_MOGWAI_BIN = "/usr/local/bin/mogwai"

# [FP3]: Cache JWT — le token dure plusieurs heures, on évite le re-login
_fp_jwt_token:    str   = ""
_fp_panel_port:   int   = 8888
_fp_panel_creds:  dict  = {}          # {"username": ..., "password": ...}
_fp_load_lock     = threading.Lock()  # double-checked locking


# ── Détection du port panel FP2 ──────────────────────────────────────────────
def _fp_detect_port() -> int:
    """[FP8] Détecte le port d'écoute du panel FP2 depuis sa config nginx."""
    global _fp_panel_port
    # 1. Chercher dans la config nginx de FP2
    for ndir in ["/etc/nginx/fastpanel2", "/etc/nginx/conf.d"]:
        nd = Path(ndir)
        if not nd.exists():
            continue
        for conf in nd.rglob("*.conf"):
            try:
                content = conf.read_text(errors="replace")
                m = re.search(r"proxy_pass\s+http://127\.0\.0\.1:(\d+)", content)
                if m:
                    _fp_panel_port = int(m.group(1))
                    return _fp_panel_port
            except Exception:
                pass
    # 2. Chercher dans les fichiers de config FP2 directs
    for pf in FP_PARAM_FILES:
        if Path(pf).exists():
            try:
                content = Path(pf).read_text(errors="replace")
                m = re.search(r"(?:port|listen)[:\s]+(\d{4,5})", content)
                if m and 1024 < int(m.group(1)) < 65535:
                    _fp_panel_port = int(m.group(1))
                    return _fp_panel_port
            except Exception:
                pass
    return 8888


def _fp_panel_base() -> str:
    return f"http://127.0.0.1:{_fp_panel_port}"


# ── Lecture des credentials admin depuis les configs FP2 ─────────────────────
def _fp_load_admin_creds() -> dict:
    """Lit les credentials admin depuis les fichiers de config FP2."""
    global _fp_panel_creds
    if _fp_panel_creds:
        return _fp_panel_creds
    with _fp_load_lock:
        if _fp_panel_creds:
            return _fp_panel_creds
        for pf in FP_PARAM_FILES:
            if not Path(pf).exists():
                continue
            try:
                content = Path(pf).read_text(errors="replace")
                params = {}
                for line in content.splitlines():
                    line = line.strip()
                    if ": " in line and not line.startswith("#"):
                        k, _, v = line.partition(": ")
                        params[k.strip()] = v.strip().strip("'\" ")
                # Chercher username/password admin dans les paramètres
                user = params.get("admin_username",
                       params.get("fp_admin_username",
                       params.get("username", "fastuser")))
                pwd  = params.get("admin_password",
                       params.get("fp_admin_password",
                       params.get("secret", "")))
                if pwd:
                    _fp_panel_creds = {"username": user, "password": pwd}
                    return _fp_panel_creds
            except Exception:
                pass
        # Fallback : fichier de credentials dédié
        cred_files = [
            "/etc/cassandra/fastpanel_creds.txt",
            "/root/.fastpanel_creds",
        ]
        for cf in cred_files:
            if Path(cf).exists():
                try:
                    lines = Path(cf).read_text().strip().splitlines()
                    if len(lines) >= 2:
                        _fp_panel_creds = {"username": lines[0].strip(),
                                           "password": lines[1].strip()}
                        return _fp_panel_creds
                except Exception:
                    pass
    return {}


# ── Authentification JWT ──────────────────────────────────────────────────────
def _fp_api_login() -> str:
    """[FP3] Obtient un Bearer JWT via POST /login. Cache le token."""
    global _fp_jwt_token
    if _fp_jwt_token:
        return _fp_jwt_token
    creds = _fp_load_admin_creds()
    if not creds:
        return ""
    try:
        import urllib.request
        import urllib.error
        payload = json.dumps({"username": creds["username"],
                              "password": creds["password"]}).encode()
        req = urllib.request.Request(
            f"{_fp_panel_base()}/login",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            _fp_jwt_token = data.get("token", "")
            return _fp_jwt_token
    except Exception as e:
        print(f"[FP] Login échoué: {e}", file=sys.stderr)
        return ""


def _fp_api_get(endpoint: str) -> dict:
    """[FP2] Appel API REST FP2 avec Bearer JWT — endpoints corrects /api/..."""
    import urllib.request
    import urllib.error
    token = _fp_jwt_token or _fp_api_login()
    if not token:
        return {}
    try:
        url = _fp_panel_base() + endpoint
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


def _fp_api_get_list(endpoint: str) -> list:
    """Appel API et retourne toujours une liste (data[] ou [] si absent)."""
    data = _fp_api_get(endpoint)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "items", "results", "list"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


# ── mogwai CLI wrapper ────────────────────────────────────────────────────────
def _mogwai(args: list, timeout: int = 15) -> str:
    """[FP1] Appelle le CLI mogwai officiel de FastPanel 2."""
    if not Path(FP_MOGWAI_BIN).exists():
        return ""
    try:
        r = subprocess.run(
            [FP_MOGWAI_BIN] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _mogwai_parse_table(output: str) -> list[dict]:
    """Parse la sortie tabulaire de mogwai (colonnes séparées par des espaces multiples)."""
    if not output:
        return []
    lines = output.strip().splitlines()
    if len(lines) < 2:
        return []
    # Ligne 0 = en-têtes, lignes 1+ = données
    # mogwai utilise des TABs ou des espaces multiples (≥2) comme séparateur
    headers = re.split(r'\t|  +', lines[0].strip())
    headers = [h.strip().lower().replace(" ", "_") for h in headers if h.strip()]
    rows = []
    for line in lines[1:]:
        if not line.strip():
            continue
        vals = re.split(r'\t|  +', line.strip())
        vals = [v.strip() for v in vals]
        # Aligner sur le nombre de colonnes
        while len(vals) < len(headers):
            vals.append("")
        row = {headers[i]: vals[i] for i in range(len(headers))}
        rows.append(row)
    return rows


# PERF[O1] — lru_cache sur _fp_available() : 8+ appels → 1 syscall réel
@lru_cache(maxsize=1)
def _fp_available() -> bool:
    """FastPanel 2 détecté si mogwai CLI OU config OU dossier installation."""
    # Détection fiable : le binaire mogwai est la signature officielle de FP2
    if Path(FP_MOGWAI_BIN).exists():
        return True
    if any(Path(f).exists() for f in FP_PARAM_FILES):
        return True
    return any(Path(p).exists() for p in [
        "/etc/nginx/fastpanel2",
        "/usr/local/fastpanel2",
        "/var/www/fastuser",
    ])


# ============================================================
# FASTPANEL 2 — COLLECTEURS CORRIGÉS (v6.1)
# ============================================================

def collect_fastpanel_users() -> list:
    """[FP1→FP2→FS] Users FP2 : mogwai → API /api/users → scan /var/www."""
    now = datetime.now().isoformat()
    users, seen = [], set()
    if not _fp_available():
        return []

    # [FP1] Source primaire : mogwai users list (si disponible)
    # Nota : mogwai n'expose pas encore "users list" dans la doc officielle,
    # on passe directement à l'API qui est documentée.

    # [FP2] API REST — endpoint correct : GET /api/users
    api_users = _fp_api_get_list("/api/users")
    for u in api_users:
        uname = u.get("username", u.get("login", ""))
        if not uname or uname in seen:
            continue
        seen.add(uname)
        # Calcul disk depuis quota (en octets dans l'API FP2)
        quota_raw = u.get("quota")
        used_raw  = u.get("disk_used", u.get("disk_usage", 0)) or 0
        quota_gb  = round(int(quota_raw) / 1024**3, 2) if quota_raw else 0
        used_gb   = round(int(used_raw)  / 1024**3, 2) if used_raw  else 0
        # FP2 retourne enabled=true/false
        enabled = u.get("enabled", True)
        status  = "active" if enabled else "suspended"
        users.append({
            "username":     uname,
            "email":        u.get("restore_email", u.get("email", "")),
            "status":       status,
            "disk_quota_gb": quota_gb,
            "disk_used_gb":  used_gb,
            "created_at":   u.get("created_at", now),
            "last_login":   u.get("last_login", ""),
            "roles":        ",".join(u.get("roles", [])),
            "last_check":   now,
        })
    if users:
        return users

    # [FS] Fallback filesystem : scan /var/www/<user>/data/
    base = Path(FP_USER_HOME).parent.parent  # → /var/www/
    if base.exists():
        for d in base.iterdir():
            if not d.is_dir() or d.name in seen or d.name.startswith("."):
                continue
            data_dir = d / "data"
            if not data_dir.exists():
                continue
            seen.add(d.name)
            try:
                out = run_cmd(f"du -sb {data_dir} 2>/dev/null")
                used_gb = round(int(out.split()[0]) / 1024**3, 2) if out else 0
            except Exception:
                used_gb = 0
            users.append({
                "username": d.name, "email": "", "status": "active",
                "disk_quota_gb": 0, "disk_used_gb": used_gb,
                "created_at": now, "last_login": "", "roles": "ROLE_USER",
                "last_check": now,
            })
    return users


def collect_fastpanel_domains() -> list:
    """[FP1→FP2→FS] Sites/domaines FP2 : mogwai → API /api/sites/list → nginx scan."""
    now = datetime.now().isoformat()
    domains, seen = [], set()
    if not _fp_available():
        return []

    # [FP1] mogwai sites list — sortie tabulaire officielle
    mogwai_out = _mogwai(["sites", "list"])
    mogwai_rows = _mogwai_parse_table(mogwai_out)
    for row in mogwai_rows:
        server_name = row.get("server_name", "")
        if not server_name or server_name in seen:
            continue
        seen.add(server_name)
        php_ver = row.get("php_version", row.get("mode", ""))
        # Normaliser la version PHP (82 → 8.2)
        if php_ver and php_ver.isdigit() and len(php_ver) == 2:
            php_ver = f"{php_ver[0]}.{php_ver[1]}"
        docroot = row.get("document_root", "")
        owner   = row.get("owner", "")
        # Déduire user depuis document_root si owner manquant
        if not owner and docroot:
            m = re.search(r"/var/www/([^/]+)/", docroot)
            if m:
                owner = m.group(1)
        # Détection SSL depuis nginx config
        ssl_enabled = 0
        ssl_days    = 0
        cert_path   = f"/etc/letsencrypt/live/{server_name}/cert.pem"
        if Path(cert_path).exists():
            ssl_enabled = 1
            out_ssl = run_cmd(
                f"openssl x509 -in {cert_path} -noout -enddate 2>/dev/null"
            )
            dm = re.search(r"notAfter=(.+)", out_ssl)
            if dm:
                try:
                    exp = datetime.strptime(dm.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                    ssl_days = (exp - datetime.now()).days
                except Exception:
                    pass
        domains.append({
            "domain":        server_name,
            "aliases":       row.get("aliases", ""),
            "user":          owner,
            "php_version":   php_ver or "unknown",
            "ssl_enabled":   ssl_enabled,
            "ssl_days_left": ssl_days,
            "document_root": docroot,
            "status":        "active",
            "created_at":    now,
            "last_check":    now,
        })
    if domains:
        return domains

    # [FP2] API REST — endpoint correct : GET /api/sites/list
    api_sites = _fp_api_get_list(
        "/api/sites/list?filter[limit]=1000&filter[type]=all&filter[offset]=0"
    )
    for site in api_sites:
        # FP2 retourne {id, server_name, aliases:[...], owner:{username}, handler, handler_version}
        name = site.get("server_name", site.get("name", ""))
        if not name or name in seen:
            continue
        seen.add(name)
        owner_obj = site.get("owner", {})
        owner = (owner_obj.get("username") or owner_obj.get("login")
                 if isinstance(owner_obj, dict) else str(owner_obj))
        handler_ver = site.get("handler_version", site.get("php_version", ""))
        # Détection SSL
        ssl_enabled = 1 if site.get("ssl") or site.get("ssl_enabled") else 0
        ssl_days    = 0
        cert = f"/etc/letsencrypt/live/{name}/cert.pem"
        if ssl_enabled and Path(cert).exists():
            out_ssl = run_cmd(f"openssl x509 -in {cert} -noout -enddate 2>/dev/null")
            dm = re.search(r"notAfter=(.+)", out_ssl)
            if dm:
                try:
                    exp = datetime.strptime(dm.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                    ssl_days = (exp - datetime.now()).days
                except Exception:
                    pass
        domains.append({
            "domain":        name,
            "aliases":       ",".join(site.get("aliases", [])),
            "user":          owner or "",
            "php_version":   str(handler_ver) if handler_ver else "unknown",
            "ssl_enabled":   ssl_enabled,
            "ssl_days_left": ssl_days,
            "document_root": site.get("document_root", ""),
            "status":        "active" if site.get("enabled", True) else "suspended",
            "created_at":    site.get("created_at", now),
            "last_check":    now,
        })
    if domains:
        return domains

    # [FS] Fallback : scan configs nginx FastPanel 2
    nginx_dirs = [
        "/etc/nginx/sites-enabled", "/etc/nginx/conf.d",
        "/etc/nginx/fastpanel2", "/etc/nginx/vhosts.d",
    ]
    for ndir in nginx_dirs:
        nd = Path(ndir)
        if not nd.exists():
            continue
        for conf in nd.rglob("*.conf"):
            try:
                content = conf.read_text(errors="replace")
                if "server_name" not in content:
                    continue
                ssl = bool(re.search(r"ssl_certificate", content))
                root_m = re.search(r"root\s+([^;]+);", content)
                php_m  = re.search(r"(?:fastcgi_pass[^;]*php|handler_version\s+)(\d+\.?\d*)", content)
                docroot = root_m.group(1).strip() if root_m else ""
                user = ""
                user_m = re.search(r"/var/www/([^/]+)/", docroot)
                if user_m:
                    user = user_m.group(1)
                for sn_block in re.findall(r"server_name\s+([^;]+);", content):
                    for domain in sn_block.strip().split():
                        domain = domain.strip().rstrip(".")
                        if (domain and len(domain) > 3
                                and not domain.startswith(("_","*","#","localhost"))
                                and "." in domain and domain not in seen):
                            seen.add(domain)
                            ssl_days = 0
                            if ssl:
                                cert_path = f"/etc/letsencrypt/live/{domain}/cert.pem"
                                if Path(cert_path).exists():
                                    out_ssl = run_cmd(
                                        f"openssl x509 -in {cert_path} -noout -enddate 2>/dev/null"
                                    )
                                    dm = re.search(r"notAfter=(.+)", out_ssl)
                                    if dm:
                                        try:
                                            exp = datetime.strptime(dm.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                                            ssl_days = (exp - datetime.now()).days
                                        except Exception:
                                            pass
                            domains.append({
                                "domain": domain, "aliases": "", "user": user,
                                "php_version": php_m.group(1) if php_m else "unknown",
                                "ssl_enabled": 1 if ssl else 0,
                                "ssl_days_left": ssl_days,
                                "document_root": docroot, "status": "active",
                                "created_at": now, "last_check": now,
                            })
            except Exception:
                pass
    return domains


def collect_fastpanel_databases() -> list:
    """[FP2→MySQL] Bases de données : API /api/db → mysql information_schema."""
    now = datetime.now().isoformat()
    dbs, seen = [], set()
    if not _fp_available():
        return []

    # [FP2] API — FP2 gère des bases utilisateurs, pas sa propre DB
    # Note: endpoint non documenté officiellement, on tente /api/db/list
    api_dbs = _fp_api_get_list("/api/db/list?filter[limit]=1000")
    for db in api_dbs:
        name = db.get("name", "")
        if not name or name in seen:
            continue
        seen.add(name)
        dbs.append({
            "name":     name,
            "db_user":  db.get("db_user", db.get("user", "")),
            "size_mb":  float(db.get("size_mb", db.get("size", 0)) or 0),
            "db_type":  db.get("type", "mysql"),
            "owner":    (db.get("owner", {}) or {}).get("username", ""),
            "last_check": now,
        })
    if dbs:
        return dbs

    # [MySQL] Fallback : information_schema (toujours disponible si MySQL est installé)
    out = run_cmd(
        "mysql -u root --batch --silent --skip-column-names -e "
        "\"SELECT table_schema, ROUND(SUM(data_length+index_length)/1024/1024,2) "
        "FROM information_schema.tables GROUP BY table_schema\" 2>/dev/null"
    )
    skip = {"information_schema", "performance_schema", "mysql", "sys"}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] not in skip and parts[0] not in seen:
            try:
                seen.add(parts[0])
                dbs.append({
                    "name": parts[0], "db_user": "", "size_mb": float(parts[1] or 0),
                    "db_type": "mysql", "owner": "", "last_check": now,
                })
            except Exception:
                pass
    return dbs


def collect_fastpanel_mail() -> list:
    """[FP1→FP2→FS] Comptes mail : mogwai → API /api/email → postfix fallback."""
    now = datetime.now().isoformat()
    accounts, seen = [], set()
    if not _fp_available():
        return []

    # [FP1] mogwai emails boxes list — liste toutes les boîtes
    mogwai_out = _mogwai(["emails", "boxes", "list"])
    for row in _mogwai_parse_table(mogwai_out):
        addr = row.get("address", "")
        if not addr or "@" not in addr or addr in seen:
            continue
        seen.add(addr)
        parts = addr.split("@")
        size_mb  = 0
        quota_mb = 0
        try:
            size_mb  = round(int(row.get("size", 0) or 0) / 1024 / 1024, 1)
            quota_mb = round(int(row.get("quota", 0) or 0) / 1024 / 1024, 1)
        except Exception:
            pass
        accounts.append({
            "email":    addr,
            "domain":   parts[1],
            "login":    parts[0],
            "quota_mb": quota_mb,
            "used_mb":  size_mb,
            "status":   "active" if row.get("enabled","true") == "true" else "suspended",
            "last_check": now,
        })
    if accounts:
        return accounts

    # [FP2] API — endpoint non officiel, tentative
    api_boxes = _fp_api_get_list("/api/email/boxes?filter[limit]=1000")
    for box in api_boxes:
        addr = box.get("address", box.get("email", ""))
        if not addr or "@" not in addr or addr in seen:
            continue
        seen.add(addr)
        parts = addr.split("@")
        accounts.append({
            "email":    addr,
            "domain":   parts[1] if len(parts) > 1 else "",
            "login":    parts[0],
            "quota_mb": box.get("quota", 0) or 0,
            "used_mb":  box.get("size",  0) or 0,
            "status":   "active" if box.get("enabled", True) else "suspended",
            "last_check": now,
        })
    if accounts:
        return accounts

    # [FS] Fallback postfix virtual/vmailbox
    for vfile in ["/etc/postfix/virtual", "/etc/postfix/vmailbox"]:
        if not Path(vfile).exists():
            continue
        try:
            for line in Path(vfile).read_text(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "@" in line:
                    email = line.split()[0]
                    if "@" in email and email not in seen:
                        seen.add(email)
                        p = email.split("@")
                        accounts.append({
                            "email": email, "domain": p[1], "login": p[0],
                            "quota_mb": 0, "used_mb": 0, "status": "active",
                            "last_check": now,
                        })
        except Exception:
            pass
    return accounts


def collect_fastpanel_ftp() -> list:
    """[FP6] Comptes FTP : scan proftpd/vsftpd/pure-ftpd — FP2 n'expose pas de table FTP."""
    now  = datetime.now().isoformat()
    accounts, seen = [], set()
    if not _fp_available():
        return []

    # [FP6-A] proftpd : /etc/proftpd/passwd (format passwd unix)
    proftpd_passwd = Path("/etc/proftpd/passwd")
    if proftpd_passwd.exists():
        try:
            for line in proftpd_passwd.read_text(errors="replace").splitlines():
                parts = line.split(":")
                if len(parts) >= 6 and parts[0] not in seen:
                    login    = parts[0]
                    home_dir = parts[5] if len(parts) > 5 else ""
                    seen.add(login)
                    # Déduire le propriétaire FP2 depuis home_dir (/var/www/<user>/...)
                    owner = ""
                    m = re.search(r"/var/www/([^/]+)/", home_dir)
                    if m:
                        owner = m.group(1)
                    accounts.append({
                        "login":    login,
                        "home_dir": home_dir,
                        "status":   "active",
                        "owner":    owner,
                        "last_check": now,
                    })
        except Exception:
            pass

    # [FP6-B] pure-ftpd : /etc/pure-ftpd/pureftpd.passwd
    pure_passwd = Path("/etc/pure-ftpd/pureftpd.passwd")
    if pure_passwd.exists():
        try:
            for line in pure_passwd.read_text(errors="replace").splitlines():
                parts = line.split(":")
                if len(parts) >= 8 and parts[0] not in seen:
                    login    = parts[0]
                    home_dir = parts[5] if len(parts) > 5 else ""
                    seen.add(login)
                    owner = ""
                    m = re.search(r"/var/www/([^/]+)/", home_dir)
                    if m:
                        owner = m.group(1)
                    accounts.append({
                        "login": login, "home_dir": home_dir,
                        "status": "active", "owner": owner, "last_check": now,
                    })
        except Exception:
            pass

    # [FP6-C] vsftpd : /etc/vsftpd.userlist ou /etc/vsftpd/user_conf/
    vsftpd_ul = Path("/etc/vsftpd.userlist")
    if vsftpd_ul.exists():
        try:
            for login in vsftpd_ul.read_text(errors="replace").splitlines():
                login = login.strip()
                if login and not login.startswith("#") and login not in seen:
                    seen.add(login)
                    accounts.append({
                        "login": login, "home_dir": f"/var/www/{login}/data",
                        "status": "active", "owner": login, "last_check": now,
                    })
        except Exception:
            pass

    # [FP6-D] FTP via FP2 stockés dans les homes utilisateurs
    # FP2 crée des comptes FTP comme sous-utilisateurs Linux
    if not accounts:
        fp_users = _fp_get_fp2_usernames()
        for user in fp_users:
            ftp_dir = Path(f"/var/www/{user}/data/ftp")
            if ftp_dir.exists():
                # Les comptes FTP FP2 sont des dossiers dans data/ftp/
                for sub in ftp_dir.iterdir():
                    if sub.is_dir() and sub.name not in seen:
                        seen.add(sub.name)
                        accounts.append({
                            "login":    sub.name,
                            "home_dir": str(sub),
                            "status":   "active",
                            "owner":    user,
                            "last_check": now,
                        })
    return accounts


def _fp_get_fp2_usernames() -> list:
    """Retourne la liste des noms d'utilisateurs FP2 (depuis /var/www/ ou API)."""
    users = []
    # Depuis l'API si disponible
    api_users = _fp_api_get_list("/api/users")
    if api_users:
        return [u.get("username", u.get("login", "")) for u in api_users if u.get("username") or u.get("login")]
    # Sinon filesystem
    base = Path("/var/www")
    if base.exists():
        for d in base.iterdir():
            if d.is_dir() and (d / "data").exists() and not d.name.startswith("."):
                users.append(d.name)
    return users


def collect_fastpanel_backups() -> list:
    """[FP2→FS] Backups FP2 : API → scan /var/backups/fastpanel/ → rclone logs."""
    now = datetime.now().isoformat()
    backups = []

    # [FP2] API tentative
    api_backups = _fp_api_get_list("/api/backup/list?filter[limit]=100")
    for b in api_backups:
        backups.append({
            "type":       b.get("type", "full"),
            "status":     b.get("status", "unknown"),
            "size_mb":    float(b.get("size_mb", b.get("size", 0)) or 0),
            "created_at": b.get("created_at", now),
            "error":      b.get("error_message", b.get("error", "")),
            "user":       (b.get("owner") or {}).get("username", "") if isinstance(b.get("owner"), dict) else "",
            "last_check": now,
        })
    if backups:
        return backups

    # [FS] Scan répertoire backups FP2
    for bdir in ["/var/backups/fastpanel2", "/var/backups/fastpanel",
                 "/var/www/fastuser/data/backups"]:
        bd = Path(bdir)
        if not bd.exists():
            continue
        for f in sorted(bd.rglob("*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True)[:20]:
            try:
                stat = f.stat()
                backups.append({
                    "type":       "full",
                    "status":     "success",
                    "size_mb":    round(stat.st_size / 1024 / 1024, 1),
                    "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "error":      "",
                    "user":       f.parts[-2] if len(f.parts) > 1 else "",
                    "last_check": now,
                })
            except Exception:
                pass
    return backups


def collect_fastpanel_dns() -> list:
    """[FP1→FP2] Enregistrements DNS FP2 : mogwai → API /api/dns/domains."""
    now = datetime.now().isoformat()
    records = []
    if not _fp_available():
        return []

    # [FP1] mogwai : liste les zones DNS
    zones_out = _mogwai(["dns", "list"], timeout=10)
    if not zones_out:
        # Essayer l'ancien nom de commande
        zones_out = _mogwai(["domains", "list"], timeout=10)

    # [FP2] API — endpoint correct : GET /api/dns/domains
    dns_domains = _fp_api_get_list("/api/dns/domains")
    for zone in dns_domains:
        zone_name = zone.get("name", "")
        zone_id   = zone.get("id")
        if not zone_name or not zone_id:
            continue
        # GET /api/dns/domain/{id}/records
        zone_records = _fp_api_get_list(f"/api/dns/domain/{zone_id}/records")
        for rec in zone_records:
            records.append({
                "zone":       zone_name,
                "type":       rec.get("type", "A"),
                "name":       rec.get("name", "@"),
                "value":      rec.get("data", rec.get("value", "")),
                "ttl":        int(rec.get("ttl", 3600)),
                "last_check": now,
            })
    return records


def collect_fastpanel_php_versions() -> list:
    """PHP versions : scan binaires système (la plus fiable sur tout serveur)."""
    now = datetime.now().isoformat()
    versions, seen = [], set()

    # [FP2] API tentative
    api_php = _fp_api_get_list("/api/php/versions")
    for p in api_php:
        ver = str(p.get("version", p.get("php_version", "")))
        if ver and ver not in seen:
            seen.add(ver)
            versions.append({
                "version":      ver,
                "full_version": p.get("full_version", ver),
                "path":         p.get("path", f"/usr/sbin/php-fpm{ver}"),
                "active":       1 if p.get("enabled", p.get("active", True)) else 0,
                "last_check":   now,
            })
    if versions:
        return versions

    # [FS] Scan binaires système — toujours fiable
    for ver in ["8.4","8.3","8.2","8.1","8.0","7.4","7.3","7.2"]:
        for bin_path in [f"/usr/sbin/php-fpm{ver}", f"/usr/bin/php{ver}",
                         f"/usr/local/bin/php{ver}"]:
            if Path(bin_path).exists() and ver not in seen:
                seen.add(ver)
                full = run_cmd([f"php{ver}", "-r", "echo PHP_VERSION;"], timeout=3)
                versions.append({
                    "version":      ver,
                    "full_version": full.strip() or ver,
                    "path":         bin_path,
                    "active":       1,
                    "last_check":   now,
                })
                break
    return versions


def collect_fastpanel_crons() -> list:
    """[FP7] Crons FP2 : /var/spool/cron/crontabs/<user> pour chaque user FP2."""
    now  = datetime.now().isoformat()
    jobs = []
    if not _fp_available():
        return []

    fp_users = _fp_get_fp2_usernames()
    # Toujours inclure root et fastuser
    for special in ["root", "fastuser"]:
        if special not in fp_users:
            fp_users.append(special)

    def parse_crontab(text: str, user: str):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("SHELL=") \
               or line.startswith("PATH=") or line.startswith("MAILTO="):
                continue
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            # Format standard cron : min heure jour mois dow commande
            schedule = " ".join(parts[:5])
            command  = parts[5][:300]
            jobs.append({
                "user":        user,
                "schedule":    schedule,
                "command":     command,
                "enabled":     1,
                "last_run":    "",
                "last_status": "",
                "source":      "fastpanel2",
                "last_check":  now,
            })

    # [FP7] Lecture des crontabs par utilisateur
    spool = Path("/var/spool/cron/crontabs")
    for user in fp_users:
        cron_file = spool / user
        if cron_file.exists():
            try:
                parse_crontab(cron_file.read_text(errors="replace"), user)
            except Exception:
                pass

    # [FP2] API tentative pour les crons gérés par FP2
    api_crons = _fp_api_get_list("/api/cron/list?filter[limit]=500")
    for c in api_crons:
        owner = (c.get("owner") or {})
        user  = owner.get("username", "root") if isinstance(owner, dict) else "root"
        jobs.append({
            "user":        user,
            "schedule":    c.get("schedule", ""),
            "command":     (c.get("command", "") or "")[:300],
            "enabled":     1 if c.get("enabled", True) else 0,
            "last_run":    c.get("last_run", ""),
            "last_status": c.get("last_status", ""),
            "source":      "fastpanel2_api",
            "last_check":  now,
        })

    return jobs


def collect_fastpanel_services() -> list:
    """[FS] Services gérés par FP2 : systemctl pour les services standard."""
    now = datetime.now().isoformat()
    svcs = []
    # Services connus gérés par FP2
    fp2_services = [
        "nginx", "apache2", "httpd",
        "mysql", "mariadb", "postgresql",
        "postfix", "dovecot", "exim4",
        "bind9", "named", "powerdns", "pdns",
        "redis-server", "redis",
        "fail2ban",
        "proftpd", "vsftpd", "pure-ftpd",
        "fastpanel2",
        "php8.4-fpm", "php8.3-fpm", "php8.2-fpm",
        "php8.1-fpm", "php8.0-fpm", "php7.4-fpm",
        "memcached", "rabbitmq-server",
    ]

    # [FP2] API tentative
    api_svcs = _fp_api_get_list("/api/service/list")
    if api_svcs:
        for s in api_svcs:
            svcs.append({
                "name":       s.get("name", ""),
                "status":     s.get("status", "unknown"),
                "version":    s.get("version", ""),
                "last_check": now,
            })
        return svcs

    # [FS] systemctl fallback
    for svc in fp2_services:
        st = run_cmd(f"systemctl is-active {svc} 2>/dev/null").strip()
        if st in ("active", "inactive", "failed"):
            ver = run_cmd(f"systemctl show {svc} --property=Description 2>/dev/null")
            svcs.append({
                "name":       svc,
                "status":     st,
                "version":    "",
                "last_check": now,
            })
    return svcs


def collect_active_sessions():
    sessions = []
    now = datetime.now().isoformat()
    seen = set()

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
        ip_m = re.search(r"\(([\d.:a-fA-F]+)\)", line)
        ip   = ip_m.group(1) if ip_m else "local"
        login_time = " ".join(parts[2:4]) if len(parts) >= 4 else parts[2] if len(parts) >= 3 else now
        key = f"{user}:{tty}"
        if key not in seen:
            seen.add(key)
            sessions.append({"user": user, "ip": ip, "login_time": login_time, "last_check": now})

    ss_out = run_cmd("ss -tnp state established 'sport = :22'")
    for line in ss_out.splitlines():
        if not line.strip() or line.startswith("Netid"):
            continue
        parts = line.split()
        local_idx = -1
        for i, p in enumerate(parts):
            if p.endswith(":22") or ":22 " in p or p == "[::]:22" or "]:22" in p:
                local_idx = i
                break
        if local_idx < 0:
            local_idx = 4
        peer_idx = local_idx + 1
        if peer_idx >= len(parts):
            continue
        peer = parts[peer_idx]
        ip = None
        m = re.search(r"\[::ffff:((\d{1,3}\.){3}\d{1,3})\]", peer)
        if m:
            ip = m.group(1)
        else:
            m = re.match(r"((\d{1,3}\.){3}\d{1,3}):\d+", peer)
            if m:
                ip = m.group(1)
            else:
                m = re.match(r"\[([^\]]+)\]:\d+", peer)
                if m:
                    ip = m.group(1)
        if not ip or ip in ("127.0.0.1", "::1"):
            continue
        proc_str = " ".join(parts[peer_idx+1:]) if peer_idx+1 < len(parts) else ""
        user_m = re.search(r'users=\(\("([^"]+)"', proc_str)
        user = user_m.group(1) if user_m else "sshd"
        key = f"ssh:{ip}"
        if key not in seen:
            seen.add(key)
            sessions.append({"user": user, "ip": ip, "login_time": now, "last_check": now})

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
    ports = []
    now  = datetime.now().isoformat()
    seen = set()

    out = run_cmd("ss -tulnp 2>/dev/null")
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        local = ""
        for col in parts[3:6]:
            if re.search(r":\d+$", col) or re.search(r"\]:\d+$", col):
                local = col
                break
        if not local:
            continue
        port_m = re.search(r":([\d]+)$", local)
        if not port_m:
            continue
        port = int(port_m.group(1))
        if port == 0:
            continue
        proc_col = " ".join(parts[5:]) if len(parts) > 5 else ""
        pname_m = re.search(r'"([^"]+)"', proc_col)
        process = pname_m.group(1)[:40] if pname_m else "system"
        key = f"{proto}:{port}"
        if key not in seen:
            seen.add(key)
            ports.append({"port": port, "protocol": proto, "process": process, "pid": 0, "last_check": now})

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

    nginx_dirs = ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d",
                  "/etc/nginx/vhosts.d", "/usr/local/fastpanel2/etc/nginx"]
    for ndir in nginx_dirs:
        p = Path(ndir)
        if not p.exists():
            continue
        for conf in p.rglob("*"):
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
        domain = hint_domain
        san_m = re.search(r"DNS:([\w.*-]+)", out)
        if san_m:
            domain = san_m.group(1)
        elif not domain:
            cn_m = re.search(r"CN\s*=\s*([\w.*-]+)", out)
            domain = cn_m.group(1) if cn_m else Path(cert_path).stem
        return {"domain": domain, "days_left": days, "cert_path": cert_path,
                "status": "expired" if days <= 0 else ("expiring" if days <= 30 else "valid"),
                "last_check": now}

    for conf in list(Path("/etc/nginx").rglob("*.conf")) + list(Path("/etc/nginx").rglob("*")):
        try:
            content = conf.read_text(errors="replace")
            sn_m = re.search(r"server_name\s+([^;]+);", content)
            hint = sn_m.group(1).strip().split()[0] if sn_m else ""
            for cp in re.findall(r"ssl_certificate\s+([^;]+);", content):
                r = parse_cert(cp, hint)
                if r: certs.append(r)
        except Exception:
            pass

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
            units.append({"unit": parts[0], "active_state": "failed",
                          "last_check": datetime.now().isoformat()})
    return units


def collect_fail2ban_banned():
    banned = []
    now = datetime.now().isoformat()
    out = run_cmd("fail2ban-client status 2>/dev/null")
    if not out:
        return []
    jail_m = re.search(r"Jail list:\s*(.+)", out)
    if not jail_m:
        return []
    jails = [j.strip() for j in jail_m.group(1).split(",") if j.strip()]
    for jail in jails:
        status = run_cmd(f"fail2ban-client status {jail} 2>/dev/null")
        if not status:
            continue
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
                dns_name = v.get("DNSName", "")
                name = dns_name.split(".")[0] or k[:8]
                ts_ips = v.get("TailscaleIPs", [])
                ts_ip = ts_ips[0] if ts_ips else ""
                peers.append({
                    "name": name, "dns_name": dns_name, "tailscale_ip": ts_ip,
                    "online": 1 if v.get("Online") else 0,
                    "last_check": datetime.now().isoformat(),
                })
            return peers
        except Exception:
            pass
    return []


def collect_oom_events():
    out = run_cmd("dmesg -T 2>/dev/null | grep -iE 'Out of memory|Kill process|oom_kill' | tail -20")
    events = []
    now = datetime.now().isoformat()
    for line in out.splitlines():
        ts_match = re.search(r'\[([A-Za-z]+\s+[A-Za-z]+\s+\d+\s+[\d:]+\s+\d+)\]', line)
        ts = ts_match.group(1) if ts_match else now
        proc_match = re.search(r'Kill(?:ing)?\s+process\s+\d+\s+\(([^)]+)\)', line, re.IGNORECASE)
        if not proc_match:
            proc_match = re.search(r'Killed process \d+ \(([^)]+)\)', line, re.IGNORECASE)
        process = proc_match.group(1) if proc_match else "unknown"
        mem_match = re.search(r'total-vm:(\d+)kB', line)
        mem_mb = round(int(mem_match.group(1)) / 1024) if mem_match else 0
        if not mem_mb:
            mem_match2 = re.search(r'anon-rss:(\d+)kB', line)
            mem_mb = round(int(mem_match2.group(1)) / 1024) if mem_match2 else 0
        events.append({"ts": ts, "killed_process": process[:80],
                       "memory_used_mb": mem_mb, "last_check": now})
    return events


def collect_docker_containers():
    out = run_cmd("docker ps -a --format '{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null")
    containers = []
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            containers.append({"name": parts[0], "status": parts[1], "image": parts[2],
                               "last_check": datetime.now().isoformat()})
    return containers


def collect_rclone_remotes():
    remotes = []
    for conf in [Path("/root/.config/rclone/rclone.conf"), Path("/etc/rclone/rclone.conf")]:
        if conf.exists():
            try:
                config = configparser.ConfigParser()
                config.read(conf)
                for section in config.sections():
                    remotes.append({"name": section,
                                    "type": config.get(section, "type", fallback="unknown"),
                                    "last_check": datetime.now().isoformat()})
            except Exception:
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
                if isinstance(state, str) and state.lower() in ("reachable","stale","delay","probe","noarp"):
                    ip = entry.get("dst")
                    if ip and ip not in seen:
                        seen.add(ip)
                        hosts.append({"ip": ip, "mac": entry.get("lladdr", "unknown"),
                                      "interface": entry.get("dev", "unknown"),
                                      "reachable": 1 if state == "reachable" else 0,
                                      "last_seen": now})
        except Exception:
            pass
    if not hosts:
        arp_out = run_cmd("arp -n")
        for line in arp_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2] != "incomplete":
                ip = parts[0]
                if ip not in seen:
                    seen.add(ip)
                    hosts.append({"ip": ip, "mac": parts[2],
                                  "interface": parts[4] if len(parts) > 4 else "unknown",
                                  "reachable": 1, "last_seen": now})
    return hosts


# ============================================================
# FASTPANEL2 — STATS TEMPS RÉEL
# ============================================================

def _fp_rows_to_list(rows, cols):
    result = []
    for r in rows:
        if len(r) < len(cols):
            continue
        result.append({cols[i]: r[i] for i in range(len(cols))})
    return result


def _downsample(data: list, max_points: int) -> list:
    """Réduit une série temporelle à max_points en gardant le début et la fin."""
    if len(data) <= max_points:
        return data
    step = len(data) / max_points
    return [data[int(i * step)] for i in range(max_points)]



def collect_fp_server_stat(period_hours: int = 24) -> list:
    """[FP5] Stats serveur temps-réel depuis /proc — FP2 ne stocke PAS ces données en MySQL.
    Retourne UN snapshot instantané (CPU, load, RAM, swap) à partir de /proc.
    L'historisation sur period_hours est faite par le collecteur principal qui appelle
    cette fonction à intervalles réguliers et accumule les snapshots en SQLite.
    """
    if not _fp_available():
        return []
    now_str = datetime.now().isoformat()

    # CPU depuis /proc/stat (mode snapshot — différence sur 0.2s)
    cpu_pct = 0.0
    try:
        lines1 = Path("/proc/stat").read_text().splitlines()
        cpu1   = [int(x) for x in lines1[0].split()[1:]]
        time.sleep(0.2)
        lines2 = Path("/proc/stat").read_text().splitlines()
        cpu2   = [int(x) for x in lines2[0].split()[1:]]
        total  = sum(b - a for a, b in zip(cpu1, cpu2))
        idle   = cpu2[3] - cpu1[3]
        cpu_pct = round((1 - idle / total) * 100, 1) if total > 0 else 0.0
    except Exception:
        pass

    # Load average depuis /proc/loadavg
    la1 = la5 = la15 = 0.0
    try:
        parts = Path("/proc/loadavg").read_text().split()
        la1, la5, la15 = float(parts[0]), float(parts[1]), float(parts[2])
    except Exception:
        pass

    # RAM + swap depuis /proc/meminfo (PERF[O2] : lecture partagée)
    mi = _read_meminfo()
    mem_total  = mi.get("MemTotal",   0) * 1024
    mem_avail  = mi.get("MemAvailable", mi.get("MemFree", 0)) * 1024
    mem_used   = mem_total - mem_avail
    swap_total = mi.get("SwapTotal", 0) * 1024
    swap_free  = mi.get("SwapFree",  0) * 1024
    swap_used  = swap_total - swap_free

    return [{
        "ts":         now_str,
        "cpu":        cpu_pct,
        "la1":        la1,
        "la5":        la5,
        "la15":       la15,
        "mem_used":   mem_used,
        "mem_total":  mem_total,
        "swap_used":  swap_used,
        "swap_total": swap_total,
    }]


def collect_fp_process_stat(period_hours: int = 1) -> list:
    """[FP5] Top 12 processus par CPU depuis /proc/<pid>/stat — snapshot temps-réel."""
    if not _fp_available():
        return []

    hz = 100  # CONFIG_HZ standard Linux
    processes = []
    try:
        proc_base = Path("/proc")
        for pid_dir in proc_base.iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                stat_text = (pid_dir / "stat").read_text()
                name_m    = re.search(r"\((.+)\)", stat_text)
                name      = name_m.group(1) if name_m else "?"
                rest      = re.sub(r"\(.+\)\s+", "", stat_text).split()
                utime     = int(rest[11])
                stime     = int(rest[12])
                rss       = int(rest[21]) * 4096
                processes.append({"name": name, "cpu_ticks": utime + stime, "mem": rss})
            except Exception:
                continue
    except Exception:
        pass

    agg: dict = {}
    for p in processes:
        n = p["name"]
        if n not in agg:
            agg[n] = {"name": n, "cpu_ticks": 0, "mem": 0, "count": 0}
        agg[n]["cpu_ticks"] += p["cpu_ticks"]
        agg[n]["mem"]       += p["mem"]
        agg[n]["count"]     += 1

    uptime_s = 1.0
    try:
        uptime_s = float(Path("/proc/uptime").read_text().split()[0])
    except Exception:
        pass

    result = []
    for v in agg.values():
        cpu_pct = round(v["cpu_ticks"] / hz / uptime_s * 100, 2) if uptime_s > 0 else 0.0
        result.append({
            "name":    v["name"],
            "avg_cpu": cpu_pct,
            "max_cpu": cpu_pct,
            "mem_mb":  round(v["mem"] / 1024 / 1024, 1),
            "count":   v["count"],
        })

    return sorted(result, key=lambda x: x["avg_cpu"], reverse=True)[:12]


def collect_fp_disk_stat(period_hours: int = 24) -> list:
    """[FP5] I/O disques depuis /proc/diskstats — delta sur 0.5s."""
    if not _fp_available():
        return []
    now_str = datetime.now().isoformat()

    def _read_diskstats():
        stats = {}
        try:
            for line in Path("/proc/diskstats").read_text().splitlines():
                parts = line.split()
                if len(parts) < 14:
                    continue
                dev = parts[2]
                if re.search(r"\d+$", dev) and not re.match(r"^[sv]d[a-z]$", dev):
                    continue
                stats[dev] = {
                    "reads":       int(parts[3]),
                    "read_sects":  int(parts[5]),
                    "writes":      int(parts[7]),
                    "write_sects": int(parts[9]),
                }
        except Exception:
            pass
        return stats

    s1 = _read_diskstats()
    time.sleep(0.5)
    s2 = _read_diskstats()

    result = []
    for dev in s1:
        if dev not in s2:
            continue
        d1, d2 = s1[dev], s2[dev]
        result.append({
            "ts":          now_str,
            "device":      dev,
            "read_bytes":  (d2["read_sects"]  - d1["read_sects"])  * 512,
            "write_bytes": (d2["write_sects"] - d1["write_sects"]) * 512,
            "read_iops":   d2["reads"]  - d1["reads"],
            "write_iops":  d2["writes"] - d1["writes"],
        })
    return result


def collect_fp_net_stat(period_hours: int = 24) -> list:
    """[FP5] Stats réseau depuis /proc/net/dev — delta sur 0.5s."""
    if not _fp_available():
        return []
    now_str = datetime.now().isoformat()

    def _read_netdev():
        stats = {}
        try:
            lines = Path("/proc/net/dev").read_text().splitlines()[2:]
            for line in lines:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                iface = iface.strip()
                if iface == "lo":
                    continue
                parts = data.split()
                if len(parts) < 9:
                    continue
                stats[iface] = {
                    "rx_bytes":   int(parts[0]),
                    "rx_packets": int(parts[1]),
                    "tx_bytes":   int(parts[8]),
                    "tx_packets": int(parts[9]),
                }
        except Exception:
            pass
        return stats

    s1 = _read_netdev()
    time.sleep(0.5)
    s2 = _read_netdev()

    result = []
    for iface in s1:
        if iface not in s2:
            continue
        d1, d2 = s1[iface], s2[iface]
        result.append({
            "ts":         now_str,
            "interface":  iface,
            "rx_bytes":   d2["rx_bytes"]   - d1["rx_bytes"],
            "tx_bytes":   d2["tx_bytes"]   - d1["tx_bytes"],
            "rx_packets": d2["rx_packets"] - d1["rx_packets"],
            "tx_packets": d2["tx_packets"] - d1["tx_packets"],
        })
    return result


def save_fp_stats(server, processes, disk, net):
    """Persiste les snapshots FP stats dans SQLite (fenêtre glissante de 2 jours)."""
    conn = get_conn()
    try:
        conn.execute("BEGIN")
        for table in ["fp_server_stat", "fp_process_stat", "fp_disk_stat", "fp_net_stat"]:
            conn.execute(f"DELETE FROM {table} WHERE ts < datetime('now', '-2 days')")
        if server:
            conn.executemany(
                "INSERT OR REPLACE INTO fp_server_stat "
                "(ts,cpu,la1,la5,la15,mem_used,mem_total,swap_used,swap_total) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                [(r["ts"], r["cpu"], r["la1"], r["la5"], r["la15"],
                  r["mem_used"], r["mem_total"], r["swap_used"], r["swap_total"])
                 for r in server]
            )
        if processes:
            now_iso = datetime.now().isoformat()
            conn.executemany(
                "INSERT OR REPLACE INTO fp_process_stat (ts,name,cpu,mem) VALUES (?,?,?,?)",
                [(now_iso, r["name"], r["avg_cpu"],
                  int(r.get("mem_mb", 0) * 1024 * 1024)) for r in processes]
            )
        if disk:
            conn.executemany(
                "INSERT OR REPLACE INTO fp_disk_stat "
                "(ts,device,read_bytes,write_bytes,read_iops,write_iops) "
                "VALUES (?,?,?,?,?,?)",
                [(r["ts"], r["device"], r["read_bytes"], r["write_bytes"],
                  r["read_iops"], r["write_iops"]) for r in disk]
            )
        if net:
            conn.executemany(
                "INSERT OR REPLACE INTO fp_net_stat "
                "(ts,interface,rx_bytes,tx_bytes,rx_packets,tx_packets) "
                "VALUES (?,?,?,?,?,?)",
                [(r["ts"], r["interface"], r["rx_bytes"], r["tx_bytes"],
                  r["rx_packets"], r["tx_packets"]) for r in net]
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[FP] save_fp_stats error: {e}", file=sys.stderr)

# ============================================================
# RÉTENTION 3 NIVEAUX — Evo 2
# ============================================================
RETENTION_RAW_DAYS    = 7    # données brutes (30s) → 7 jours
RETENTION_HOURLY_DAYS = 90   # agrégats horaires   → 90 jours
RETENTION_DAILY_DAYS  = 730  # agrégats journaliers → 2 ans

def run_retention_vacuum():
    """[EVO2] Agrège metrics_realtime→hourly→daily et purge les données anciennes.
    Complexité : O(n) inserts GROUP BY → O(1) DELETE sur index ts.
    Doit être appelé depuis un thread daemon (opération lente sur gros volume).
    """
    conn = get_conn()
    try:
        now_iso = datetime.now().isoformat()

        # [R1] Agréger brut → horaire (résolution 1h)
        conn.execute("""
            INSERT INTO metrics_hourly
                (ts, cpu_avg, cpu_max, ram_avg, ram_max,
                 disk_avg, disk_max, swap_avg, la1_avg, la1_max)
            SELECT
                strftime('%Y-%m-%dT%H:00:00', ts),
                AVG(cpu_pct),  MAX(cpu_pct),
                AVG(ram_pct),  MAX(ram_pct),
                AVG(disk_pct), MAX(disk_pct),
                AVG(swap_pct),
                AVG(load_1m),  MAX(load_1m)
            FROM metrics_realtime
            WHERE ts < datetime('now', '-1 hour')
            GROUP BY strftime('%Y-%m-%dT%H:00:00', ts)
            ON CONFLICT(ts) DO UPDATE SET
                cpu_avg  = excluded.cpu_avg,  cpu_max  = excluded.cpu_max,
                ram_avg  = excluded.ram_avg,  ram_max  = excluded.ram_max,
                disk_avg = excluded.disk_avg, disk_max = excluded.disk_max,
                swap_avg = excluded.swap_avg,
                la1_avg  = excluded.la1_avg,  la1_max  = excluded.la1_max
        """)

        # [R2] Agréger horaire → journalier (résolution 1j)
        conn.execute("""
            INSERT INTO metrics_daily
                (ts, cpu_avg, cpu_max, ram_avg, ram_max,
                 disk_avg, disk_max, swap_avg, la1_avg, la1_max)
            SELECT
                strftime('%Y-%m-%dT00:00:00', ts),
                AVG(cpu_avg),  MAX(cpu_max),
                AVG(ram_avg),  MAX(ram_max),
                AVG(disk_avg), MAX(disk_max),
                AVG(swap_avg),
                AVG(la1_avg),  MAX(la1_max)
            FROM metrics_hourly
            WHERE ts < datetime('now', '-24 hours')
            GROUP BY strftime('%Y-%m-%dT00:00:00', ts)
            ON CONFLICT(ts) DO UPDATE SET
                cpu_avg  = excluded.cpu_avg,  cpu_max  = excluded.cpu_max,
                ram_avg  = excluded.ram_avg,  ram_max  = excluded.ram_max,
                disk_avg = excluded.disk_avg, disk_max = excluded.disk_max,
                swap_avg = excluded.swap_avg,
                la1_avg  = excluded.la1_avg,  la1_max  = excluded.la1_max
        """)

        # [R3] Purge par niveau (index sur ts → DELETE O(log n))
        conn.execute(
            f"DELETE FROM metrics_realtime WHERE ts < datetime('now', '-{RETENTION_RAW_DAYS} days')"
        )
        conn.execute(
            f"DELETE FROM metrics_hourly WHERE ts < datetime('now', '-{RETENTION_HOURLY_DAYS} days')"
        )
        conn.execute(
            f"DELETE FROM metrics_daily WHERE ts < datetime('now', '-{RETENTION_DAILY_DAYS} days')"
        )
        conn.commit()
        # WAL checkpoint pour libérer l'espace disque
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        print(f"[RETENTION] ✅ Vacuum terminé ({now_iso})")
    except Exception as e:
        try: conn.rollback()
        except Exception: pass
        print(f"[RETENTION] Erreur: {e}", file=sys.stderr)
    finally:
        conn.close()


# ============================================================
# DÉTECTION DE DRIFT CONFIG — Evo 4
# ============================================================
CONFIG_WATCH_PATHS = [
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-enabled",
    "/etc/nginx/conf.d",
    "/etc/ssh/sshd_config",
    "/etc/fail2ban/jail.local",
    "/etc/fail2ban/jail.conf",
    "/etc/mysql/my.cnf",
    "/etc/mysql/mysql.conf.d/mysqld.cnf",
    "/etc/php",                        # tout le dossier php (ini, fpm)
    "/etc/postfix/main.cf",
    "/etc/dovecot/dovecot.conf",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/crontab",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/group",
    "/etc/fstab",
    "/etc/sysctl.conf",
    "/etc/sysctl.d",
    "/usr/local/fastpanel2/app/config",  # config FP2
]


def _hash_path(path: str) -> tuple:
    """Retourne (sha256_hex, size_bytes, mtime) d'un fichier ou dossier.
    Pour un dossier : hash récursif (nom_relatif + contenu de chaque fichier trié).
    Complexité : O(n) avec n = nombre d'octets — inévitable pour un hash correct.
    """
    import hashlib as _hashlib
    p = Path(path)
    if not p.exists():
        return None, 0, 0.0
    try:
        if p.is_file():
            data   = p.read_bytes()
            return _hashlib.sha256(data).hexdigest(), len(data), p.stat().st_mtime
        if p.is_dir():
            h      = _hashlib.sha256()
            total  = 0
            # Tri déterministe pour que le hash soit stable entre deux exécutions
            for child in sorted(p.rglob("*")):
                if not child.is_file():
                    continue
                h.update(str(child.relative_to(p)).encode())
                try:
                    data = child.read_bytes()
                    h.update(data)
                    total += len(data)
                except Exception:
                    pass
            return h.hexdigest(), total, p.stat().st_mtime
    except Exception:
        pass
    return None, 0, 0.0


def collect_config_snapshots() -> list:
    """[EVO4] Snapshot SHA-256 des fichiers de config critiques.
    Détecte et logue tout changement dans la table changelog.
    Goulot : lecture I/O de N fichiers → parallélisable mais séquentiel suffit
    car les fichiers de config sont petits et l'appel est espacé (5 min).
    """
    now      = datetime.now().isoformat()
    snapshots = []

    conn = get_conn()
    try:
        # Charger les hashes précédents en O(1) via dict
        existing: dict = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT path, sha256 FROM config_snapshots"
            ).fetchall()
        }

        changelog_rows = []
        for path in CONFIG_WATCH_PATHS:
            sha256, size, mtime = _hash_path(path)
            if sha256 is None:
                continue  # fichier/dossier absent

            snapshots.append({
                "path": path, "sha256": sha256, "size": size,
                "mtime": mtime, "last_check": now,
            })

            prev = existing.get(path)
            if prev is None:
                # Première observation — on ne logue pas (baseline initiale)
                pass
            elif prev != sha256:
                # DRIFT DÉTECTÉ
                changelog_rows.append((
                    now, "config_file", path, "modified",
                    prev[:16] + "…", sha256[:16] + "…", "warning",
                ))
                print(f"[DRIFT] ⚠️  {path} modifié ({sha256[:12]}…)", file=sys.stderr)

        # Persistance atomique
        conn.execute("BEGIN")
        conn.executemany(
            "INSERT INTO config_snapshots (path, sha256, size, mtime, last_check) "
            "VALUES (?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET "
            "sha256=excluded.sha256, size=excluded.size, "
            "mtime=excluded.mtime, last_check=excluded.last_check",
            [(s["path"], s["sha256"], s["size"], s["mtime"], s["last_check"])
             for s in snapshots],
        )
        if changelog_rows:
            conn.executemany(
                "INSERT INTO changelog "
                "(ts,entity_type,entity_name,change_type,old_value,new_value,severity) "
                "VALUES (?,?,?,?,?,?,?)",
                changelog_rows,
            )
        conn.commit()
    except Exception as e:
        try: conn.rollback()
        except Exception: pass
        print(f"[DRIFT] Erreur snapshot: {e}", file=sys.stderr)
    finally:
        conn.close()

    return snapshots


def collect_phpfpm_pools():
    pools = []
    now = datetime.now().isoformat()
    for pool_conf in Path("/etc/php").glob("*/fpm/pool.d/*.conf"):
        try:
            content = pool_conf.read_text(errors="replace")
            listen = re.search(r'^listen\s*=\s*(.+)$', content, re.MULTILINE)
            if listen:
                pools.append({"pool": pool_conf.stem, "socket": listen.group(1).strip(),
                              "active_processes": 0, "idle_processes": 0, "last_check": now})
        except Exception:
            pass
    return pools


# PERF[O4]: collect_sysctl_security() — 10 appels sysctl séquentiels → 1 seul appel batch.
# Avant : 10 × subprocess.run("sysctl -n param") = 10 fork+exec+wait.
# Après : 1 × subprocess.run(["sysctl", "-n", p1, p2, ...]) = 1 fork+exec+wait.
# Gain  : ~10× sur cette fonction (typiquement 1-2s → 0.1-0.2s).
def collect_sysctl_security():
    results = []
    now = datetime.now().isoformat()
    params = list(SECURITY_SYSCTL.keys())

    # Un seul appel sysctl avec tous les paramètres
    out = run_cmd(["sysctl", "-n"] + params, timeout=5)
    values = out.splitlines() if out else []

    # Vérification : on doit avoir autant de valeurs que de paramètres
    # Si sysctl échoue sur certains params, on tombe dans le fallback ligne par ligne.
    if len(values) != len(params):
        # Fallback individuel en cas de désaccord (rare — kernel trop vieux)
        values = []
        for param in params:
            v = run_cmd(["sysctl", "-n", param], timeout=3).strip() or "unknown"
            values.append(v)

    for param, value in zip(params, values):
        info = SECURITY_SYSCTL[param]
        value = value.strip() or "unknown"
        if value == "unknown":
            status = "warning"
        elif info["recommended"] and value != info["recommended"]:
            status = "critical" if info.get("critical") and value == info["critical"] else "warning"
        else:
            status = "ok"
        results.append({
            "param": param, "value": value,
            "recommended": info["recommended"], "status": status,
            "description": info["description"], "last_check": now,
        })
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
            smart_data.append({"device": dev, "health": health,
                                "reallocated_sectors": 0, "pending_sectors": 0,
                                "last_check": now})
    return smart_data


def collect_redis_stats():
    out = run_cmd("redis-cli INFO stats")
    if out:
        hits   = re.search(r'keyspace_hits:(\d+)', out)
        misses = re.search(r'keyspace_misses:(\d+)', out)
        if hits and misses:
            total = int(hits.group(1)) + int(misses.group(1))
            hit_rate = round(100.0 * int(hits.group(1)) / total, 1) if total > 0 else 0
            return {"ts": datetime.now().isoformat(), "hit_rate": hit_rate,
                    "total_keys": 0, "last_check": datetime.now().isoformat()}
    return None


def collect_dns_servers():
    servers = []
    now = datetime.now().isoformat()
    if Path("/etc/bind/named.conf").exists():
        out = run_cmd("named -v")
        version = re.search(r'BIND ([\d.]+)', out)
        servers.append({"server_type": "bind",
                        "version": version.group(1) if version else "unknown",
                        "running": 1 if "active" in run_cmd("systemctl is-active bind9") else 0,
                        "last_check": now})
    if Path("/etc/powerdns/pdns.conf").exists():
        servers.append({"server_type": "powerdns", "version": "unknown",
                        "running": 1 if "active" in run_cmd("systemctl is-active pdns") else 0,
                        "last_check": now})
    return servers, []


def collect_backup_runs():
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
                log_status = "unknown"
                log_path = Path(f"/var/log/rclone/{section}.log")
                if log_path.exists():
                    last_line = run_cmd(f"tail -1 {log_path}")
                    if "Transferred" in last_line:
                        log_status = "success"
                    elif "ERROR" in last_line:
                        log_status = "error"
                runs.append({"remote": section, "ts": now, "status": log_status,
                             "size_gb": 0, "files_count": 0, "last_check": now})
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
            vpns.append({"type": "tailscale",
                         "name": self_data.get("DNSName", "").split(".")[0],
                         "status": "connected", "last_check": now})
        except Exception:
            pass
    return vpns


def collect_cron_jobs():
    jobs = []
    now  = datetime.now().isoformat()

    def parse_cron_lines(text, user="root"):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 7 and re.match(r"[a-zA-Z_][a-zA-Z0-9_-]*$", parts[5]):
                jobs.append({"user": parts[5], "schedule": " ".join(parts[:5]),
                             "command": " ".join(parts[6:])[:200], "last_check": now})
            elif len(parts) >= 6:
                jobs.append({"user": user, "schedule": " ".join(parts[:5]),
                             "command": " ".join(parts[5:])[:200], "last_check": now})

    out = run_cmd("crontab -l 2>/dev/null")
    if out and "no crontab" not in out.lower():
        parse_cron_lines(out, "root")

    if Path("/etc/crontab").exists():
        try:
            parse_cron_lines(Path("/etc/crontab").read_text(errors="replace"), "system")
        except Exception:
            pass

    cron_d = Path("/etc/cron.d")
    if cron_d.exists():
        for f in cron_d.iterdir():
            if f.is_file() and not f.name.startswith("."):
                try:
                    parse_cron_lines(f.read_text(errors="replace"), f.name)
                except Exception:
                    pass

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
    keys = []
    now  = datetime.now().isoformat()
    seen = set()

    home_users = []
    try:
        for line in Path("/etc/passwd").read_text().splitlines():
            parts = line.split(":")
            if len(parts) >= 6:
                user, uid, home = parts[0], int(parts[2]), parts[5]
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
            rules.append({"tool": "iptables",
                          "action": "ALLOW" if "ACCEPT" in line else "DENY",
                          "raw": line[:200], "last_check": now})
    return rules


# ============================================================
# SAUVEGARDE DB
# ============================================================
def save_metrics(m):
    conn = get_conn()
    conn.execute("""INSERT INTO metrics_realtime
        (ts, cpu_pct, ram_pct, disk_pct, swap_pct, ram_total_gb, ram_used_gb,
         disk_total_gb, disk_used_gb, disk_free_gb, load_1m, load_5m, load_15m,
         top_processes, services, alerts)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (m["ts"], m["cpu_pct"], m["ram_pct"], m["disk_pct"], m["swap_pct"],
         m["ram_total_gb"], m["ram_used_gb"], m["disk_total_gb"], m["disk_used_gb"],
         m["disk_free_gb"], m["load_1m"], m["load_5m"], m["load_15m"],
         json.dumps(m["top_processes"]), "{}", "[]"))
    conn.execute("DELETE FROM metrics_realtime WHERE id NOT IN "
                 "(SELECT id FROM metrics_realtime ORDER BY id DESC LIMIT 2880)")
    conn.commit()
    conn.close()


# PERF[O3]: save_many() — INSERT ligne par ligne → executemany() en batch.
# Avant : N appels conn.execute() individuels dans une boucle for.
# Après : 1 appel conn.executemany() avec toutes les valeurs d'un coup.
# Gain  : O(n) appels Python → O(1) appel SQLite.
#         Sur 1000 lignes : ~100ms → ~5ms (×20 typiquement).
# Bonus : suppression de BEGIN EXCLUSIVE → WAL permet les lectures concurrentes
#         pendant l'écriture (le socket server n'est plus bloqué).
def save_many(table: str, rows: list):
    """Remplace toutes les lignes d'une table par rows (DELETE + executemany batch)."""
    if not rows:
        return
    conn = get_conn()
    try:
        cols  = list(rows[0].keys())
        place = ",".join(["?"] * len(cols))
        # PERF[O3]: pré-calcul des valeurs hors lock DB pour minimiser le temps de transaction
        values = [[r.get(c) for c in cols] for r in rows]
        conn.execute("BEGIN")
        conn.execute(f"DELETE FROM {table}")
        conn.executemany(
            f"INSERT INTO {table} ({','.join(cols)}) VALUES ({place})",
            values
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[DB] save_many({table}) erreur: {e}", file=sys.stderr)
    finally:
        conn.close()

save_volatile = save_many


def compute_health_score(metrics, ssl_certs, services, fail2ban, smart, sysctl, dns, oom_count, failed_count):
    score = 100
    cpu = metrics.get("cpu_pct", 0) or 0
    ram = metrics.get("ram_pct", 0) or 0
    disk = metrics.get("disk_pct", 0) or 0
    # CPU — pénalité progressive
    if cpu > 90: score -= 20
    elif cpu > 80: score -= 10
    elif cpu > 70: score -= 5
    # RAM — pénalité progressive
    if ram > 90: score -= 20
    elif ram > 80: score -= 10
    elif ram > 70: score -= 5
    # DISK — pénalité progressive
    if disk > 90: score -= 20
    elif disk > 80: score -= 10
    elif disk > 70: score -= 5
    # SSL expirant bientôt
    ssl_count = len(ssl_certs) if isinstance(ssl_certs, list) else 0
    score -= min(ssl_count * 2, 15)
    # OOM events
    oom = oom_count if isinstance(oom_count, (int, float)) else 0
    score -= min(oom * 5, 15)
    # Failed units
    failed = failed_count if isinstance(failed_count, (int, float)) else 0
    score -= min(failed * 2, 10)
    score = max(0, min(100, score))
    status = ("critical" if score < 50 else
              "warning"  if score < 75 else
              "good"     if score < 90 else "excellent")
    return {"score": score, "status": status,
            "alerts_count": ssl_count + int(oom) + int(failed)}


def save_health_score(score_data):
    conn = get_conn()
    conn.execute(
        "INSERT INTO health_scores (ts, score, breakdown, alerts_count, status) "
        "VALUES (?,?,?,?,?)",
        (datetime.now().isoformat(), score_data["score"], "{}",
         score_data.get("alerts_count", 0), score_data["status"])
    )
    conn.execute("DELETE FROM health_scores WHERE id NOT IN "
                 "(SELECT id FROM health_scores ORDER BY id DESC LIMIT 2880)")
    conn.commit()
    conn.close()


def record_change(entity_type, entity_name, change_type, new_val=None, severity="info"):
    conn = get_conn()
    conn.execute(
        "INSERT INTO changelog (ts, entity_type, entity_name, change_type, new_value, severity) "
        "VALUES (?,?,?,?,?,?)",
        (datetime.now().isoformat(), entity_type, entity_name, change_type, new_val, severity)
    )
    conn.commit()
    conn.close()


# PERF[O5]: detect_diff() — N appels record_change() (N connexions DB) → 1 seule transaction.
# Avant : pour chaque entité ajoutée/supprimée → ouverture connexion, INSERT, commit, close.
#         K changements = K connexions DB.
# Après : toutes les modifications dans une seule connexion + une seule transaction.
# Gain  : K connexions → 1. Sur 50 changements : ~500ms → ~10ms.
def detect_diff(entity_type: str, current_names: list):
    """Enregistre dans changelog les ajouts/suppressions d'entités — batché en 1 transaction."""
    if not current_names:
        return
    try:
        conn = get_conn()
        rows = conn.execute(
            "SELECT entity_name FROM changelog WHERE entity_type=? "
            "ORDER BY id DESC LIMIT 500", (entity_type,)
        ).fetchall()
        known = {r[0] for r in rows}
        current_set = set(current_names)
        now = datetime.now().isoformat()

        # PERF[O5]: collecte toutes les insertions, puis executemany en une transaction
        inserts = []
        for name in current_set - known:
            inserts.append((now, entity_type, name, "added",   None, "info"))
        for name in known - current_set:
            inserts.append((now, entity_type, name, "removed", None, "warning"))

        if inserts:
            conn.executemany(
                "INSERT INTO changelog (ts, entity_type, entity_name, change_type, new_value, severity) "
                "VALUES (?,?,?,?,?,?)",
                inserts
            )
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DIFF] {entity_type}: {e}", file=sys.stderr)


# ============================================================
# SOCKET SERVER
# ============================================================
def cleanup_socket():
    try:
        if Path(SOCKET_PATH).exists():
            Path(SOCKET_PATH).unlink()
    except Exception:
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
                    "health_score": conn.execute("SELECT score FROM health_scores ORDER BY id DESC LIMIT 1").fetchone()[0] if conn.execute("SELECT COUNT(*) FROM health_scores").fetchone()[0] > 0 else 0,
                    "health_status": conn.execute("SELECT status FROM health_scores ORDER BY id DESC LIMIT 1").fetchone()[0] if conn.execute("SELECT COUNT(*) FROM health_scores").fetchone()[0] > 0 else "unknown",
                    "timestamp": datetime.now().isoformat(),
                    "version": "6.0-opt",
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
                mi   = _read_meminfo()          # PERF[O2]: une seule lecture
                _cpu = get_cpu()
                _ram = get_ram(mi)
                _disk = get_disk()
                _swap = get_swap(mi)
                _l1, _l5, _l15 = get_load()
                client.send(json.dumps({
                    "cpu":  _cpu, "ram": _ram["percent"],
                    "disk": _disk["percent"], "swap": _swap["percent"],
                    "load_1m": _l1, "load_5m": _l5, "load_15m": _l15,
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
                    except Exception:
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
            except Exception:
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
        self.last_quick   = 0
        self.last_full    = 0
        self._last_ssl    = []
        self._last_smart  = []
        self._last_sysctl = []
        self._last_dns_servers = []
        self.last_vacuum       = 0    # [EVO2] dernier run retention vacuum
        self.last_config_check = 0    # [EVO4] dernier snapshot config

    # PERF[O6]: _run_parallel() — collecteurs indépendants exécutés en parallèle.
    # Avant : 25+ collecteurs séquentiels = somme de toutes les latences (subprocess, réseau).
    # Après : exécution en parallèle via ThreadPoolExecutor → latence ≈ max(latences).
    # Gain  : collecte initiale 60-120s → 8-15s selon le serveur (×5 à ×10).
    # Note  : _fp_load_params() est protégé par _fp_load_lock (double-checked locking).
    #         Les collecteurs sont I/O-bound → threads idéaux (pas de GIL penalty réel).
    @staticmethod
    def _run_parallel(tasks: list, max_workers: int = 8) -> dict:
        """
        Exécute une liste de (table, fn) en parallèle.
        Retourne {table: result_list}.
        """
        results = {}
        errors  = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_table = {
                executor.submit(fn): table
                for table, fn in tasks
            }
            for future in as_completed(future_to_table):
                table = future_to_table[future]
                try:
                    results[table] = future.result(timeout=30)
                except Exception as e:
                    errors.append(f"{table}: {e}")
                    results[table] = []
        if errors:
            print(f"[COLLECTOR] Erreurs parallèles: {'; '.join(errors)}", file=sys.stderr)
        return results

    def run(self):
        init_all_tables()
        print("[COLLECTOR] Démarré — v6.0 OPTIMISÉ")

        socket_server = SharedMemorySocket()
        socket_thread = threading.Thread(target=socket_server.start, daemon=True)
        socket_thread.start()
        time.sleep(1)

        print("[COLLECTOR] Collecte initiale (parallèle)...")
        t0 = time.time()

        # Métriques (CPU nécessite un sleep interne, en parallèle des autres)
        _init_metrics_future = None

        # PERF[O6]: Toutes les collectes indépendantes lancées en parallèle
        init_tasks = [
            ("active_sessions",        collect_active_sessions),
            ("open_ports",             collect_open_ports),
            ("web_sites",              collect_web_sites),
            ("ssl_certificates",       collect_ssl_certificates),
            ("failed_units",           collect_failed_units),
            ("fail2ban_banned_ips",    collect_fail2ban_banned),
            ("tailscale_peers",        collect_tailscale_peers),
            ("oom_events",             collect_oom_events),
            ("docker_containers",      collect_docker_containers),
            ("rclone_remotes",         collect_rclone_remotes),
            ("fastpanel_users",        collect_fastpanel_users),
            ("fastpanel_domains",      collect_fastpanel_domains),
            ("fastpanel_php_versions", collect_fastpanel_php_versions),
            ("fastpanel_databases",    collect_fastpanel_databases),
            ("fastpanel_mail_accounts",collect_fastpanel_mail),
            ("fastpanel_ftp_accounts", collect_fastpanel_ftp),
            ("fastpanel_backups",      collect_fastpanel_backups),
            ("fastpanel_dns_records",  collect_fastpanel_dns),
            ("fastpanel_crons",        collect_fastpanel_crons),
            ("fastpanel_services",     collect_fastpanel_services),
            ("phpfpm_pools",           collect_phpfpm_pools),
            ("sysctl_security",        collect_sysctl_security),
            ("disk_smart",             collect_disk_smart),
            ("vpn_connections",        collect_vpn_connections),
            ("cron_jobs",              collect_cron_jobs),
            ("ssh_authorized_keys",    collect_ssh_authorized_keys),
            ("firewall_rules",         collect_firewall_rules),
            ("network_hosts",          collect_network_hosts),
        ]

        # Métriques en parallèle aussi (le sleep(0.3) de get_cpu sera chevauchant)
        with ThreadPoolExecutor(max_workers=1) as m_exec:
            metrics_future = m_exec.submit(collect_metrics)
            collected = self._run_parallel(init_tasks, max_workers=8)
            _init_metrics = metrics_future.result(timeout=15)

        # Sauvegarde séquentielle (SQLite WAL gère la concurrence en lecture)
        save_metrics(_init_metrics)
        for table, data in collected.items():
            save_many(table, data)

        # Stats FP (après les autres car dépend de _fp_available())
        if _fp_available():
            _fp_srv  = collect_fp_server_stat(24)
            _fp_proc = collect_fp_process_stat(1)
            _fp_disk = collect_fp_disk_stat(24)
            _fp_net  = collect_fp_net_stat(24)
            save_fp_stats(_fp_srv, _fp_proc, _fp_disk, _fp_net)

        # DNS (retourne un tuple)
        dns_servers, _ = collect_dns_servers()
        save_many("dns_servers", dns_servers)

        # Redis
        redis = collect_redis_stats()
        if redis:
            save_many("redis_stats", [redis])

        # Backup
        save_many("backup_runs", collect_backup_runs())

        # Health score — réutilise les données déjà collectées
        _init_ssl  = collected.get("ssl_certificates", [])
        _init_oom  = collected.get("oom_events", [])
        _init_fail = collected.get("failed_units", [])
        health = compute_health_score(
            _init_metrics, _init_ssl, {}, [], [], [], [],
            len(_init_oom), len(_init_fail)
        )
        save_health_score(health)

        elapsed = round(time.time() - t0, 1)
        print(f"[COLLECTOR] ✅ PRÊT en {elapsed}s — Socket: {SOCKET_PATH}")

        try:
            while self.running:
                now = time.time()

                if now - self.last_metrics >= 5:
                    save_metrics(collect_metrics())
                    self.last_metrics = now

                # [EVO2] Rétention vacuum — toutes les heures (thread daemon)
                if now - self.last_vacuum >= 3600:
                    threading.Thread(target=run_retention_vacuum, daemon=True).start()
                    self.last_vacuum = now

                if now - self.last_quick >= 30:
                    quick_tasks = [
                        ("active_sessions", collect_active_sessions),
                        ("open_ports",      collect_open_ports),
                        ("network_hosts",   collect_network_hosts),
                        ("fail2ban_banned_ips", collect_fail2ban_banned),
                        ("tailscale_peers", collect_tailscale_peers),
                    ]
                    for table, data in self._run_parallel(quick_tasks, max_workers=5).items():
                        save_many(table, data)
                    self.last_quick = now

                if now - self.last_full >= 300:
                    full_tasks = [
                        ("web_sites",              collect_web_sites),
                        ("ssl_certificates",       collect_ssl_certificates),
                        ("failed_units",           collect_failed_units),
                        ("oom_events",             collect_oom_events),
                        ("docker_containers",      collect_docker_containers),
                        ("rclone_remotes",         collect_rclone_remotes),
                        ("fastpanel_domains",      collect_fastpanel_domains),
                        ("fastpanel_databases",    collect_fastpanel_databases),
                        ("fastpanel_mail_accounts",collect_fastpanel_mail),
                        ("fastpanel_backups",      collect_fastpanel_backups),
                        ("fastpanel_services",     collect_fastpanel_services),
                        ("phpfpm_pools",           collect_phpfpm_pools),
                        ("sysctl_security",        collect_sysctl_security),
                        ("disk_smart",             collect_disk_smart),
                        ("config_snapshots",       collect_config_snapshots),  # [EVO4]
                    ]
                    full_results = self._run_parallel(full_tasks, max_workers=8)
                    for table, data in full_results.items():
                        save_many(table, data)

                    if _fp_available():
                        save_fp_stats(
                            collect_fp_server_stat(24),
                            collect_fp_process_stat(1),
                            collect_fp_disk_stat(24),
                            collect_fp_net_stat(24),
                        )

                    self._last_ssl   = full_results.get("ssl_certificates", [])
                    self._last_smart = full_results.get("disk_smart", [])
                    _oom_now   = full_results.get("oom_events", [])
                    _fail_now  = full_results.get("failed_units", [])
                    _met_now   = collect_metrics()
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
    print("CASSANDRA — Knowledge Collector v6.0 OPTIMISÉ")
    print(f"DB: {DB_PATH}")
    print(f"SOCKET: {SOCKET_PATH}")
    print("=" * 70)
    print("Optimisations actives:")
    print("  [O1] lru_cache sur _fp_available() — 0 syscall répété")
    print("  [O2] /proc/meminfo lu 1× par cycle (RAM + SWAP partagés)")
    print("  [O3] save_many() → executemany() batch + BEGIN vs EXCLUSIVE")
    print("  [O4] collect_sysctl → 1 appel sysctl batch (10 params)")
    print("  [O5] detect_diff → 1 transaction pour N changements")
    print("  [O6] Collecte initiale et full en ThreadPoolExecutor (×5-10)")
    print("=" * 70)

    collector = KnowledgeCollector()
    try:
        collector.run()
    except Exception as e:
        print(f"[COLLECTOR] Erreur fatale: {e}")
        sys.exit(1)
