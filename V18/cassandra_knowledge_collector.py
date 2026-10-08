#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Drisse ATEK
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
import shlex
import threading
import atexit
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed   # PERF[O6]
from functools import lru_cache                                    # PERF[O1]
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============================================================
# CONFIGURATION
# ============================================================
DB_PATH = "/var/lib/cassandra/cassandra.db"
# Socket dans /run (tmpfs, non nettoyé, hors /tmp world-traversable) + perms root-only.
SOCKET_PATH = "/run/cassandra/knowledge.sock"
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
    "kernel.kptr_restrict": {"recommended": "2", "critical": "0", "accepted": ["1", "2"], "description": "Restriction des pointeurs kernel"},
    "kernel.dmesg_restrict": {"recommended": "1", "critical": "0", "description": "Restriction d'accès à dmesg"},
    "kernel.randomize_va_space": {"recommended": "2", "critical": "0", "description": "ASLR"},
    # 2 = mode souple : le strict (1) casse Tailscale et Docker ; le souple protège quand même de l'usurpation.
    "net.ipv4.conf.all.rp_filter": {"recommended": "2", "critical": "0", "accepted": ["1", "2"], "description": "Protection anti-spoofing"},
    "net.ipv4.tcp_syncookies": {"recommended": "1", "critical": "0", "description": "Protection contre SYN flood"},
    "net.ipv4.conf.all.accept_redirects": {"recommended": "0", "critical": "1", "description": "Acceptation des redirections ICMP"},
    "fs.protected_symlinks": {"recommended": "1", "critical": "0", "description": "Protection des liens symboliques"},
    "fs.protected_hardlinks": {"recommended": "1", "critical": "0", "description": "Protection des hardlinks"},
    "fs.protected_fifos": {"recommended": "1", "critical": "0", "accepted": ["1", "2"], "description": "Protection des FIFOs"},
    "fs.protected_regular": {"recommended": "1", "critical": "0", "accepted": ["1", "2"], "description": "Protection des fichiers réguliers"},
}

# ============================================================
# BASE DE DONNÉES
# ============================================================
def get_conn():
    _d = Path(DB_PATH).parent
    _d.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    try:
        os.chmod(_d, 0o700)          # dossier root-only (données sensibles : mail/ftp/ssh…)
        os.chmod(DB_PATH, 0o600)     # base root-only (le dossier 700 couvre déjà -wal/-shm)
    except Exception:
        pass
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
        CREATE TABLE IF NOT EXISTS fastpanel_users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT, disk_quota_gb REAL, disk_used_gb REAL, status TEXT, roles TEXT, ssh_access INTEGER, home_dir TEXT, sites_count INTEGER, databases_count INTEGER, created_at TEXT, last_check TEXT);
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
        CREATE TABLE IF NOT EXISTS world_model (wkey TEXT PRIMARY KEY, category TEXT, value TEXT, detail TEXT, severity TEXT DEFAULT 'info', source TEXT DEFAULT 'observed', observed_at TEXT, updated_at TEXT);
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
        CREATE TABLE IF NOT EXISTS fastpanel_databases (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, db_user TEXT, size_mb REAL, db_type TEXT, owner TEXT, site TEXT, charset TEXT, dump_at TEXT, created_at TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_mail_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, domain TEXT, login TEXT, quota_mb INTEGER, used_mb INTEGER, status TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS fastpanel_ftp_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT UNIQUE, home_dir TEXT, status TEXT, owner TEXT, site TEXT, created_at TEXT, last_check TEXT);
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
        CREATE TABLE IF NOT EXISTS cassandra_config (id INTEGER PRIMARY KEY AUTOINCREMENT, cle TEXT UNIQUE, etat TEXT, valeur TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS storage_health (id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT UNIQUE, type TEXT, etat TEXT, detail TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS interfaces (id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT UNIQUE, etat TEXT, adresses TEXT, route_defaut INTEGER, last_check TEXT);
        CREATE TABLE IF NOT EXISTS hardware_state (id INTEGER PRIMARY KEY AUTOINCREMENT, temp_max REAL, batterie TEXT, heure_synchro TEXT, fuseau TEXT, os TEXT, arch TEXT, virtualisation TEXT, pare_feu TEXT, securite_noyau TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS sensor_health (famille TEXT PRIMARY KEY, periode_s INTEGER, dernier_ok TEXT, derniere_erreur TEXT, erreur TEXT, n_lignes INTEGER, n_precedent INTEGER, duree_ms INTEGER);
        CREATE TABLE IF NOT EXISTS mounts_history (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, mountpoint TEXT, used_gb REAL, total_gb REAL);
        CREATE INDEX IF NOT EXISTS idx_mounts_history ON mounts_history(mountpoint, ts);
        CREATE TABLE IF NOT EXISTS proc_mem_history (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, nom TEXT, rss_mb REAL);
        CREATE INDEX IF NOT EXISTS idx_proc_mem_history ON proc_mem_history(nom, ts);
        CREATE TABLE IF NOT EXISTS projections (cle TEXT PRIMARY KEY, valeur TEXT, severite TEXT, detail TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS backups_state (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT UNIQUE, type TEXT, dernier TEXT, age_h REAL, taille_mb REAL, taille_prec_mb REAL, hors_machine INTEGER, etat TEXT, detail TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS config_contenu (path TEXT PRIMARY KEY, texte TEXT);
        CREATE TABLE IF NOT EXISTS correlations (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, entite TEXT, alerte TEXT, causes TEXT);
        CREATE TABLE IF NOT EXISTS paquets_curseur (source TEXT PRIMARY KEY, inode INTEGER, position INTEGER);
        CREATE TABLE IF NOT EXISTS controles (id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT UNIQUE, ok INTEGER, valeur TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS mesures_diverses (id INTEGER PRIMARY KEY AUTOINCREMENT, cle TEXT UNIQUE, categorie TEXT, valeur TEXT, severite TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS logiciels (id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT UNIQUE, installe INTEGER, chemin TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS apt_updates (id INTEGER PRIMARY KEY AUTOINCREMENT, total INTEGER, securite INTEGER, paquets TEXT, last_check TEXT);
        CREATE TABLE IF NOT EXISTS system_state (id INTEGER PRIMARY KEY AUTOINCREMENT, uptime_s INTEGER, reboot_required INTEGER, reboot_pkgs TEXT, tailscale TEXT, tailscale_ip TEXT, last_check TEXT);
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
    print("[COLLECTOR] Tables initialisées (V18 : rétention, dérive de configuration)")

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
        # Le pourcentage de `df` : utilisé / (utilisé + disponible POUR LES UTILISATEURS). Avec la réserve
        # root comptée comme libre, le disque paraissait moins plein que ce que df affiche (08-10).
        dispo = stat.f_bavail * stat.f_frsize
        return {"percent": round(100.0 * used / max(used + dispo, 1), 1),
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
#   - Stockage    : SQLite en mode WAL — /usr/local/fastpanel2/app/db/fastpanel2.db
#     (FP2 n'utilise PAS MySQL pour ses propres données ; les champs database_*
#      de parameters.yml sont vides sur une installation standard. Le MySQL du
#      serveur n'héberge que les bases DES SITES, pas la config du panel.)
#   - Schéma réel constaté (2026-08-05) : les tables `domain`, `site`,
#     `ftp_account`, `certificate`, `panel_account`, `db` existent bien. Il n'y a
#     en revanche NI table `user` NI table `ssl_certificate` — noms qu'employait
#     à tort l'accès direct côté agent.
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
    # mogwai sépare par des TABULATIONS et complète chaque cellule d'espaces ; une cellule vide n'est
    # que des espaces. Couper sur « tabulation OU deux espaces » faisait glisser les colonnes (20-09 :
    # l'OWNER d'un site devenait son alias). Quand il y a des tabulations, on ne coupe que sur elles.
    sep = r'\t' if "\t" in lines[0] else r'  +'
    headers = re.split(sep, lines[0].strip())
    headers = [h.strip().lower().replace(" ", "_") for h in headers if h.strip()]
    rows = []
    for line in lines[1:]:
        if not line.strip():
            continue
        vals = re.split(sep, line.strip())
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

    # [FP0] La base de FastPanel d'abord : elle seule donne les rôles, l'accès
    # SSH et le quota réel. Le balayage de /var/www ne devinait qu'un login.
    for u in _fp_sqlite_users():
        if u["username"] and u["username"] not in seen:
            seen.add(u["username"])
            u["last_check"] = now
            users.append(u)
    if users:
        return users

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
                out = run_cmd(f"du -sb {shlex.quote(str(data_dir))} 2>/dev/null")
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


_NOM_SITE_VALIDE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")


def _nom_de_site_valide(nom) -> bool:
    """Un nom d'hôte, rien d'autre : ni le « _ » de la page par défaut de nginx, ni une ligne de tirets, ni un
    joker. Deux « sites fantômes » recevaient des alertes de sauvegarde (24-09)."""
    return bool(_NOM_SITE_VALIDE.match(str(nom or "").strip().rstrip(".").lower()))


def collect_fastpanel_domains() -> list:
    """Les sites de FastPanel, sans ce qui n'est pas un nom d'hôte (quel que soit le chemin qui l'a amené)."""
    return [d for d in (_collect_fastpanel_domains_brut() or []) if not isinstance(d, dict) or _nom_de_site_valide(d.get("domain"))]


def _collect_fastpanel_domains_brut() -> list:
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
            out_ssl = run_cmd(f"openssl x509 -in {shlex.quote(str(cert))} -noout -enddate 2>/dev/null")
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


_FP_SQLITE_PATHS = ("/usr/local/fastpanel2/app/db/fastpanel2.db",
                    "/usr/local/fastpanel/app/db/fastpanel.db")


def _fp_sqlite_query(sql: str) -> list:
    """Interroge la base de FastPanel en LECTURE SEULE STRICTE.

    C'est la base d'un autre programme, en service : `mode=ro` empêche SQLite
    d'écrire quoi que ce soit, jusqu'au journal qui suffirait à la verrouiller."""
    import sqlite3 as _sq
    for p in _FP_SQLITE_PATHS:
        if not os.path.isfile(p) or not os.access(p, os.R_OK):
            continue
        try:
            conn = _sq.connect("file:%s?mode=ro" % p, uri=True, timeout=5)
            try:
                return conn.execute(sql).fetchall()
            finally:
                conn.close()
        except Exception as e:
            print(f"[FP-SQLITE] {str(e)[:150]}", file=sys.stderr)
    return []


def _fp_sqlite_users() -> list:
    """Comptes du panneau : rôles, accès SSH, quota, sites et bases possédés."""
    rows = _fp_sqlite_query(
        "SELECT p.username, COALESCE(p.restore_email,''), COALESCE(p.status,'active'), "
        "       COALESCE(p.roles,''), COALESCE(p.ssh_access,0), COALESCE(p.quota_value,0), "
        "       COALESCE(p.home_dir,''), COALESCE(p.created_at,''), "
        "       (SELECT COUNT(*) FROM site s WHERE s.owner_id = p.id), "
        "       (SELECT COUNT(*) FROM db d WHERE d.owner_id = p.id) "
        "FROM panel_account p ORDER BY p.username")
    out = []
    for r in rows:
        if not r or not r[0]:
            continue
        # `quota_value` est en octets.
        q = round(float(r[5] or 0) / 1073741824.0, 2)
        out.append({"username": r[0], "email": r[1], "status": r[2],
                    "roles": r[3], "ssh_access": 1 if str(r[4]) in ("1", "True", "true") else 0,
                    "disk_quota_gb": q, "home_dir": r[6],
                    "created_at": str(r[7] or "")[:19],
                    "sites_count": r[8], "databases_count": r[9]})
    return out


def _fp_sqlite_ftp() -> list:
    """Comptes FTP avec le site qu'ils servent."""
    rows = _fp_sqlite_query(
        "SELECT f.name, COALESCE(f.home_dir,''), "
        "       CASE WHEN CAST(f.enabled AS TEXT) IN ('1','true') THEN 'active' "
        "            ELSE 'suspended' END, "
        "       COALESCE(p.username,''), COALESCE(s.domain,''), COALESCE(f.created,'') "
        "FROM ftp_account f "
        "LEFT JOIN panel_account p ON f.owner_id = p.id "
        "LEFT JOIN site s ON f.virtualhost_id = s.id ORDER BY f.name")
    return [{"login": r[0], "home_dir": r[1], "status": r[2], "owner": r[3],
             "site": r[4], "created_at": str(r[5] or "")[:19]}
            for r in rows if r and r[0]]


def _fp_sqlite_databases() -> list:
    rows = _fp_sqlite_query(
        "SELECT d.name, COALESCE(d.engine,'mysql'), COALESCE(d.size,0), "
        "       COALESCE(p.username,''), COALESCE(s.domain,''), COALESCE(d.charset,''), "
        "       COALESCE(d.dump_at,''), COALESCE(d.created_at,''), "
        "       (SELECT GROUP_CONCAT(du.login, ', ') FROM datbases_users lu "
        "        JOIN database_user du ON du.id = lu.user_id "
        "        WHERE lu.database_id = d.id) "
        "FROM db d "
        "LEFT JOIN panel_account p ON d.owner_id = p.id "
        "LEFT JOIN site s ON d.site_id = s.id "
        "ORDER BY d.name")
    out = []
    for r in rows:
        if not r or not r[0]:
            continue
        out.append({
            "name": r[0], "db_user": r[8] or "", "db_type": r[1] or "mysql",
            # `db.size` est en octets côté FastPanel.
            "size_mb": round(float(r[2] or 0) / 1048576.0, 2),
            "owner": r[3] or "", "site": r[4] or "", "charset": r[5] or "",
            "dump_at": str(r[6] or "")[:19], "created_at": str(r[7] or "")[:19],
        })
    return out


def collect_fastpanel_databases() -> list:
    """[FP2→MySQL] Bases de données : API /api/db → mysql information_schema."""
    now = datetime.now().isoformat()
    dbs, seen = [], set()
    if not _fp_available():
        return []

    # [FP2→SQLite] La base de FastPanel EN PREMIER : elle seule connaît le
    # propriétaire, les utilisateurs MySQL (via `datbases_users`, la faute de
    # frappe est de FastPanel) et `db.site_id` — le rattachement au site.
    # L'API et `information_schema` ne donnent que le nom et la taille, d'où
    # les colonnes « User DB » et « Propriétaire » restées vides à l'écran.
    for d in _fp_sqlite_databases():
        if d["name"] and d["name"] not in seen:
            seen.add(d["name"])
            d["last_check"] = now
            dbs.append(d)
    if dbs:
        return dbs

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
    """[FP6] Comptes FTP : base FastPanel → scan proftpd/vsftpd/pure-ftpd.

    Le commentaire d'origine affirmait que « FP2 n'expose pas de table FTP » :
    c'est faux, `ftp_account` existe et porte même `virtualhost_id`, donc le
    site servi. Le balayage des fichiers de mots de passe ne le savait pas."""
    now  = datetime.now().isoformat()
    accounts, seen = [], set()
    if not _fp_available():
        return []

    for a in _fp_sqlite_ftp():
        if a["login"] and a["login"] not in seen:
            seen.add(a["login"])
            a["last_check"] = now
            accounts.append(a)
    if accounts:
        return accounts

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
    """Backups FastPanel2 via mogwai (CLI officiel). mogwai n'expose que les PLANS de
    sauvegarde (pas l'historique des fichiers — ceux-ci partent sur le compte distant, ex.
    un NAS distant en FTP). On remonte donc l'état de chaque plan : nom, planification, périmètre
    (sites/bases), activé ?, dernière exécution. Un plan activé jamais exécuté est signalé."""
    now = datetime.now().isoformat()
    backups = []

    # [FP1] mogwai backup list --json : la source fiable des plans de sauvegarde
    raw = _mogwai(["backup", "list", "--json"], timeout=15)
    plans = []
    if raw:
        try:
            plans = json.loads(raw)
        except Exception:
            plans = []
    # owner (username) via la sortie tabulaire (le JSON ne donne que owner_id)
    owners = {}
    try:
        for r in _mogwai_parse_table(_mogwai(["backup", "list"], timeout=15)):
            oid = r.get("ID") or r.get("id")
            if oid:
                owners[str(oid)] = r.get("OWNER") or r.get("owner") or ""
    except Exception:
        pass
    for p in plans if isinstance(plans, list) else []:
        try:
            name    = p.get("name", "plan")
            enabled = bool(p.get("enabled", False))
            sites   = len(p.get("VirtualHostBackupPlans") or [])
            dbs     = len(p.get("DatabasePlans") or [])
            hour    = str(p.get("hour", "*"))
            sched   = ("toutes les %sh" % hour[2:]) if hour.startswith("*/") else ("planifié" if hour != "*" else "horaire")
            last    = (p.get("last_run_time") or "").strip()
            # NB : mogwai ne renseigne pas toujours last_run_time/executed_at même quand les
            # sauvegardes tournent (elles partent sur le compte distant, ex. un NAS distant en FTP).
            # On ne crie donc PAS au loup : un plan activé = "actif", point.
            backups.append({
                "type":       "%s · %d sites · %d bases" % (name, sites, dbs),
                "status":     ("actif · %s" % sched) if enabled else "désactivé",
                "size_mb":    0,
                "created_at": last or "—",
                "error":      "",
                "user":       owners.get(str(p.get("id")), "") or ("#%s" % p.get("owner_id", "")),
                "last_check": now,
            })
        except Exception:
            continue
    if backups:
        return backups

    # [FP2] Repli API (si un jour exposée)
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

    # [FS] Repli : scan répertoire backups FP2 (cas backups locaux)
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


_CRON_RUN_RE = re.compile(r"CRON\[\d+\]:\s*\((?P<user>[^)]+)\)\s+CMD\s+\((?P<cmd>.*)\)\s*$")


def _cron_run_lookup(runs: dict, user: str, command: str) -> str:
    """Dernière exécution d'une commande de crontab.

    Le journal reproduit la commande telle qu'écrite, mais cron applique parfois
    des retouches (échappement des %, redirections). On tente l'égalité stricte,
    puis l'inclusion, avant d'abandonner — mieux vaut « inconnu » qu'un faux
    rattachement qui masquerait un cron réellement muet."""
    cmd = (command or "").strip()[:300]
    exact = runs.get((user, cmd))
    if exact:
        return exact
    best = ""
    for (u, c), ts in runs.items():
        if u != user:
            continue
        if c.startswith(cmd[:120]) or cmd.startswith(c[:120]):
            if ts > best:
                best = ts
    return best


def _cron_last_runs() -> dict:
    """{(utilisateur, commande) -> dernier horodatage d'exécution}.

    `last_run` était écrit en dur à "" : aucune exécution n'était jamais
    enregistrée, donc impossible de détecter qu'un cron avait cessé de tourner.
    On lit le journal système, seule source de vérité sur ce qui s'est réellement
    exécuté. journalctl d'abord (systemd), repli sur /var/log/syslog."""
    out = {}
    txt = run_cmd("journalctl -u cron --since '-14 days' --no-pager -o short-iso 2>/dev/null | tail -4000",
                  timeout=25)
    if not txt.strip():
        txt = run_cmd("grep -h CRON /var/log/syslog /var/log/syslog.1 2>/dev/null | tail -4000", timeout=20)
    for line in txt.splitlines():
        m = _CRON_RUN_RE.search(line)
        if not m:
            continue
        # Horodatage en tête de ligne : ISO avec journalctl -o short-iso,
        # « Aug  5 22:01:03 » avec syslog. On normalise en 'YYYY-MM-DD HH:MM'.
        ts = ""
        iso = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})", line)
        if iso:
            ts = "%s %s" % (iso.group(1), iso.group(2))
        else:
            sysl = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2})", line)
            if sysl:
                try:
                    mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                           "Aug", "Sep", "Oct", "Nov", "Dec"].index(sysl.group(1)) + 1
                    y = datetime.now().year
                    d = datetime(y, mon, int(sysl.group(2)))
                    # Une date future signifie que la ligne date de l'an dernier
                    # (syslog n'écrit pas l'année).
                    if d > datetime.now() + timedelta(days=1):
                        d = d.replace(year=y - 1)
                    ts = "%s %s" % (d.strftime("%Y-%m-%d"), sysl.group(3))
                except Exception:
                    continue
        if not ts:
            continue
        key = (m.group("user").strip(), m.group("cmd").strip()[:300])
        if ts > out.get(key, ""):
            out[key] = ts
    return out


def collect_fastpanel_crons() -> list:
    """[FP7] Crons FP2 : /var/spool/cron/crontabs/<user> pour chaque user FP2,
    enrichis de leur DERNIÈRE EXÉCUTION réelle lue dans le journal système."""
    now  = datetime.now().isoformat()
    jobs = []
    if not _fp_available():
        return []
    try:
        runs = _cron_last_runs()
    except Exception as e:
        print("[FP7] lecture des exécutions cron impossible : %s" % e, file=sys.stderr)
        runs = {}

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
            last     = _cron_run_lookup(runs, user, command)
            jobs.append({
                "user":        user,
                "schedule":    schedule,
                "command":     command,
                "enabled":     1,
                "last_run":    last,
                # Le journal cron n'enregistre pas le code de sortie : une ligne
                # CMD prouve le lancement, pas la réussite. On ne prétend donc
                # pas connaître le statut, seulement l'exécution.
                "last_status": "ran" if last else "",
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
            "last_run":    c.get("last_run", "") or _cron_run_lookup(
                               runs, user, c.get("command", "") or ""),
            "last_status": c.get("last_status", "") or (
                               "ran" if _cron_run_lookup(
                                   runs, user, c.get("command", "") or "") else ""),
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

    # [FS] systemctl fallback — SEULES LES UNITÉS INSTALLÉES (19-09). `is-active` répond « inactive »
    # pour une unité qui n'existe pas : 19 des 28 noms de la liste n'étaient pas installés sur la
    # machine, et l'écran les comptait « tombés », avec un bouton « démarrer » sur du vide.
    for svc in fp2_services:
        charge = run_cmd(f"systemctl show {svc} -p LoadState --value 2>/dev/null").strip()
        if charge != "loaded":
            continue
        st = run_cmd(f"systemctl is-active {svc} 2>/dev/null").strip()
        if st in ("active", "inactive", "failed", "activating", "deactivating"):
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

    def add_site(domain, ssl, server_type, doc_root="", php="", ip=""):
        domain = domain.strip().lower().rstrip(".")
        # « server_name --; » ou « _ » : des attrape-tout, pas des sites (le faux site « -- » d'Orion, 08-10)
        if not domain or domain in seen or not _nom_de_site_valide(domain):
            return
        seen.add(domain)
        sites.append({"domain": domain, "ssl_enabled": 1 if ssl else 0,
                      "server_type": server_type, "php_version": php,
                      "document_root": doc_root, "status": "active", "listen_ip": ip,
                      "last_check": now})

    # /etc/nginx/fastpanel2-sites : les sites ACTIFS de FastPanel 2 (un dossier par utilisateur). Il manquait :
    # coffre, app, search… n'existaient pas pour le sensorium (08-10). Les « .includes » et leurs copies
    # (.bak, .avant-…) ne déclarent pas de site : seuls les .conf sont lus là-dedans.
    nginx_dirs = ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d",
                  "/etc/nginx/vhosts.d", "/usr/local/fastpanel2/etc/nginx", "/etc/nginx/fastpanel2-sites"]
    for ndir in nginx_dirs:
        p = Path(ndir)
        if not p.exists():
            continue
        for conf in p.rglob("*"):
            if not conf.is_file():
                continue
            if ndir.endswith("fastpanel2-sites") and conf.suffix != ".conf":
                continue
            try:
                content = conf.read_text(errors="replace")
                ssl = bool(re.search(r"ssl_certificate", content))
                root_m = re.search(r"root\s+([^;]+);", content)
                root = root_m.group(1).strip() if root_m else ""
                ip_m = re.search(r"^\s*listen\s+(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d+", content, re.M)
                for sn in re.findall(r"server_name\s+([^;]+);", content):
                    for domain in sn.strip().split():
                        if domain and not domain.startswith(("_", "*", "#")):
                            add_site(domain, ssl, "nginx", root, ip=ip_m.group(1) if ip_m else "")
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

    # LE SITE RÉPOND-IL ? Le statut était « active » par principe, jamais mesuré. Sondé ici, en parallèle.
    if sites:
        with ThreadPoolExecutor(max_workers=8) as ex:
            def _sonde_confirmee(st):
                # Un 502/503 ou un silence peut être l'instant d'un redémarrage (un déploiement redémarre
                # l'application ET le collecteur) : revérifié 3 s plus tard avant d'être une alerte (08-10).
                c = _sonde_http(st["domain"], st.get("listen_ip") or "")
                for attente in (3, 12):       # un redémarrage d'application dure une quinzaine de secondes
                    if c not in ("000", "502", "503", "504"):
                        break
                    time.sleep(attente)
                    c = _sonde_http(st["domain"], st.get("listen_ip") or "")
                return c
            for site, code in zip(sites, ex.map(_sonde_confirmee, sites)):
                site["http_code"] = code
                # `status` reste « active » (le site est déclaré) : l'écran Sites et le tableau de bord le lisent
                # ainsi. La MESURE va dans sa propre colonne.
                site["reponse"] = "répond" if code != "000" and int(code) < 500 else ("erreur %s" % code if code != "000" else "ne répond pas")
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
        out = run_cmd(f"openssl x509 -in {shlex.quote(cert_path)} -noout -enddate -subject -issuer -ext subjectAltName 2>/dev/null")
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
        # garde-fou domaine : jamais vide ni "--" → on retombe sur le nom du fichier
        if not domain or domain.strip(" -") == "":
            domain = Path(cert_path).stem
        # issuer : on isole la ligne issuer= (après subject=) puis O= ou CN=
        issuer = ""
        iss_m = re.search(r"issuer=(.+)", out)
        if iss_m:
            s = iss_m.group(1)
            o_m  = re.search(r"\bO\s*=\s*([^,/\n]+)", s)
            cn_m = re.search(r"\bCN\s*=\s*([^,/\n]+)", s)
            issuer = (o_m.group(1).strip() if o_m else (cn_m.group(1).strip() if cn_m else s.strip()))[:60]
        return {"domain": domain, "days_left": days, "cert_path": cert_path,
                "issuer": issuer, "expiry_date": expiry.strftime("%Y-%m-%d"),
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
    """Collecte les unités systemd en échec. Gère le bullet '●' en début de ligne."""
    units = []
    now = datetime.now().isoformat()
    out = run_cmd("systemctl list-units --type=service --state=failed --no-legend --no-pager")
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        # Systemctl peut préfixer avec ● • ○ * - → l'ignorer
        BULLETS = {"●", "•", "○", "*", "-", "✗", "x"}
        idx = 1 if parts[0] in BULLETS else 0
        if len(parts) <= idx:
            continue
        unit = parts[idx]
        # Ignorer les lignes d'en-tête ou de résumé
        if unit.lower() in ("unit", "load", "active", "sub", "description", "listed"):
            continue
        # Description = tout ce qui est après les 4 colonnes (unit load active sub)
        desc_start = idx + 4
        desc = " ".join(parts[desc_start:]) if len(parts) > desc_start else ""
        units.append({
            "unit": unit,
            "active_state": "failed",
            "description": desc,
            "last_check": now
        })
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
        status = run_cmd(f"fail2ban-client status {shlex.quote(jail)} 2>/dev/null")
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
        # dmesg garde ses OOM jusqu'au redémarrage : sans leur date, un OOM d'il y a trois semaines pénalisait
        # encore le score de santé (08-10). « recent » = dans les dernières 24 h.
        recent = 0
        try:
            quand = datetime.strptime(" ".join(str(ts).split()), "%a %b %d %H:%M:%S %Y")
            recent = 1 if datetime.now() - quand < timedelta(hours=24) else 0
        except Exception:
            recent = 0 if ts_match else 1
        events.append({"ts": ts, "killed_process": process[:80],
                       "memory_used_mb": mem_mb, "recent": recent, "last_check": now})
    return events


def collect_docker_containers():
    # Docker, ou Podman là où Docker n'est pas (RHEL, Fedora) : même format de sortie (08-10).
    moteur = "docker" if _qui("docker") else ("podman" if _qui("podman") else "")
    if not moteur:
        return []
    out = run_cmd(moteur + " ps -a --format '{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null")
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
                # `ip -j neigh` rend l'état en LISTE (["REACHABLE"]) : comparé comme une chaîne, aucun voisin
                # n'était jamais retenu et la table restait vide (08-10).
                if isinstance(state, list):
                    state = state[0] if state else ""
                state = str(state).lower()
                if state in ("reachable", "stale", "delay", "probe", "noarp", "permanent"):
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
            conn.execute("DELETE FROM %s WHERE %s < datetime('now', 'localtime', '-%d days')"
                         % (table, _TS_SQL, RETENTION_FP_DAYS))
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
    finally:
        conn.close()

# ============================================================
# RÉTENTION 3 NIVEAUX — Evo 2
# ============================================================
RETENTION_RAW_DAYS    = 7    # données brutes (une ligne / 30 s) → 7 jours
RETENTION_HOURLY_DAYS = 90   # agrégats horaires   → 90 jours
RETENTION_DAILY_DAYS  = 730  # agrégats journaliers → 2 ans
RETENTION_HEALTH_DAYS = 90   # score de santé (une ligne / 5 min)
RETENTION_LOG_ERRORS_DAYS = 90   # erreurs relevées dans les journaux
RETENTION_FP_DAYS     = 28   # statistiques FastPanel (réseau, disque, processus) : trois semaines
                             # pour connaître l'habitude d'un créneau (décision du 15-09), une de marge

# UNE DATE SE COMPARE NORMALISÉE (15-09). Le collecteur écrit `datetime.now().isoformat()` :
# « 2026-09-15T16:01:32 » ; SQLite rend « 2026-09-15 19:26:05 ». Comparées comme du texte,
# « …T16:01 » < « … 19:26 » est FAUX ('T' = 0x54 > espace = 0x20) : l'agrégation horaire n'a
# agrégé AUCUNE ligne de la journée (mesuré : 0 sur 2 880) et seules passaient, après minuit, les
# heures 21 à 23 de la veille. Toute comparaison passe par cette forme, et par l'heure LOCALE —
# celle qu'écrit datetime.now().
_TS_SQL = "replace(substr(ts,1,19),'T',' ')"

# ============================================================
# ERREURS APPLICATIVES — la source de la courbe « Erreurs applicatives »
# ============================================================
# La table log_errors existait sans un seul écrivain (15-09) : la courbe restait vide et rien ne
# disait pourquoi. Toutes les 5 minutes, on lit ce qui s'est AJOUTÉ aux journaux depuis la
# dernière lecture (un curseur par fichier, qui suit la rotation) ; chaque ligne d'erreur devient
# une ligne datée de SON heure. Premier passage : on part de la fin — on ne date pas à notre place
# un historique qu'on n'a pas vu naître.
LOG_DIR = os.environ.get("CASSANDRA_LOG_DIR") or "/var/log"
LOG_ERREURS_FICHIERS = (
    # (service, fichier ou motif, ligne d'erreur → (date, niveau, message), format de la date)
    ("cassandra", LOG_DIR + "/cassandra.log",
     r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (ERROR|CRITICAL)\s+(.*)$", "%Y-%m-%d %H:%M:%S"),
    ("nginx", "/var/log/nginx/error.log",
     r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(error|crit|alert|emerg)\] (.*)$", "%Y/%m/%d %H:%M:%S"),
    ("php-fpm", "/var/log/php*-fpm*.log",
     r"^\[(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2})\] (ERROR|ALERT|CRITICAL|EMERGENCY): (.*)$", "%d-%b-%Y %H:%M:%S"),
)
LOG_ERREURS_JOURNALD = True          # erreurs du journal système (priorité err et au-dessus)
LOG_ERREURS_MAX_PAR_PASSE = 200      # lignes détaillées par source ; au-delà, une ligne de synthèse
LOG_ERREURS_LECTURE_MAX = 8 * 1024 * 1024
_NIVEAU_JOURNALD = {0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR"}
_MOIS_ANGLAIS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _log_erreur_date(texte, fmt):
    """La date d'une ligne, rendue « AAAA-MM-JJ HH:MM:SS ». Le mois abrégé (php-fpm) est traduit à
    la main : `%b` dépend de la langue du processus."""
    try:
        if "%b" in fmt:
            for i, m in enumerate(_MOIS_ANGLAIS):
                if "-%s-" % m in texte:
                    texte = texte.replace("-%s-" % m, "-%02d-" % (i + 1))
                    break
            fmt = fmt.replace("%b", "%m")
        return datetime.strptime(texte, fmt).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _log_errors_curseur(conn, source, inode, position, curseur, maintenant):
    conn.execute("INSERT OR REPLACE INTO log_errors_curseur (source, inode, position, curseur, maj) "
                 "VALUES (?,?,?,?,?)", (source, inode, position, curseur, maintenant))


def _log_errors_journald(conn, maintenant):
    """Erreurs du journal système depuis le dernier curseur. Cassandra écrit déjà dans son propre
    fichier : les lignes de son unité ne sont pas comptées deux fois."""
    import shutil as _sh
    if not _sh.which("journalctl"):
        return []
    r = conn.execute("SELECT curseur FROM log_errors_curseur WHERE source='journald'").fetchone()
    if r is None or not r["curseur"]:
        sortie = subprocess.run(["journalctl", "-n", "0", "--show-cursor", "--no-pager"],
                                capture_output=True, text=True, timeout=20).stdout
        m = re.search(r"cursor:\s*(\S+)", sortie or "")
        if m:
            _log_errors_curseur(conn, "journald", None, None, m.group(1), maintenant)
        return []
    p = subprocess.run(["journalctl", "-p", "err", "-o", "json", "--no-pager", "--after-cursor", r["curseur"]],
                       capture_output=True, text=True, timeout=30)
    par_service, dernier = {}, r["curseur"]
    for ligne in (p.stdout or "").splitlines():
        try:
            e = json.loads(ligne)
        except Exception:
            continue
        dernier = e.get("__CURSOR") or dernier
        unite = e.get("_SYSTEMD_UNIT") or ""
        if unite.startswith("cassandra.service"):
            continue
        service = str(e.get("SYSLOG_IDENTIFIER") or unite or "système")[:60]
        try:
            ts = datetime.fromtimestamp(int(e.get("__REALTIME_TIMESTAMP") or 0) / 1e6).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = maintenant
        try:
            niveau = _NIVEAU_JOURNALD.get(int(e.get("PRIORITY") or 3), "ERROR")
        except Exception:
            niveau = "ERROR"
        msg = e.get("MESSAGE")
        if isinstance(msg, list):
            msg = bytes(msg).decode("utf-8", "replace")
        par_service.setdefault(service, []).append((ts, service, niveau, str(msg or "")[:500]))
    _log_errors_curseur(conn, "journald", None, None, dernier, maintenant)
    return list(par_service.items())


def collect_log_errors():
    """Relève les lignes d'erreur AJOUTÉES aux journaux depuis la dernière passe. Rend le nombre de
    lignes écrites dans log_errors."""
    import glob as _glob
    conn = get_conn()
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS log_errors (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, "
                     "service TEXT, level TEXT, message TEXT, count INTEGER, last_seen TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS log_errors_curseur (source TEXT PRIMARY KEY, inode INTEGER, "
                     "position INTEGER, curseur TEXT, maj TEXT)")
        maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        a_ecrire = []
        for service, motif, rx, fmt in LOG_ERREURS_FICHIERS:
            expr = re.compile(rx)
            for chemin in sorted(_glob.glob(motif)):
                cle = "fichier:" + chemin
                try:
                    st = os.stat(chemin)
                except OSError:
                    continue
                r = conn.execute("SELECT inode, position FROM log_errors_curseur WHERE source=?", (cle,)).fetchone()
                if r is None:
                    _log_errors_curseur(conn, cle, st.st_ino, st.st_size, None, maintenant)
                    continue
                # Rotation : autre inode, ou fichier plus court que ce qu'on avait lu → depuis le début.
                pos = r["position"] or 0
                if r["inode"] != st.st_ino or st.st_size < pos:
                    pos = 0
                if st.st_size == pos:
                    continue
                with open(chemin, "rb") as f:
                    f.seek(pos)
                    bloc = f.read(LOG_ERREURS_LECTURE_MAX)
                fin = bloc.rfind(b"\n")
                if fin < 0:
                    continue          # une ligne en cours d'écriture : elle sera lue entière la prochaine fois
                utile = bloc[:fin + 1]
                trouvees = []
                for brute in utile.decode("utf-8", "replace").splitlines():
                    m = expr.match(brute)
                    if m:
                        trouvees.append((_log_erreur_date(m.group(1), fmt), service,
                                         m.group(2).upper(), m.group(3).strip()[:500]))
                if trouvees:
                    a_ecrire.append((service, trouvees))
                _log_errors_curseur(conn, cle, st.st_ino, pos + len(utile), None, maintenant)
        if LOG_ERREURS_JOURNALD:
            try:
                a_ecrire.extend(_log_errors_journald(conn, maintenant))
            except Exception as e:
                print(f"[LOG-ERRORS] journal système : {e}", file=sys.stderr)
        n = 0
        for service, trouvees in a_ecrire:
            detail, reste = trouvees[:LOG_ERREURS_MAX_PAR_PASSE], trouvees[LOG_ERREURS_MAX_PAR_PASSE:]
            for ts, srv, niveau, msg in detail:
                conn.execute("INSERT INTO log_errors (ts, service, level, message, count, last_seen) "
                             "VALUES (?,?,?,?,1,?)", (ts, srv, niveau, msg, maintenant))
                n += 1
            if reste:
                # Une avalanche ne noie pas la base : une ligne de synthèse porte le compte exact.
                conn.execute("INSERT INTO log_errors (ts, service, level, message, count, last_seen) "
                             "VALUES (?,?,?,?,?,?)",
                             (reste[-1][0], service, "ERROR",
                              "… et %d autres erreurs de %s dans cette passe, non détaillées" % (len(reste), service),
                              len(reste), maintenant))
                n += 1
        conn.commit()
        return n
    finally:
        conn.close()


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
            WHERE """ + _TS_SQL + """ < strftime('%Y-%m-%d %H:00:00', 'now', 'localtime')
              AND """ + _TS_SQL + """ >= datetime('now', 'localtime', '-6 days')
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
            WHERE """ + _TS_SQL + """ < date('now', 'localtime')
              AND """ + _TS_SQL + """ >= date('now', 'localtime', '-3 days')
            GROUP BY strftime('%Y-%m-%dT00:00:00', ts)
            ON CONFLICT(ts) DO UPDATE SET
                cpu_avg  = excluded.cpu_avg,  cpu_max  = excluded.cpu_max,
                ram_avg  = excluded.ram_avg,  ram_max  = excluded.ram_max,
                disk_avg = excluded.disk_avg, disk_max = excluded.disk_max,
                swap_avg = excluded.swap_avg,
                la1_avg  = excluded.la1_avg,  la1_max  = excluded.la1_max
        """)

        # [R3] Purge par niveau, par le TEMPS et sur la date normalisée
        for _table, _jours in (("metrics_realtime", RETENTION_RAW_DAYS),
                               ("metrics_hourly", RETENTION_HOURLY_DAYS),
                               ("metrics_daily", RETENTION_DAILY_DAYS),
                               ("health_scores", RETENTION_HEALTH_DAYS),
                               ("log_errors", RETENTION_LOG_ERRORS_DAYS)):
            try:
                conn.execute("DELETE FROM %s WHERE %s < datetime('now', 'localtime', '-%d days')"
                             % (_table, _TS_SQL, _jours))
            except sqlite3.OperationalError as _e:
                print(f"[RETENTION] {_table} : {_e}", file=sys.stderr)
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


# CE QUI A CHANGÉ, ET NON « MODIFIÉ (a1b2…) » (08-10). Le journal du collecteur disait « /etc/passwd modifié »
# plusieurs fois par heure, sans un mot de plus. On garde le texte des petits fichiers : pour ceux qui ne
# portent jamais de secret, le changement se dit en clair (compte ajouté, shell changé, ligne sudo) ; pour
# les autres (dovecot, mysql… qui peuvent porter un mot de passe), seulement le NOM des directives touchées.
# Un dossier se résume par fichier : ajouté, retiré, modifié.
_DERIVE_EN_CLAIR = ("/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/hosts", "/etc/resolv.conf", "/etc/fstab",
                    "/etc/crontab", "/etc/sysctl.conf", "/etc/ssh/sshd_config", "/etc/nginx/nginx.conf")
_DERIVE_TEXTE_MAX = 256 * 1024


def _derive_etat(path: str):
    """Le contenu gardé pour comparer : le texte d'un petit fichier, ou {fichier: sha} d'un dossier."""
    p = Path(path)
    try:
        if p.is_file():
            if p.stat().st_size > _DERIVE_TEXTE_MAX:
                return None
            return p.read_text(errors="replace")
        if p.is_dir():
            carte = {}
            for f in sorted(p.rglob("*")):
                if f.is_file():
                    try:
                        carte[str(f.relative_to(p))] = hashlib.sha256(f.read_bytes()).hexdigest()[:16]
                    except Exception:
                        pass
            return json.dumps(carte, sort_keys=True)
    except Exception:
        return None
    return None


def _derive_resume(path: str, ancien, nouveau) -> str:
    """Une phrase sur ce qui a changé, jamais un secret."""
    if ancien is None or nouveau is None:
        return "modifié (contenu précédent inconnu : le détail viendra au prochain changement)"
    if Path(path).is_dir():
        try:
            a, b = json.loads(ancien), json.loads(nouveau)
        except Exception:
            return "modifié"
        aj = sorted(set(b) - set(a)); re_ = sorted(set(a) - set(b)); mo = sorted(k for k in set(a) & set(b) if a[k] != b[k])
        morceaux = []
        for lib, l in (("ajouté", aj), ("retiré", re_), ("modifié", mo)):
            if l:
                morceaux.append("%s : %s%s" % (lib, ", ".join(l[:5]), " (+%d)" % (len(l) - 5) if len(l) > 5 else ""))
        return " · ".join(morceaux) or "modifié (métadonnées seules)"
    la = [l for l in ancien.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    lb = [l for l in nouveau.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    if la == lb:
        return "réécrit à l'identique (commentaires ou espaces seulement)"
    if path in ("/etc/passwd", "/etc/group"):
        def carte(lignes):
            return {l.split(":", 1)[0]: l for l in lignes if ":" in l}
        a, b = carte(la), carte(lb)
        morceaux = []
        for nom in sorted(set(b) - set(a)):
            morceaux.append("%s ajouté" % (("compte " if path == "/etc/passwd" else "groupe ") + nom))
        for nom in sorted(set(a) - set(b)):
            morceaux.append("%s retiré" % (("compte " if path == "/etc/passwd" else "groupe ") + nom))
        for nom in sorted(k for k in set(a) & set(b) if a[k] != b[k]):
            pa, pb = a[nom].split(":"), b[nom].split(":")
            if path == "/etc/passwd" and len(pa) >= 7 and len(pb) >= 7:
                ch = []
                if pa[6] != pb[6]:
                    ch.append("shell %s → %s" % (pa[6], pb[6]))
                if pa[5] != pb[5]:
                    ch.append("dossier %s → %s" % (pa[5], pb[5]))
                if pa[2:4] != pb[2:4]:
                    ch.append("uid/gid %s → %s" % (":".join(pa[2:4]), ":".join(pb[2:4])))
                morceaux.append("compte %s : %s" % (nom, ", ".join(ch) or "champ texte modifié"))
            elif path == "/etc/group" and len(pa) >= 4 and len(pb) >= 4:
                ma, mb = set(filter(None, pa[3].split(","))), set(filter(None, pb[3].split(",")))
                d = ["+" + x for x in sorted(mb - ma)] + ["-" + x for x in sorted(ma - mb)]
                morceaux.append("groupe %s : %s" % (nom, " ".join(d) or "modifié"))
        return " · ".join(morceaux[:8]) + (" (+%d)" % (len(morceaux) - 8) if len(morceaux) > 8 else "") or "modifié"
    import difflib
    ajout = [l.strip() for l in lb if l not in la]
    retrait = [l.strip() for l in la if l not in lb]
    if path in _DERIVE_EN_CLAIR:
        d = ["+ " + l[:100] for l in ajout[:4]] + ["- " + l[:100] for l in retrait[:4]]
        reste = len(ajout) + len(retrait) - len(d)
        return " | ".join(d) + (" (+%d lignes)" % reste if reste > 0 else "")
    def directive(l):
        return re.split(r"[\s=:{]", l, 1)[0][:40]
    noms = sorted({directive(l) for l in ajout + retrait if directive(l)})
    return "%d ligne(s) ajoutée(s), %d retirée(s) ; directives touchées : %s" % (len(ajout), len(retrait), ", ".join(noms[:8]) or "?")


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
            etat = _derive_etat(path)
            if prev is None:
                # Première observation — on ne logue pas (baseline initiale)
                pass
            elif prev != sha256:
                ancien = conn.execute("SELECT texte FROM config_contenu WHERE path=?", (path,)).fetchone()
                resume = _derive_resume(path, ancien[0] if ancien else None, etat)
                if not resume.startswith("réécrit à l'identique"):
                    sens = path in ("/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config")
                    changelog_rows.append((now, "config_file", path, "modified", prev[:16] + "…", resume[:500],
                                           "warning" if sens else "info"))
                    print(f"[DRIFT] {path} : {resume[:200]}", file=sys.stderr)
            if etat is not None:
                conn.execute("INSERT INTO config_contenu (path, texte) VALUES (?,?) ON CONFLICT(path) DO UPDATE SET texte=excluded.texte",
                             (path, etat))

        # Persistance atomique — la transaction est déjà ouverte par les écritures de config_contenu
        # (sqlite3 l'ouvre seul au premier INSERT) : un BEGIN ici échouait et perdait toute la passe (08-10).
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
        elif info["recommended"] and value not in info.get("accepted", [info["recommended"]]):
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
            out = run_cmd(f"smartctl -H {shlex.quote(dev)}")
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
                    last_line = run_cmd(f"tail -1 {shlex.quote(str(log_path))}")
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
    """Les RÈGLES, pas les en-têtes de chaîne (08-10 : « Chain INPUT (policy ACCEPT) » comptait comme une règle) ;
    iptables (forme -S) et nftables (Orion filtre en nft : le relevé ne voyait rien de ses 84 règles)."""
    rules = []
    now = datetime.now().isoformat()
    for l in (run_cmd(["iptables", "-S"], timeout=10) or "").splitlines() if _qui("iptables") else []:
        if l.startswith("-A "):
            act = "DENY" if re.search(r"-j (DROP|REJECT)", l) else ("ALLOW" if "-j ACCEPT" in l else "AUTRE")
            m = re.search(r"--dport (\d+)", l)
            rules.append({"tool": "iptables", "chain": l.split()[1], "action": act, "port": m.group(1) if m else "",
                          "raw": l[:200], "last_check": now})
    if _qui("nft"):
        chaine = ""
        for l in (run_cmd(["nft", "list", "ruleset"], timeout=10) or "").splitlines():
            t = l.strip()
            if t.startswith("chain "):
                chaine = t.split()[1]
            elif t and not t.startswith(("table ", "chain ", "type ", "policy ", "}", "#", "set ", "elements", "flags ", "counter packets")) \
                    and re.search(r"\b(accept|drop|reject|jump|goto|return|dnat|snat|masquerade)\b", t):
                act = "DENY" if re.search(r"\b(drop|reject)\b", t) else ("ALLOW" if " accept" in " " + t else "AUTRE")
                m = re.search(r"dport (\d+)", t)
                rules.append({"tool": "nftables", "chain": chaine, "action": act, "port": m.group(1) if m else "",
                              "raw": t[:200], "last_check": now})
    return rules


# ============================================================
# LE SENSORIUM ÉLARGI (08-10) — ce que la mémoire notait faute de capteur
# ============================================================
# « config.json est vide », « omniroute n'est pas installé », « faststat.service existe » : ces
# souvenirs sont nés parce qu'aucun capteur ne relevait ces états, et ils sont restés faux des jours
# après la réparation. Un état se MESURE : services, config de Cassandra, logiciels, mises à jour.

def collect_system_services() -> list:
    """Tous les services systemd chargés, en UN appel : état, sous-état, activation au démarrage, type.
    La table system_services existait sans écrivain : le modèle du monde ne connaissait aucun service."""
    now = datetime.now().isoformat()
    if not _qui("systemctl"):
        return collect_services_sans_systemd()
    out = run_cmd(["systemctl", "show", "*.service", "--no-pager",
                   "-p", "Id,LoadState,ActiveState,SubState,UnitFileState,Type,Description"], timeout=20)
    services, cur = [], {}

    def _pousser(u):
        nom = (u.get("Id") or "").strip()
        if not nom.endswith(".service") or u.get("LoadState") != "loaded":
            return
        services.append({"name": nom[:-8], "status": u.get("ActiveState") or "?",
                         "sub_state": u.get("SubState") or "", "unit_file_state": u.get("UnitFileState") or "",
                         "unit_type": u.get("Type") or "", "description": (u.get("Description") or "")[:120],
                         "enabled": 1 if u.get("UnitFileState") == "enabled" else 0,
                         "active": 1 if u.get("ActiveState") == "active" else 0, "last_check": now})

    for ligne in (out or "").splitlines():
        if not ligne.strip():
            _pousser(cur)
            cur = {}
            continue
        if "=" in ligne:
            k, v = ligne.split("=", 1)
            cur[k.strip()] = v.strip()
    _pousser(cur)
    return sorted(services, key=lambda s: s["name"])


# Les clés dont on peut dire la VALEUR : adresses, modèles, fournisseurs, interrupteurs. Tout ce qui ressemble
# à un secret n'est jamais lu au-delà de « posé / vide ».
_CONFIG_SECRET_RE = re.compile(r"(?i)(key|token|secret|pass|pwd|cred|auth|cookie|session|salt|cle|mdp)")
_CONFIG_SURE_RE = re.compile(r"(?i)(_url$|^url$|model$|provider$|_enabled$|^enabled$|_paused$|_hour$|_day$|^lang)")
CASSANDRA_CONFIG = "/etc/cassandra/config.json"


def _config_valeur_sure(cle: str, v) -> str:
    if isinstance(v, bool):
        return "oui" if v else "non"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", s):
        s = re.sub(r"(?i)^([a-z][a-z0-9+.-]*://)[^/@]*@", r"\1", s)    # jamais d'identifiants d'URL
        s = s.split("?", 1)[0]
    return s[:120]


def collect_cassandra_config() -> list:
    """La config de Cassandra, clé par clé : posée ou vide, et la valeur des seules clés sans secret.
    Le fichier lui-même est un relevé : absent, vide (0 octet) ou illisible se dit tel quel."""
    now = datetime.now().isoformat()
    lignes = []
    try:
        st = os.stat(CASSANDRA_CONFIG)
    except OSError:
        return [{"cle": "__fichier__", "etat": "absent", "valeur": "", "last_check": now}]
    if st.st_size == 0:
        return [{"cle": "__fichier__", "etat": "vide", "valeur": "0 octet", "last_check": now}]
    try:
        with open(CASSANDRA_CONFIG, encoding="utf-8") as f:
            d = json.load(f)
        if not isinstance(d, dict):
            raise ValueError("pas un objet JSON")
    except Exception as e:
        return [{"cle": "__fichier__", "etat": "illisible", "valeur": str(e)[:120], "last_check": now}]
    lignes.append({"cle": "__fichier__", "etat": "ok", "valeur": "%d clés, %d octets" % (len(d), st.st_size), "last_check": now})
    for cle in sorted(d):
        v = d[cle]
        vide = v is None or v == "" or v == [] or v == {}
        sure = bool(_CONFIG_SURE_RE.search(cle)) and not _CONFIG_SECRET_RE.search(cle) and not isinstance(v, (dict, list))
        lignes.append({"cle": str(cle)[:80], "etat": "vide" if vide else "posé",
                       "valeur": "" if (vide or not sure) else _config_valeur_sure(cle, v), "last_check": now})
    return lignes


# Les logiciels dont l'absence ou la présence change une réponse. On relève aussi l'ABSENCE : « omniroute
# n'est pas installé » doit pouvoir se lire, pas se supposer.
LOGICIELS_SUIVIS = ("nginx", "apache2", "docker", "tailscale", "ollama", "omniroute", "fail2ban-client", "mysql",
                    "mariadb", "psql", "redis-server", "php", "certbot", "rclone", "node", "npm", "python3", "git",
                    "ufw", "nft", "iptables", "smartctl", "postfix", "dovecot", "proftpd", "mogwai", "caddy",
                    "claude", "sqlite3", "curl", "wg")


def collect_installed_software() -> list:
    import shutil as _sh
    now = datetime.now().isoformat()
    chemin = os.environ.get("PATH", "") + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
    out = []
    for nom in LOGICIELS_SUIVIS:
        p = _sh.which(nom, path=chemin)
        out.append({"nom": nom, "installe": 1 if p else 0, "chemin": p or "", "last_check": now})
    return out


def _qui(nom: str) -> str:
    import shutil as _sh
    return _sh.which(nom, path=os.environ.get("PATH", "") + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") or ""


def collect_apt_updates() -> list:
    """Mises à jour en attente, QUEL QUE SOIT le gestionnaire (08-10 : Cassandra n'est pas faite pour la seule
    Debian d'Orion). Lecture seule partout : simulation apt, `check-update` dnf/yum, `checkupdates` pacman (base
    temporaire, jamais la vraie), `zypper list-updates`, `apk version`. Une passe par heure suffit."""
    now = datetime.now().isoformat()
    total, secu, noms, gest = None, 0, [], ""
    if _qui("apt-get"):
        gest = "apt"
        sortie = run_cmd(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=120)
        inst = [l for l in (sortie or "").splitlines() if l.startswith("Inst ")]
        s_l = [l for l in inst if "-security" in l or "Debian-Security" in l]
        total, secu, noms = len(inst), len(s_l), [l.split()[1] for l in s_l[:12]]
    elif _qui("dnf") or _qui("yum"):
        gest = "dnf" if _qui("dnf") else "yum"
        sortie = run_cmd([gest, "-q", "check-update"], timeout=180)
        lignes = [l for l in (sortie or "").splitlines() if l and not l.startswith((" ", "Last", "Obsoleting")) and len(l.split()) == 3]
        total = len(lignes)
        sec = run_cmd([gest, "-q", "updateinfo", "list", "--security"], timeout=180)
        s_l = [l for l in (sec or "").splitlines() if l.strip() and len(l.split()) >= 3]
        secu, noms = len(s_l), [l.split()[-1] for l in s_l[:12]]
    elif _qui("checkupdates"):
        gest = "pacman"
        sortie = run_cmd(["checkupdates"], timeout=180)
        total = len([l for l in (sortie or "").splitlines() if "->" in l])
    elif _qui("zypper"):
        gest = "zypper"
        sortie = run_cmd(["zypper", "-q", "--non-interactive", "list-updates"], timeout=180)
        total = len([l for l in (sortie or "").splitlines() if l.startswith("v ")])
        sec = run_cmd(["zypper", "-q", "--non-interactive", "list-patches", "--category", "security"], timeout=180)
        secu = len([l for l in (sec or "").splitlines() if "| security" in l])
    elif _qui("apk"):
        gest = "apk"
        sortie = run_cmd(["apk", "version", "-l", "<"], timeout=120)
        total = len([l for l in (sortie or "").splitlines() if "<" in l])
    if total is None:
        return []
    return [{"total": total, "securite": secu, "paquets": ", ".join(noms), "gestionnaire": gest, "last_check": now}]


def collect_mounts() -> list:
    """TOUS les systèmes de fichiers réels (08-10) : le relevé ne regardait que « / ». Une machine qui sert
    /var ou /home sur un autre disque, un NAS monté, un volume de sauvegarde — leur remplissage, et celui des
    inodes (un disque à 40 % peut être plein d'inodes)."""
    now = datetime.now().isoformat()
    types_exclus = ("tmpfs", "devtmpfs", "overlay", "squashfs", "proc", "sysfs", "cgroup", "cgroup2", "efivarfs",
                    "ramfs", "autofs", "fuse.lxcfs", "nsfs", "tracefs", "debugfs")
    cmd = ["df", "-P", "-T", "-k"]
    for t in types_exclus:
        cmd += ["-x", t]
    out = run_cmd(cmd, timeout=15)
    inodes = {}
    out_i = run_cmd(["df", "-P", "-i"] + [a for t in types_exclus for a in ("-x", t)], timeout=15)
    for l in (out_i or "").splitlines()[1:]:
        p = l.split()
        if len(p) >= 6 and p[4].endswith("%"):
            try:
                inodes[p[5]] = float(p[4].rstrip("%"))
            except ValueError:
                pass
    montages, vus = [], set()
    for l in (out or "").splitlines()[1:]:
        p = l.split()
        if len(p) < 7 or not p[5].endswith("%"):
            continue
        dev, fstype, mp = p[0], p[1], " ".join(p[6:])
        if mp in vus or mp.startswith(("/snap/", "/var/lib/docker/", "/run/")):
            continue
        vus.add(mp)
        try:
            total_gb, used_gb = int(p[2]) / 1024 ** 2, int(p[3]) / 1024 ** 2
            pct = float(p[5].rstrip("%"))
        except ValueError:
            continue
        montages.append({"device": dev, "mountpoint": mp, "fstype": fstype, "total_gb": round(total_gb, 1),
                         "used_gb": round(used_gb, 1), "percent": pct, "inode_pct": inodes.get(mp), "last_check": now})
    return montages


def collect_storage_health() -> list:
    """RAID logiciel (mdadm) et pools ZFS : un miroir dégradé ne se voit pas dans le remplissage du disque."""
    now = datetime.now().isoformat()
    out = []
    try:
        md = Path("/proc/mdstat").read_text(errors="replace")
        nom = None
        for l in md.splitlines():
            m = re.match(r"^(md\d+)\s*:\s*(\w+)\s+(\w+)", l)
            if m:
                nom = m.group(1)
                out.append({"nom": nom, "type": m.group(3), "etat": m.group(2), "detail": "", "last_check": now})
            elif nom and re.search(r"\[[U_]+\]", l):
                motif = re.search(r"\[([U_]+)\]", l).group(1)
                out[-1]["detail"] = motif
                if "_" in motif:
                    out[-1]["etat"] = "dégradé"
            if re.search(r"(recovery|resync)\s*=", l) and out:
                out[-1]["detail"] += " · reconstruction en cours"
    except Exception:
        pass
    if _qui("zpool"):
        for l in (run_cmd(["zpool", "list", "-H", "-o", "name,health,capacity"], timeout=15) or "").splitlines():
            p = l.split("\t")
            if len(p) >= 3:
                out.append({"nom": p[0], "type": "zfs", "etat": p[1].lower(), "detail": "rempli à %s" % p[2], "last_check": now})
    return out


def collect_interfaces() -> list:
    """Les interfaces réseau, leur état et leurs adresses, et laquelle porte la route par défaut."""
    now = datetime.now().isoformat()
    out = []
    try:
        adr = json.loads(run_cmd(["ip", "-j", "addr"], timeout=5) or "[]")
    except Exception:
        adr = []
    defaut = ""
    try:
        rt = json.loads(run_cmd(["ip", "-j", "route", "show", "default"], timeout=5) or "[]")
        if rt:
            defaut = rt[0].get("dev") or ""
    except Exception:
        pass
    for itf in adr:
        nom = itf.get("ifname") or ""
        if not nom or nom == "lo" or nom.startswith(("veth", "br-", "docker")):
            continue
        infos = [a for a in (itf.get("addr_info") or []) if a.get("local") and a.get("scope") == "global"]
        v4 = [a["local"] for a in infos if a.get("family") == "inet"]
        v6 = [a["local"] for a in infos if a.get("family") == "inet6"]
        ips = v4[:3] + v6[:1] + (["+%d IPv6" % (len(v6) - 1)] if len(v6) > 1 else [])
        out.append({"nom": nom, "etat": (itf.get("operstate") or "?").lower(), "adresses": ", ".join(ips),
                    "route_defaut": 1 if nom == defaut else 0, "last_check": now})
    return out


def collect_hardware_state() -> list:
    """Températures (zones thermiques et hwmon), batterie (portables), heure synchronisée, OS, virtualisation,
    pare-feu actif, AppArmor / SELinux. Chaque mesure absente reste vide : rien n'est inventé."""
    now = datetime.now().isoformat()
    e = {"last_check": now}
    temps = []
    for f in list(Path("/sys/class/thermal").glob("thermal_zone*/temp")) + list(Path("/sys/class/hwmon").glob("hwmon*/temp*_input")):
        try:
            v = int(f.read_text().strip()) / 1000.0
            if 0 < v < 150:
                temps.append(v)
        except Exception:
            pass
    e["temp_max"] = round(max(temps), 1) if temps else None
    bat = sorted(Path("/sys/class/power_supply").glob("BAT*"))
    if bat:
        try:
            e["batterie"] = "%s%% · %s" % ((bat[0] / "capacity").read_text().strip(), (bat[0] / "status").read_text().strip().lower())
        except Exception:
            e["batterie"] = ""
    else:
        e["batterie"] = ""
    td = run_cmd(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "Timezone"], timeout=5) if _qui("timedatectl") else ""
    e["heure_synchro"] = "oui" if "NTPSynchronized=yes" in (td or "") else ("non" if "NTPSynchronized=no" in (td or "") else "")
    m = re.search(r"Timezone=(\S+)", td or "")
    e["fuseau"] = m.group(1) if m else ""
    try:
        osr = dict(l.split("=", 1) for l in Path("/etc/os-release").read_text().splitlines() if "=" in l)
        e["os"] = osr.get("PRETTY_NAME", "").strip('"')
    except Exception:
        e["os"] = ""
    e["arch"] = os.uname().machine
    e["virtualisation"] = (run_cmd(["systemd-detect-virt"], timeout=5) or "").strip() if _qui("systemd-detect-virt") else ""
    # Le pare-feu RÉELLEMENT actif : on demande à chacun, dans l'ordre où ils se superposent.
    fw = ""
    if _qui("ufw"):
        s = run_cmd(["ufw", "status"], timeout=8) or ""
        if "Status: active" in s or "État : actif" in s:
            fw = "ufw actif"
    if not fw and _qui("firewall-cmd"):
        if (run_cmd(["firewall-cmd", "--state"], timeout=8) or "").strip() == "running":
            fw = "firewalld actif"
    if not fw and _qui("nft"):
        n = len([l for l in (run_cmd(["nft", "list", "ruleset"], timeout=8) or "").splitlines() if l.strip().startswith(("ip ", "tcp ", "udp ", "ct ", "iif", "oif", "counter", "drop", "accept", "reject"))])
        if n:
            fw = "nftables (%d règles)" % n
    if not fw and _qui("iptables"):
        n = len([l for l in (run_cmd(["iptables", "-S"], timeout=8) or "").splitlines() if l.startswith("-A ")])
        fw = ("iptables (%d règles)" % n) if n else "aucune règle"
    e["pare_feu"] = fw
    mac = []
    try:
        if Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y":
            mac.append("AppArmor")
    except Exception:
        pass
    if _qui("getenforce"):
        mac.append("SELinux " + (run_cmd(["getenforce"], timeout=5) or "?").strip().lower())
    e["securite_noyau"] = ", ".join(mac)
    return [e]


def collect_services_sans_systemd() -> list:
    """Une machine sans systemd (Alpine, conteneur, vieille Devuan) : `service --status-all` ou `rc-status`."""
    now = datetime.now().isoformat()
    out = []
    if _qui("rc-status"):
        for l in (run_cmd(["rc-status", "-a"], timeout=15) or "").splitlines():
            m = re.match(r"^\s*(\S+)\s+\[\s*(\w+)\s*\]", l)
            if m:
                out.append({"name": m.group(1), "status": "active" if m.group(2) == "started" else m.group(2),
                            "sub_state": m.group(2), "unit_file_state": "", "unit_type": "", "description": "",
                            "enabled": 0, "active": 1 if m.group(2) == "started" else 0, "last_check": now})
    elif _qui("service"):
        for l in (run_cmd(["service", "--status-all"], timeout=20) or "").splitlines():
            m = re.match(r"^\s*\[\s*([+\-?])\s*\]\s+(\S+)", l)
            if m:
                act = {"+": "active", "-": "inactive"}.get(m.group(1), "?")
                out.append({"name": m.group(2), "status": act, "sub_state": "", "unit_file_state": "", "unit_type": "",
                            "description": "", "enabled": 0, "active": 1 if act == "active" else 0, "last_check": now})
    return out


def collect_system_state() -> list:
    """Uptime, redémarrage requis, état de Tailscale sur cette machine : les petits faits qu'on cite souvent."""
    now = datetime.now().isoformat()
    etat = {"last_check": now}
    try:
        with open("/proc/uptime") as f:
            etat["uptime_s"] = int(float(f.read().split()[0]))
    except Exception:
        etat["uptime_s"] = None
    etat["reboot_required"] = 1 if Path("/var/run/reboot-required").exists() else 0
    try:
        etat["reboot_pkgs"] = Path("/var/run/reboot-required.pkgs").read_text(errors="replace").replace("\n", " ").strip()[:200]
    except Exception:
        etat["reboot_pkgs"] = ""
    ts = run_cmd(["tailscale", "status", "--json"], timeout=8)
    try:
        d = json.loads(ts) if ts else {}
        etat["tailscale"] = d.get("BackendState") or ""
        etat["tailscale_ip"] = ((d.get("Self") or {}).get("TailscaleIPs") or [""])[0]
    except Exception:
        etat["tailscale"], etat["tailscale_ip"] = "", ""
    return [etat]


def _sonde_http(domaine: str, ip: str = "") -> str:
    """Le site répond-il, ICI, par le serveur web ? Sur l'adresse où le site ÉCOUTE (FastPanel lie ses sites à
    l'IP du réseau local, pas à 127.0.0.1 : sondés sur 127.0.0.1, tous « ne répondaient pas »), puis par le DNS
    public. HTTPS d'abord (certificat non vérifié : le certificat a son propre relevé), HTTP sinon. Rend le
    code, ou « 000 » si rien ne répond."""
    cibles = []
    for adr in ([ip] if ip else []) + ["127.0.0.1", ""]:
        if adr not in cibles:
            cibles.append(adr)
    for adr in cibles:
        for schema, port in (("https", 443), ("http", 80)):
            cmd = ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "4"]
            if adr:
                cmd += ["--resolve", "%s:%d:%s" % (domaine, port, adr.strip("[]"))]
            code = (run_cmd(cmd + ["%s://%s/" % (schema, domaine)], timeout=6) or "").strip()[-3:]
            if code.isdigit() and code != "000":
                return code
    return "000"


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
    # PLUS DE PLAFOND EN LIGNES (15-09). « Garder 2880 lignes » valait 48 h à une mesure par
    # minute ; écrite toutes les 5 s, la table ne gardait que 4 h 20 et la rétention de 7 jours
    # annoncée plus bas n'était jamais atteinte. La purge se fait par le TEMPS, dans
    # run_retention_vacuum.
    conn.commit()
    conn.close()


# ============================================================
# LE SENSORIUM SE SURVEILLE (08-10)
# ============================================================
# Un capteur qui plantait l'écrivait sur stderr, et c'était tout : la table gardait ses vieilles lignes, le
# modèle du monde les servait comme fraîches. Chaque famille note ici sa dernière réussite, sa dernière
# erreur, son nombre de lignes et sa période ; build_world_model en fait des entités « capteur.* ».
# Une famille d'état PERMANENT qui rend soudain zéro ligne alors qu'elle en rendait est suspecte (un capteur
# qui avale ses erreurs) ; une famille INSTANTANÉE (unités en échec, IP bannies) a le droit d'être vide.
_CAPTEURS_JAMAIS_VIDES = {"system_services", "web_sites", "open_ports", "interfaces", "system_mounts", "logiciels",
                          "cassandra_config", "hardware_state", "system_state", "docker_containers", "tailscale_peers",
                          "sysctl_security", "ssl_certificates", "firewall_rules"}


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def noter_capteur(famille: str, ok: bool, n_lignes=None, duree_ms=None, erreur: str = "", periode_s=None):
    try:
        conn = get_conn()
        try:
            r = conn.execute("SELECT n_lignes FROM sensor_health WHERE famille=?", (famille,)).fetchone()
            prec = r[0] if r else None
            now = _utc_iso()
            if ok:
                conn.execute("INSERT INTO sensor_health (famille, periode_s, dernier_ok, n_lignes, n_precedent, duree_ms, erreur) "
                             "VALUES (?,?,?,?,?,?, '') ON CONFLICT(famille) DO UPDATE SET "
                             "periode_s=COALESCE(excluded.periode_s, periode_s), dernier_ok=excluded.dernier_ok, "
                             "n_precedent=n_lignes, n_lignes=excluded.n_lignes, duree_ms=excluded.duree_ms, erreur=''",
                             (famille, periode_s, now, n_lignes, prec, duree_ms))
            else:
                conn.execute("INSERT INTO sensor_health (famille, periode_s, derniere_erreur, erreur, duree_ms) VALUES (?,?,?,?,?) "
                             "ON CONFLICT(famille) DO UPDATE SET periode_s=COALESCE(excluded.periode_s, periode_s), "
                             "derniere_erreur=excluded.derniere_erreur, erreur=excluded.erreur, duree_ms=excluded.duree_ms",
                             (famille, periode_s, now, str(erreur)[:300], duree_ms))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[CAPTEUR] {famille} : {e}", file=sys.stderr)


def releve(table: str, fn, periode_s: int, enregistrer: bool = True):
    """Un relevé mesuré : exécute, chronomètre, enregistre, et note la santé du capteur. Rend les lignes."""
    t0 = time.time()
    try:
        rows = fn()
    except Exception as e:
        noter_capteur(table, False, duree_ms=int((time.time() - t0) * 1000), erreur=str(e), periode_s=periode_s)
        print(f"[CAPTEUR] {table} en échec : {e}", file=sys.stderr)
        return []
    if enregistrer:
        save_many(table, rows if isinstance(rows, list) else [rows] if rows else [])
    noter_capteur(table, True, n_lignes=len(rows) if isinstance(rows, list) else (1 if rows else 0),
                  duree_ms=int((time.time() - t0) * 1000), periode_s=periode_s)
    return rows


# ============================================================
# ANTICIPER (08-10) — la tendance, pas seulement l'instant
# ============================================================
# Un disque à 70 % n'alarme personne ; un disque à 70 % qui prend 4 Go par jour sera plein dans onze jours.
# Les relevés sont gardés : on en tire la pente (moindres carrés), et on ne parle que d'une pente nette —
# assez de points, assez de jours, et une droite qui explique vraiment la courbe (r² ≥ 0,6).
PROJ_DISQUE_JOURS_ALERTE = 30
PROJ_HISTO_JOURS = 30


def _pente(points):
    """(pente par jour, r²) d'une série [(t_jours, y)], ou (None, 0)."""
    n = len(points)
    if n < 6:
        return None, 0.0
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n
    sxx = sum((p[0] - mx) ** 2 for p in points)
    if sxx <= 0:
        return None, 0.0
    sxy = sum((p[0] - mx) * (p[1] - my) for p in points)
    a = sxy / sxx
    syy = sum((p[1] - my) ** 2 for p in points)
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else 0.0
    return a, r2


def noter_historiques(montages: list):
    """Une ligne par montage et par processus (les 15 plus gros en mémoire, regroupés par nom), toutes les 5 min."""
    now = _utc_iso()
    procs = {}
    for l in (run_cmd(["ps", "-eo", "rss=,comm="], timeout=10) or "").splitlines():
        p = l.split(None, 1)
        if len(p) == 2 and p[0].isdigit():
            procs[p[1].strip()[:40]] = procs.get(p[1].strip()[:40], 0) + int(p[0]) / 1024.0
    gros = sorted(procs.items(), key=lambda x: -x[1])[:15]
    conn = get_conn()
    try:
        conn.executemany("INSERT INTO mounts_history (ts, mountpoint, used_gb, total_gb) VALUES (?,?,?,?)",
                         [(now, m["mountpoint"], m["used_gb"], m["total_gb"]) for m in (montages or [])])
        conn.executemany("INSERT INTO proc_mem_history (ts, nom, rss_mb) VALUES (?,?,?)", [(now, n, round(v, 1)) for n, v in gros])
        limite = (datetime.now(timezone.utc) - timedelta(days=PROJ_HISTO_JOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn.execute("DELETE FROM mounts_history WHERE ts < ?", (limite,))
        conn.execute("DELETE FROM proc_mem_history WHERE ts < ?", (limite,))
        conn.commit()
    finally:
        conn.close()


def _jours_depuis(ts, t0):
    try:
        return (datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S") - t0).total_seconds() / 86400.0
    except Exception:
        return None


def calculer_projections() -> list:
    now = datetime.now().isoformat()
    out = []
    conn = get_conn()
    try:
        t0 = datetime(2026, 1, 1)
        # Disques : jours avant plein, sur 7 jours d'historique (au moins 1 jour couvert)
        depuis = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        montages = {r[0] for r in conn.execute("SELECT DISTINCT mountpoint FROM mounts_history").fetchall()} | {"/"}
        for mp in sorted(montages):
            rows = conn.execute("SELECT ts, used_gb, total_gb FROM mounts_history WHERE mountpoint=? AND ts >= ? ORDER BY ts",
                                (mp, depuis)).fetchall()
            if mp == "/" and (len(rows) < 12 or _jours_depuis(rows[-1][0], t0) - _jours_depuis(rows[0][0], t0) < 1.0):
                # « / » a sept jours de métriques déjà gardées : la tendance existe dès le premier jour
                lim_local = (datetime.now() - timedelta(days=7)).isoformat()
                rows = conn.execute("SELECT ts, disk_used_gb, disk_total_gb FROM metrics_realtime WHERE ts >= ? AND id % 10 = 0 "
                                    "ORDER BY id", (lim_local,)).fetchall()
            pts = [(_jours_depuis(r[0], t0), r[1]) for r in rows if r[1] is not None]
            pts = [p for p in pts if p[0] is not None]
            if len(pts) < 12 or pts[-1][0] - pts[0][0] < 1.0:
                continue
            a, r2 = _pente(pts)
            libre = (rows[-1][2] or 0) - (rows[-1][1] or 0)
            if a is None:
                continue
            if a > 0.05 and r2 >= 0.6:
                jours = libre / a
                sev = "warning" if jours <= PROJ_DISQUE_JOURS_ALERTE else "info"
                val = "plein dans ~%d jours (+%.1f Go/jour, %.0f Go libres)" % (jours, a, libre)
            else:
                sev, val = "info", "stable (%+.2f Go/jour)" % a
            out.append({"cle": "disque.%s" % mp, "valeur": val, "severite": sev, "detail": "r2=%.2f" % r2, "last_check": now})
        # Mémoire des processus : une fuite = croissance régulière sur 3 jours, > 10 %/jour et > 50 Mo/jour
        depuis = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for (nom,) in conn.execute("SELECT DISTINCT nom FROM proc_mem_history WHERE ts >= ?", (depuis,)).fetchall():
            rows = conn.execute("SELECT ts, rss_mb FROM proc_mem_history WHERE nom=? AND ts >= ? ORDER BY ts", (nom, depuis)).fetchall()
            pts = [(_jours_depuis(r[0], t0), r[1]) for r in rows]
            pts = [p for p in pts if p[0] is not None]
            if len(pts) < 24 or pts[-1][0] - pts[0][0] < 1.0:
                continue
            a, r2 = _pente(pts)
            moy = sum(p[1] for p in pts) / len(pts)
            if a and a > 50 and moy > 0 and a / moy > 0.10 and r2 >= 0.7:
                out.append({"cle": "memoire.%s" % nom, "severite": "warning", "detail": "r2=%.2f" % r2, "last_check": now,
                            "valeur": "grossit de %.0f Mo/jour depuis %.0f jours (%.0f Mo aujourd'hui) : fuite probable"
                                      % (a, pts[-1][0] - pts[0][0], pts[-1][1])})
        # Certificats : un renouvellement automatique se fait à 30 jours ; à moins de 21, il a raté
        for dom, dl, iss in conn.execute("SELECT domain, days_left, issuer FROM ssl_certificates WHERE days_left IS NOT NULL").fetchall():
            if dl is not None and 0 < dl < 21:
                auto = "let's encrypt" in (iss or "").lower() or "zerossl" in (iss or "").lower() or "r3" == (iss or "").lower()
                out.append({"cle": "certificat.%s" % dom, "severite": "warning", "detail": iss or "", "last_check": now,
                            "valeur": ("expire dans %d j : le renouvellement automatique aurait dû passer à 30 j" % dl) if auto
                                      else ("expire dans %d j : à renouveler à la main" % dl)})
    finally:
        conn.close()
    return out


# ============================================================
# LES SAUVEGARDES MESURÉES (08-10)
# ============================================================
# Une sauvegarde qui échoue ne fait aucun bruit : on l'apprend le jour où on en a besoin. Ici on mesure ce
# qui existe VRAIMENT, sans rien supposer : dossiers de sauvegarde (le fichier le plus récent, sa taille,
# celle du précédent), unités systemd de sauvegarde (dernier passage, résultat), FastPanel, rclone. Et la
# seule question qui compte au jour du sinistre : y a-t-il une copie HORS de cette machine ?
# (Les copies d'avant-évolution et d'avant-déploiement ne sont pas planifiées : leur âge ne dit rien.)
SAUVEGARDE_DOSSIERS = ["/var/lib/cassandra/memory_backups", "/backup", "/backups",
                       "/srv/backup", "/srv/backups", "/var/backups/borg", "/var/backups/restic", "/var/backups/mysql",
                       "/var/backups/fastpanel", "/var/www/backups", "/home/backup", "/home/backups"]
SAUVEGARDE_DOSSIERS_ENV = "CASSANDRA_SAUVEGARDES"     # chemins supplémentaires, séparés par « : »
SAUVEGARDE_AGE_MAX_H = 26
_FS_RESEAU = ("nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse.sshfs", "fuse.rclone", "davfs", "glusterfs", "ceph", "9p")


def _fs_de(chemin: str):
    """(type de système de fichiers, point de montage) qui porte ce chemin."""
    meilleur = ("", "")
    try:
        with open("/proc/mounts") as f:
            for l in f:
                p = l.split()
                if len(p) >= 3 and (chemin == p[1] or chemin.startswith(p[1].rstrip("/") + "/")) and len(p[1]) >= len(meilleur[1]):
                    meilleur = (p[2], p[1])
    except Exception:
        pass
    return meilleur


def _dernier_fichier(dossier: str):
    """Les deux fichiers les plus récents (profondeur 3), en ignorant les fichiers en cours d'écriture."""
    fichiers = []
    base = Path(dossier)
    try:
        for i, f in enumerate(base.rglob("*")):
            if i > 20000:          # un dépôt de sauvegarde de millions de fichiers ne bloque pas le collecteur
                break
            try:
                if len(f.relative_to(base).parts) > 3 or not f.is_file() or f.name.endswith((".tmp", ".part", ".lock")):
                    continue
                st = f.stat()
                fichiers.append((st.st_mtime, st.st_size, str(f)))
            except Exception:
                continue
    except Exception:
        return None, None
    fichiers.sort(reverse=True)
    return (fichiers[0] if fichiers else None), (fichiers[1] if len(fichiers) > 1 else None)


def collect_backups() -> list:
    now = datetime.now().isoformat()
    out = []
    dossiers = list(SAUVEGARDE_DOSSIERS) + [d for d in os.environ.get(SAUVEGARDE_DOSSIERS_ENV, "").split(":") if d]
    for m in ("/mnt", "/media"):          # un disque ou un partage monté là, avec un dossier de sauvegarde
        try:
            for d in Path(m).glob("*/*"):
                if d.is_dir() and re.search(r"(?i)backup|sauvegarde", d.name):
                    dossiers.append(str(d))
        except Exception:
            pass
    vus = set()
    for d in dossiers:
        if d in vus or not os.path.isdir(d):
            continue
        vus.add(d)
        dernier, prec = _dernier_fichier(d)
        if not dernier:
            out.append({"source": d, "type": "dossier", "dernier": "", "age_h": None, "taille_mb": None, "taille_prec_mb": None,
                        "hors_machine": 0, "etat": "vide", "detail": "aucun fichier", "last_check": now})
            continue
        fs, mp = _fs_de(d)
        age_h = (time.time() - dernier[0]) / 3600.0
        t, tp = dernier[1] / 1048576.0, (prec[1] / 1048576.0 if prec else None)
        etat = "ok"
        if age_h > SAUVEGARDE_AGE_MAX_H:
            etat = "trop vieille"
        elif tp and t < 0.5 * tp:
            etat = "taille anormale"
        out.append({"source": d, "type": "dossier", "dernier": datetime.fromtimestamp(dernier[0]).isoformat(timespec="minutes"),
                    "age_h": round(age_h, 1), "taille_mb": round(t, 1), "taille_prec_mb": round(tp, 1) if tp else None,
                    "hors_machine": 1 if fs in _FS_RESEAU else 0, "etat": etat,
                    "detail": "%s sur %s (%s)" % (Path(dernier[2]).name, mp or "?", fs or "?"), "last_check": now})
    # Unités systemd de sauvegarde : dernier passage et résultat
    if _qui("systemctl"):
        noms = run_cmd(["systemctl", "list-units", "--all", "--no-legend", "--plain", "--type=service",
                        "*backup*", "*sauvegarde*", "*borg*", "*restic*", "*duplicity*", "*rsnapshot*", "*bacula*"], timeout=10) or ""
        for l in noms.splitlines():
            u = l.split()[0] if l.split() else ""
            if not u.endswith(".service") or u.startswith(("dpkg-db-backup",)):
                continue
            info = dict(x.split("=", 1) for x in (run_cmd(["systemctl", "show", u, "-p", "Result,ExecMainExitTimestamp,ExecMainStatus"], timeout=5) or "").splitlines() if "=" in x)
            ts = info.get("ExecMainExitTimestamp", "")
            age_h = None
            try:
                age_h = (datetime.now() - datetime.strptime(" ".join(ts.split()[1:3]), "%Y-%m-%d %H:%M:%S")).total_seconds() / 3600.0
            except Exception:
                pass
            ok = info.get("Result") == "success" and info.get("ExecMainStatus", "0") == "0"
            out.append({"source": u[:-8], "type": "unité systemd", "dernier": ts, "age_h": round(age_h, 1) if age_h is not None else None,
                        "taille_mb": None, "taille_prec_mb": None,
                        "hors_machine": 1 if re.search(r"(?i)borg|restic|rclone|duplicity|offsite|distant|s3|b2", u) else 0,
                        "etat": ("ok" if ok and (age_h is None or age_h <= SAUVEGARDE_AGE_MAX_H) else ("trop vieille" if ok else "échec")),
                        "detail": "résultat %s" % info.get("Result", "?"), "last_check": now})
    # FastPanel : sa dernière sauvegarde réussie
    try:
        conn = get_conn()
        try:
            r = conn.execute("SELECT created_at, status, size_mb FROM fastpanel_backups ORDER BY created_at DESC LIMIT 1").fetchone()
        finally:
            conn.close()
        if r and r[0]:
            try:
                age_h = (datetime.now() - datetime.fromisoformat(str(r[0])[:19])).total_seconds() / 3600.0
            except Exception:
                age_h = None
            out.append({"source": "fastpanel", "type": "FastPanel", "dernier": str(r[0])[:16], "age_h": round(age_h, 1) if age_h is not None else None,
                        "taille_mb": r[2], "taille_prec_mb": None, "hors_machine": 0,
                        "etat": "ok" if (str(r[1]).lower() in ("success", "ok", "done", "completed") and (age_h or 0) <= SAUVEGARDE_AGE_MAX_H) else "à vérifier",
                        "detail": "statut %s" % r[1], "last_check": now})
    except Exception:
        pass
    # rclone : une destination distante configurée (le journal dit le reste, dans backup_runs)
    for conf in (Path("/root/.config/rclone/rclone.conf"), Path("/etc/rclone/rclone.conf")):
        if conf.exists():
            try:
                cp = configparser.ConfigParser()
                cp.read(conf)
                for sec in cp.sections():
                    out.append({"source": "rclone:%s" % sec, "type": "rclone", "dernier": "", "age_h": None, "taille_mb": None,
                                "taille_prec_mb": None, "hors_machine": 1, "etat": "configuré",
                                "detail": cp.get(sec, "type", fallback="?"), "last_check": now})
            except Exception:
                pass
    return out


# ============================================================
# CAUSES ET EFFETS (08-10)
# ============================================================
# Une alerte seule dit « nginx est tombé ». Avec ce qui a changé juste avant, elle dit « nginx est tombé
# 2 min après la mise à jour de nginx-common ». Deux pièces : les mouvements de paquets entrent au journal
# des changements (dpkg, dnf), et toute entité qui PASSE en alerte cherche les changements des 30 minutes
# précédentes. On dit « cause probable », jamais « cause » : une coïncidence reste possible.
CAUSES_FENETRE_MIN = 30
_PAQUETS_JOURNAUX = (("dpkg", "/var/log/dpkg.log", re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (install|upgrade|remove|purge) (\S+) (\S+) (\S+)")),
                     ("dnf", "/var/log/dnf.rpm.log", re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S* SUBDEBUG (Upgrade|Installed|Erase|Upgraded|Install): (\S+)")))


def collect_paquets_mouvements() -> int:
    """Les paquets installés, mis à jour ou retirés depuis le dernier passage, au journal des changements."""
    n = 0
    conn = get_conn()
    try:
        for source, chemin, rx in _PAQUETS_JOURNAUX:
            try:
                st = os.stat(chemin)
            except OSError:
                continue
            r = conn.execute("SELECT inode, position FROM paquets_curseur WHERE source=?", (source,)).fetchone()
            pos = 0 if (r is None or r[0] != st.st_ino or st.st_size < (r[1] or 0)) else (r[1] or 0)
            if r is None:
                pos = st.st_size          # premier passage : on part de la fin, on ne date pas un passé qu'on n'a pas vu
            lignes = []
            if st.st_size > pos:
                with open(chemin, "rb") as f:
                    f.seek(pos)
                    bloc = f.read(4 * 1024 * 1024)
                fin = bloc.rfind(b"\n")
                if fin >= 0:
                    lignes = bloc[:fin + 1].decode("utf-8", "replace").splitlines()
                    pos += fin + 1
            for l in lignes:
                m = rx.match(l)
                if not m:
                    continue
                if source == "dpkg":
                    ts, act, pq, avant, apres = m.groups()
                    verbe = {"install": "installé", "upgrade": "mis à jour", "remove": "retiré", "purge": "purgé"}[act]
                    txt = "%s %s" % (pq.split(":")[0], verbe) + ((" (%s → %s)" % (avant, apres)) if act == "upgrade" else "")
                else:
                    ts, act, pq = m.groups()
                    verbe = {"Upgrade": "mis à jour", "Upgraded": "remplacé", "Installed": "installé", "Install": "installé", "Erase": "retiré"}.get(act, act)
                    txt = "%s %s" % (pq, verbe)
                conn.execute("INSERT INTO changelog (ts, entity_type, entity_name, change_type, old_value, new_value, severity) "
                             "VALUES (?,?,?,?,?,?,?)", (ts.replace(" ", "T"), "paquet", pq.split(":")[0][:80], "modified", None, txt[:300], "info"))
                n += 1
            conn.execute("INSERT INTO paquets_curseur (source, inode, position) VALUES (?,?,?) "
                         "ON CONFLICT(source) DO UPDATE SET inode=excluded.inode, position=excluded.position", (source, st.st_ino, pos))
        conn.commit()
    finally:
        conn.close()
    return n


_CAUSES_TYPES = ("config_file", "paquet", "service", "docker", "logiciel", "network", "config", "security", "system", "web")


def causes_probables(conn, entite: str, maintenant_local: str = None) -> list:
    """Les changements des 30 minutes qui précèdent, hors bruit (mesures continues, capteurs, prévisions), et hors
    l'entité elle-même. Les plus proches d'abord."""
    t = datetime.fromisoformat(maintenant_local) if maintenant_local else datetime.now()
    depuis = (t - timedelta(minutes=CAUSES_FENETRE_MIN)).isoformat()
    rows = conn.execute(
        "SELECT ts, entity_type, entity_name, change_type, new_value FROM changelog WHERE ts >= ? AND ts <= ? "
        "AND entity_type IN (%s) AND entity_name <> ? ORDER BY ts DESC LIMIT 8" % ",".join("?" * len(_CAUSES_TYPES)),
        [depuis, t.isoformat()] + list(_CAUSES_TYPES) + [entite]).fetchall()
    out = []
    for ts, typ, nom, chg, nv in rows:
        if typ == "config_file":
            txt = "%s modifié : %s" % (nom, (nv or "")[:140])
        elif typ == "paquet":
            txt = nv or nom
        else:
            txt = "%s %s%s" % (nom, {"added": "apparu", "removed": "disparu", "modified": "a changé"}.get(chg, chg),
                               (" → %s" % nv[:80]) if nv and chg == "modified" else "")
        out.append("%s · %s" % (str(ts)[11:16], txt))
    return out


# ============================================================
# CONTRÔLES DE BOUT EN BOUT (08-10)
# ============================================================
# Un port ouvert n'est pas un service qui marche. Ici on fait ce que ferait un visiteur : une poignée de main
# TLS VÉRIFIÉE sur chaque site (chaîne et nom — un mauvais certificat servi se voit, même si le fichier sur
# disque est bon), la résolution DNS publique de chaque domaine, la bannière des ports de courriel ouverts,
# et la page de connexion de Cassandra. Rien n'envoie de données : on lit ce que le service dit de lui-même.
def _tls_verifie(domaine: str, ip: str = "", port: int = 443):
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    try:
        with socket.create_connection((ip or domaine, port), timeout=6) as sk:
            with ctx.wrap_socket(sk, server_hostname=domaine) as t:
                cert = t.getpeercert()
        fin = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return True, "certificat valide, %d j restants" % (fin - datetime.utcnow()).days
    except _ssl.SSLCertVerificationError as e:
        return False, "certificat refusé : %s" % (getattr(e, "verify_message", "") or str(e))[:120]
    except Exception as e:
        return False, "pas de TLS : %s" % str(e)[:100]


def _dns_public(domaine: str) -> list:
    if _qui("dig"):
        out = run_cmd(["dig", "+short", "+time=3", "+tries=1", "@1.1.1.1", "A", domaine], timeout=8) or ""
        ips = [l.strip() for l in out.splitlines() if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", l.strip())]
        if ips:
            return ips
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(domaine, 443, socket.AF_INET)})
    except Exception:
        return []


def _banniere(port: int, tls: bool) -> str:
    import ssl as _ssl
    try:
        sk = socket.create_connection(("127.0.0.1", port), timeout=5)
        if tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sk = ctx.wrap_socket(sk)
        sk.settimeout(5)
        b = sk.recv(256).decode("utf-8", "replace").strip()
        sk.close()
        return b.splitlines()[0][:80] if b else ""
    except Exception as e:
        return "!" + str(e)[:60]


_PORTS_COURRIEL = {25: ("SMTP", False, "220"), 465: ("SMTPS", True, "220"), 587: ("submission", False, "220"),
                   143: ("IMAP", False, "* OK"), 993: ("IMAPS", True, "* OK"), 110: ("POP3", False, "+OK"), 995: ("POP3S", True, "+OK")}


def collect_controles() -> list:
    now = datetime.now().isoformat()
    out = []
    conn = get_conn()
    try:
        sites = conn.execute("SELECT domain, ssl_enabled, listen_ip FROM web_sites").fetchall() if \
            "listen_ip" in {r[1] for r in conn.execute("PRAGMA table_info(web_sites)")} else \
            [(r[0], r[1], "") for r in conn.execute("SELECT domain, ssl_enabled FROM web_sites").fetchall()]
        ports = {int(r[0]) for r in conn.execute("SELECT port FROM open_ports WHERE protocol LIKE 'tcp%'").fetchall() if r[0] is not None}
    finally:
        conn.close()
    # TLS vérifié et DNS public, en parallèle
    def _site(r):
        dom, ssl_on, ip = r[0], r[1], (r[2] or "").strip("[]")
        res = []
        if ssl_on:
            ok, v = _tls_verifie(dom, ip)
            res.append({"nom": "tls.%s" % dom, "ok": 1 if ok else 0, "valeur": v, "last_check": now})
        ips = _dns_public(dom)
        res.append({"nom": "dns.%s" % dom, "ok": 1 if ips else 0, "valeur": ("→ %s" % ", ".join(ips[:3])) if ips else "ne résout pas", "last_check": now})
        return res
    with ThreadPoolExecutor(max_workers=6) as ex:
        for res in ex.map(_site, list(sites)):
            out.extend(res)
    # Cohérence DNS : un domaine qui pointe ailleurs que la majorité des autres
    dns = [x for x in out if x["nom"].startswith("dns.") and x["ok"]]
    compte = {}
    for x in dns:
        compte[x["valeur"]] = compte.get(x["valeur"], 0) + 1
    if len(dns) >= 3:
        majo = max(compte, key=compte.get)
        for x in dns:
            if x["valeur"] != majo and compte[x["valeur"]] == 1:
                x["valeur"] += " (les autres sites : %s)" % majo[2:]
    # Courriel : la bannière de chaque port ouvert
    for port, (nom, tls, attendu) in _PORTS_COURRIEL.items():
        if port in ports:
            b = _banniere(port, tls)
            out.append({"nom": "courriel.%s" % nom, "ok": 1 if b.startswith(attendu) else 0,
                        "valeur": ("répond : %s" % b) if b.startswith(attendu) else ("ne répond pas comme attendu : %s" % (b or "rien")),
                        "last_check": now})
    # L'interface de Cassandra : sa page de connexion
    try:
        cfg = json.load(open(CASSANDRA_CONFIG, encoding="utf-8"))
        url = (cfg.get("app_public_url") or cfg.get("base_url") or "").rstrip("/")
    except Exception:
        url = ""
    if url:
        corps = run_cmd(["curl", "-skL", "--max-time", "8", url + "/"], timeout=12) or ""
        ok = "login-username" in corps or 'id="login' in corps
        if not ok:
            time.sleep(3)      # même prudence qu'en sondant les sites : l'instant d'un redémarrage n'est pas une panne
            corps = run_cmd(["curl", "-skL", "--max-time", "8", url + "/"], timeout=12) or ""
            ok = "login-username" in corps or 'id="login' in corps
        out.append({"nom": "cassandra.connexion", "ok": 1 if ok else 0,
                    "valeur": ("la page de connexion s'affiche (%s)" % url) if ok else ("page de connexion introuvable sur %s" % url),
                    "last_check": now})
    return out


# ============================================================
# LES MESURES QUI MANQUAIENT (08-10)
# ============================================================
# Chaque collecteur rend des lignes {cle, categorie, valeur, severite} ; le modèle du monde les reprend telles
# quelles sous `<cle>`. File d'attente du courrier, connexions SSH ratées, ressources de chaque conteneur,
# renouvellement des certificats, poids des journaux.
def _mesure(cle, cat, val, sev="info"):
    return {"cle": cle, "categorie": cat, "valeur": str(val)[:300], "severite": sev, "last_check": datetime.now().isoformat()}


def collect_file_courriel() -> list:
    """Les messages coincés au départ (exim, postfix) : un serveur qui n'arrive plus à envoyer ne le dit à personne."""
    if _qui("exim"):
        n = (run_cmd(["exim", "-bpc"], timeout=15) or "").strip()
        if n.isdigit():
            n = int(n)
            gel = len([l for l in (run_cmd(["exim", "-bp"], timeout=15) or "").splitlines() if "*** frozen ***" in l]) if n else 0
            return [_mesure("courriel.file_attente", "courriel", "%d message%s en attente (exim)%s" % (n, "s" if n > 1 else "", ", dont %d gelés" % gel if gel else ""),
                            "warning" if n >= 50 or gel else "info")]
    if _qui("postqueue"):
        sortie = run_cmd(["postqueue", "-p"], timeout=15) or ""
        if "Mail queue is empty" in sortie:
            return [_mesure("courriel.file_attente", "courriel", "0 message en attente (postfix)")]
        m = re.search(r"in (\d+) Request", sortie)
        n = int(m.group(1)) if m else 0
        return [_mesure("courriel.file_attente", "courriel", "%d messages en attente (postfix)" % n, "warning" if n >= 50 else "info")]
    return []


def collect_ssh_echecs() -> list:
    """Connexions SSH ratées sur l'heure écoulée, et les adresses qui insistent le plus."""
    texte = ""
    if _qui("journalctl"):
        for unite in ("ssh", "sshd"):
            texte += run_cmd(["journalctl", "-u", unite, "--since", "-1h", "--no-pager", "-q", "-o", "cat"], timeout=20) or ""
    else:
        for f in ("/var/log/auth.log", "/var/log/secure"):
            try:
                texte += "\n".join(Path(f).read_text(errors="replace").splitlines()[-5000:])
            except Exception:
                pass
    echecs = re.findall(r"(?:Failed password|Invalid user|authentication failure|Connection closed by authenticating user)[^\n]*?from (\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{6,})", texte)
    par_ip = {}
    for ip in echecs:
        par_ip[ip] = par_ip.get(ip, 0) + 1
    top = sorted(par_ip.items(), key=lambda x: -x[1])[:3]
    val = "%d échec%s en 1 h" % (len(echecs), "s" if len(echecs) > 1 else "") + ((" · surtout %s" % ", ".join("%s (%d)" % t for t in top)) if top else "")
    return [_mesure("ssh.echecs", "security", val, "warning" if len(echecs) >= 50 else "info")]


def collect_docker_ressources() -> list:
    """CPU et mémoire de chaque conteneur (un instantané, sans flux)."""
    moteur = "docker" if _qui("docker") else ("podman" if _qui("podman") else "")
    if not moteur:
        return []
    out = []
    for l in (run_cmd([moteur, "stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}"], timeout=30) or "").splitlines():
        p = l.split("|")
        if len(p) >= 4:
            try:
                mp = float(p[3].strip().rstrip("%") or 0)
            except ValueError:
                mp = 0
            out.append(_mesure("conteneur_ressources.%s" % p[0].strip(), "resource",
                               "CPU %s · mémoire %s (%s)" % (p[1].strip(), p[2].strip(), p[3].strip()), "warning" if mp >= 90 else "info"))
    return out


def collect_certbot() -> list:
    """Le renouvellement automatique des certificats : dernier passage, résultat, certificats suivis."""
    out = []
    ren = Path("/etc/letsencrypt/renewal")
    n = len(list(ren.glob("*.conf"))) if ren.is_dir() else 0
    if _qui("systemctl"):
        info = dict(x.split("=", 1) for x in (run_cmd(["systemctl", "show", "certbot.service", "-p", "Result,ExecMainExitTimestamp,LoadState"], timeout=5) or "").splitlines() if "=" in x)
        if info.get("LoadState") == "loaded":
            ok = info.get("Result") == "success"
            out.append(_mesure("certbot.renouvellement", "security",
                               "%s · dernier passage %s · %d certificat%s suivi%s" % ("réussi" if ok else "ÉCHEC (" + info.get("Result", "?") + ")",
                                                                                   (info.get("ExecMainExitTimestamp") or "jamais")[:30], n, "s" if n > 1 else "", "s" if n > 1 else ""),
                               "info" if ok else "warning"))
    if not out and n:
        out.append(_mesure("certbot.renouvellement", "security", "%d certificat%s certbot suivi%s (planification hors systemd)" % (n, "s" if n > 1 else "", "s" if n > 1 else "")))
    return out


def collect_journaux_poids() -> list:
    """Le poids des journaux : un journal qui gonfle remplit un disque sans bruit."""
    out = []
    if _qui("journalctl"):
        m = re.search(r"take up ([\d.]+[KMGT])", run_cmd(["journalctl", "--disk-usage"], timeout=10) or "")
        if m:
            out.append(_mesure("journaux.journald", "resource", "%so sur le disque" % m.group(1), "warning" if m.group(1).endswith(("G", "T")) and float(m.group(1)[:-1]) >= 4 else "info"))
    gros = []
    try:
        for f in Path("/var/log").rglob("*"):
            try:
                if f.is_file() and f.stat().st_size >= 500 * 1048576:
                    gros.append((f.stat().st_size, str(f)))
            except Exception:
                continue
    except Exception:
        pass
    gros.sort(reverse=True)
    out.append(_mesure("journaux.fichiers_lourds", "resource",
                       ("; ".join("%s (%.1f Go)" % (pth, t / 1073741824) for t, pth in gros[:3])) if gros else "aucun fichier de plus de 500 Mo dans /var/log",
                       "warning" if gros and gros[0][0] >= 2 * 1073741824 else "info"))
    return out


def collect_mesures_diverses() -> list:
    rows = []
    for fn in (collect_file_courriel, collect_ssh_echecs, collect_docker_ressources, collect_certbot, collect_journaux_poids):
        try:
            rows.extend(fn() or [])
        except Exception as e:
            print(f"[MESURES] {fn.__name__} : {e}", file=sys.stderr)
    return rows


# PERF[O3]: save_many() — INSERT ligne par ligne → executemany() en batch.
# Avant : N appels conn.execute() individuels dans une boucle for.
# Après : 1 appel conn.executemany() avec toutes les valeurs d'un coup.
# Gain  : O(n) appels Python → O(1) appel SQLite.
#         Sur 1000 lignes : ~100ms → ~5ms (×20 typiquement).
# Bonus : suppression de BEGIN EXCLUSIVE → WAL permet les lectures concurrentes
#         pendant l'écriture (le socket server n'est plus bloqué).
# LES RELEVÉS D'ÉTAT INSTANTANÉ, où « vide » est une vraie réponse (24-09) : sans cette liste, un relevé vide ne
# touchait pas la table, et le dernier service en échec (ou la dernière adresse bannie) y restait pour toujours —
# openipmi, désactivé à 05:00, rouvrait « Service en échec » toute la journée sur Orion.
_TABLES_INSTANTANE = {"failed_units", "fail2ban_banned_ips"}


def save_many(table: str, rows: list):
    """Remplace toutes les lignes d'une table par rows (DELETE + executemany batch)."""
    if not rows:
        if table in _TABLES_INSTANTANE:
            conn = get_conn()
            try:
                conn.execute(f"DELETE FROM {table}")
                conn.commit()
            except Exception as e:
                print(f"[DB] save_many({table}) vidage : {e}", file=sys.stderr)
            finally:
                conn.close()
        return
    conn = get_conn()
    try:
        cols  = list(rows[0].keys())
        # AUTO-MIGRATION : ajoute les colonnes manquantes pour absorber toute dérive de
        # schéma (ex: le code produit 'aliases' mais la table ne l'a pas). Évite les
        # erreurs 'has no column named X' qui vidaient la table en silence.
        try:
            existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            for c in cols:
                if c not in existing:
                    conn.execute(f'ALTER TABLE {table} ADD COLUMN "{c}"')
                    print(f"[DB] {table}: colonne '{c}' ajoutée (auto-migration)", file=sys.stderr)
        except Exception as _me:
            print(f"[DB] {table}: auto-migration impossible: {_me}", file=sys.stderr)
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
        noter_capteur(table, False, erreur="écriture en base : %s" % e)
    finally:
        conn.close()

save_volatile = save_many


def compute_health_score(metrics, ssl_certs, services, fail2ban, smart, sysctl, dns, oom_count, failed_count):
    """
    Calcul du score de santé (0–100).
    PERF: ssl_certs = liste complète → on filtre ici pour ne pénaliser que les expirés/expirants.
    Ancienne logique: -2pts par cert (même valides!) → -12pts avec 6 sites normaux = score faussé.
    """
    score = 100
    breakdown = {}

    # CPU
    cpu = metrics.get("cpu_pct", 0)
    if   cpu > 95: score -= 20; breakdown["cpu"] = -20
    elif cpu > 85: score -= 12; breakdown["cpu"] = -12
    elif cpu > 75: score -= 5;  breakdown["cpu"] = -5

    # RAM
    ram = metrics.get("ram_pct", 0)
    if   ram > 95: score -= 20; breakdown["ram"] = -20
    elif ram > 85: score -= 12; breakdown["ram"] = -12
    elif ram > 75: score -= 5;  breakdown["ram"] = -5

    # Disque
    disk = metrics.get("disk_pct", 0)
    if   disk > 95: score -= 20; breakdown["disk"] = -20
    elif disk > 85: score -= 12; breakdown["disk"] = -12
    elif disk > 75: score -= 5;  breakdown["disk"] = -5

    # SSL — UNIQUEMENT certs expirés ou expirant dans les 14 jours (pas tous les certs!)
    ssl_problems = []
    for c in (ssl_certs or []):
        days = c.get("days_left", 999)
        if isinstance(days, (int, float)):
            if days <= 0:
                ssl_problems.append(("expired", c.get("domain", "?")))
            elif days <= 14:
                ssl_problems.append(("expiring", c.get("domain", "?")))
    ssl_penalty = min(len(ssl_problems) * 5, 20)
    if ssl_penalty:
        score -= ssl_penalty
        breakdown["ssl"] = -ssl_penalty

    # OOM
    oom_penalty = min(oom_count * 5, 15)
    if oom_penalty:
        score -= oom_penalty
        breakdown["oom"] = -oom_penalty

    # Services en échec
    fail_penalty = min(failed_count * 5, 20)
    if fail_penalty:
        score -= fail_penalty
        breakdown["failed_units"] = -fail_penalty

    # SMART disques
    for d in (smart or []):
        if d.get("health", "PASSED") == "FAILED":
            score -= 10; breakdown["smart"] = -10; break
        if (d.get("reallocated_sectors", 0) or 0) > 0:
            score -= 5; breakdown.setdefault("smart_warn", -5)

    score = max(0, min(100, score))
    status = ("critical"  if score < 50 else
              "warning"   if score < 75 else
              "good"      if score < 90 else "excellent")
    return {
        "score": score,
        "status": status,
        "breakdown": breakdown,
        "alerts_count": len(ssl_problems) + oom_count + failed_count,
    }


def save_health_score(score_data):
    import json as _json
    conn = get_conn()
    breakdown_json = _json.dumps(score_data.get("breakdown", {}))
    conn.execute(
        "INSERT INTO health_scores (ts, score, breakdown, alerts_count, status) "
        "VALUES (?,?,?,?,?)",
        (datetime.now().isoformat(), score_data["score"], breakdown_json,
         score_data.get("alerts_count", 0), score_data["status"])
    )
    # Purge par le temps (RETENTION_HEALTH_DAYS), dans run_retention_vacuum : le plafond de 2880
    # lignes ne gardait que dix jours de la courbe « Score de santé ».
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
# SENSORIUM — MODÈLE DU MONDE (état courant grounded + changements de valeur)
# ============================================================
# LE JOURNAL DES CHANGEMENTS DIT CE QUI CHANGE D'ÉTAT, PAS CE QUI BOUGE (08-10) : la charge CPU qui passe de
# 2 % à 3 % écrivait une ligne toutes les 30 s — 7 193 par jour, qui noyaient les vrais changements (un
# service tombé, un port ouvert). Une mesure continue n'entre au journal que si sa GRAVITÉ change.
_WORLD_CONTINUS = ("resource", "prevision", "controle", "erreurs")
_WORLD_CONTINUS_CLES = ("system.uptime",)


def _world_maintenant() -> str:
    """L'heure du relevé, en UTC (08-10). Écrite en heure locale, elle était lue comme de l'UTC par la perception
    de Cassandra : à Paris, tout relevé paraissait deux heures plus jeune, et un état figé depuis 1 h 50
    s'affichait « relevé il y a 0 s »."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def upsert_world(conn, key, category, value, detail=None, severity="info", vus=None):
    """Upsert une entrée du world model sur la connexion fournie. Un changement d'état (valeur, ou gravité pour
    une mesure continue) va au journal des changements, une apparition aussi. `vus` reçoit la clé : ce qui n'y
    est pas à la fin d'une construction a disparu. Robuste : n'élève jamais."""
    try:
        if vus is not None:
            vus.add(key)
        value = "" if value is None else str(value)[:500]
        now = _world_maintenant()
        local = datetime.now().isoformat()
        row = conn.execute("SELECT value, severity, detail FROM world_model WHERE wkey=?", (key,)).fetchone()
        det = json.dumps(detail, ensure_ascii=False) if detail is not None else None
        continu = category in _WORLD_CONTINUS or key in _WORLD_CONTINUS_CLES
        if row is None:
            if severity == "warning" and category not in ("capteur", "prevision"):
                try:
                    causes = causes_probables(conn, key, local)
                    if causes:
                        d = dict(detail) if isinstance(detail, dict) else {}
                        d["causes_probables"] = causes
                        det = json.dumps(d, ensure_ascii=False)
                except Exception:
                    pass
            conn.execute(
                "INSERT INTO world_model (wkey, category, value, detail, severity, source, observed_at, updated_at) "
                "VALUES (?,?,?,?,?, 'observed', ?, ?)",
                (key, category, value, det, severity, now, now))
            if not continu:
                conn.execute(
                    "INSERT INTO changelog (ts, entity_type, entity_name, change_type, old_value, new_value, severity) "
                    "VALUES (?,?,?,?,?,?,?)", (local, category, key, "added", None, value, severity))
        elif row[0] != value or row[1] != severity:
            if severity == "warning" and row[1] != "warning" and category not in ("capteur", "prevision"):
                # L'ENTITÉ PASSE EN ALERTE : qu'est-ce qui a changé juste avant ?
                try:
                    causes = causes_probables(conn, key, local)
                    if causes:
                        d = dict(detail) if isinstance(detail, dict) else ({"valeur": detail} if detail is not None else {})
                        d["causes_probables"] = causes
                        det = json.dumps(d, ensure_ascii=False)
                        conn.execute("INSERT INTO correlations (ts, entite, alerte, causes) VALUES (?,?,?,?)",
                                     (local, key, value, json.dumps(causes, ensure_ascii=False)))
                except Exception as _ce:
                    print(f"[CAUSES] {key} : {_ce}", file=sys.stderr)
            if severity == "warning" and row[1] == "warning" and row[2] and "causes_probables" in str(row[2]):
                # toujours en alerte : la cause trouvée au passage en alerte reste attachée
                try:
                    d = dict(detail) if isinstance(detail, dict) else {}
                    d["causes_probables"] = json.loads(row[2]).get("causes_probables")
                    det = json.dumps(d, ensure_ascii=False)
                except Exception:
                    pass
            conn.execute(
                "UPDATE world_model SET value=?, detail=?, severity=?, observed_at=?, updated_at=? WHERE wkey=?",
                (value, det, severity, now, now, key))
            if not continu or row[1] != severity:
                conn.execute(
                    "INSERT INTO changelog (ts, entity_type, entity_name, change_type, old_value, new_value, severity) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (local, category, key, "modified", str(row[0])[:500], value, severity))
        else:
            conn.execute("UPDATE world_model SET observed_at=? WHERE wkey=?", (now, key))
    except Exception as e:
        print(f"[WORLD] upsert {key}: {e}", file=sys.stderr)


def _world_elaguer(conn, prefixe: str, vus: set) -> int:
    """Ce que la source ne rapporte plus a disparu : on le retire, et on le dit au journal. Sans cela, le modèle
    gardait 551 ports pour 39 ouverts, et un site retiré le 1er octobre y vivait encore (08-10)."""
    n = 0
    local = datetime.now().isoformat()
    for wk, cat, val in conn.execute("SELECT wkey, category, value FROM world_model WHERE wkey LIKE ?",
                                     (prefixe + "%",)).fetchall():
        if wk not in vus:
            conn.execute("DELETE FROM world_model WHERE wkey=?", (wk,))
            if cat not in _WORLD_CONTINUS and not (prefixe == "port." and n > 50):
                conn.execute(
                    "INSERT INTO changelog (ts, entity_type, entity_name, change_type, old_value, new_value, severity) "
                    "VALUES (?,?,?,?,?,?,?)", (local, cat, wk, "removed", str(val)[:500], None, "info"))
            n += 1
    return n


def _duree_txt(sec) -> str:
    try:
        sec = int(sec)
    except Exception:
        return "?"
    j, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    return ("%d j %d h" % (j, h)) if j else ("%d h %d min" % (h, r // 60))


def build_world_model():
    """Dérive l'état courant compact (clé→valeur) depuis les tables collectées, en UNE transaction. Chaque
    famille est isolée : un échec n'empêche jamais les autres. Une famille relue sans erreur est ÉLAGUÉE : ce
    qu'elle ne rapporte plus disparaît du modèle. C'est le socle « vérité-terrain » de la perception."""
    try:
        conn = get_conn()
    except Exception:
        return
    familles_ok = []          # (préfixe, clés vues) des familles relues sans erreur

    def _q(sql, *p):
        """Rend (lignes, ok) : une table absente n'est pas une famille vide."""
        try:
            return conn.execute(sql, p).fetchall(), True
        except Exception:
            return [], False

    def _famille(prefixe, lignes_ok, remplir):
        lignes, ok = lignes_ok
        vus = set()
        try:
            remplir(lignes, vus)
        except Exception as e:
            print(f"[WORLD] {prefixe} : {e}", file=sys.stderr)
            return
        if ok:
            familles_ok.append((prefixe, vus))

    def U(key, cat, val, vus, sev="info", detail=None):
        upsert_world(conn, key, cat, val, detail=detail, severity=sev, vus=vus)

    try:
        divers = set()
        # Identité système
        try:
            u = os.uname()
            U("system.hostname", "system", u.nodename, divers)
            U("system.kernel", "system", u.release, divers)
        except Exception:
            pass
        st, _ok = _q("SELECT uptime_s, reboot_required, reboot_pkgs, tailscale, tailscale_ip FROM system_state LIMIT 1")
        if st:
            r = st[0]
            if r["uptime_s"] is not None:
                U("system.uptime", "system", _duree_txt(r["uptime_s"]), divers)
            U("system.redemarrage_requis", "system",
              ("oui (%s)" % r["reboot_pkgs"]) if r["reboot_required"] and r["reboot_pkgs"] else ("oui" if r["reboot_required"] else "non"),
              divers, sev="warning" if r["reboot_required"] else "info")
            if r["tailscale"]:
                U("system.tailscale", "system", "%s · %s" % (r["tailscale"], r["tailscale_ip"] or "?"), divers,
                  sev="info" if r["tailscale"] == "Running" else "warning")
        # Ressources (dernière métrique)
        m, _ok = _q("SELECT cpu_pct, ram_pct, disk_pct, swap_pct, load_1m, ram_used_gb, ram_total_gb, "
                    "disk_used_gb, disk_total_gb FROM metrics_realtime ORDER BY id DESC LIMIT 1")
        if m:
            r = m[0]
            def _sev(p, thr=90):
                return "warning" if (isinstance(p, (int, float)) and p >= thr) else "info"
            U("cpu.load", "resource", "%.0f%%" % (r["cpu_pct"] or 0), divers, _sev(r["cpu_pct"]))
            U("ram.usage", "resource", "%.0f%% (%.1f/%.1f Go)" % (r["ram_pct"] or 0, r["ram_used_gb"] or 0, r["ram_total_gb"] or 0),
              divers, _sev(r["ram_pct"]))
            U("disk./.usage", "resource", "%.0f%% (%.0f/%.0f Go)" % (r["disk_pct"] or 0, r["disk_used_gb"] or 0, r["disk_total_gb"] or 0),
              divers, _sev(r["disk_pct"]))
            U("swap.usage", "resource", "%.0f%%" % (r["swap_pct"] or 0), divers, _sev(r["swap_pct"], 50))
            U("load.1m", "resource", str(r["load_1m"] or 0), divers)

        # Services systemd — TOUS, avec leur activation au démarrage. Un service activé mais arrêté (hors
        # tâches ponctuelles) est un signal ; un service en échec, une alerte.
        def _services(lignes, vus):
            for r in lignes:
                nm = (r["name"] or "").strip()
                if not nm:
                    continue
                act, sub, ufs, typ = r["status"] or "?", r["sub_state"] or "", r["unit_file_state"] or "", r["unit_type"] or ""
                val = act + (" (%s)" % sub if sub and sub != act else "") + (" · %s au démarrage" % {
                    "enabled": "activé", "disabled": "désactivé", "static": "statique", "masked": "masqué"}.get(ufs, ufs) if ufs else "")
                grave = act == "failed" or (ufs == "enabled" and act == "inactive" and typ not in ("oneshot", ""))
                U("service.%s" % nm, "service", val, vus, "warning" if grave else "info",
                  detail={"description": r["description"] or ""} if r["description"] else None)
        _famille("service.", _q("SELECT name, status, sub_state, unit_file_state, unit_type, description FROM system_services"), _services)

        # Unités en échec : le compte ET les noms
        def _echecs(lignes, vus):
            noms = [r["unit"] for r in lignes]
            U("systemd.failed_units", "system", ("%d : %s" % (len(noms), ", ".join(noms[:8]))) if noms else "0",
              vus, "warning" if noms else "info")
        _famille("systemd.", _q("SELECT unit FROM failed_units WHERE active_state='failed'"), _echecs)

        # Conteneurs docker
        def _docker(lignes, vus):
            for r in lignes:
                nm = (r["name"] or "").strip()
                if nm:
                    stt = r["status"] or "?"
                    grave = not stt.startswith("Up") or "unhealthy" in stt
                    U("docker.%s" % nm, "service", stt + (" · %s" % r["image"] if r["image"] else ""), vus,
                      "warning" if grave else "info")
        _famille("docker.", _q("SELECT name, status, image FROM docker_containers"), _docker)

        # Certificats (expiration), indexés pour les sites
        jours_ssl = {}
        def _ssl(lignes, vus):
            for r in lignes:
                d = (r["domain"] or "").strip().lower()
                if d and d not in jours_ssl:
                    dl = r["days_left"]
                    jours_ssl[d] = dl
                    U("ssl.%s" % d, "security", "%s jours" % dl, vus,
                      "warning" if (isinstance(dl, (int, float)) and dl <= 14) else "info")
        _famille("ssl.", _q("SELECT domain, days_left FROM ssl_certificates WHERE days_left IS NOT NULL ORDER BY days_left ASC"), _ssl)

        # Sites web : la réponse HTTP mesurée, le certificat, le serveur
        def _web(lignes, vus):
            for r in lignes:
                d = (r["domain"] or "").strip()
                if not d:
                    continue
                code = r["http_code"] if "http_code" in r.keys() else None
                stt = (r["reponse"] if "reponse" in r.keys() and r["reponse"] else None) or "déclaré (non sondé)"
                morceaux = [("%s (HTTP %s)" % (stt, code)) if code and code != "000" else stt]
                if r["ssl_enabled"]:
                    dl = jours_ssl.get(d.lower())
                    morceaux.append("ssl oui" + (" · %s j" % dl if dl is not None else ""))
                else:
                    morceaux.append("ssl non")
                if r["php_version"]:
                    morceaux.append("php %s" % r["php_version"])
                grave = stt.startswith("ne répond") or stt.startswith("erreur")
                U("web.%s" % d, "web", " · ".join(morceaux), vus, "warning" if grave else "info")
        _famille("web.", _q("SELECT * FROM web_sites"), _web)

        # Ports à l'écoute — TCP, et UDP hors plage éphémère (un port UDP tiré au hasard à chaque redémarrage
        # de tailscaled n'est pas un fait sur la machine)
        def _ports(lignes, vus):
            par_port = {}
            for r in lignes:
                if r["port"] is None:
                    continue
                proto = (r["protocol"] or "").lower()
                if proto.startswith("udp") and int(r["port"]) >= 32768:
                    continue
                par_port.setdefault(int(r["port"]), set()).add("%s %s" % (r["process"] or "?", "udp" if proto.startswith("udp") else "tcp"))
            for port, quoi in par_port.items():
                U("port.%s" % port, "network", ", ".join(sorted(quoi)), vus)
        _famille("port.", _q("SELECT port, protocol, process FROM open_ports"), _ports)

        # Sysctl sécurité
        def _sysctl(lignes, vus):
            for r in lignes:
                pr = (r["param"] or "").strip()
                if pr:
                    U("security.%s" % pr, "security", "%s (%s)" % (r["value"], r["status"]), vus,
                      "warning" if r["status"] == "critical" else "info")
        _famille("security.", _q("SELECT param, value, status FROM sysctl_security"), _sysctl)

        # Flotte (Tailscale)
        def _flotte(lignes, vus):
            for r in lignes:
                nm = (r["name"] or "").strip()
                if nm:
                    U("fleet.%s" % nm, "fleet", "en ligne" if r["online"] else "hors ligne", vus,
                      "info" if r["online"] else "warning")
        lignes_flotte = _q("SELECT name, online FROM tailscale_peers")
        if lignes_flotte[0]:      # Tailscale muet : on n'efface pas la flotte sur un silence
            _famille("fleet.", lignes_flotte, _flotte)

        # Config de Cassandra : posée / vide, valeur des seules clés sans secret
        def _config(lignes, vus):
            for r in lignes:
                cle = r["cle"]
                if cle == "__fichier__":
                    U("config.fichier", "config", "%s%s" % (r["etat"], (" · " + r["valeur"]) if r["valeur"] else ""), vus,
                      "info" if r["etat"] == "ok" else "warning")
                else:
                    U("config.%s" % cle, "config", (r["valeur"] if r["valeur"] else r["etat"]), vus)
        _famille("config.", _q("SELECT cle, etat, valeur FROM cassandra_config"), _config)

        # Logiciels : installés OU absents (l'absence est un fait qu'on cite)
        def _logiciels(lignes, vus):
            for r in lignes:
                U("logiciel.%s" % r["nom"], "logiciel", ("installé (%s)" % r["chemin"]) if r["installe"] else "absent", vus)
        _famille("logiciel.", _q("SELECT nom, installe, chemin FROM logiciels"), _logiciels)

        # Mises à jour en attente (tout gestionnaire)
        maj, _ok = _q("SELECT * FROM apt_updates LIMIT 1")
        if maj:
            r = maj[0]
            gest = r["gestionnaire"] if "gestionnaire" in r.keys() and r["gestionnaire"] else "apt"
            U("maj.paquets", "system", "%d en attente (%s), dont %d de sécurité%s" % (
                r["total"] or 0, gest, r["securite"] or 0, (" : %s" % r["paquets"]) if r["paquets"] else ""),
              divers, "warning" if (r["securite"] or 0) else "info")

        # Systèmes de fichiers : remplissage et inodes, chacun
        def _montages(lignes, vus):
            for r in lignes:
                mp = r["mountpoint"]
                ino = r["inode_pct"] if "inode_pct" in r.keys() else None
                val = "%.0f%% (%.0f/%.0f Go, %s)" % (r["percent"] or 0, r["used_gb"] or 0, r["total_gb"] or 0, r["fstype"] or "?")
                if ino is not None:
                    val += " · inodes %.0f%%" % ino
                grave = (r["percent"] or 0) >= 90 or (ino or 0) >= 90
                U("montage.%s" % mp, "resource", val, vus, "warning" if grave else "info")
        _famille("montage.", _q("SELECT * FROM system_mounts"), _montages)

        # RAID et pools ZFS
        def _stockage(lignes, vus):
            for r in lignes:
                sain = r["etat"] in ("active", "online", "clean")
                U("stockage.%s" % r["nom"], "storage", "%s · %s%s" % (r["type"], r["etat"], (" · " + r["detail"]) if r["detail"] else ""),
                  vus, "info" if sain else "warning")
        _famille("stockage.", _q("SELECT nom, type, etat, detail FROM storage_health"), _stockage)

        # Interfaces réseau
        def _interfaces(lignes, vus):
            for r in lignes:
                U("interface.%s" % r["nom"], "network", "%s%s%s" % (r["etat"], (" · " + r["adresses"]) if r["adresses"] else "",
                  " · route par défaut" if r["route_defaut"] else ""), vus,
                  "warning" if (r["route_defaut"] and r["etat"] not in ("up", "unknown")) else "info")
        _famille("interface.", _q("SELECT nom, etat, adresses, route_defaut FROM interfaces"), _interfaces)

        # Matériel, heure, OS, pare-feu, protections du noyau
        hw, _ok = _q("SELECT * FROM hardware_state LIMIT 1")
        if hw:
            r = hw[0]
            if r["os"]:
                U("system.os", "system", "%s · %s%s" % (r["os"], r["arch"] or "?", (" · " + r["virtualisation"]) if r["virtualisation"] and r["virtualisation"] != "none" else ""), divers)
            if r["temp_max"] is not None:
                U("system.temperature", "resource", "%.0f °C au plus chaud" % r["temp_max"], divers,
                  "warning" if r["temp_max"] >= 85 else "info")
            if r["batterie"]:
                U("system.batterie", "resource", r["batterie"], divers)
            if r["heure_synchro"]:
                U("system.heure", "system", "synchronisée" if r["heure_synchro"] == "oui" else "NON synchronisée",
                  divers, "info" if r["heure_synchro"] == "oui" else "warning")
            if r["fuseau"]:
                U("system.fuseau", "system", r["fuseau"], divers)
            if r["pare_feu"]:
                U("system.pare_feu", "security", r["pare_feu"], divers, "warning" if r["pare_feu"] == "aucune règle" else "info")
            if r["securite_noyau"]:
                U("system.protection_noyau", "security", r["securite_noyau"], divers)

        # Mesures diverses (courriel, SSH, conteneurs, certbot, journaux)
        def _diverses(lignes, vus):
            for r in lignes:
                U(r["cle"], r["categorie"] or "divers", r["valeur"], vus, r["severite"] or "info")
        for _pref in ("courriel.", "ssh.", "conteneur_ressources.", "certbot.", "journaux."):
            _famille(_pref, _q("SELECT cle, categorie, valeur, severite FROM mesures_diverses WHERE cle LIKE ?", _pref + "%"), _diverses)

        # Clés SSH autorisées, une par une : une clé ajoutée ou retirée entre au journal des changements
        def _cles(lignes, vus):
            for r in lignes:
                U("cle_ssh.%s.%s" % (r["user"], r["key_hash"][:8]), "security", "%s %s" % (r["key_type"], r["comment"] or "(sans commentaire)"), vus)
        _famille("cle_ssh.", _q("SELECT user, key_type, key_hash, comment FROM ssh_authorized_keys"), _cles)

        # Pare-feu : le nombre de règles par outil, et ce qu'elles bloquent
        def _parefeu(lignes, vus):
            par = {}
            for r in lignes:
                t = r["tool"] or "?"
                d = par.setdefault(t, {"n": 0, "bloque": set()})
                d["n"] += 1
                if r["action"] == "DENY" and r["port"]:
                    d["bloque"].add(r["port"])
            for t, d in par.items():
                U("pare_feu.%s" % t, "security", "%d règles%s" % (d["n"], (" · bloque les ports %s" % ", ".join(sorted(d["bloque"], key=lambda x: int(x))[:10])) if d["bloque"] else ""), vus)
        _famille("pare_feu.", _q("SELECT tool, action, port FROM firewall_rules"), _parefeu)

        # Fail2ban : les adresses bannies maintenant, par prison
        def _f2b(lignes, vus):
            par = {}
            for r in lignes:
                par[r["jail"]] = par.get(r["jail"], 0) + 1
            for j, n in par.items():
                U("fail2ban.%s" % j, "security", "%d adresse%s bannie%s" % (n, "s" if n > 1 else "", "s" if n > 1 else ""), vus)
            if not par:
                U("fail2ban.total", "security", "aucune adresse bannie" if _qui("fail2ban-client") else "fail2ban absent", vus)
        _famille("fail2ban.", _q("SELECT jail FROM fail2ban_banned_ips"), _f2b)

        # Tâches planifiées, par propriétaire
        def _crons(lignes, vus):
            par = {}
            for r in lignes:
                par[r["user"] or "?"] = par.get(r["user"] or "?", 0) + 1
            for u_, n in par.items():
                U("cron.%s" % u_, "system", "%d tâche%s planifiée%s" % (n, "s" if n > 1 else "", "s" if n > 1 else ""), vus)
        _famille("cron.", _q("SELECT user FROM cron_jobs"), _crons)

        # FastPanel : comptes, bases (et leur taille), boîtes mail (et leur remplissage), FTP
        fpv = set()
        for r in _q("SELECT username, status, sites_count, databases_count FROM fastpanel_users")[0]:
            U("fastpanel.compte.%s" % r["username"], "fastpanel", "%s · %s site(s) · %s base(s)" % (r["status"] or "?", r["sites_count"] or 0, r["databases_count"] or 0), fpv)
        for r in _q("SELECT name, size_mb, owner, site FROM fastpanel_databases")[0]:
            U("fastpanel.base.%s" % r["name"], "fastpanel", "%.1f Mo · %s%s" % (float(r["size_mb"] or 0), r["owner"] or "?", (" · " + r["site"]) if r["site"] else ""), fpv)
        for r in _q("SELECT email, quota_mb, used_mb, status FROM fastpanel_mail_accounts")[0]:
            q_, u_ = float(r["quota_mb"] or 0), float(r["used_mb"] or 0)
            pct = (100 * u_ / q_) if q_ else 0
            U("fastpanel.boite.%s" % r["email"], "fastpanel", "%.0f Mo%s · %s" % (u_, (" sur %.0f (%.0f %%)" % (q_, pct)) if q_ else "", r["status"] or "?"), fpv,
              "warning" if pct >= 90 else "info")
        n_ftp = _q("SELECT COUNT(*) AS n FROM fastpanel_ftp_accounts")[0]
        if n_ftp:
            U("fastpanel.ftp", "fastpanel", "%d compte(s) FTP" % n_ftp[0]["n"], fpv)
        if _q("SELECT COUNT(*) FROM fastpanel_users")[1]:
            familles_ok.append(("fastpanel.", fpv))

        # Erreurs des journaux sur l'heure écoulée, par service (la courbe existait, le modèle ne la voyait pas)
        def _erreurs(lignes, vus):
            for r in lignes:
                U("erreurs.%s" % r["service"], "erreurs", "%d erreur%s dans l'heure" % (r["n"], "s" if r["n"] > 1 else ""), vus,
                  "warning" if r["n"] >= 30 else "info")
        _depuis = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        _famille("erreurs.", _q("SELECT service, SUM(COALESCE(count,1)) AS n FROM log_errors WHERE ts >= ? GROUP BY service", _depuis), _erreurs)

        # Contrôles de bout en bout
        def _controles(lignes, vus):
            for r in lignes:
                U("controle.%s" % r["nom"], "controle", r["valeur"], vus, "info" if r["ok"] else "warning")
        _famille("controle.", _q("SELECT nom, ok, valeur FROM controles"), _controles)

        # Sauvegardes : chacune, et la question du sinistre
        def _sauvegardes(lignes, vus):
            hors = False
            for r in lignes:
                if r["hors_machine"] and r["etat"] in ("ok", "configuré"):
                    hors = True
                morceaux = [r["etat"]]
                if r["age_h"] is not None:
                    morceaux.append("dernière il y a %s" % (("%.0f h" % r["age_h"]) if r["age_h"] < 48 else ("%.0f j" % (r["age_h"] / 24))))
                if r["taille_mb"] is not None:
                    morceaux.append("%.0f Mo" % r["taille_mb"] + ((" (précédente %.0f Mo)" % r["taille_prec_mb"]) if r["taille_prec_mb"] else ""))
                if r["hors_machine"]:
                    morceaux.append("hors machine")
                if r["detail"]:
                    morceaux.append(r["detail"])
                U("sauvegarde.%s" % r["source"], "sauvegarde", " · ".join(morceaux), vus,
                  "info" if r["etat"] in ("ok", "configuré") else "warning")
            U("sauvegarde.hors_machine", "sauvegarde",
              "oui" if hors else "AUCUNE copie hors de cette machine : un disque mort emporte tout", vus,
              "info" if hors else "warning")
        _famille("sauvegarde.", _q("SELECT * FROM backups_state"), _sauvegardes)

        # Ce qui VA arriver : disque plein, fuite de mémoire, certificat non renouvelé
        def _previsions(lignes, vus):
            for r in lignes:
                U("prevision.%s" % r["cle"], "prevision", r["valeur"], vus, r["severite"] or "info")
        _famille("prevision.", _q("SELECT cle, valeur, severite FROM projections"), _previsions)

        # LE SENSORIUM LUI-MÊME : chaque capteur, sa dernière réussite, son silence ou sa panne
        def _capteurs(lignes, vus):
            maint = datetime.now(timezone.utc)
            for r in lignes:
                fam, per = r["famille"], r["periode_s"] or 300
                ok_ts = r["dernier_ok"]
                age = None
                if ok_ts:
                    try:
                        age = (maint - datetime.strptime(ok_ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)).total_seconds()
                    except Exception:
                        age = None
                en_erreur = bool(r["erreur"]) and (not ok_ts or (r["derniere_erreur"] or "") > ok_ts)
                muet = age is None or age > 3 * per + 60
                vide_suspect = (fam in _CAPTEURS_JAMAIS_VIDES and (r["n_lignes"] or 0) == 0 and (r["n_precedent"] or 0) > 0)
                if en_erreur:
                    val, sev = "en panne depuis %s : %s" % ((r["derniere_erreur"] or "?")[11:16] + " UTC", (r["erreur"] or "")[:160]), "warning"
                elif muet:
                    val, sev = ("muet depuis %s UTC" % ok_ts[11:16]) if ok_ts else "jamais relevé", "warning"
                elif vide_suspect:
                    val, sev = "vide (rendait %d lignes au relevé précédent)" % (r["n_precedent"] or 0), "warning"
                else:
                    val, sev = "ok · toutes les %s" % (("%d s" % per) if per < 60 else ("%d min" % (per // 60))), "info"
                U("capteur.%s" % fam, "capteur", val, vus, sev,
                  detail={"dernier_ok": ok_ts, "lignes": r["n_lignes"], "duree_ms": r["duree_ms"]})
        _famille("capteur.", _q("SELECT * FROM sensor_health"), _capteurs)

        # Santé globale
        h, _ok = _q("SELECT score, status FROM health_scores ORDER BY id DESC LIMIT 1")
        if h:
            U("health.score", "system", "%s/100 (%s)" % (h[0]["score"], h[0]["status"]), divers,
              "warning" if (h[0]["status"] in ("degraded", "critical", "warning")) else "info")

        for prefixe, vus in familles_ok:
            _world_elaguer(conn, prefixe, vus)
        conn.commit()
    except Exception as e:
        print(f"[WORLD] build: {e}", file=sys.stderr)
    finally:
        try:
            conn.close()
        except Exception:
            pass


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
        """
        Met à jour le cache socket avec TOUTES les données du dashboard.
        FIX: ajout health_score + health_status (absents → score 0 côté agent).
        FIX: failed_units avec WHERE active_state='failed' (évite comptage fantôme).
        """
        try:
            conn = get_conn()
            hs_row = conn.execute(
                "SELECT score, status FROM health_scores ORDER BY id DESC LIMIT 1"
            ).fetchone()
            remotes_count = 0
            try:
                remotes_count = conn.execute("SELECT COUNT(*) FROM rclone_remotes").fetchone()[0]
            except Exception:
                pass
            with self._cache_lock:
                self.cache = {
                    "timestamp":      datetime.now().isoformat(),
                    "version":        "6.1-opt",
                    "sites":          conn.execute("SELECT COUNT(*) FROM web_sites WHERE status='active'").fetchone()[0],
                    "ssl_expiring":   conn.execute("SELECT COUNT(*) FROM ssl_certificates WHERE days_left <= 30 AND days_left >= 0").fetchone()[0],
                    "fail2ban_banned":conn.execute("SELECT COUNT(*) FROM fail2ban_banned_ips").fetchone()[0],
                    "tailscale_peers":conn.execute("SELECT COUNT(*) FROM tailscale_peers WHERE online=1").fetchone()[0],
                    # FIX: WHERE active_state='failed' — ne pas compter les unités historiques
                    "failed_units":   conn.execute("SELECT COUNT(*) FROM failed_units WHERE active_state='failed'").fetchone()[0],
                    "oom_events_24h": self._oom_24h(conn),
                    "remotes":        remotes_count,
                    # FIX CRITIQUE: health_score + health_status inclus dans le cache socket
                    "health_score":   hs_row[0] if hs_row else 0,
                    "health_status":  hs_row[1] if hs_row else "unknown",
                }
            conn.close()
        except Exception as e:
            print(f"[CACHE] Erreur update_cache: {e}")

    @staticmethod
    def _oom_24h(conn) -> int:
        # La colonne ts porte la date de dmesg (« Thu Oct  8 04:08:16 2026 ») : comparée à datetime('now')
        # comme du texte, elle ne voulait rien dire. Le collecteur pose « recent » lui-même.
        try:
            return conn.execute("SELECT COUNT(*) FROM oom_events WHERE recent=1").fetchone()[0]
        except Exception:
            return 0

    def handle_client(self, client):
        try:
            data = client.recv(4096).decode().strip()
            if not data:
                return

            if data == "PING":
                client.sendall(b"PONG")
            elif data == "GET_METRICS":
                mi   = _read_meminfo()          # PERF[O2]: une seule lecture
                _cpu = get_cpu()
                _ram = get_ram(mi)
                _disk = get_disk()
                _swap = get_swap(mi)
                _l1, _l5, _l15 = get_load()
                client.sendall(json.dumps({
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
                    client.sendall(json.dumps(self.cache).encode())
            elif data.startswith("GET_ENTITY:"):
                entity = data.split(":", 1)[1]
                if entity in SOCKET_ALLOWED_ENTITIES:
                    try:
                        conn = get_conn()
                        rows = conn.execute(f"SELECT * FROM {entity} LIMIT 100").fetchall()
                        conn.close()
                        client.sendall(json.dumps([dict(r) for r in rows]).encode())
                    except Exception:
                        client.sendall(b"[]")
                else:
                    client.sendall(b"[]")
            elif data == "GET_WORLD" or data.startswith("GET_WORLD:"):
                prefix = data.split(":", 1)[1].strip() if ":" in data else ""
                try:
                    conn = get_conn()
                    if prefix:
                        rows = conn.execute(
                            "SELECT wkey, category, value, severity, observed_at, detail FROM world_model "
                            "WHERE wkey LIKE ? ORDER BY wkey LIMIT 500", (prefix + "%",)).fetchall()
                    else:
                        rows = conn.execute(
                            "SELECT wkey, category, value, severity, observed_at, detail FROM world_model "
                            "ORDER BY wkey LIMIT 3000").fetchall()
                    conn.close()
                    client.sendall(json.dumps([dict(r) for r in rows]).encode())
                except Exception:
                    client.sendall(b"[]")
            elif data.startswith("QUERY_WORLD:"):
                term = data.split(":", 1)[1].strip()
                try:
                    conn = get_conn()
                    like = "%" + term + "%"
                    rows = conn.execute(
                        "SELECT wkey, category, value, severity, observed_at FROM world_model "
                        "WHERE wkey LIKE ? OR value LIKE ? ORDER BY (severity='warning') DESC, wkey LIMIT 60",
                        (like, like)).fetchall()
                    conn.close()
                    client.sendall(json.dumps([dict(r) for r in rows]).encode())
                except Exception:
                    client.sendall(b"[]")
            elif data == "GET_CHANGES" or data.startswith("GET_CHANGES:"):
                since = data.split(":", 1)[1].strip() if ":" in data else ""
                try:
                    conn = get_conn()
                    if since:
                        rows = conn.execute(
                            "SELECT ts, entity_type, entity_name, change_type, old_value, new_value, severity "
                            "FROM changelog WHERE ts >= ? ORDER BY id DESC LIMIT 100", (since,)).fetchall()
                    else:
                        rows = conn.execute(
                            "SELECT ts, entity_type, entity_name, change_type, old_value, new_value, severity "
                            "FROM changelog ORDER BY id DESC LIMIT 50").fetchall()
                    conn.close()
                    client.sendall(json.dumps([dict(r) for r in rows]).encode())
                except Exception:
                    client.sendall(b"[]")
            else:
                client.sendall(b"ERROR")
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
            os.makedirs(os.path.dirname(SOCKET_PATH), mode=0o700, exist_ok=True)
            try:
                os.chmod(os.path.dirname(SOCKET_PATH), 0o700)
            except Exception:
                pass
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(SOCKET_PATH)
            self.sock.listen(10)
            self.sock.settimeout(1.0)
            os.chmod(SOCKET_PATH, 0o600)   # root only : données système sensibles (serveur multi-tenant)
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
        self.last_world        = 0    # [SENSORIUM] dernière construction du world model
        self.last_slow         = time.time()   # 08-10 : les relevés lents, relus toutes les 15 min
        self.last_hourly       = 0             # 08-10 : mises à jour de paquets (lent : jusqu'à 2 min), à part, toutes les heures

    # PERF[O6]: _run_parallel() — collecteurs indépendants exécutés en parallèle.
    # Avant : 25+ collecteurs séquentiels = somme de toutes les latences (subprocess, réseau).
    # Après : exécution en parallèle via ThreadPoolExecutor → latence ≈ max(latences).
    # Gain  : collecte initiale 60-120s → 8-15s selon le serveur (×5 à ×10).
    # Note  : _fp_load_params() est protégé par _fp_load_lock (double-checked locking).
    #         Les collecteurs sont I/O-bound → threads idéaux (pas de GIL penalty réel).
    @staticmethod
    def _run_parallel(tasks: list, max_workers: int = 8, periode_s: int = None) -> dict:
        """
        Exécute une liste de (table, fn) en parallèle.
        Retourne {table: result_list}.
        """
        results = {}
        errors  = []
        def _chrono(fn):
            t0 = time.time()
            r = fn()
            return r, int((time.time() - t0) * 1000)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_table = {
                executor.submit(_chrono, fn): table
                for table, fn in tasks
            }
            for future in as_completed(future_to_table):
                table = future_to_table[future]
                try:
                    results[table], duree = future.result(timeout=30)
                    noter_capteur(table, True, n_lignes=len(results[table] or []), duree_ms=duree, periode_s=periode_s)
                except Exception as e:
                    errors.append(f"{table}: {e}")
                    results[table] = []
                    noter_capteur(table, False, erreur=str(e), periode_s=periode_s)
        if errors:
            print(f"[COLLECTOR] Erreurs parallèles: {'; '.join(errors)}", file=sys.stderr)
        return results

    def _relire_lents(self):
        try:
            lents = [
                ("cron_jobs",              collect_cron_jobs),
                ("ssh_authorized_keys",    collect_ssh_authorized_keys),
                ("firewall_rules",         collect_firewall_rules),
                ("vpn_connections",        collect_vpn_connections),
                ("fastpanel_users",        collect_fastpanel_users),
                ("fastpanel_php_versions", collect_fastpanel_php_versions),
                ("fastpanel_ftp_accounts", collect_fastpanel_ftp),
                ("fastpanel_dns_records",  collect_fastpanel_dns),
                ("fastpanel_crons",        collect_fastpanel_crons),
                ("backup_runs",            collect_backup_runs),
            ]
            for table, data in self._run_parallel(lents, max_workers=4, periode_s=900).items():
                save_many(table, data)
            dns, _ = collect_dns_servers()
            save_many("dns_servers", dns)
            self._last_dns_servers = dns
            redis = collect_redis_stats()
            if redis:
                save_many("redis_stats", [redis])
        except Exception as e:
            print(f"[COLLECTOR] relevés lents : {e}", file=sys.stderr)

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
            ("system_services",        collect_system_services),
            ("cassandra_config",       collect_cassandra_config),
            ("logiciels",              collect_installed_software),
            ("system_state",           collect_system_state),
            ("system_mounts",          collect_mounts),
            ("storage_health",         collect_storage_health),
            ("interfaces",             collect_interfaces),
            ("hardware_state",         collect_hardware_state),
            ("backups_state",          collect_backups),
        ]

        # Métriques en parallèle aussi (le sleep(0.3) de get_cpu sera chevauchant)
        with ThreadPoolExecutor(max_workers=1) as m_exec:
            metrics_future = m_exec.submit(collect_metrics)
            collected = self._run_parallel(init_tasks, max_workers=8, periode_s=300)
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
        self._last_dns_servers = dns_servers
        self._last_sysctl = collected.get("sysctl_security", [])

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
            sum(1 for e in _init_oom if e.get("recent")), len(_init_fail)
        )
        save_health_score(health)

        # [SENSORIUM] Première construction du modèle du monde, prêt dès le démarrage
        try:
            build_world_model()
        except Exception as _we:
            print(f"[WORLD] build initial: {_we}", file=sys.stderr)

        elapsed = round(time.time() - t0, 1)
        print(f"[COLLECTOR] ✅ PRÊT en {elapsed}s — Socket: {SOCKET_PATH}")

        try:
            while self.running:
                now = time.time()

                # LA BASE TOUTES LES 30 S (15-09). Écrite toutes les 5 s, elle ne servait aucun
                # lecteur : le direct passe par le socket (GET_METRICS mesure à la demande), les
                # autres prennent la dernière ligne. 21,6 Mo pour 7 jours au lieu de 122.
                if now - self.last_metrics >= 30:
                    try:
                        save_metrics(collect_metrics())
                        noter_capteur("metrics_realtime", True, n_lignes=1, periode_s=30)
                    except Exception as _me:
                        noter_capteur("metrics_realtime", False, erreur=str(_me), periode_s=30)
                    self.last_metrics = now

                # [SENSORIUM] Reconstruit le modèle du monde (état grounded) toutes les 30s
                if now - self.last_world >= 30:
                    threading.Thread(target=build_world_model, daemon=True).start()
                    self.last_world = now

                # [EVO2] Rétention vacuum — toutes les heures (thread daemon)
                if now - self.last_vacuum >= 3600:
                    threading.Thread(target=run_retention_vacuum, daemon=True).start()
                    self.last_vacuum = now

                if now - self.last_quick >= 30:
                    quick_tasks = [
                        ("system_services", collect_system_services),
                        ("interfaces",      collect_interfaces),
                        ("active_sessions", collect_active_sessions),
                        ("open_ports",      collect_open_ports),
                        ("network_hosts",   collect_network_hosts),
                        ("fail2ban_banned_ips", collect_fail2ban_banned),
                        ("tailscale_peers", collect_tailscale_peers),
                    ]
                    for table, data in self._run_parallel(quick_tasks, max_workers=5, periode_s=30).items():
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
                        ("cassandra_config",       collect_cassandra_config),
                        ("system_state",           collect_system_state),
                        ("system_mounts",          collect_mounts),
                        ("storage_health",         collect_storage_health),
                        ("hardware_state",         collect_hardware_state),
                        ("backups_state",          collect_backups),
                        ("controles",              collect_controles),
                        ("mesures_diverses",       collect_mesures_diverses),
                        ("firewall_rules",         collect_firewall_rules),
                        ("ssh_authorized_keys",    collect_ssh_authorized_keys),
                    ]
                    full_results = self._run_parallel(full_tasks, max_workers=8, periode_s=300)
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
                    self._last_sysctl = full_results.get("sysctl_security", []) or self._last_sysctl
                    try:
                        noter_historiques(full_results.get("system_mounts", []))
                    except Exception as _he:
                        print(f"[PROJECTION] historiques : {_he}", file=sys.stderr)
                    releve("projections", calculer_projections, 300)
                    releve("paquets_mouvements", lambda: [None] * collect_paquets_mouvements(), 300, enregistrer=False)
                    _oom_now   = full_results.get("oom_events", [])
                    _fail_now  = full_results.get("failed_units", [])
                    _met_now   = collect_metrics()
                    health = compute_health_score(
                        _met_now, self._last_ssl, {}, [],
                        self._last_smart, self._last_sysctl, self._last_dns_servers,
                        sum(1 for e in _oom_now if e.get("recent")), len(_fail_now)
                    )
                    save_health_score(health)
                    try:
                        collect_log_errors()
                    except Exception as _le:
                        print(f"[LOG-ERRORS] {_le}", file=sys.stderr)
                    self.last_full = now

                # 08-10 : CE QUI N'ÉTAIT LU QU'AU DÉMARRAGE. Clés SSH, règles du pare-feu, crons, comptes et DNS de
                # FastPanel restaient figés jusqu'au prochain redémarrage du collecteur : une clé SSH ajoutée
                # ce matin n'existait pas pour le sensorium. Relus toutes les 15 minutes.
                if now - self.last_slow >= 900:
                    threading.Thread(target=self._relire_lents, daemon=True).start()
                    self.last_slow = now
                if now - self.last_hourly >= 3600:
                    threading.Thread(target=lambda: releve("apt_updates", collect_apt_updates, 3600), daemon=True).start()
                    threading.Thread(target=lambda: releve("logiciels", collect_installed_software, 3600), daemon=True).start()
                    self.last_hourly = now

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
    # SELFTEST : exécution isolée par _self_selftest() de l'agent. Si le module
    # s'importe sans crash, on sort proprement sans démarrer le collecteur.
    if os.environ.get("CASSANDRA_SELFTEST") == "1":
        print("SELFTEST_OK")
        sys.exit(0)

    # 08-10 : la sortie va dans un fichier (StandardOutput=append:…) ; mise en tampon par blocs, le journal
    # du collecteur n'avait rien reçu depuis le 3 octobre alors que le collecteur tournait.
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass

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
