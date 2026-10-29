#!/usr/bin/env python3
"""
CASSANDRA — Knowledge Collector v4.0
=====================================
FONCTIONNALITÉS COMPLÈTES :
  [CRITIQUE] fail2ban, firewall, logs, SMART
  [IMPORTANT] Redis, PHP-FPM, nginx access, Postfix/Dovecot, backups
  [UTILE] changelog, health_scores, apache2, versions, swap, inodes, ssh_keys
  [V4] systemd services unit status, DNS servers (BIND/PowerDNS/Unbound/Knot/NSD), sysctl sécurité, Prometheus exporter

TOUS LES COLLECTEURS DE V3 SONT CONSERVÉS :
  - rclone_remotes, rclone_mounts
  - nfs_exports, nfs_mounts
  - docker, vpn, tunnels, redis, phpfpm, etc.
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
import glob
import configparser
import threading
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============================================================
# CONFIGURATION
# ============================================================
DB_PATH = os.environ.get("CASSANDRA_DB", "/var/lib/cassandra/cassandra.db")
SOCKET_PATH = "/tmp/cassandra_knowledge.sock"
PROMETHEUS_PORT = int(os.environ.get("CASSANDRA_PROMETHEUS_PORT", "9103"))
PROMETHEUS_ENABLED = os.environ.get("CASSANDRA_PROMETHEUS_ENABLED", "1") == "1"

SCAN_PATHS = [
    "/var/www",
    "/var/www/html",
    "/var/www/fastuser/data/www",
    "/home",
    "/opt",
    "/usr/share",
    "/etc/nginx/sites-enabled",
    "/etc/nginx/sites-available",
    "/etc/apache2/sites-enabled",
    "/etc/apache2/sites-available",
]

CMS_DETECTORS = {
    "wordpress":   ["wp-config.php", "wp-content", "wp-includes"],
    "joomla":      ["configuration.php", "administrator", "media"],
    "drupal":      ["core", "sites/default/settings.php"],
    "moodle":      ["config.php", "theme", "lib"],
    "prestashop":  ["config/settings.inc.php", "classes", "controllers"],
    "magento":     ["app/etc/local.xml", "app/code", "pub"],
    "nextcloud":   ["config/config.php", "apps", "themes"],
    "owncloud":    ["config/config.php"],
    "laravel":     [".env", "artisan", "bootstrap"],
    "symfony":     [".env", "bin/console", "config"],
    "bookstack":   [".env", "bootstrap", "app"],
    "dolibarr":    ["conf/conf.php", "htdocs"],
    "grav":        ["user/config", "system"],
    "codeigniter": ["application/config/config.php", "system"],
    "cakephp":     ["config/app.php", "src"],
    "opencart":    ["config.php", "catalog", "admin"],
}

SAFE_IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')

# ============================================================
# BASE DE DONNÉES (V4)
# ============================================================
def get_conn() -> sqlite3.Connection:
    try:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_all_tables():
    conn = get_conn()
    conn.executescript("""
        -- ====================================================
        -- MÉTRIQUES TEMPS RÉEL
        -- ====================================================
        CREATE TABLE IF NOT EXISTS metrics_realtime (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts              TEXT NOT NULL,
            cpu_pct         REAL,
            ram_pct         REAL,
            ram_total_gb    REAL,
            ram_used_gb     REAL,
            ram_free_gb     REAL,
            ram_buffers_gb  REAL,
            ram_cached_gb   REAL,
            swap_total_gb   REAL,
            swap_used_gb    REAL,
            swap_free_gb    REAL,
            swap_pct        REAL,
            disk_pct        REAL,
            disk_total_gb   REAL,
            disk_used_gb    REAL,
            disk_free_gb    REAL,
            load_1m         REAL,
            load_5m         REAL,
            load_15m        REAL,
            top_processes   TEXT,
            services        TEXT,
            alerts          TEXT
        );

        -- ====================================================
        -- SWAP
        -- ====================================================
        CREATE TABLE IF NOT EXISTS swap_usage (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            total_gb    REAL,
            used_gb     REAL,
            free_gb     REAL,
            pct         REAL,
            last_check  TEXT
        );

        -- ====================================================
        -- INODES
        -- ====================================================
        CREATE TABLE IF NOT EXISTS inode_usage (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mountpoint  TEXT NOT NULL,
            total       INTEGER,
            used        INTEGER,
            free        INTEGER,
            pct         REAL,
            last_check  TEXT,
            UNIQUE(mountpoint)
        );

        -- ====================================================
        -- SITES WEB & CMS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS web_sites (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            domain        TEXT NOT NULL UNIQUE,
            document_root TEXT,
            owner         TEXT,
            php_version   TEXT,
            php_fpm_pool  TEXT,
            ssl_enabled   INTEGER DEFAULT 0,
            ssl_cert      TEXT,
            config_file   TEXT,
            server_type   TEXT DEFAULT 'nginx',
            status        TEXT DEFAULT 'active',
            last_check    TEXT
        );

        CREATE TABLE IF NOT EXISTS cms_sites (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            domain        TEXT,
            path          TEXT,
            cms_type      TEXT NOT NULL,
            version       TEXT,
            theme         TEXT,
            plugins       TEXT,
            plugins_count INTEGER,
            db_name       TEXT,
            db_user       TEXT,
            admin_user    TEXT,
            config_file   TEXT,
            last_check    TEXT,
            UNIQUE(path)
        );

        -- ====================================================
        -- BASES DE DONNÉES
        -- ====================================================
        CREATE TABLE IF NOT EXISTS databases (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            type         TEXT NOT NULL,
            size_mb      REAL,
            tables_count INTEGER,
            host         TEXT,
            last_check   TEXT,
            UNIQUE(name, type)
        );

        -- ====================================================
        -- EMAILS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS email_accounts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT NOT NULL UNIQUE,
            domain      TEXT,
            quota_mb    INTEGER,
            used_mb     INTEGER,
            forward_to  TEXT,
            autoreply   TEXT,
            status      TEXT,
            last_check  TEXT
        );

        CREATE TABLE IF NOT EXISTS email_queues (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            queue_type  TEXT,
            count       INTEGER,
            oldest_age  INTEGER,
            last_check  TEXT
        );

        CREATE TABLE IF NOT EXISTS email_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            stat_type   TEXT,
            today_count INTEGER,
            week_count  INTEGER,
            spam_count  INTEGER,
            bounce_count INTEGER,
            last_check  TEXT
        );

        -- ====================================================
        -- CERTIFICATS SSL
        -- ====================================================
        CREATE TABLE IF NOT EXISTS ssl_certificates (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL,
            cert_path   TEXT,
            issuer      TEXT,
            subject     TEXT,
            expiry_date TEXT,
            days_left   INTEGER,
            status      TEXT,
            last_check  TEXT,
            UNIQUE(cert_path)
        );

        -- ====================================================
        -- RCLONE
        -- ====================================================
        CREATE TABLE IF NOT EXISTS rclone_remotes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            type        TEXT,
            path        TEXT,
            total_gb    REAL,
            used_gb     REAL,
            files_count INTEGER,
            last_check  TEXT
        );

        CREATE TABLE IF NOT EXISTS rclone_mounts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mountpoint  TEXT NOT NULL UNIQUE,
            remote      TEXT,
            fstype      TEXT,
            total_gb    REAL,
            used_gb     REAL,
            percent     REAL,
            last_check  TEXT
        );

        -- ====================================================
        -- NFS (V3 - CONSERVÉ)
        -- ====================================================
        CREATE TABLE IF NOT EXISTS nfs_exports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            export_path TEXT NOT NULL,
            client      TEXT,
            options     TEXT,
            last_check  TEXT,
            UNIQUE(export_path, client)
        );

        CREATE TABLE IF NOT EXISTS nfs_mounts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mountpoint  TEXT NOT NULL UNIQUE,
            server      TEXT,
            export_path TEXT,
            fstype      TEXT,
            options     TEXT,
            total_gb    REAL,
            used_gb     REAL,
            percent     REAL,
            last_check  TEXT
        );

        -- ====================================================
        -- DOCKER
        -- ====================================================
        CREATE TABLE IF NOT EXISTS docker_containers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            image       TEXT,
            status      TEXT,
            state       TEXT,
            ports       TEXT,
            networks    TEXT,
            mounts      TEXT,
            created     TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- VPN & TUNNELS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS vpn_connections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT NOT NULL,
            name        TEXT,
            interface   TEXT,
            ip          TEXT,
            endpoint    TEXT,
            status      TEXT,
            last_check  TEXT,
            UNIQUE(type, name)
        );

        CREATE TABLE IF NOT EXISTS tunnels (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT NOT NULL,
            role        TEXT,
            config      TEXT,
            url         TEXT,
            port        INTEGER,
            status      TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- UTILISATEURS & SESSIONS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS system_users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL UNIQUE,
            uid         INTEGER,
            gid         INTEGER,
            home        TEXT,
            shell       TEXT,
            last_login  TEXT,
            status      TEXT
        );

        CREATE TABLE IF NOT EXISTS active_sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user        TEXT,
            tty         TEXT,
            login_time  TEXT,
            ip          TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- SSH AUTHORIZED KEYS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS ssh_authorized_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user        TEXT NOT NULL,
            key_type    TEXT,
            key_hash    TEXT,
            comment     TEXT,
            key_file    TEXT,
            last_check  TEXT,
            UNIQUE(user, key_hash)
        );

        -- ====================================================
        -- CRON
        -- ====================================================
        CREATE TABLE IF NOT EXISTS cron_jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user        TEXT,
            schedule    TEXT,
            command     TEXT,
            description TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- SERVICES SYSTÈME (V4 - enrichi)
        -- ====================================================
        CREATE TABLE IF NOT EXISTS system_services (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            status      TEXT,
            enabled     INTEGER,
            active      INTEGER,
            description TEXT,
            load_state  TEXT,
            sub_state   TEXT,
            active_state TEXT,
            unit_file_state TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- PORTS OUVERTS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS open_ports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            port        INTEGER,
            protocol    TEXT,
            process     TEXT,
            pid         INTEGER,
            state       TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- MONTAGES SYSTÈME
        -- ====================================================
        CREATE TABLE IF NOT EXISTS system_mounts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device      TEXT,
            mountpoint  TEXT NOT NULL UNIQUE,
            fstype      TEXT,
            options     TEXT,
            total_gb    REAL,
            used_gb     REAL,
            percent     REAL,
            last_check  TEXT
        );

        -- ====================================================
        -- RÉSEAU
        -- ====================================================
        CREATE TABLE IF NOT EXISTS network_info (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            interface   TEXT,
            ip_address  TEXT,
            mac_address TEXT,
            gateway     TEXT,
            dns         TEXT,
            last_seen   TEXT
        );

        CREATE TABLE IF NOT EXISTS network_hosts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT,
            mac         TEXT,
            hostname    TEXT,
            interface   TEXT,
            reachable   INTEGER,
            last_seen   TEXT,
            UNIQUE(ip)
        );

        -- ====================================================
        -- FASTPANEL
        -- ====================================================
        CREATE TABLE IF NOT EXISTS fastpanel_users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT NOT NULL UNIQUE,
            email           TEXT,
            disk_quota_gb   REAL,
            disk_used_gb    REAL,
            status          TEXT,
            last_check      TEXT
        );

        CREATE TABLE IF NOT EXISTS fastpanel_domains (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL UNIQUE,
            user        TEXT,
            php_version TEXT,
            ssl_enabled INTEGER,
            status      TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- FIREWALL
        -- ====================================================
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            tool        TEXT NOT NULL,
            chain       TEXT,
            action      TEXT,
            protocol    TEXT,
            port        TEXT,
            source      TEXT,
            destination TEXT,
            raw         TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- FAIL2BAN
        -- ====================================================
        CREATE TABLE IF NOT EXISTS fail2ban_status (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            jail            TEXT NOT NULL UNIQUE,
            currently_failed INTEGER DEFAULT 0,
            total_failed    INTEGER DEFAULT 0,
            currently_banned INTEGER DEFAULT 0,
            total_banned    INTEGER DEFAULT 0,
            last_check      TEXT
        );

        CREATE TABLE IF NOT EXISTS fail2ban_banned_ips (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            jail        TEXT NOT NULL,
            ip          TEXT NOT NULL,
            banned_at   TEXT,
            last_check  TEXT,
            UNIQUE(jail, ip)
        );

        -- ====================================================
        -- LOGS D'ERREUR
        -- ====================================================
        CREATE TABLE IF NOT EXISTS log_errors (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            service     TEXT NOT NULL,
            level       TEXT,
            message     TEXT,
            count       INTEGER DEFAULT 1,
            last_seen   TEXT
        );

        -- ====================================================
        -- SMART DISQUES
        -- ====================================================
        CREATE TABLE IF NOT EXISTS disk_smart (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device          TEXT NOT NULL UNIQUE,
            model           TEXT,
            serial          TEXT,
            health          TEXT,
            temperature     INTEGER,
            power_on_hours  INTEGER,
            reallocated_sectors INTEGER,
            pending_sectors INTEGER,
            uncorrectable   INTEGER,
            last_check      TEXT
        );

        -- ====================================================
        -- REDIS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS redis_stats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts              TEXT NOT NULL,
            used_memory_mb  REAL,
            max_memory_mb   REAL,
            pct_memory      REAL,
            total_keys      INTEGER,
            hit_rate        REAL,
            connected_clients INTEGER,
            uptime_seconds  INTEGER,
            version         TEXT,
            last_check      TEXT
        );

        -- ====================================================
        -- PHP-FPM POOLS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS phpfpm_pools (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            pool            TEXT NOT NULL,
            socket          TEXT,
            listen          TEXT,
            active_processes INTEGER,
            idle_processes  INTEGER,
            total_processes INTEGER,
            max_active      INTEGER,
            slow_requests   INTEGER,
            total_requests  INTEGER,
            last_check      TEXT,
            UNIQUE(pool)
        );

        -- ====================================================
        -- NGINX ACCESS STATS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS nginx_access_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            domain      TEXT,
            period      TEXT,
            total_reqs  INTEGER,
            req_2xx     INTEGER,
            req_3xx     INTEGER,
            req_4xx     INTEGER,
            req_5xx     INTEGER,
            top_ips     TEXT,
            top_paths   TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- BACKUP RUNS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS backup_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            remote      TEXT NOT NULL,
            ts          TEXT,
            status      TEXT,
            size_gb     REAL,
            files_count INTEGER,
            duration_s  INTEGER,
            error       TEXT,
            last_check  TEXT,
            UNIQUE(remote)
        );

        -- ====================================================
        -- CHANGELOG INFRA
        -- ====================================================
        CREATE TABLE IF NOT EXISTS changelog (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_name TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_value   TEXT,
            new_value   TEXT,
            severity    TEXT DEFAULT 'info'
        );

        -- ====================================================
        -- HEALTH SCORES
        -- ====================================================
        CREATE TABLE IF NOT EXISTS health_scores (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            score       INTEGER NOT NULL,
            breakdown   TEXT,
            alerts_count INTEGER DEFAULT 0,
            status      TEXT
        );

        -- ====================================================
        -- VERSIONS DES PACKAGES
        -- ====================================================
        CREATE TABLE IF NOT EXISTS package_versions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            package     TEXT NOT NULL UNIQUE,
            version     TEXT,
            path        TEXT,
            vulnerable  INTEGER DEFAULT 0,
            cve_note    TEXT,
            last_check  TEXT
        );

        -- ====================================================
        -- APACHE2 VHOSTS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS apache_vhosts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL,
            document_root TEXT,
            config_file TEXT,
            ssl_enabled INTEGER DEFAULT 0,
            last_check  TEXT,
            UNIQUE(domain, config_file)
        );

        -- ====================================================
        -- DNS SERVERS (V4)
        -- ====================================================
        CREATE TABLE IF NOT EXISTS dns_servers (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            server_type     TEXT NOT NULL,
            version         TEXT,
            config_file     TEXT,
            zones_count     INTEGER,
            running         INTEGER DEFAULT 0,
            last_check      TEXT,
            UNIQUE(server_type)
        );

        CREATE TABLE IF NOT EXISTS dns_zones (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            zone_name       TEXT NOT NULL,
            server_type     TEXT NOT NULL,
            zone_file       TEXT,
            serial          TEXT,
            records_count   INTEGER,
            last_check      TEXT,
            UNIQUE(zone_name, server_type)
        );

        -- ====================================================
        -- SYSCTL SÉCURITÉ (V4)
        -- ====================================================
        CREATE TABLE IF NOT EXISTS sysctl_security (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            param           TEXT NOT NULL UNIQUE,
            value           TEXT,
            recommended     TEXT,
            status          TEXT,
            description     TEXT,
            last_check      TEXT
        );

        -- ====================================================
        -- COLLECTOR RUNS
        -- ====================================================
        CREATE TABLE IF NOT EXISTS collector_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            run_type    TEXT NOT NULL,
            duration_ms INTEGER,
            items_count INTEGER,
            errors      TEXT,
            status      TEXT DEFAULT 'ok'
        );

        -- INDICES
        CREATE INDEX IF NOT EXISTS idx_metrics_ts       ON metrics_realtime(ts);
        CREATE INDEX IF NOT EXISTS idx_web_domain       ON web_sites(domain);
        CREATE INDEX IF NOT EXISTS idx_cms_type         ON cms_sites(cms_type);
        CREATE INDEX IF NOT EXISTS idx_ssl_expiry       ON ssl_certificates(days_left);
        CREATE INDEX IF NOT EXISTS idx_docker_name      ON docker_containers(name);
        CREATE INDEX IF NOT EXISTS idx_changelog_ts     ON changelog(ts);
        CREATE INDEX IF NOT EXISTS idx_health_ts        ON health_scores(ts);
        CREATE INDEX IF NOT EXISTS idx_log_errors_svc   ON log_errors(service);
        CREATE INDEX IF NOT EXISTS idx_log_errors_ts    ON log_errors(ts);
        CREATE INDEX IF NOT EXISTS idx_f2b_jail         ON fail2ban_status(jail);
        CREATE INDEX IF NOT EXISTS idx_f2b_ip           ON fail2ban_banned_ips(ip);
        CREATE INDEX IF NOT EXISTS idx_backup_remote    ON backup_runs(remote);
        CREATE INDEX IF NOT EXISTS idx_dns_server       ON dns_servers(server_type);
        CREATE INDEX IF NOT EXISTS idx_sysctl_param     ON sysctl_security(param);
        CREATE INDEX IF NOT EXISTS idx_nfs_export       ON nfs_exports(export_path);
        CREATE INDEX IF NOT EXISTS idx_nfs_mount        ON nfs_mounts(mountpoint);
    """)
    conn.commit()
    conn.close()
    print("[COLLECTOR] Tables initialisées (V4 complète)", file=sys.stderr)


# ============================================================
# HELPERS
# ============================================================
def run_cmd(args: list, timeout: int = 10, input_data: str = None) -> str:
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            shell=False,
            env={"PATH": "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin"},
            input=input_data
        )
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""


def log_collector_run(run_type: str, duration_ms: int,
                      items: int, errors: list, status: str = "ok"):
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO collector_runs (ts, run_type, duration_ms, items_count, errors, status) "
            "VALUES (?,?,?,?,?,?)",
            (datetime.now().isoformat(), run_type, duration_ms,
             items, json.dumps(errors[:10]), status)
        )
        conn.execute(
            "DELETE FROM collector_runs WHERE id NOT IN "
            "(SELECT id FROM collector_runs ORDER BY id DESC LIMIT 500)"
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[COLLECTOR] log_run error: {e}", file=sys.stderr)


# ============================================================
# CHANGELOG
# ============================================================
def _get_snapshot(entity_type: str) -> set:
    try:
        conn = get_conn()
        table_map = {
            "web_site":   ("web_sites",        "domain"),
            "container":  ("docker_containers", "name"),
            "port":       ("open_ports",        "port"),
            "ssl":        ("ssl_certificates",  "domain"),
            "vpn":        ("vpn_connections",   "name"),
            "service":    ("system_services",   "name"),
            "db":         ("databases",         "name"),
            "dns_server": ("dns_servers",       "server_type"),
        }
        if entity_type not in table_map:
            conn.close()
            return set()
        table, col = table_map[entity_type]
        rows = conn.execute(f"SELECT {col} FROM {table}").fetchall()
        conn.close()
        return {str(r[0]) for r in rows if r[0]}
    except Exception:
        return set()


def record_change(entity_type: str, entity_name: str,
                  change_type: str, old_val: str = None,
                  new_val: str = None, severity: str = "info"):
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO changelog (ts, entity_type, entity_name, change_type, old_value, new_value, severity) "
            "VALUES (?,?,?,?,?,?,?)",
            (datetime.now().isoformat(), entity_type, entity_name,
             change_type, old_val, new_val, severity)
        )
        conn.execute(
            "DELETE FROM changelog WHERE id NOT IN "
            "(SELECT id FROM changelog ORDER BY id DESC LIMIT 5000)"
        )
        conn.commit()
        conn.close()
        print(f"[CHANGELOG] {change_type} {entity_type}: {entity_name}", file=sys.stderr)
    except Exception as e:
        print(f"[COLLECTOR] record_change error: {e}", file=sys.stderr)


def detect_diff(entity_type: str, current_names: set):
    previous = _get_snapshot(entity_type)
    appeared = current_names - previous
    disappeared = previous - current_names
    severity_map = {
        "port": "warning", "container": "info",
        "web_site": "info", "ssl": "warning",
        "service": "warning", "vpn": "info", "db": "info",
        "dns_server": "warning",
    }
    sev = severity_map.get(entity_type, "info")
    for name in appeared:
        record_change(entity_type, name, "appeared", severity=sev)
    for name in disappeared:
        record_change(entity_type, name, "disappeared",
                      severity="warning" if sev == "info" else "critical")


# ============================================================
# MÉTRIQUES TEMPS RÉEL
# ============================================================
def get_cpu_percent() -> float:
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


def collect_ram() -> dict:
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        total = mi.get("MemTotal", 1)
        avail = mi.get("MemAvailable", total)
        used = total - avail
        return {
            "total_gb":   round(total / 1024**2, 1),
            "used_gb":    round(used  / 1024**2, 1),
            "free_gb":    round(mi.get("MemFree", 0) / 1024**2, 1),
            "percent":    round(100.0 * used / total, 1),
            "buffers_gb": round(mi.get("Buffers", 0) / 1024**2, 1),
            "cached_gb":  round(mi.get("Cached",  0) / 1024**2, 1),
        }
    except Exception:
        return {"total_gb": 0, "used_gb": 0, "free_gb": 0,
                "percent": 0, "buffers_gb": 0, "cached_gb": 0}


def collect_swap() -> dict:
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        total = mi.get("SwapTotal", 0)
        free = mi.get("SwapFree", 0)
        used = total - free
        return {
            "total_gb": round(total / 1024**2, 1),
            "used_gb":  round(used  / 1024**2, 1),
            "free_gb":  round(free  / 1024**2, 1),
            "pct":      round(100.0 * used / total, 1) if total > 0 else 0.0,
        }
    except Exception:
        return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "pct": 0.0}


def collect_disk() -> dict:
    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        return {
            "percent":  round(100.0 * used / total, 1),
            "total_gb": round(total / 1024**3, 1),
            "used_gb":  round(used  / 1024**3, 1),
            "free_gb":  round(free  / 1024**3, 1),
        }
    except Exception:
        return {"percent": 0, "total_gb": 0, "used_gb": 0, "free_gb": 0}


def collect_load() -> Tuple[float, float, float]:
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except Exception:
        return 0.0, 0.0, 0.0


def collect_top_processes(limit: int = 10) -> list:
    processes = []
    out = run_cmd(["/bin/ps", "aux", "--sort=-%cpu", "--no-headers"], timeout=5)
    for line in out.splitlines()[:limit]:
        parts = line.split(None, 10)
        if len(parts) >= 11:
            try:
                processes.append({
                    "user": parts[0], "pid": int(parts[1]),
                    "cpu": float(parts[2]), "mem": float(parts[3]),
                    "command": parts[10][:100]
                })
            except ValueError:
                pass
    return processes


def collect_services() -> dict:
    services = {}
    svc_list = [
        "nginx", "apache2", "php8.1-fpm", "php8.2-fpm", "php8.3-fpm",
        "mysql", "mariadb", "postgresql", "redis-server", "redis",
        "docker", "fail2ban", "ufw", "ssh", "postfix", "dovecot",
    ]
    for svc in svc_list:
        out = run_cmd(["/bin/systemctl", "is-active", svc], timeout=3)
        services[svc] = out.strip() == "active"
    return services


def collect_alerts(cpu: float, ram: float, disk: float, swap: float) -> list:
    alerts = []
    if cpu > 85:
        alerts.append({"level": "critical", "msg": f"CPU à {cpu}%"})
    elif cpu > 70:
        alerts.append({"level": "warning", "msg": f"CPU à {cpu}%"})
    if ram > 85:
        alerts.append({"level": "critical", "msg": f"RAM à {ram}%"})
    elif ram > 70:
        alerts.append({"level": "warning", "msg": f"RAM à {ram}%"})
    if disk > 85:
        alerts.append({"level": "critical", "msg": f"Disque à {disk}%"})
    elif disk > 75:
        alerts.append({"level": "warning", "msg": f"Disque à {disk}%"})
    if swap > 80:
        alerts.append({"level": "warning", "msg": f"Swap à {swap}%"})
    return alerts


def collect_metrics() -> dict:
    cpu = get_cpu_percent()
    ram = collect_ram()
    disk = collect_disk()
    swap = collect_swap()
    load_1m, load_5m, load_15m = collect_load()
    return {
        "ts":           datetime.now().isoformat(),
        "cpu_pct":      cpu,
        "ram_pct":      ram["percent"],
        "ram_total_gb": ram["total_gb"],
        "ram_used_gb":  ram["used_gb"],
        "ram_free_gb":  ram["free_gb"],
        "ram_buffers_gb": ram["buffers_gb"],
        "ram_cached_gb":  ram["cached_gb"],
        "swap_total_gb":  swap["total_gb"],
        "swap_used_gb":   swap["used_gb"],
        "swap_free_gb":   swap["free_gb"],
        "swap_pct":       swap["pct"],
        "disk_pct":     disk["percent"],
        "disk_total_gb": disk["total_gb"],
        "disk_used_gb": disk["used_gb"],
        "disk_free_gb": disk["free_gb"],
        "load_1m": load_1m, "load_5m": load_5m, "load_15m": load_15m,
        "top_processes": collect_top_processes(10),
        "services":      collect_services(),
        "alerts":        collect_alerts(cpu, ram["percent"], disk["percent"], swap["pct"]),
    }


# ============================================================
# SYSTEMD SERVICES UNIT STATUS (V4)
# ============================================================
def collect_systemd_services() -> List[Dict]:
    """Collecte détaillée des services systemd"""
    services = []
    now = datetime.now().isoformat()

    out = run_cmd(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"], timeout=15)
    if not out:
        return services

    for line in out.splitlines():
        parts = line.split(maxsplit=4)
        if len(parts) < 4:
            continue

        unit = parts[0]
        if not unit.endswith(".service"):
            continue

        name = unit[:-8]

        show_out = run_cmd(["systemctl", "show", unit, "--no-pager"], timeout=10)
        if not show_out:
            continue

        props = {}
        for prop_line in show_out.splitlines():
            if "=" in prop_line:
                k, v = prop_line.split("=", 1)
                props[k] = v

        services.append({
            "name": name,
            "status": props.get("ActiveState", "unknown"),
            "enabled": 1 if props.get("UnitFileState") == "enabled" else 0,
            "active": 1 if props.get("ActiveState") == "active" else 0,
            "description": props.get("Description", "")[:200],
            "load_state": props.get("LoadState", "unknown"),
            "sub_state": props.get("SubState", "unknown"),
            "active_state": props.get("ActiveState", "unknown"),
            "unit_file_state": props.get("UnitFileState", "unknown"),
            "last_check": now,
        })

    return services


# ============================================================
# DNS SERVERS DETECTION (V4)
# ============================================================
def detect_bind() -> Optional[Dict]:
    config_paths = ["/etc/bind/named.conf", "/etc/named.conf"]
    for conf in config_paths:
        if Path(conf).exists():
            out = run_cmd(["named", "-v"], timeout=5)
            version = re.search(r'BIND ([\d.]+)', out) if out else None
            version_str = version.group(1) if version else "unknown"

            zones = []
            try:
                content = Path(conf).read_text(errors="replace")
                zone_matches = re.findall(r'zone\s+"([^"]+)"\s+{', content)
                zones = zone_matches
            except Exception:
                pass

            running = run_cmd(["systemctl", "is-active", "named"], timeout=3).strip() == "active" or \
                      run_cmd(["systemctl", "is-active", "bind9"], timeout=3).strip() == "active"

            return {
                "server_type": "bind",
                "version": version_str,
                "config_file": conf,
                "zones_count": len(zones),
                "running": 1 if running else 0,
            }
    return None


def detect_powerdns() -> Optional[Dict]:
    config_paths = ["/etc/powerdns/pdns.conf", "/etc/pdns/pdns.conf"]
    for conf in config_paths:
        if Path(conf).exists():
            out = run_cmd(["pdns_server", "--version"], timeout=5)
            version = re.search(r'PowerDNS Authoritative Server ([\d.]+)', out) if out else None
            version_str = version.group(1) if version else "unknown"

            zones = []
            try:
                config = configparser.ConfigParser()
                config.read(conf)
                if config.has_section("") or config.has_section("general"):
                    section = config[""] if config.has_section("") else config["general"]
                    launch = section.get("launch", "")
                    if "gmysql" in launch or "gpgsql" in launch:
                        zones_out = run_cmd(["pdnsutil", "list-all-zones"], timeout=10)
                        if zones_out:
                            zones = [z.strip() for z in zones_out.splitlines() if z.strip()]
            except Exception:
                pass

            running = run_cmd(["systemctl", "is-active", "pdns"], timeout=3).strip() == "active"

            return {
                "server_type": "powerdns",
                "version": version_str,
                "config_file": conf,
                "zones_count": len(zones),
                "running": 1 if running else 0,
            }
    return None


def detect_unbound() -> Optional[Dict]:
    config_paths = ["/etc/unbound/unbound.conf"]
    for conf in config_paths:
        if Path(conf).exists():
            out = run_cmd(["unbound", "-V"], timeout=5)
            version = re.search(r'Version ([\d.]+)', out) if out else None
            version_str = version.group(1) if version else "unknown"

            zones = []
            try:
                content = Path(conf).read_text(errors="replace")
                zone_matches = re.findall(r'^\s*(?:zone|local-zone):\s+"([^"]+)"', content, re.MULTILINE)
                zones = zone_matches
            except Exception:
                pass

            running = run_cmd(["systemctl", "is-active", "unbound"], timeout=3).strip() == "active"

            return {
                "server_type": "unbound",
                "version": version_str,
                "config_file": conf,
                "zones_count": len(zones),
                "running": 1 if running else 0,
            }
    return None


def detect_knot() -> Optional[Dict]:
    config_paths = ["/etc/knot/knot.conf"]
    for conf in config_paths:
        if Path(conf).exists():
            out = run_cmd(["knotd", "-V"], timeout=5)
            version = re.search(r'Knot DNS ([\d.]+)', out) if out else None
            version_str = version.group(1) if version else "unknown"

            zones = []
            try:
                content = Path(conf).read_text(errors="replace")
                zone_matches = re.findall(r'^\s*zone:\s*domain:\s*"([^"]+)"', content, re.MULTILINE)
                zones = zone_matches
            except Exception:
                pass

            running = run_cmd(["systemctl", "is-active", "knot"], timeout=3).strip() == "active"

            return {
                "server_type": "knot",
                "version": version_str,
                "config_file": conf,
                "zones_count": len(zones),
                "running": 1 if running else 0,
            }
    return None


def detect_nsd() -> Optional[Dict]:
    config_paths = ["/etc/nsd/nsd.conf"]
    for conf in config_paths:
        if Path(conf).exists():
            out = run_cmd(["nsd", "-v"], timeout=5)
            version = re.search(r'NSD ([\d.]+)', out) if out else None
            version_str = version.group(1) if version else "unknown"

            zones = []
            try:
                content = Path(conf).read_text(errors="replace")
                zone_matches = re.findall(r'^\s*zone:\s*name:\s*"([^"]+)"', content, re.MULTILINE)
                zones = zone_matches
            except Exception:
                pass

            running = run_cmd(["systemctl", "is-active", "nsd"], timeout=3).strip() == "active"

            return {
                "server_type": "nsd",
                "version": version_str,
                "config_file": conf,
                "zones_count": len(zones),
                "running": 1 if running else 0,
            }
    return None


def detect_dnsmasq() -> Optional[Dict]:
    config_paths = ["/etc/dnsmasq.conf"]
    for conf in config_paths:
        if Path(conf).exists():
            out = run_cmd(["dnsmasq", "-v"], timeout=5)
            version = re.search(r'Dnsmasq version ([\d.]+)', out) if out else None
            version_str = version.group(1) if version else "unknown"

            running = run_cmd(["systemctl", "is-active", "dnsmasq"], timeout=3).strip() == "active"

            return {
                "server_type": "dnsmasq",
                "version": version_str,
                "config_file": conf,
                "zones_count": 0,
                "running": 1 if running else 0,
            }
    return None


def collect_dns_servers() -> Tuple[List[Dict], List[Dict]]:
    servers = []
    zones = []
    now = datetime.now().isoformat()

    detectors = [
        detect_bind,
        detect_powerdns,
        detect_unbound,
        detect_knot,
        detect_nsd,
        detect_dnsmasq,
    ]

    for detector in detectors:
        try:
            result = detector()
            if result:
                result["last_check"] = now
                servers.append(result)
        except Exception as e:
            print(f"[DNS] Erreur détection {detector.__name__}: {e}", file=sys.stderr)

    for server in servers:
        if server["server_type"] == "bind" and server.get("running"):
            zones_out = run_cmd(["rndc", "status"], timeout=10)
            if zones_out:
                m = re.search(r'number of zones:\s*(\d+)', zones_out)
                if m:
                    server["zones_count"] = int(m.group(1))

            list_zones = run_cmd(["rndc", "list-zones"], timeout=15)
            for line in list_zones.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    zones.append({
                        "zone_name": parts[0],
                        "server_type": "bind",
                        "zone_file": None,
                        "serial": None,
                        "records_count": 0,
                        "last_check": now,
                    })

        if server["server_type"] == "powerdns" and server.get("running"):
            list_out = run_cmd(["pdnsutil", "list-all-zones"], timeout=15)
            for line in list_out.splitlines():
                zone = line.strip()
                if zone:
                    zones.append({
                        "zone_name": zone,
                        "server_type": "powerdns",
                        "zone_file": None,
                        "serial": None,
                        "records_count": 0,
                        "last_check": now,
                    })

    return servers, zones[:500]


# ============================================================
# SYSCTL SÉCURITÉ (V4)
# ============================================================
SECURITY_SYSCTL = {
    "kernel.kptr_restrict": {
        "recommended": "2",
        "critical": "0",
        "description": "Restriction des pointeurs kernel dans /proc/kallsyms",
        "severity_if_wrong": "critical"
    },
    "kernel.dmesg_restrict": {
        "recommended": "1",
        "critical": "0",
        "description": "Restriction d'accès à dmesg",
        "severity_if_wrong": "critical"
    },
    "kernel.printk": {
        "recommended": "3 3 3 3",
        "critical": None,
        "description": "Niveau de logging kernel",
        "severity_if_wrong": "info"
    },
    "kernel.randomize_va_space": {
        "recommended": "2",
        "critical": "0",
        "description": "ASLR (2=full, 1=conservative, 0=off)",
        "severity_if_wrong": "critical"
    },
    "net.ipv4.conf.all.rp_filter": {
        "recommended": "1",
        "critical": "0",
        "description": "Protection anti-spoofing",
        "severity_if_wrong": "warning"
    },
    "net.ipv4.conf.default.rp_filter": {
        "recommended": "1",
        "critical": "0",
        "description": "Protection anti-spoofing (default)",
        "severity_if_wrong": "warning"
    },
    "net.ipv4.tcp_syncookies": {
        "recommended": "1",
        "critical": "0",
        "description": "Protection contre SYN flood",
        "severity_if_wrong": "warning"
    },
    "net.ipv4.icmp_echo_ignore_all": {
        "recommended": "0",
        "critical": None,
        "description": "Ignore toutes les requêtes ICMP echo",
        "severity_if_wrong": "info"
    },
    "net.ipv4.icmp_ignore_bogus_error_responses": {
        "recommended": "1",
        "critical": "0",
        "description": "Ignore les réponses d'erreur ICMP bogus",
        "severity_if_wrong": "info"
    },
    "net.ipv4.conf.all.accept_redirects": {
        "recommended": "0",
        "critical": "1",
        "description": "Acceptation des redirections ICMP",
        "severity_if_wrong": "warning"
    },
    "net.ipv6.conf.all.accept_redirects": {
        "recommended": "0",
        "critical": "1",
        "description": "Acceptation des redirections ICMP IPv6",
        "severity_if_wrong": "warning"
    },
    "net.ipv4.conf.all.secure_redirects": {
        "recommended": "0",
        "critical": "1",
        "description": "Redirections sécurisées",
        "severity_if_wrong": "warning"
    },
    "net.ipv4.conf.all.send_redirects": {
        "recommended": "0",
        "critical": "1",
        "description": "Envoi de redirections ICMP",
        "severity_if_wrong": "warning"
    },
    "net.ipv6.conf.all.forwarding": {
        "recommended": "0",
        "critical": None,
        "description": "Forwarding IPv6",
        "severity_if_wrong": "info"
    },
    "net.ipv4.ip_forward": {
        "recommended": "0",
        "critical": None,
        "description": "Forwarding IPv4",
        "severity_if_wrong": "info"
    },
    "fs.protected_symlinks": {
        "recommended": "1",
        "critical": "0",
        "description": "Protection des liens symboliques dans /tmp",
        "severity_if_wrong": "warning"
    },
    "fs.protected_hardlinks": {
        "recommended": "1",
        "critical": "0",
        "description": "Protection des hardlinks",
        "severity_if_wrong": "warning"
    },
    "fs.protected_fifos": {
        "recommended": "1",
        "critical": "0",
        "description": "Protection des FIFOs dans /tmp",
        "severity_if_wrong": "warning"
    },
    "fs.protected_regular": {
        "recommended": "1",
        "critical": "0",
        "description": "Protection des fichiers réguliers dans /tmp",
        "severity_if_wrong": "warning"
    },
    "kernel.modules_disabled": {
        "recommended": "0",
        "critical": None,
        "description": "Désactivation du chargement de modules",
        "severity_if_wrong": "info"
    },
    "kernel.core_uses_pid": {
        "recommended": "1",
        "critical": "0",
        "description": "Ajout du PID dans les core dumps",
        "severity_if_wrong": "info"
    },
}


def collect_sysctl_security() -> List[Dict]:
    results = []
    now = datetime.now().isoformat()

    for param, info in SECURITY_SYSCTL.items():
        out = run_cmd(["sysctl", "-n", param], timeout=5)
        value = out.strip() if out else "unknown"

        recommended = info["recommended"]
        critical = info.get("critical")
        status = "ok"
        severity = info.get("severity_if_wrong", "warning")

        if value == "unknown":
            status = "warning"
        elif recommended and value != recommended:
            if critical and value == critical:
                status = "critical"
            else:
                status = severity
        elif critical and value == critical:
            status = "critical"

        results.append({
            "param": param,
            "value": value,
            "recommended": recommended,
            "status": status,
            "description": info["description"],
            "last_check": now,
        })

    return results


# ============================================================
# INODE USAGE
# ============================================================
def collect_inode_usage() -> List[Dict]:
    result = []
    try:
        with open("/proc/mounts") as f:
            mounts = [line.split() for line in f if len(line.split()) >= 3]
        seen = set()
        for parts in mounts:
            mp = parts[1]
            if mp in seen or mp.startswith(("/proc", "/sys", "/dev")):
                continue
            seen.add(mp)
            try:
                st = os.statvfs(mp)
                total = st.f_files
                free = st.f_ffree
                used = total - free
                pct = round(100.0 * used / total, 1) if total > 0 else 0.0
                result.append({
                    "mountpoint": mp, "total": total,
                    "used": used, "free": free, "pct": pct,
                })
            except Exception:
                pass
    except Exception:
        pass
    return result


# ============================================================
# SITES WEB — Nginx + Apache
# ============================================================
def collect_nginx_sites() -> List[Dict]:
    sites = []
    nginx_dirs = [
        "/etc/nginx/sites-enabled", "/etc/nginx/conf.d",
        "/etc/nginx/sites-available",
    ]
    seen_domains = set()
    for nginx_dir in nginx_dirs:
        for conf_file in Path(nginx_dir).glob("*.conf") if Path(nginx_dir).exists() else []:
            try:
                content = conf_file.read_text(errors="replace")
                server_names = re.findall(r'server_name\s+([^;]+);', content, re.DOTALL)
                roots = re.findall(r'root\s+([^;]+);', content)
                ssl_enabled = "ssl_certificate" in content
                ssl_cert_m = re.search(r'ssl_certificate\s+([^;]+);', content)
                php_match = re.search(r'fastcgi_pass\s+.*?php([\d.]+)[^/]*fpm', content)
                php_version = php_match.group(1) if php_match else "unknown"

                for sn_group in server_names:
                    for domain in sn_group.strip().split():
                        if domain.startswith(("_", "*")) or domain in seen_domains:
                            continue
                        seen_domains.add(domain)
                        sites.append({
                            "domain":        domain,
                            "document_root": roots[0].strip() if roots else "unknown",
                            "config_file":   str(conf_file),
                            "ssl_enabled":   1 if ssl_enabled else 0,
                            "ssl_cert":      ssl_cert_m.group(1).strip() if ssl_cert_m else None,
                            "php_version":   php_version,
                            "server_type":   "nginx",
                        })
            except Exception:
                pass
    return sites


def collect_apache_vhosts() -> List[Dict]:
    vhosts = []
    apache_dirs = ["/etc/apache2/sites-enabled", "/etc/apache2/conf-enabled"]
    seen = set()
    for adir in apache_dirs:
        for conf_file in Path(adir).glob("*.conf") if Path(adir).exists() else []:
            try:
                content = conf_file.read_text(errors="replace")
                vhost_blocks = re.findall(r'<VirtualHost[^>]*>(.*?)</VirtualHost>', content, re.DOTALL)
                for block in vhost_blocks:
                    server_name = re.search(r'ServerName\s+(\S+)', block)
                    server_alias = re.search(r'ServerAlias\s+(\S+)', block)
                    doc_root = re.search(r'DocumentRoot\s+(\S+)', block)
                    ssl_enabled = "SSLEngine on" in block

                    domain = (server_name.group(1) if server_name else
                             (server_alias.group(1) if server_alias else conf_file.stem))
                    key = f"{domain}:{conf_file}"
                    if key in seen:
                        continue
                    seen.add(key)
                    vhosts.append({
                        "domain": domain,
                        "document_root": doc_root.group(1) if doc_root else "unknown",
                        "config_file": str(conf_file),
                        "ssl_enabled": 1 if ssl_enabled else 0,
                        "server_type": "apache",
                    })
            except Exception:
                pass
    return vhosts


# ============================================================
# CMS
# ============================================================
def detect_cms(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    for cms_type, files in CMS_DETECTORS.items():
        found = sum(1 for f in files if (path / f).exists())
        if found >= 2:
            return cms_type
    return None


def get_cms_version(path: Path, cms_type: str) -> str:
    try:
        checks = {
            "wordpress": (
                path / "wp-includes" / "version.php",
                r"\$wp_version\s*=\s*'([^']+)'"
            ),
            "joomla": (
                path / "libraries" / "cms" / "version" / "version.php",
                r"RELEASE\s*=\s*'([^']+)'"
            ),
            "drupal": (
                path / "core" / "lib" / "Drupal.php",
                r"const VERSION = '([^']+)'"
            ),
            "nextcloud": (
                path / "version.php",
                r"\$OC_VersionString\s*=\s*'([^']+)'"
            ),
            "laravel": (
                path / "vendor" / "laravel" / "framework" / "src" / "Illuminate" / "Foundation" / "Application.php",
                r"const VERSION = '([^']+)'"
            ),
        }
        if cms_type in checks:
            vfile, pattern = checks[cms_type]
            if vfile.exists():
                m = re.search(pattern, vfile.read_text(errors="replace"))
                if m:
                    return m.group(1)
    except Exception:
        pass
    return "unknown"


def collect_cms_sites() -> List[Dict]:
    cms_sites = []
    scanned = set()
    for base_path in SCAN_PATHS:
        p = Path(base_path)
        if not p.exists() or str(p) in scanned:
            continue
        scanned.add(str(p))
        try:
            items = list(p.iterdir())
        except PermissionError:
            continue
        for item in items:
            if not item.is_dir() or str(item) in scanned:
                continue
            scanned.add(str(item))
            cms_type = detect_cms(item)
            if not cms_type:
                continue
            version = get_cms_version(item, cms_type)
            plugins, theme, db_name, db_user = [], "unknown", None, None

            if cms_type == "wordpress":
                wp_config = item / "wp-config.php"
                if wp_config.exists():
                    try:
                        c = wp_config.read_text(errors="replace")
                        m = re.search(r"DB_NAME\s*,\s*'([^']+)'", c)
                        if m: db_name = m.group(1)
                        m = re.search(r"DB_USER\s*,\s*'([^']+)'", c)
                        if m: db_user = m.group(1)
                    except Exception:
                        pass
                plugin_dir = item / "wp-content" / "plugins"
                if plugin_dir.exists():
                    try:
                        plugins = [p.name for p in plugin_dir.iterdir()
                                   if p.is_dir() and not p.name.startswith(".")]
                    except Exception:
                        pass
                theme_dir = item / "wp-content" / "themes"
                if theme_dir.exists():
                    try:
                        for td in theme_dir.iterdir():
                            if td.is_dir():
                                style = td / "style.css"
                                if style.exists():
                                    m = re.search(r"Theme Name:\s*(.+)", style.read_text(errors="replace"))
                                    if m:
                                        theme = m.group(1).strip()
                                    break
                    except Exception:
                        pass

            cms_sites.append({
                "domain": item.name, "path": str(item),
                "cms_type": cms_type, "version": version,
                "theme": theme, "plugins": json.dumps(plugins[:30]),
                "plugins_count": len(plugins),
                "db_name": db_name, "db_user": db_user,
                "last_check": datetime.now().isoformat(),
            })
    return cms_sites


# ============================================================
# BASES DE DONNÉES
# ============================================================
def collect_mysql_databases() -> List[Dict]:
    databases = []
    out = run_cmd(["mysql", "-e", "SHOW DATABASES", "-N", "--batch"], timeout=10)
    skip = {"information_schema", "performance_schema", "mysql", "sys"}
    for db in out.splitlines():
        db = db.strip()
        if not db or db in skip:
            continue
        if not SAFE_IDENTIFIER_RE.match(db):
            continue
        size_out = run_cmd([
            "mysql", "-e",
            f"SELECT ROUND(SUM(data_length+index_length)/1024/1024,2) "
            f"FROM information_schema.tables WHERE table_schema='{db}'",
            "-N", "--batch"
        ], timeout=10)
        tables_out = run_cmd([
            "mysql", "-e",
            f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{db}'",
            "-N", "--batch"
        ], timeout=10)
        try:
            size = float(size_out.strip() or 0)
            tables = int(tables_out.strip() or 0)
        except ValueError:
            size, tables = 0.0, 0
        databases.append({
            "name": db, "type": "mysql",
            "size_mb": size, "tables_count": tables, "host": "localhost",
            "last_check": datetime.now().isoformat(),
        })
    return databases


def collect_postgresql_databases() -> List[Dict]:
    databases = []
    out = run_cmd([
        "sudo", "-u", "postgres", "psql", "-t", "-c",
        "SELECT datname FROM pg_database WHERE datistemplate = false"
    ], timeout=15)
    for db in out.splitlines():
        db = db.strip()
        if not db or not SAFE_IDENTIFIER_RE.match(db):
            continue
        size_out = run_cmd([
            "sudo", "-u", "postgres", "psql", "-t", "-c",
            f"SELECT pg_database_size('{db}')/1024/1024"
        ], timeout=10)
        try:
            size = float(size_out.strip() or 0)
        except ValueError:
            size = 0.0
        databases.append({
            "name": db, "type": "postgresql",
            "size_mb": size, "host": "localhost",
            "last_check": datetime.now().isoformat(),
        })
    return databases


# ============================================================
# EMAILS
# ============================================================
def collect_email_accounts() -> List[Dict]:
    accounts = []
    seen = set()
    now = datetime.now().isoformat()

    for df in ["/etc/dovecot/users", "/etc/dovecot/passwd"]:
        if not Path(df).exists():
            continue
        try:
            for line in Path(df).read_text(errors="replace").splitlines():
                if ":" in line and "@" in line:
                    email = line.split(":")[0]
                    if email not in seen:
                        seen.add(email)
                        accounts.append({
                            "email": email,
                            "domain": email.split("@")[1],
                            "status": "active",
                            "last_check": now,
                        })
        except Exception:
            pass

    for vmail in ["/var/vmail", "/var/mail/vhosts"]:
        if not Path(vmail).exists():
            continue
        for domain_dir in Path(vmail).iterdir():
            if not domain_dir.is_dir():
                continue
            for user_dir in domain_dir.iterdir():
                if not user_dir.is_dir():
                    continue
                email = f"{user_dir.name}@{domain_dir.name}"
                if email in seen:
                    continue
                seen.add(email)
                try:
                    size_out = run_cmd(["du", "-sm", str(user_dir)], timeout=10)
                    size_mb = int(size_out.split()[0]) if size_out else 0
                except Exception:
                    size_mb = 0
                accounts.append({
                    "email": email,
                    "domain": domain_dir.name,
                    "used_mb": size_mb,
                    "status": "active",
                    "last_check": now,
                })
    return accounts


def collect_email_queue() -> Dict:
    queue_stats = {"queue_type": "postfix", "count": 0, "oldest_age": 0}
    out = run_cmd(["mailq"], timeout=10)
    if out:
        lines = out.splitlines()
        for line in lines:
            if "deferred" in line.lower():
                queue_stats["count"] += 1
        age_match = re.search(r'(\d+) days', out)
        if age_match:
            queue_stats["oldest_age"] = int(age_match.group(1))
    return queue_stats


def collect_email_stats() -> Dict:
    stats = {
        "stat_type": "daily",
        "today_count": 0,
        "week_count": 0,
        "spam_count": 0,
        "bounce_count": 0,
    }
    today = datetime.now().strftime("%b %d")
    log_file = "/var/log/mail.log"
    if Path(log_file).exists():
        out = run_cmd(["tail", "-n", "5000", log_file], timeout=10)
        for line in out.splitlines():
            if today in line:
                if "status=sent" in line:
                    stats["today_count"] += 1
                if "spam" in line.lower():
                    stats["spam_count"] += 1
                if "bounce" in line.lower():
                    stats["bounce_count"] += 1
    return stats


# ============================================================
# SSL
# ============================================================
def collect_ssl_certificates() -> List[Dict]:
    certs = []
    cert_paths = set()
    for conf_file in Path("/etc/nginx").rglob("*.conf"):
        try:
            content = conf_file.read_text(errors="replace")
            for cp in re.findall(r'ssl_certificate\s+([^;]+);', content):
                cp = cp.strip().strip('"\'')
                if cp in cert_paths or not Path(cp).exists():
                    continue
                cert_paths.add(cp)
                out = run_cmd(["openssl", "x509", "-in", cp, "-noout",
                               "-dates", "-issuer", "-subject"], timeout=5)
                not_after = re.search(r'notAfter=(.+)', out)
                issuer = re.search(r'issuer=(.+)', out)
                subject = re.search(r'subject=(.+)', out)
                if not_after:
                    try:
                        expiry = datetime.strptime(
                            not_after.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.now()).days
                        status = ("expired" if days_left <= 0
                                  else "expiring" if days_left <= 30
                                  else "valid")
                        domain = re.search(r'CN\s*=\s*([^,/]+)',
                                           subject.group(1) if subject else "")
                        certs.append({
                            "domain":      domain.group(1).strip() if domain else conf_file.stem,
                            "cert_path":   cp,
                            "issuer":      issuer.group(1).strip() if issuer else "unknown",
                            "subject":     subject.group(1).strip() if subject else "unknown",
                            "expiry_date": expiry.isoformat(),
                            "days_left":   days_left,
                            "status":      status,
                            "last_check":  datetime.now().isoformat(),
                        })
                        if days_left <= 14:
                            record_change("ssl", domain.group(1) if domain else cp,
                                          "expiring_soon",
                                          new_val=f"{days_left}j restants",
                                          severity="critical" if days_left <= 7 else "warning")
                    except ValueError:
                        pass
        except Exception:
            pass
    return certs


# ============================================================
# FIREWALL
# ============================================================
def collect_firewall_rules() -> List[Dict]:
    rules = []
    now = datetime.now().isoformat()

    ufw_out = run_cmd(["ufw", "status", "numbered"], timeout=5)
    if ufw_out and "inactive" not in ufw_out.lower():
        for line in ufw_out.splitlines():
            m = re.match(r'\[\s*\d+\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s*(IN|OUT|FWD)?\s*(.*)',
                         line, re.IGNORECASE)
            if m:
                rules.append({
                    "tool": "ufw", "chain": m.group(3) or "IN",
                    "action": m.group(2), "protocol": "",
                    "port": m.group(1).strip(), "source": m.group(4).strip(),
                    "destination": "", "raw": line.strip(), "last_check": now,
                })

    ipt_out = run_cmd(["iptables", "-L", "-n", "--line-numbers"], timeout=5)
    current_chain = ""
    for line in ipt_out.splitlines():
        chain_m = re.match(r'^Chain\s+(\S+)', line)
        if chain_m:
            current_chain = chain_m.group(1)
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit():
            rules.append({
                "tool": "iptables", "chain": current_chain,
                "action": parts[1], "protocol": parts[2],
                "port": "", "source": parts[3],
                "destination": parts[4] if len(parts) > 4 else "",
                "raw": line.strip(), "last_check": now,
            })

    return rules


# ============================================================
# FAIL2BAN
# ============================================================
def collect_fail2ban() -> Tuple[List[Dict], List[Dict]]:
    jails, banned = [], []
    now = datetime.now().isoformat()

    jails_out = run_cmd(["fail2ban-client", "status"], timeout=5)
    jail_names = re.findall(r'Jail list:\s*(.+)', jails_out)
    if not jail_names:
        return [], []
    for jname in jail_names[0].split(","):
        jname = jname.strip()
        if not jname:
            continue
        status_out = run_cmd(["fail2ban-client", "status", jname], timeout=5)
        cf_m = re.search(r'Currently failed:\s*(\d+)', status_out)
        tf_m = re.search(r'Total failed:\s*(\d+)', status_out)
        cb_m = re.search(r'Currently banned:\s*(\d+)', status_out)
        tb_m = re.search(r'Total banned:\s*(\d+)', status_out)
        ips_m = re.search(r'Banned IP list:\s*(.+)', status_out)
        jails.append({
            "jail":             jname,
            "currently_failed": int(cf_m.group(1)) if cf_m else 0,
            "total_failed":     int(tf_m.group(1)) if tf_m else 0,
            "currently_banned": int(cb_m.group(1)) if cb_m else 0,
            "total_banned":     int(tb_m.group(1)) if tb_m else 0,
            "last_check":       now,
        })
        if ips_m:
            for ip in ips_m.group(1).split():
                ip = ip.strip()
                if ip:
                    banned.append({"jail": jname, "ip": ip,
                                   "banned_at": now, "last_check": now})
    return jails, banned


# ============================================================
# LOGS D'ERREUR
# ============================================================
def collect_log_errors() -> List[Dict]:
    errors = []
    now = datetime.now().isoformat()

    sources = {
        "nginx": ["/var/log/nginx/error.log", "/var/log/nginx/error.log.1"],
        "php": ["/var/log/php8.1-fpm.log", "/var/log/php8.3-fpm.log", "/var/log/php_errors.log"],
        "mysql": ["/var/log/mysql/error.log", "/var/log/mysql.err"],
        "syslog": ["/var/log/syslog"],
        "auth": ["/var/log/auth.log"],
    }

    error_patterns = {
        "nginx": re.compile(r'\[(error|crit|alert|emerg)\](.{0,200})', re.IGNORECASE),
        "php": re.compile(r'(PHP (?:Fatal|Parse|Warning|Notice) error.{0,200})', re.IGNORECASE),
        "mysql": re.compile(r'\[ERROR\](.{0,200})', re.IGNORECASE),
        "syslog": re.compile(r'(error|critical|failed|killed).{0,150}', re.IGNORECASE),
        "auth": re.compile(r'(Failed password|Invalid user|authentication failure).{0,150}', re.IGNORECASE),
    }

    seen_msgs: Dict[str, int] = defaultdict(int)

    for service, log_files in sources.items():
        pattern = error_patterns.get(service, re.compile(r'error', re.IGNORECASE))
        for log_file in log_files:
            if not Path(log_file).exists():
                continue
            out = run_cmd(["tail", "-n", "500", log_file], timeout=5)
            for line in out.splitlines():
                m = pattern.search(line)
                if not m:
                    continue
                msg = m.group(0)[:300].strip()
                key = f"{service}:{hashlib.md5(msg.encode()).hexdigest()[:8]}"
                seen_msgs[key] += 1
                if seen_msgs[key] == 1:
                    errors.append({
                        "ts": now,
                        "service": service,
                        "level": "error",
                        "message": msg,
                        "count": 1,
                        "last_seen": now,
                    })

    return errors[:200]


# ============================================================
# SMART DISQUES
# ============================================================
def collect_disk_smart() -> List[Dict]:
    smart_data = []
    now = datetime.now().isoformat()

    lsblk_out = run_cmd(["lsblk", "-d", "-n", "-o", "NAME,TYPE"], timeout=5)
    devices = []
    for line in lsblk_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] in ("disk",):
            devices.append(f"/dev/{parts[0]}")

    for dev in devices:
        out = run_cmd(["smartctl", "-A", "-H", dev], timeout=10)
        if not out:
            continue
        health_m = re.search(r'overall-health\s+\w+\s+result:\s*(\w+)', out, re.IGNORECASE)
        temp_m = re.search(r'Temperature_Celsius.*?(\d+)\s*\(', out)
        if not temp_m:
            temp_m = re.search(r'(?:190|194)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', out)
        hours_m = re.search(r'Power_On_Hours.*?(\d+)', out)
        realloc_m = re.search(r'Reallocated_Sector_Ct.*?(\d+)\s*$', out, re.MULTILINE)
        pending_m = re.search(r'Current_Pending_Sector.*?(\d+)\s*$', out, re.MULTILINE)
        uncorr_m = re.search(r'Offline_Uncorrectable.*?(\d+)\s*$', out, re.MULTILINE)
        model_m = re.search(r'Device Model:\s*(.+)', out)
        serial_m = re.search(r'Serial Number:\s*(.+)', out)

        smart_data.append({
            "device": dev,
            "model": model_m.group(1).strip() if model_m else "unknown",
            "serial": serial_m.group(1).strip() if serial_m else "unknown",
            "health": health_m.group(1).strip() if health_m else "unknown",
            "temperature": int(temp_m.group(1)) if temp_m else None,
            "power_on_hours": int(hours_m.group(1)) if hours_m else None,
            "reallocated_sectors": int(realloc_m.group(1)) if realloc_m else 0,
            "pending_sectors": int(pending_m.group(1)) if pending_m else 0,
            "uncorrectable": int(uncorr_m.group(1)) if uncorr_m else 0,
            "last_check": now,
        })

        if smart_data[-1]["reallocated_sectors"] > 0 or smart_data[-1]["pending_sectors"] > 0:
            record_change("disk_smart", dev, "bad_sectors",
                          new_val=f"reallocated={smart_data[-1]['reallocated_sectors']}",
                          severity="critical")

    return smart_data


# ============================================================
# REDIS
# ============================================================
def collect_redis_stats() -> Optional[Dict]:
    now = datetime.now().isoformat()
    out = run_cmd(["redis-cli", "INFO"], timeout=5)
    if not out:
        return None

    def _get(key):
        m = re.search(rf'^{key}:(.+)$', out, re.MULTILINE)
        return m.group(1).strip() if m else None

    try:
        used_mem = int(_get("used_memory") or 0)
        max_mem = int(_get("maxmemory") or 0)
        hits = int(_get("keyspace_hits") or 0)
        misses = int(_get("keyspace_misses") or 0)
        total_req = hits + misses

        total_keys = 0
        for line in out.splitlines():
            km = re.search(r'db\d+:keys=(\d+)', line)
            if km:
                total_keys += int(km.group(1))

        return {
            "ts": now,
            "used_memory_mb": round(used_mem / 1024**2, 1),
            "max_memory_mb": round(max_mem / 1024**2, 1) if max_mem else 0,
            "pct_memory": round(100.0 * used_mem / max_mem, 1) if max_mem else 0,
            "total_keys": total_keys,
            "hit_rate": round(100.0 * hits / total_req, 1) if total_req else 0,
            "connected_clients": int(_get("connected_clients") or 0),
            "uptime_seconds": int(_get("uptime_in_seconds") or 0),
            "version": _get("redis_version") or "unknown",
            "last_check": now,
        }
    except Exception:
        return None


# ============================================================
# PHP-FPM POOLS
# ============================================================
def collect_phpfpm_pools() -> List[Dict]:
    pools = []
    now = datetime.now().isoformat()

    fpm_conf_dirs = list(Path("/etc").glob("php/*/fpm/pool.d"))
    sockets = []
    for conf_dir in fpm_conf_dirs:
        for pool_conf in conf_dir.glob("*.conf"):
            try:
                content = pool_conf.read_text(errors="replace")
                m = re.search(r'^listen\s*=\s*(.+)$', content, re.MULTILINE)
                name_m = re.search(r'^\[(.+)\]', content, re.MULTILINE)
                if m:
                    sockets.append({
                        "socket": m.group(1).strip(),
                        "pool": name_m.group(1).strip() if name_m else pool_conf.stem,
                    })
            except Exception:
                pass

    for sinfo in sockets:
        sock = sinfo["socket"]
        pool = sinfo["pool"]
        status_out = ""
        if sock.startswith("/"):
            status_out = run_cmd([
                "cgi-fcgi", "-bind", "-connect", sock
            ], timeout=5, input_data="SCRIPT_NAME=/status\r\nSCRIPT_FILENAME=/status\r\nREQUEST_METHOD=GET\r\n\r\n")
        elif ":" in sock:
            host, port = sock.rsplit(":", 1)
            status_out = run_cmd(["curl", "-sf", f"http://{host}:{port}/status"], timeout=5)

        if not status_out:
            continue

        def _fpm(key):
            m = re.search(rf'{key}:\s*(\d+)', status_out, re.IGNORECASE)
            return int(m.group(1)) if m else 0

        pools.append({
            "pool": pool,
            "socket": sock,
            "listen": sock,
            "active_processes": _fpm("active processes"),
            "idle_processes": _fpm("idle processes"),
            "total_processes": _fpm("total processes"),
            "max_active": _fpm("max active processes"),
            "slow_requests": _fpm("slow requests"),
            "total_requests": _fpm("accepted conn"),
            "last_check": now,
        })
    return pools


# ============================================================
# NGINX ACCESS STATS
# ============================================================
def collect_nginx_access_stats() -> List[Dict]:
    stats = []
    now = datetime.now().isoformat()
    log_dirs = ["/var/log/nginx"]

    for log_dir in log_dirs:
        if not Path(log_dir).exists():
            continue
        for log_file in Path(log_dir).glob("*access*.log"):
            try:
                domain = log_file.stem.replace("_access", "").replace("-access", "") or "default"
                out = run_cmd(["tail", "-n", "5000", str(log_file)], timeout=10)
                lines = out.splitlines()
                total = len(lines)
                if total == 0:
                    continue

                counters = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
                ip_counter: Dict[str, int] = defaultdict(int)
                path_counter: Dict[str, int] = defaultdict(int)

                for line in lines:
                    m = re.match(r'(\S+) \S+ \S+ \[.+?\] "(\S+) (\S+)[^"]*" (\d+)', line)
                    if m:
                        ip, method, path, code = m.groups()
                        code_int = int(code)
                        if 200 <= code_int < 300:
                            counters["2xx"] += 1
                        elif 300 <= code_int < 400:
                            counters["3xx"] += 1
                        elif 400 <= code_int < 500:
                            counters["4xx"] += 1
                        elif 500 <= code_int < 600:
                            counters["5xx"] += 1
                        ip_counter[ip] += 1
                        if path and path != "-":
                            path_counter[path.split("?")[0]] += 1

                top_ips = sorted(ip_counter.items(), key=lambda x: -x[1])[:5]
                top_paths = sorted(path_counter.items(), key=lambda x: -x[1])[:5]

                stats.append({
                    "ts": now,
                    "domain": domain,
                    "period": "last_5000_lines",
                    "total_reqs": total,
                    "req_2xx": counters["2xx"],
                    "req_3xx": counters["3xx"],
                    "req_4xx": counters["4xx"],
                    "req_5xx": counters["5xx"],
                    "top_ips": json.dumps(top_ips),
                    "top_paths": json.dumps(top_paths),
                    "last_check": now,
                })
            except Exception:
                pass
    return stats


# ============================================================
# BACKUP RUNS
# ============================================================
def collect_backup_runs() -> List[Dict]:
    runs = []
    now = datetime.now().isoformat()

    rclone_configs = [
        Path("/root/.config/rclone/rclone.conf"),
        *Path("/home").glob("*/.config/rclone/rclone.conf"),
    ]
    remotes = set()
    for conf in rclone_configs:
        if not conf.exists():
            continue
        config = configparser.ConfigParser()
        try:
            config.read(conf)
            for section in config.sections():
                remotes.add(section)
        except Exception:
            pass

    for remote in remotes:
        about_out = run_cmd(["rclone", "about", f"{remote}:", "--json"], timeout=15)
        if about_out:
            try:
                about = json.loads(about_out)
                runs.append({
                    "remote": remote,
                    "ts": now,
                    "status": "ok",
                    "size_gb": round(about.get("used", 0) / 1024**3, 2),
                    "files_count": about.get("objects", 0),
                    "duration_s": 0,
                    "error": None,
                    "last_check": now,
                })
                continue
            except json.JSONDecodeError:
                pass

        runs.append({
            "remote": remote,
            "ts": now,
            "status": "unreachable",
            "size_gb": 0,
            "files_count": 0,
            "duration_s": 0,
            "error": "rclone about failed",
            "last_check": now,
        })

    return runs


# ============================================================
# RCLONE REMOTES & MOUNTS (V3 - CONSERVÉ)
# ============================================================
def collect_rclone_remotes() -> List[Dict]:
    remotes = []
    seen = set()
    now = datetime.now().isoformat()

    rclone_configs = [
        Path("/root/.config/rclone/rclone.conf"),
        *Path("/home").glob("*/.config/rclone/rclone.conf"),
        Path("/etc/rclone/rclone.conf"),
    ]

    for conf_path in rclone_configs:
        if not conf_path.exists():
            continue
        config = configparser.ConfigParser()
        try:
            config.read(conf_path)
            for section in config.sections():
                if section not in seen:
                    seen.add(section)
                    remotes.append({
                        "name": section,
                        "type": config.get(section, "type", fallback="unknown"),
                        "path": str(conf_path),
                        "total_gb": 0,
                        "used_gb": 0,
                        "files_count": 0,
                        "last_check": now,
                    })
        except Exception as e:
            print(f"[RCLONE] Erreur lecture {conf_path}: {e}", file=sys.stderr)

    return remotes


def collect_rclone_mounts() -> List[Dict]:
    mounts = []
    now = datetime.now().isoformat()

    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mp, fstype = parts[0], parts[1], parts[2]

                if "rclone" in fstype.lower() or "fuse.rclone" in device:
                    try:
                        st = os.statvfs(mp)
                        total = st.f_blocks * st.f_frsize
                        free = st.f_bfree * st.f_frsize
                        used = total - free
                        mounts.append({
                            "mountpoint": mp,
                            "remote": device.split(":")[0] if ":" in device else "unknown",
                            "fstype": fstype,
                            "total_gb": round(total / 1024**3, 1),
                            "used_gb": round(used / 1024**3, 1),
                            "percent": round(100.0 * used / total, 1) if total > 0 else 0,
                            "last_check": now,
                        })
                    except Exception:
                        mounts.append({
                            "mountpoint": mp,
                            "remote": device.split(":")[0] if ":" in device else "unknown",
                            "fstype": fstype,
                            "total_gb": 0,
                            "used_gb": 0,
                            "percent": 0,
                            "last_check": now,
                        })
    except Exception as e:
        print(f"[RCLONE] Erreur lecture mounts: {e}", file=sys.stderr)

    return mounts


# ============================================================
# NFS (V3 - CONSERVÉ)
# ============================================================
def collect_nfs_exports() -> List[Dict]:
    exports = []
    now = datetime.now().isoformat()
    exports_file = "/etc/exports"

    if Path(exports_file).exists():
        try:
            content = Path(exports_file).read_text(errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    export_path = parts[0]
                    for client in parts[1:]:
                        if client.startswith("("):
                            options = client
                            client = "*"
                        else:
                            options = parts[2] if len(parts) > 2 else ""
                        exports.append({
                            "export_path": export_path,
                            "client": client if client != "(" else "*",
                            "options": options.strip("()") if options else "",
                            "last_check": now,
                        })
        except Exception as e:
            print(f"[NFS] Erreur lecture exports: {e}", file=sys.stderr)

    return exports


def collect_nfs_mounts() -> List[Dict]:
    mounts = []
    now = datetime.now().isoformat()

    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mp, fstype = parts[0], parts[1], parts[2]

                if "nfs" in fstype or "nfs4" in fstype:
                    server = device.split(":")[0] if ":" in device else ""
                    export = device.split(":")[1] if ":" in device else device
                    try:
                        st = os.statvfs(mp)
                        total = st.f_blocks * st.f_frsize
                        free = st.f_bfree * st.f_frsize
                        used = total - free
                        mounts.append({
                            "mountpoint": mp,
                            "server": server,
                            "export_path": export,
                            "fstype": fstype,
                            "options": "",
                            "total_gb": round(total / 1024**3, 1),
                            "used_gb": round(used / 1024**3, 1),
                            "percent": round(100.0 * used / total, 1) if total > 0 else 0,
                            "last_check": now,
                        })
                    except Exception:
                        mounts.append({
                            "mountpoint": mp,
                            "server": server,
                            "export_path": export,
                            "fstype": fstype,
                            "options": "",
                            "total_gb": 0,
                            "used_gb": 0,
                            "percent": 0,
                            "last_check": now,
                        })
    except Exception as e:
        print(f"[NFS] Erreur lecture mounts: {e}", file=sys.stderr)

    return mounts


# ============================================================
# DOCKER
# ============================================================
def collect_docker_containers() -> List[Dict]:
    containers = []
    out = run_cmd(["docker", "ps", "-a", "--format", "json"], timeout=15)
    for line in out.splitlines():
        try:
            c = json.loads(line)
            containers.append({
                "name": c.get("Names", "").lstrip("/"),
                "image": c.get("Image", ""),
                "status": c.get("Status", ""),
                "state": c.get("State", ""),
                "ports": c.get("Ports", ""),
                "networks": c.get("Networks", ""),
                "created": c.get("CreatedAt", ""),
                "last_check": datetime.now().isoformat(),
            })
        except json.JSONDecodeError:
            continue
    return containers


# ============================================================
# VPN & TUNNELS
# ============================================================
def collect_vpn_connections() -> List[Dict]:
    vpns = []
    now = datetime.now().isoformat()

    out = run_cmd(["wg", "show", "all", "dump"], timeout=10)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            vpns.append({
                "type": "wireguard", "name": parts[0],
                "interface": parts[0], "endpoint": parts[2], "status": "active",
                "last_check": now,
            })

    ps_out = run_cmd(["ps", "aux"], timeout=5)
    for line in ps_out.splitlines():
        if "openvpn" in line and "grep" not in line:
            conf_m = re.search(r'--config\s+(\S+)', line)
            vpns.append({
                "type": "openvpn", "name": "openvpn",
                "endpoint": conf_m.group(1) if conf_m else "unknown",
                "status": "active",
                "last_check": now,
            })

    ts_out = run_cmd(["tailscale", "status", "--json"], timeout=10)
    if ts_out:
        try:
            data = json.loads(ts_out)
            self_data = data.get("Self", {})
            vpns.append({
                "type": "tailscale",
                "name": self_data.get("DNSName", "").split(".")[0],
                "interface": "tailscale0",
                "ip": (self_data.get("TailscaleIPs") or [None])[0] or "",
                "status": "connected",
                "last_check": now,
            })
        except Exception:
            pass

    return vpns


def collect_cloudflare_tunnels() -> List[Dict]:
    tunnels = []
    now = datetime.now().isoformat()
    ps_out = run_cmd(["ps", "aux"], timeout=5)
    for line in ps_out.splitlines():
        if "cloudflared" in line and "grep" not in line:
            tunnel_m = re.search(r'tunnel\s+--url\s+(\S+)', line)
            tunnels.append({
                "type": "cloudflared",
                "url": tunnel_m.group(1) if tunnel_m else "unknown",
                "status": "active",
                "last_check": now,
            })
    return tunnels


def collect_ssh_tunnels() -> List[Dict]:
    tunnels = []
    now = datetime.now().isoformat()
    ps_out = run_cmd(["ps", "aux"], timeout=5)
    for line in ps_out.splitlines():
        if "ssh" in line and "grep" not in line:
            local = re.search(r'-L\s+(\d+):([^\s]+)', line)
            remote = re.search(r'-R\s+(\d+):([^\s]+)', line)
            if local or remote:
                tunnels.append({
                    "type": "ssh",
                    "local_forward": f"{local.group(1)} -> {local.group(2)}" if local else None,
                    "remote_forward": f"{remote.group(1)} -> {remote.group(2)}" if remote else None,
                    "status": "active",
                    "last_check": now,
                })
    return tunnels


# ============================================================
# SESSIONS, PORTS, MONTAGES
# ============================================================
def collect_active_sessions() -> List[Dict]:
    sessions = []
    out = run_cmd(["who"], timeout=5)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            sessions.append({
                "user": parts[0],
                "tty": parts[1],
                "login_time": f"{parts[2]} {parts[3]}",
                "ip": parts[4].strip("()") if len(parts) > 4 else "local",
            })
    return sessions


def collect_open_ports() -> List[Dict]:
    ports = []
    out = run_cmd(["ss", "-tulnp"], timeout=5)
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        port_m = re.search(r':(\d+)$', parts[4])
        if not port_m:
            continue
        process = parts[-1] if len(parts) > 5 else "unknown"
        pid_m = re.search(r'pid=(\d+)', process)
        proc_name = re.search(r'"([^"]+)"', process)
        ports.append({
            "port": int(port_m.group(1)),
            "protocol": parts[0],
            "state": parts[1],
            "process": proc_name.group(1)[:50] if proc_name else process[:50],
            "pid": int(pid_m.group(1)) if pid_m else None,
            "last_check": datetime.now().isoformat(),
        })
    return ports


def collect_system_mounts() -> List[Dict]:
    mounts = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                device, mp, fstype = parts[0], parts[1], parts[2]
                if mp.startswith(("/proc", "/sys")) or mp == "/dev":
                    continue
                try:
                    st = os.statvfs(mp)
                    total = st.f_blocks * st.f_frsize
                    free = st.f_bfree * st.f_frsize
                    used = total - free
                    mounts.append({
                        "device": device, "mountpoint": mp, "fstype": fstype,
                        "total_gb": round(total / 1024**3, 1),
                        "used_gb": round(used / 1024**3, 1),
                        "percent": round(100.0 * used / total, 1) if total > 0 else 0,
                        "last_check": datetime.now().isoformat(),
                    })
                except Exception:
                    mounts.append({"device": device, "mountpoint": mp,
                                   "fstype": fstype, "error": True})
    except Exception:
        pass
    return mounts


def collect_network_hosts() -> List[Dict]:
    hosts = []
    now = datetime.now().isoformat()
    seen = set()

    arp_out = run_cmd(["arp", "-n"], timeout=5)
    for line in arp_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[2] != "incomplete":
            ip = parts[0]
            if ip not in seen:
                seen.add(ip)
                hosts.append({
                    "ip": ip,
                    "mac": parts[2],
                    "interface": parts[4] if len(parts) > 4 else "unknown",
                    "reachable": 1,
                    "last_seen": now,
                })

    if not hosts:
        neigh_out = run_cmd(["ip", "neigh"], timeout=5)
        for line in neigh_out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[4] not in ("FAILED", "INCOMPLETE"):
                ip = parts[0]
                if ip not in seen:
                    seen.add(ip)
                    mac_m = re.search(r'([0-9a-f:]{17})', line)
                    hosts.append({
                        "ip": ip,
                        "mac": mac_m.group(1) if mac_m else "unknown",
                        "interface": parts[2] if len(parts) > 2 else "unknown",
                        "reachable": 1,
                        "last_seen": now,
                    })

    return hosts


# ============================================================
# FASTPANEL
# ============================================================
def collect_fastpanel_users() -> List[Dict]:
    users = []
    now = datetime.now().isoformat()
    user_dir = Path("/var/www/fastuser/data")
    if user_dir.exists():
        for u in user_dir.iterdir():
            if u.is_dir():
                try:
                    size_out = run_cmd(["du", "-sm", str(u)], timeout=10)
                    size_mb = int(size_out.split()[0]) if size_out else 0
                    users.append({
                        "username": u.name,
                        "disk_used_gb": round(size_mb / 1024, 1),
                        "disk_quota_gb": None,
                        "status": "active",
                        "last_check": now,
                    })
                except Exception:
                    pass
    return users


def collect_fastpanel_domains() -> List[Dict]:
    domains = []
    now = datetime.now().isoformat()
    user_dir = Path("/var/www/fastuser/data")
    if user_dir.exists():
        for user in user_dir.iterdir():
            www_dir = user / "www"
            if www_dir.exists():
                for domain_dir in www_dir.iterdir():
                    if domain_dir.is_dir():
                        domains.append({
                            "domain": domain_dir.name,
                            "user": user.name,
                            "status": "active",
                            "last_check": now,
                        })
    return domains


# ============================================================
# CRON JOBS
# ============================================================
def collect_cron_jobs() -> List[Dict]:
    jobs = []
    now = datetime.now().isoformat()

    users = ["root"]
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    uname, uid, shell = parts[0], int(parts[2]), parts[6]
                    if uid >= 1000 and shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin"):
                        users.append(uname)
    except Exception:
        pass

    for user in set(users):
        out = run_cmd(["crontab", "-u", user, "-l"], timeout=5)
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                jobs.append({
                    "user": user,
                    "schedule": " ".join(parts[:5]),
                    "command": " ".join(parts[5:])[:200],
                    "last_check": now,
                })

    for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                     "/etc/cron.weekly", "/etc/cron.monthly"]:
        if not Path(cron_dir).exists():
            continue
        for f in Path(cron_dir).iterdir():
            if f.is_file() and not f.name.startswith("."):
                try:
                    for line in f.read_text(errors="replace").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith("PATH"):
                            continue
                        parts = line.split()
                        if len(parts) >= 7:
                            jobs.append({
                                "user": parts[5],
                                "schedule": " ".join(parts[:5]),
                                "command": " ".join(parts[6:])[:200],
                                "last_check": now,
                            })
                except Exception:
                    pass

    return jobs


# ============================================================
# SSH AUTHORIZED KEYS
# ============================================================
def collect_ssh_authorized_keys() -> List[Dict]:
    keys = []
    now = datetime.now().isoformat()

    users_to_check = []
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 6:
                    username, home, shell = parts[0], parts[5], parts[6] if len(parts) > 6 else ""
                    if home.startswith("/") and Path(home).exists():
                        users_to_check.append((username, home))
    except Exception:
        pass

    users_to_check.append(("root", "/root"))

    seen = set()
    for username, home in users_to_check:
        auth_file = Path(home) / ".ssh" / "authorized_keys"
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
                comment = parts[2] if len(parts) > 2 else ""
                key_hash = hashlib.sha256(key_data.encode()).hexdigest()[:16]
                uid = f"{username}:{key_hash}"
                if uid in seen:
                    continue
                seen.add(uid)
                keys.append({
                    "user": username,
                    "key_type": key_type,
                    "key_hash": key_hash,
                    "comment": comment[:100],
                    "key_file": str(auth_file),
                    "last_check": now,
                })
        except Exception:
            pass
    return keys


# ============================================================
# PACKAGE VERSIONS
# ============================================================
def collect_package_versions() -> List[Dict]:
    packages = []
    now = datetime.now().isoformat()
    checks = [
        ("nginx", ["nginx", "-v"], r'nginx/([\d.]+)'),
        ("mysql", ["mysql", "--version"], r'([\d.]+)'),
        ("openssl", ["openssl", "version"], r'OpenSSL ([\d.]+)'),
        ("python3", ["python3", "--version"], r'([\d.]+)'),
        ("docker", ["docker", "--version"], r'([\d.]+)'),
        ("redis", ["redis-server", "--version"], r'v=([\d.]+)'),
    ]
    for php_bin in Path("/usr/bin").glob("php*"):
        if re.match(r'php\d', php_bin.name):
            checks.append((str(php_bin.name), [str(php_bin), "--version"], r'PHP ([\d.]+)'))

    for pkg, cmd, pattern in checks:
        out = run_cmd(cmd, timeout=5)
        m = re.search(pattern, out, re.IGNORECASE)
        version = m.group(1) if m else "not_found"
        path = run_cmd(["which", cmd[0]], timeout=3)
        packages.append({
            "package": pkg,
            "version": version,
            "path": path.strip(),
            "vulnerable": 0,
            "cve_note": None,
            "last_check": now,
        })
    return packages


# ============================================================
# HEALTH SCORE (V4 - avec DNS et sysctl)
# ============================================================
def compute_health_score(metrics: dict, ssl_certs: list,
                         services: dict, fail2ban_jails: list,
                         smart_data: list, sysctl_params: list = None,
                         dns_servers: list = None) -> Dict:
    score = 100
    breakdown = {}
    alerts_count = 0

    cpu = metrics.get("cpu_pct", 0)
    cpu_penalty = 0
    if cpu > 90:
        cpu_penalty = 20
    elif cpu > 80:
        cpu_penalty = 12
    elif cpu > 70:
        cpu_penalty = 6
    score -= cpu_penalty
    breakdown["cpu"] = {"value": cpu, "penalty": cpu_penalty}

    ram = metrics.get("ram_pct", 0)
    ram_penalty = 0
    if ram > 90:
        ram_penalty = 20
    elif ram > 80:
        ram_penalty = 12
    elif ram > 70:
        ram_penalty = 6
    score -= ram_penalty
    breakdown["ram"] = {"value": ram, "penalty": ram_penalty}

    disk = metrics.get("disk_pct", 0)
    disk_penalty = 0
    if disk > 90:
        disk_penalty = 20
    elif disk > 85:
        disk_penalty = 12
    elif disk > 75:
        disk_penalty = 6
    score -= disk_penalty
    breakdown["disk"] = {"value": disk, "penalty": disk_penalty}
    if disk > 85:
        alerts_count += 1

    ssl_penalty = 0
    for cert in ssl_certs:
        days = cert.get("days_left", 999)
        if days <= 0:
            ssl_penalty = max(ssl_penalty, 20)
            alerts_count += 1
        elif days <= 7:
            ssl_penalty = max(ssl_penalty, 15)
            alerts_count += 1
        elif days <= 14:
            ssl_penalty = max(ssl_penalty, 10)
        elif days <= 30:
            ssl_penalty = max(ssl_penalty, 5)
    score -= ssl_penalty
    breakdown["ssl"] = {"expiring": sum(1 for c in ssl_certs if c.get("days_left", 999) < 30), "penalty": ssl_penalty}

    critical_svcs = ["nginx", "mysql", "php8.1-fpm", "php8.3-fpm"]
    stopped = [s for s in critical_svcs if not services.get(s, False)]
    svc_penalty = min(len(stopped) * 5, 15)
    score -= svc_penalty
    breakdown["services"] = {"stopped": stopped, "penalty": svc_penalty}
    alerts_count += len(stopped)

    smart_penalty = 0
    for d in smart_data:
        if d.get("health", "").upper() not in ("PASSED", "OK", ""):
            smart_penalty = max(smart_penalty, 15)
            alerts_count += 1
        elif (d.get("reallocated_sectors") or 0) > 0:
            smart_penalty = max(smart_penalty, 10)
        elif (d.get("pending_sectors") or 0) > 0:
            smart_penalty = max(smart_penalty, 5)
    score -= smart_penalty
    breakdown["smart"] = {"penalty": smart_penalty}

    # V4: Sysctl sécurité
    sysctl_penalty = 0
    if sysctl_params:
        critical_sysctl = sum(1 for p in sysctl_params if p.get("status") == "critical")
        warning_sysctl = sum(1 for p in sysctl_params if p.get("status") == "warning")
        sysctl_penalty = min(critical_sysctl * 3 + warning_sysctl * 1, 10)
        score -= sysctl_penalty
        breakdown["sysctl"] = {"critical": critical_sysctl, "warning": warning_sysctl, "penalty": sysctl_penalty}
        alerts_count += critical_sysctl

    # V4: DNS
    dns_penalty = 0
    if dns_servers:
        not_running = sum(1 for s in dns_servers if s.get("running") == 0)
        dns_penalty = min(not_running * 3, 5)
        score -= dns_penalty
        breakdown["dns"] = {"not_running": not_running, "penalty": dns_penalty}

    score = max(0, min(100, score))
    status = ("critical" if score < 50
              else "warning" if score < 75
              else "good" if score < 90
              else "excellent")

    return {
        "score": score,
        "breakdown": breakdown,
        "alerts_count": alerts_count,
        "status": status,
    }


# ============================================================
# PROMETHEUS EXPORTER (V4)
# ============================================================
class PrometheusHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            metrics = self.get_metrics_text()
            self.wfile.write(metrics.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def get_metrics_text(self) -> str:
        lines = []
        now = time.time()

        try:
            conn = get_conn()
            row = conn.execute(
                "SELECT cpu_pct, ram_pct, disk_pct, swap_pct, load_1m, load_5m, load_15m "
                "FROM metrics_realtime ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row:
                lines.append(f"# HELP cassandra_cpu_percent CPU usage percentage")
                lines.append(f"# TYPE cassandra_cpu_percent gauge")
                lines.append(f"cassandra_cpu_percent {row['cpu_pct']} {now}")
                lines.append(f"# HELP cassandra_ram_percent RAM usage percentage")
                lines.append(f"# TYPE cassandra_ram_percent gauge")
                lines.append(f"cassandra_ram_percent {row['ram_pct']} {now}")
                lines.append(f"# HELP cassandra_disk_percent Disk usage percentage")
                lines.append(f"# TYPE cassandra_disk_percent gauge")
                lines.append(f"cassandra_disk_percent {row['disk_pct']} {now}")
                lines.append(f"# HELP cassandra_swap_percent Swap usage percentage")
                lines.append(f"# TYPE cassandra_swap_percent gauge")
                lines.append(f"cassandra_swap_percent {row['swap_pct']} {now}")

            health = conn.execute(
                "SELECT score, status FROM health_scores ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if health:
                lines.append(f"# HELP cassandra_health_score Global health score (0-100)")
                lines.append(f"# TYPE cassandra_health_score gauge")
                lines.append(f"cassandra_health_score {health['score']} {now}")

            conn.close()
        except Exception as e:
            lines.append(f"# Error: {e}")

        return "\n".join(lines)


def start_prometheus_exporter():
    if not PROMETHEUS_ENABLED:
        print("[PROMETHEUS] Exporter désactivé", file=sys.stderr)
        return

    def run_server():
        try:
            server = HTTPServer(("0.0.0.0", PROMETHEUS_PORT), PrometheusHandler)
            print(f"[PROMETHEUS] Exporter démarré sur port {PROMETHEUS_PORT}", file=sys.stderr)
            while prometheus_running:
                server.handle_request()
        except Exception as e:
            print(f"[PROMETHEUS] Erreur: {e}", file=sys.stderr)

    global prometheus_running
    prometheus_running = True
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()


# ============================================================
# SAUVEGARDE EN BASE
# ============================================================
def save_metrics(metrics: dict):
    conn = get_conn()
    conn.execute("""
        INSERT INTO metrics_realtime
        (ts, cpu_pct, ram_pct, ram_total_gb, ram_used_gb, ram_free_gb,
         ram_buffers_gb, ram_cached_gb, swap_total_gb, swap_used_gb, swap_free_gb, swap_pct,
         disk_pct, disk_total_gb, disk_used_gb, disk_free_gb,
         load_1m, load_5m, load_15m, top_processes, services, alerts)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        metrics["ts"], metrics["cpu_pct"], metrics["ram_pct"],
        metrics["ram_total_gb"], metrics["ram_used_gb"], metrics["ram_free_gb"],
        metrics["ram_buffers_gb"], metrics["ram_cached_gb"],
        metrics["swap_total_gb"], metrics["swap_used_gb"], metrics["swap_free_gb"], metrics["swap_pct"],
        metrics["disk_pct"], metrics["disk_total_gb"],
        metrics["disk_used_gb"], metrics["disk_free_gb"],
        metrics["load_1m"], metrics["load_5m"], metrics["load_15m"],
        json.dumps(metrics["top_processes"]),
        json.dumps(metrics["services"]),
        json.dumps(metrics["alerts"]),
    ))
    conn.execute(
        "DELETE FROM metrics_realtime WHERE id NOT IN "
        "(SELECT id FROM metrics_realtime ORDER BY id DESC LIMIT 2880)"
    )
    conn.commit()
    conn.close()


def save_many(table: str, rows: list, replace: bool = True):
    if not rows:
        return
    conn = get_conn()
    cols = list(rows[0].keys())
    marks = ", ".join("?" * len(cols))
    keyword = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
    stmt = f"{keyword} INTO {table} ({', '.join(cols)}) VALUES ({marks})"
    conn.executemany(stmt, [tuple(r.get(c) for c in cols) for r in rows])
    conn.commit()
    conn.close()


def save_volatile(table: str, rows: list):
    conn = get_conn()
    conn.execute(f"DELETE FROM {table}")
    if rows:
        cols = list(rows[0].keys())
        marks = ", ".join("?" * len(cols))
        conn.executemany(
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({marks})",
            [tuple(r.get(c) for c in cols) for r in rows]
        )
    conn.commit()
    conn.close()


def save_fail2ban(jails: list, banned: list):
    conn = get_conn()
    now = datetime.now().isoformat()
    for j in jails:
        conn.execute("""
            INSERT OR REPLACE INTO fail2ban_status
            (jail, currently_failed, total_failed, currently_banned, total_banned, last_check)
            VALUES (?,?,?,?,?,?)
        """, (j["jail"], j["currently_failed"], j["total_failed"],
              j["currently_banned"], j["total_banned"], now))
    conn.execute("DELETE FROM fail2ban_banned_ips")
    for b in banned:
        conn.execute("""
            INSERT OR IGNORE INTO fail2ban_banned_ips (jail, ip, banned_at, last_check)
            VALUES (?,?,?,?)
        """, (b["jail"], b["ip"], b["banned_at"], now))
    conn.commit()
    conn.close()


def save_log_errors(errors: list):
    if not errors:
        return
    conn = get_conn()
    conn.execute("DELETE FROM log_errors WHERE ts < ?",
                 ((datetime.now() - timedelta(hours=24)).isoformat(),))
    for e in errors:
        conn.execute("""
            INSERT INTO log_errors (ts, service, level, message, count, last_seen)
            VALUES (?,?,?,?,?,?)
        """, (e["ts"], e["service"], e["level"], e["message"], e["count"], e["last_seen"]))
    conn.execute(
        "DELETE FROM log_errors WHERE id NOT IN "
        "(SELECT id FROM log_errors ORDER BY id DESC LIMIT 1000)"
    )
    conn.commit()
    conn.close()


def save_health_score(score_data: dict):
    conn = get_conn()
    conn.execute(
        "INSERT INTO health_scores (ts, score, breakdown, alerts_count, status) VALUES (?,?,?,?,?)",
        (datetime.now().isoformat(), score_data["score"],
         json.dumps(score_data["breakdown"]),
         score_data["alerts_count"], score_data["status"])
    )
    conn.execute(
        "DELETE FROM health_scores WHERE id NOT IN "
        "(SELECT id FROM health_scores ORDER BY id DESC LIMIT 2880)"
    )
    conn.commit()
    conn.close()


def save_redis(stats: Optional[dict]):
    if not stats:
        return
    conn = get_conn()
    conn.execute("""
        INSERT INTO redis_stats
        (ts, used_memory_mb, max_memory_mb, pct_memory, total_keys,
         hit_rate, connected_clients, uptime_seconds, version, last_check)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (stats["ts"], stats["used_memory_mb"], stats["max_memory_mb"],
          stats["pct_memory"], stats["total_keys"], stats["hit_rate"],
          stats["connected_clients"], stats["uptime_seconds"],
          stats["version"], stats["last_check"]))
    conn.execute(
        "DELETE FROM redis_stats WHERE id NOT IN "
        "(SELECT id FROM redis_stats ORDER BY id DESC LIMIT 1440)"
    )
    conn.commit()
    conn.close()


# ============================================================
# COLLECTEUR PRINCIPAL (V4)
# ============================================================
class KnowledgeCollector:
    def __init__(self):
        self.running = True
        self.last_metrics = 0.0
        self.last_quick = 0.0
        self.last_full = 0.0
        self.metrics_interval = 5
        self.quick_interval = 30
        self.full_interval = 300

        self._last_ssl: list = []
        self._last_services: dict = {}
        self._last_f2b: list = []
        self._last_smart: list = []
        self._last_sysctl: list = []
        self._last_dns_servers: list = []

    def _safe(self, name: str, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            print(f"[COLLECTOR] ERREUR dans {name}: {e}", file=sys.stderr)
            return None

    def collect_metrics_cycle(self):
        t0 = time.time()
        metrics = self._safe("collect_metrics", collect_metrics)
        if not metrics:
            return
        self._safe("save_metrics", save_metrics, metrics)
        self._last_services = metrics.get("services", {})

        score = self._safe("compute_health_score", compute_health_score,
                           metrics, self._last_ssl,
                           self._last_services, self._last_f2b, self._last_smart,
                           self._last_sysctl, self._last_dns_servers)
        if score:
            self._safe("save_health_score", save_health_score, score)

        ms = int((time.time() - t0) * 1000)
        log_collector_run("metrics", ms, 1, [])

    def collect_quick(self):
        t0 = time.time()
        errors = []
        count = 0

        sessions = self._safe("collect_active_sessions", collect_active_sessions) or []
        self._safe("save_volatile", save_volatile, "active_sessions",
                   [{**s, "last_check": datetime.now().isoformat()} for s in sessions])
        count += len(sessions)

        ports = self._safe("collect_open_ports", collect_open_ports) or []
        prev_ports = {str(p["port"]) for p in ports}
        self._safe("detect_diff", detect_diff, "port", prev_ports)
        self._safe("save_volatile", save_volatile, "open_ports", ports)
        count += len(ports)

        mounts = self._safe("collect_system_mounts", collect_system_mounts) or []
        self._safe("save_many", save_many, "system_mounts", mounts)
        count += len(mounts)

        hosts = self._safe("collect_network_hosts", collect_network_hosts) or []
        self._safe("save_volatile", save_volatile, "network_hosts", hosts)
        count += len(hosts)

        swap = collect_swap()
        conn = get_conn()
        conn.execute(
            "INSERT INTO swap_usage (ts, total_gb, used_gb, free_gb, pct, last_check) VALUES (?,?,?,?,?,?)",
            (datetime.now().isoformat(), swap["total_gb"], swap["used_gb"],
             swap["free_gb"], swap["pct"], datetime.now().isoformat())
        )
        conn.execute("DELETE FROM swap_usage WHERE id NOT IN (SELECT id FROM swap_usage ORDER BY id DESC LIMIT 1440)")
        conn.commit()
        conn.close()

        inodes = self._safe("collect_inode_usage", collect_inode_usage) or []
        self._safe("save_many", save_many, "inode_usage",
                   [{**i, "last_check": datetime.now().isoformat()} for i in inodes])

        log_errors = self._safe("collect_log_errors", collect_log_errors) or []
        self._safe("save_log_errors", save_log_errors, log_errors)

        f2b_jails, f2b_banned = self._safe("collect_fail2ban", collect_fail2ban) or ([], [])
        self._safe("save_fail2ban", save_fail2ban, f2b_jails, f2b_banned)
        self._last_f2b = f2b_jails

        email_queue = self._safe("collect_email_queue", collect_email_queue) or {}
        self._safe("save_many", save_many, "email_queues", [email_queue])
        email_stats = self._safe("collect_email_stats", collect_email_stats) or {}
        self._safe("save_many", save_many, "email_stats", [email_stats])

        ms = int((time.time() - t0) * 1000)
        log_collector_run("quick", ms, count, errors)
        print(f"[COLLECTOR] Collecte rapide : {count} éléments en {ms}ms", file=sys.stderr)

    def collect_full(self):
        t0 = time.time()
        errors = []
        count = 0

        # Sites web
        nginx_sites = self._safe("collect_nginx_sites", collect_nginx_sites) or []
        apache_vhosts = self._safe("collect_apache_vhosts", collect_apache_vhosts) or []
        all_sites = nginx_sites + apache_vhosts
        prev_domains = {s["domain"] for s in all_sites}
        self._safe("detect_diff", detect_diff, "web_site", prev_domains)
        self._safe("save_many", save_many, "web_sites",
                   [{**s, "last_check": datetime.now().isoformat()} for s in all_sites])
        self._safe("save_many", save_many, "apache_vhosts", apache_vhosts)
        count += len(all_sites)

        # CMS
        cms = self._safe("collect_cms_sites", collect_cms_sites) or []
        self._safe("save_many", save_many, "cms_sites", cms)
        count += len(cms)

        # Bases de données
        dbs = ((self._safe("collect_mysql_databases", collect_mysql_databases) or []) +
               (self._safe("collect_postgresql_databases", collect_postgresql_databases) or []))
        self._safe("detect_diff", detect_diff, "db", {d["name"] for d in dbs})
        self._safe("save_many", save_many, "databases", dbs)
        count += len(dbs)

        # Emails
        emails = self._safe("collect_email_accounts", collect_email_accounts) or []
        self._safe("save_many", save_many, "email_accounts", emails)
        count += len(emails)

        # SSL
        ssl = self._safe("collect_ssl_certificates", collect_ssl_certificates) or []
        self._safe("detect_diff", detect_diff, "ssl", {c["domain"] for c in ssl})
        self._safe("save_many", save_many, "ssl_certificates", ssl)
        self._last_ssl = ssl
        count += len(ssl)

        # Firewall
        fw = self._safe("collect_firewall_rules", collect_firewall_rules) or []
        self._safe("save_volatile", save_volatile, "firewall_rules", fw)
        count += len(fw)

        # Rclone (V3 conservé)
        rclone_remotes = self._safe("collect_rclone_remotes", collect_rclone_remotes) or []
        self._safe("save_many", save_many, "rclone_remotes", rclone_remotes)
        count += len(rclone_remotes)

        rclone_mounts = self._safe("collect_rclone_mounts", collect_rclone_mounts) or []
        self._safe("save_many", save_many, "rclone_mounts", rclone_mounts)
        count += len(rclone_mounts)

        # NFS (V3 conservé)
        nfs_exports = self._safe("collect_nfs_exports", collect_nfs_exports) or []
        self._safe("save_many", save_many, "nfs_exports", nfs_exports)
        count += len(nfs_exports)

        nfs_mounts = self._safe("collect_nfs_mounts", collect_nfs_mounts) or []
        self._safe("save_many", save_many, "nfs_mounts", nfs_mounts)
        count += len(nfs_mounts)

        # Backups
        backups = self._safe("collect_backup_runs", collect_backup_runs) or []
        self._safe("save_many", save_many, "backup_runs", backups)
        count += len(backups)

        # Docker
        containers = self._safe("collect_docker_containers", collect_docker_containers) or []
        self._safe("detect_diff", detect_diff, "container", {c["name"] for c in containers})
        self._safe("save_many", save_many, "docker_containers", containers)
        count += len(containers)

        # VPN & tunnels
        vpns = self._safe("collect_vpn_connections", collect_vpn_connections) or []
        cf = self._safe("collect_cloudflare_tunnels", collect_cloudflare_tunnels) or []
        ssh_tun = self._safe("collect_ssh_tunnels", collect_ssh_tunnels) or []
        self._safe("detect_diff", detect_diff, "vpn", {v.get("name", "") for v in vpns})
        self._safe("save_many", save_many, "vpn_connections", vpns)
        tunnels = [{"type": t["type"], "url": t.get("url", ""),
                    "status": t.get("status", ""), "last_check": datetime.now().isoformat()}
                   for t in cf + ssh_tun]
        self._safe("save_many", save_many, "tunnels", tunnels)
        count += len(vpns) + len(tunnels)

        # Cron
        cron = self._safe("collect_cron_jobs", collect_cron_jobs) or []
        self._safe("save_volatile", save_volatile, "cron_jobs", cron)
        count += len(cron)

        # SMART
        smart = self._safe("collect_disk_smart", collect_disk_smart) or []
        self._safe("save_many", save_many, "disk_smart", smart)
        self._last_smart = smart
        count += len(smart)

        # Redis
        redis = self._safe("collect_redis_stats", collect_redis_stats)
        self._safe("save_redis", save_redis, redis)

        # PHP-FPM
        fpm = self._safe("collect_phpfpm_pools", collect_phpfpm_pools) or []
        self._safe("save_many", save_many, "phpfpm_pools", fpm)
        count += len(fpm)

        # Nginx access stats
        ng_stats = self._safe("collect_nginx_access_stats", collect_nginx_access_stats) or []
        self._safe("save_many", save_many, "nginx_access_stats", ng_stats, replace=False)
        count += len(ng_stats)

        # Package versions
        versions = self._safe("collect_package_versions", collect_package_versions) or []
        self._safe("save_many", save_many, "package_versions", versions)
        count += len(versions)

        # SSH keys
        ssh_keys = self._safe("collect_ssh_authorized_keys", collect_ssh_authorized_keys) or []
        self._safe("save_many", save_many, "ssh_authorized_keys", ssh_keys)
        count += len(ssh_keys)

        # FastPanel
        fp_users = self._safe("collect_fastpanel_users", collect_fastpanel_users) or []
        fp_domains = self._safe("collect_fastpanel_domains", collect_fastpanel_domains) or []
        self._safe("save_many", save_many, "fastpanel_users", fp_users)
        self._safe("save_many", save_many, "fastpanel_domains", fp_domains)
        count += len(fp_users) + len(fp_domains)

        # ================================================
        # V4 NOUVEAUTÉS
        # ================================================

        # Systemd services
        systemd_services = self._safe("collect_systemd_services", collect_systemd_services) or []
        self._safe("detect_diff", detect_diff, "service", {s["name"] for s in systemd_services})
        self._safe("save_many", save_many, "system_services", systemd_services)
        count += len(systemd_services)

        # DNS servers
        dns_servers, dns_zones = self._safe("collect_dns_servers", collect_dns_servers) or ([], [])
        self._safe("detect_diff", detect_diff, "dns_server", {s["server_type"] for s in dns_servers})
        self._safe("save_many", save_many, "dns_servers", dns_servers)
        self._safe("save_many", save_many, "dns_zones", dns_zones)
        self._last_dns_servers = dns_servers
        count += len(dns_servers) + len(dns_zones)

        # Sysctl sécurité
        sysctl_params = self._safe("collect_sysctl_security", collect_sysctl_security) or []
        self._safe("save_many", save_many, "sysctl_security", sysctl_params)
        self._last_sysctl = sysctl_params
        count += len(sysctl_params)

        ms = int((time.time() - t0) * 1000)
        log_collector_run("full", ms, count, errors)
        print(f"[COLLECTOR] Collecte complète V4 : {count} éléments en {ms}ms", file=sys.stderr)

    def run(self):
        init_all_tables()
        print("[COLLECTOR] Démarré — v4.0 complète (systemd, DNS, sysctl, Prometheus)", file=sys.stderr)

        start_prometheus_exporter()

        self.collect_full()
        self.last_full = time.time()

        while self.running:
            try:
                now = time.time()

                if now - self.last_metrics >= self.metrics_interval:
                    self.collect_metrics_cycle()
                    self.last_metrics = now

                if now - self.last_quick >= self.quick_interval:
                    self.collect_quick()
                    self.last_quick = now

                if now - self.last_full >= self.full_interval:
                    self.collect_full()
                    self.last_full = now

                time.sleep(1)

            except Exception as e:
                print(f"[COLLECTOR] ERREUR GLOBALE: {e}", file=sys.stderr)
                log_collector_run("error", 0, 0, [str(e)], status="error")
                time.sleep(5)

    def stop(self):
        self.running = False
        global prometheus_running
        prometheus_running = False


# ============================================================
# DÉMARRAGE
# ============================================================
prometheus_running = True

if __name__ == "__main__":
    print("=" * 60, file=sys.stderr)
    print("CASSANDRA — Knowledge Collector v4.0 (COMPLÈTE)", file=sys.stderr)
    print(f"DB: {DB_PATH}", file=sys.stderr)
    print(f"Prometheus: {'enabled' if PROMETHEUS_ENABLED else 'disabled'} port {PROMETHEUS_PORT}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    collector = KnowledgeCollector()
    try:
        collector.run()
    except KeyboardInterrupt:
        print("\n[COLLECTOR] Arrêt demandé", file=sys.stderr)
        collector.stop()
    except Exception as e:
        print(f"[COLLECTOR] Erreur fatale: {e}", file=sys.stderr)
        sys.exit(1)