#!/usr/bin/env python3
"""
CASSANDRA — Knowledge Collector v1.0 
=============================================
SCAN EXHAUSTIF DE L'INFRASTRUCTURE
Ne laisse RIEN passer :
- Métriques temps réel (CPU/RAM/DISK/LOAD)
- Sites web (Nginx/Apache)
- CMS (WordPress, Joomla, Drupal, Nextcloud, Laravel, etc.)
- Bases de données (MySQL, PostgreSQL)
- Comptes email (Dovecot, Postfix, FastPanel, Maildir)
- Certificats SSL
- Rclone (remotes + montages)
- Docker (conteneurs + images)
- Système (utilisateurs, sessions, services, cron)
- Réseau (interfaces, ARP, ports ouverts)
- VPN (WireGuard, OpenVPN, Tailscale, ZeroTier)
- Tunnels (Cloudflare, ngrok, FRP, SSH)
- Stockage (disques, montages, NFS, CIFS)
"""

import os
import sys
import json
import sqlite3
import subprocess
import re
import socket
import time
import threading
import hashlib
import glob
import configparser
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
from collections import defaultdict

# ============================================================
# CONFIGURATION
# ============================================================
DB_PATH = "/var/lib/cassandra/cassandra.db"
SOCKET_PATH = "/tmp/cassandra_knowledge.sock"

# Chemins à scanner
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

# Détection des CMS
CMS_DETECTORS = {
    "wordpress": ["wp-config.php", "wp-content", "wp-includes"],
    "joomla": ["configuration.php", "administrator", "media"],
    "drupal": ["core", "sites/default/settings.php", "index.php"],
    "moodle": ["config.php", "theme", "lib"],
    "prestashop": ["config/settings.inc.php", "classes", "controllers"],
    "magento": ["app/etc/local.xml", "app/code", "pub"],
    "bookstack": [".env", "bootstrap", "app"],
    "dolibarr": ["conf/conf.php", "htdocs"],
    "nextcloud": ["config/config.php", "apps", "themes"],
    "owncloud": ["config/config.php"],
    "grav": ["user/config", "system"],
    "sylius": [".env", "config/bundles.php"],
    "laravel": [".env", "artisan", "bootstrap"],
    "symfony": [".env", "bin/console", "config"],
    "codeigniter": ["application/config/config.php", "system"],
    "cakephp": ["config/app.php", "src"],
}


# ============================================================
# BASE DE DONNÉES
# ============================================================
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_all_tables():
    """Initialise TOUTES les tables"""
    conn = get_conn()
    conn.executescript("""
        -- ========================================
        -- MÉTRIQUES TEMPS RÉEL
        -- ========================================
        CREATE TABLE IF NOT EXISTS metrics_realtime (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            cpu_pct     REAL,
            ram_pct     REAL,
            ram_total_gb REAL,
            ram_used_gb  REAL,
            ram_free_gb  REAL,
            ram_buffers_gb REAL,
            ram_cached_gb REAL,
            disk_pct    REAL,
            disk_total_gb REAL,
            disk_used_gb  REAL,
            disk_free_gb  REAL,
            load_1m     REAL,
            load_5m     REAL,
            load_15m    REAL,
            top_processes TEXT,
            services    TEXT,
            alerts      TEXT
        );

        -- ========================================
        -- SITES WEB & DOMAINES
        -- ========================================
        CREATE TABLE IF NOT EXISTS web_sites (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL UNIQUE,
            document_root TEXT,
            owner       TEXT,
            php_version TEXT,
            php_fpm_pool TEXT,
            ssl_enabled INTEGER DEFAULT 0,
            ssl_issuer  TEXT,
            ssl_expiry  TEXT,
            ssl_days_left INTEGER,
            config_file TEXT,
            status      TEXT DEFAULT 'active',
            last_check  TEXT
        );

        -- ========================================
        -- CMS
        -- ========================================
        CREATE TABLE IF NOT EXISTS cms_sites (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT,
            path        TEXT,
            cms_type    TEXT NOT NULL,
            version     TEXT,
            theme       TEXT,
            plugins     TEXT,
            plugins_count INTEGER,
            db_name     TEXT,
            db_user     TEXT,
            admin_user  TEXT,
            config_file TEXT,
            last_check  TEXT
        );

        -- ========================================
        -- BASES DE DONNÉES
        -- ========================================
        CREATE TABLE IF NOT EXISTS databases (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            type        TEXT NOT NULL,
            size_mb     REAL,
            tables_count INTEGER,
            host        TEXT,
            UNIQUE(name, type)
        );

        -- ========================================
        -- COMPTES EMAIL
        -- ========================================
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

        -- ========================================
        -- CERTIFICATS SSL
        -- ========================================
        CREATE TABLE IF NOT EXISTS ssl_certificates (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL,
            cert_path   TEXT,
            issuer      TEXT,
            subject     TEXT,
            expiry_date TEXT,
            days_left   INTEGER,
            status      TEXT,
            last_check  TEXT
        );

        -- ========================================
        -- RCLONE
        -- ========================================
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
            device      TEXT,
            total_gb    REAL,
            used_gb     REAL,
            percent     REAL,
            last_check  TEXT
        );

        -- ========================================
        -- DOCKER
        -- ========================================
        CREATE TABLE IF NOT EXISTS docker_containers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            image       TEXT,
            status      TEXT,
            state       TEXT,
            ports       TEXT,
            networks    TEXT,
            mounts      TEXT,
            created     TEXT,
            last_check  TEXT
        );

        CREATE TABLE IF NOT EXISTS docker_images (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            repository  TEXT,
            tag         TEXT,
            size_mb     REAL,
            created     TEXT,
            last_check  TEXT
        );

        -- ========================================
        -- VPN & TUNNELS
        -- ========================================
        CREATE TABLE IF NOT EXISTS vpn_connections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT NOT NULL,
            name        TEXT,
            interface   TEXT,
            ip          TEXT,
            endpoint    TEXT,
            status      TEXT,
            last_check  TEXT
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

        CREATE TABLE IF NOT EXISTS tun_interfaces (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            type        TEXT,
            ips         TEXT,
            state       TEXT,
            last_check  TEXT
        );

        -- ========================================
        -- UTILISATEURS & SESSIONS
        -- ========================================
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

        -- ========================================
        -- CRON
        -- ========================================
        CREATE TABLE IF NOT EXISTS cron_jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user        TEXT,
            schedule    TEXT,
            command     TEXT,
            description TEXT,
            last_check  TEXT
        );

        -- ========================================
        -- SERVICES SYSTÈME
        -- ========================================
        CREATE TABLE IF NOT EXISTS system_services (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            status      TEXT,
            enabled     INTEGER,
            active      INTEGER,
            description TEXT,
            last_check  TEXT
        );

        -- ========================================
        -- PORTS OUVERTS
        -- ========================================
        CREATE TABLE IF NOT EXISTS open_ports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            port        INTEGER,
            protocol    TEXT,
            process     TEXT,
            pid         INTEGER,
            state       TEXT,
            last_check  TEXT
        );

        -- ========================================
        -- MONTAGES SYSTÈME
        -- ========================================
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

        -- ========================================
        -- RÉSEAU
        -- ========================================
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
            last_seen   TEXT
        );

        -- ========================================
        -- FASTPANEL
        -- ========================================
        CREATE TABLE IF NOT EXISTS fastpanel_users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL UNIQUE,
            email       TEXT,
            disk_quota_gb REAL,
            disk_used_gb REAL,
            status      TEXT,
            last_check  TEXT
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

        -- ========================================
        -- INDICES
        -- ========================================
        CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics_realtime(ts);
        CREATE INDEX IF NOT EXISTS idx_web_domain ON web_sites(domain);
        CREATE INDEX IF NOT EXISTS idx_cms_type ON cms_sites(cms_type);
        CREATE INDEX IF NOT EXISTS idx_ssl_expiry ON ssl_certificates(days_left);
        CREATE INDEX IF NOT EXISTS idx_rclone_name ON rclone_remotes(name);
        CREATE INDEX IF NOT EXISTS idx_docker_name ON docker_containers(name);
        CREATE INDEX IF NOT EXISTS idx_vpn_type ON vpn_connections(type);
        CREATE INDEX IF NOT EXISTS idx_tunnel_type ON tunnels(type);
        CREATE INDEX IF NOT EXISTS idx_ports_port ON open_ports(port);
    """)
    conn.commit()
    conn.close()
    print("[CASSANDRA] Tables initialisées", file=sys.stderr)


# ============================================================
# COLLECTE MÉTRIQUES TEMPS RÉEL
# ============================================================
def get_cpu_percent():
    """Pourcentage CPU en temps réel"""
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        vals = list(map(int, line.split()[1:]))
        idle1, total1 = vals[3], sum(vals)
        time.sleep(0.2)
        with open("/proc/stat") as f:
            line = f.readline()
        vals = list(map(int, line.split()[1:]))
        idle2, total2 = vals[3], sum(vals)
        return round(100.0 * (1 - (idle2 - idle1) / max(total2 - total1, 1)), 1)
    except Exception:
        return 0


def collect_ram() -> dict:
    """RAM usage détaillé"""
    try:
        with open("/proc/meminfo") as f:
            mi = {}
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        total = mi.get("MemTotal", 1)
        avail = mi.get("MemAvailable", total)
        free = mi.get("MemFree", 0)
        buffers = mi.get("Buffers", 0)
        cached = mi.get("Cached", 0)
        used = total - avail
        return {
            "total_gb": round(total / 1024 / 1024, 1),
            "used_gb": round(used / 1024 / 1024, 1),
            "free_gb": round(free / 1024 / 1024, 1),
            "percent": round(100.0 * used / total, 1),
            "buffers_gb": round(buffers / 1024 / 1024, 1),
            "cached_gb": round(cached / 1024 / 1024, 1)
        }
    except Exception:
        return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0, "buffers_gb": 0, "cached_gb": 0}


def collect_disk() -> dict:
    """Disque système"""
    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        return {
            "percent": round(100.0 * used / total, 1),
            "total_gb": round(total / 1024**3, 1),
            "used_gb": round(used / 1024**3, 1),
            "free_gb": round(free / 1024**3, 1)
        }
    except Exception:
        return {"percent": 0, "total_gb": 0, "used_gb": 0, "free_gb": 0}


def collect_load():
    """Load average"""
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            return float(parts[0]), float(parts[1]), float(parts[2])
    except Exception:
        return 0.0, 0.0, 0.0


def collect_top_processes(limit: int = 10) -> list:
    """Top processus CPU"""
    processes = []
    try:
        out = subprocess.run(["/bin/ps", "aux", "--sort=-%cpu", "--no-headers"],
                            capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines()[:limit]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({
                    "user": parts[0],
                    "pid": int(parts[1]),
                    "cpu": float(parts[2]),
                    "mem": float(parts[3]),
                    "command": parts[10][:100]
                })
    except Exception:
        pass
    return processes


def collect_services() -> dict:
    """État des services système"""
    services = {}
    for svc in ["nginx", "php8.1-fpm", "php8.3-fpm", "mysql", "mariadb",
                "docker", "redis", "postgresql", "ssh", "fail2ban", "ufw"]:
        try:
            out = subprocess.run(["/bin/systemctl", "is-active", svc],
                               capture_output=True, text=True, timeout=3)
            services[svc] = out.strip() == "active"
        except Exception:
            services[svc] = False
    return services


def collect_alerts(cpu: float, ram: float, disk: float) -> list:
    """Alertes basées sur seuils"""
    alerts = []
    if cpu > 85:
        alerts.append({"level": "critical", "msg": f"CPU à {cpu}%", "threshold": 85})
    elif cpu > 70:
        alerts.append({"level": "warning", "msg": f"CPU à {cpu}%", "threshold": 70})
    if ram > 85:
        alerts.append({"level": "critical", "msg": f"RAM à {ram}%", "threshold": 85})
    elif ram > 70:
        alerts.append({"level": "warning", "msg": f"RAM à {ram}%", "threshold": 70})
    if disk > 85:
        alerts.append({"level": "critical", "msg": f"Disque système à {disk}%", "threshold": 85})
    elif disk > 75:
        alerts.append({"level": "warning", "msg": f"Disque système à {disk}%", "threshold": 75})
    return alerts


def collect_metrics() -> dict:
    """Collecte complète des métriques"""
    cpu = get_cpu_percent()
    ram = collect_ram()
    disk = collect_disk()
    load_1m, load_5m, load_15m = collect_load()

    return {
        "ts": datetime.now().isoformat(),
        "cpu_pct": cpu,
        "ram_pct": ram["percent"],
        "ram_total_gb": ram["total_gb"],
        "ram_used_gb": ram["used_gb"],
        "ram_free_gb": ram["free_gb"],
        "ram_buffers_gb": ram["buffers_gb"],
        "ram_cached_gb": ram["cached_gb"],
        "disk_pct": disk["percent"],
        "disk_total_gb": disk["total_gb"],
        "disk_used_gb": disk["used_gb"],
        "disk_free_gb": disk["free_gb"],
        "load_1m": load_1m,
        "load_5m": load_5m,
        "load_15m": load_15m,
        "top_processes": collect_top_processes(10),
        "services": collect_services(),
        "alerts": collect_alerts(cpu, ram["percent"], disk["percent"])
    }


# ============================================================
# COLLECTE SITES WEB & CMS
# ============================================================
def collect_nginx_sites() -> List[Dict]:
    """Liste TOUS les sites Nginx"""
    sites = []
    nginx_dirs = ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d", "/etc/nginx/sites-available"]

    for nginx_dir in nginx_dirs:
        if Path(nginx_dir).exists():
            for conf_file in Path(nginx_dir).glob("*.conf"):
                try:
                    content = conf_file.read_text()
                    server_names = re.findall(r'server_name\s+([^;]+);', content, re.DOTALL)
                    roots = re.findall(r'root\s+([^;]+);', content)

                    ssl_enabled = "ssl_certificate" in content
                    ssl_cert = re.search(r'ssl_certificate\s+([^;]+);', content)

                    php_version = "unknown"
                    php_match = re.search(r'fastcgi_pass\s+.*?php([\d.]+)fpm', content)
                    if php_match:
                        php_version = php_match.group(1)

                    for domain in server_names:
                        for d in domain.strip().split():
                            if d and not d.startswith('_') and not d.startswith('*'):
                                sites.append({
                                    "domain": d,
                                    "document_root": roots[0] if roots else "unknown",
                                    "config_file": str(conf_file),
                                    "ssl_enabled": 1 if ssl_enabled else 0,
                                    "ssl_cert": str(ssl_cert.group(1)) if ssl_cert else None,
                                    "php_version": php_version
                                })
                except Exception:
                    pass
    return sites


def detect_cms(path: Path) -> Optional[str]:
    """Détecte le type de CMS"""
    if not path.exists():
        return None
    for cms_type, files in CMS_DETECTORS.items():
        found = 0
        for f in files:
            if (path / f).exists():
                found += 1
        if found >= 2:
            return cms_type
    return None


def get_cms_version(path: Path, cms_type: str) -> str:
    """Récupère la version du CMS"""
    try:
        if cms_type == "wordpress":
            wp_file = path / "wp-includes" / "version.php"
            if wp_file.exists():
                content = wp_file.read_text()
                match = re.search(r"\$wp_version\s*=\s*'([^']+)'", content)
                if match:
                    return match.group(1)
        elif cms_type == "joomla":
            version_file = path / "libraries" / "cms" / "version" / "version.php"
            if version_file.exists():
                content = version_file.read_text()
                match = re.search(r"RELEASE\s*=\s*'([^']+)'", content)
                if match:
                    rel = match.group(1)
                    match_dev = re.search(r"DEV_LEVEL\s*=\s*'(\d+)'", content)
                    dev = match_dev.group(1) if match_dev else "0"
                    return f"{rel}.{dev}"
        elif cms_type == "drupal":
            php_file = path / "core" / "lib" / "Drupal.php"
            if php_file.exists():
                content = php_file.read_text()
                match = re.search(r"const VERSION = '([^']+)'", content)
                if match:
                    return match.group(1)
        elif cms_type == "nextcloud":
            version_file = path / "version.php"
            if version_file.exists():
                content = version_file.read_text()
                match = re.search(r"\$OC_VersionString\s*=\s*'([^']+)'", content)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return "unknown"


def collect_cms_sites() -> List[Dict]:
    """Scanne TOUS les dossiers pour détecter les CMS"""
    cms_sites = []
    scanned = set()

    for base_path in SCAN_PATHS:
        for path in Path("/").glob(base_path):
            if not path.exists() or str(path) in scanned:
                continue
            scanned.add(str(path))

            for item in path.iterdir():
                if not item.is_dir():
                    continue

                cms_type = detect_cms(item)
                if cms_type:
                    version = get_cms_version(item, cms_type)
                    domain = item.name
                    plugins = []
                    theme = "unknown"
                    db_name = None
                    db_user = None

                    if cms_type == "wordpress":
                        wp_config = item / "wp-config.php"
                        if wp_config.exists():
                            content = wp_config.read_text()
                            db_match = re.search(r"DB_NAME\s*,\s*'([^']+)'", content)
                            if db_match:
                                db_name = db_match.group(1)
                            user_match = re.search(r"DB_USER\s*,\s*'([^']+)'", content)
                            if user_match:
                                db_user = user_match.group(1)

                            theme_dir = item / "wp-content" / "themes"
                            if theme_dir.exists():
                                for td in theme_dir.iterdir():
                                    if td.is_dir() and not td.name.startswith('.'):
                                        style_css = td / "style.css"
                                        if style_css.exists():
                                            css = style_css.read_text()
                                            match = re.search(r"Theme Name:\s*(.+)", css)
                                            if match:
                                                theme = match.group(1).strip()
                                            break

                            plugins_dir = item / "wp-content" / "plugins"
                            if plugins_dir.exists():
                                plugins = [p.name for p in plugins_dir.iterdir() if p.is_dir() and not p.name.startswith('.')]

                    cms_sites.append({
                        "domain": domain,
                        "path": str(item),
                        "cms_type": cms_type,
                        "version": version,
                        "theme": theme,
                        "plugins": json.dumps(plugins[:20]),
                        "plugins_count": len(plugins),
                        "db_name": db_name,
                        "db_user": db_user,
                        "last_check": datetime.now().isoformat()
                    })

    return cms_sites


# ============================================================
# COLLECTE BASES DE DONNÉES
# ============================================================
def collect_mysql_databases() -> List[Dict]:
    """Liste TOUTES les bases MySQL/MariaDB"""
    databases = []
    try:
        result = subprocess.run(["mysql", "-e", "SHOW DATABASES", "-N", "--batch"],
                               capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for db in result.stdout.splitlines():
                if db not in ['information_schema', 'performance_schema', 'mysql', 'sys']:
                    size_result = subprocess.run(
                        ["mysql", "-e", f"SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) FROM information_schema.tables WHERE table_schema='{db}'",
                         "-N", "--batch"], capture_output=True, text=True, timeout=10)
                    size = float(size_result.stdout.strip() or 0)

                    tables_result = subprocess.run(
                        ["mysql", "-e", f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{db}'",
                         "-N", "--batch"], capture_output=True, text=True, timeout=10)
                    tables = int(tables_result.stdout.strip() or 0)

                    databases.append({
                        "name": db,
                        "type": "mysql",
                        "size_mb": size,
                        "tables_count": tables,
                        "host": "localhost"
                    })
    except Exception:
        pass
    return databases


def collect_postgresql_databases() -> List[Dict]:
    """Liste TOUTES les bases PostgreSQL"""
    databases = []
    try:
        result = subprocess.run(["sudo", "-u", "postgres", "psql", "-t", "-c",
                                "SELECT datname FROM pg_database WHERE datistemplate = false"],
                               capture_output=True, text=True, timeout=15)
        for db in result.stdout.splitlines():
            db = db.strip()
            if db:
                size_result = subprocess.run(["sudo", "-u", "postgres", "psql", "-t", "-c",
                                             f"SELECT pg_database_size('{db}')/1024/1024"],
                                            capture_output=True, text=True, timeout=10)
                size = float(size_result.stdout.strip() or 0)
                databases.append({
                    "name": db,
                    "type": "postgresql",
                    "size_mb": size,
                    "host": "localhost"
                })
    except Exception:
        pass
    return databases


# ============================================================
# COLLECTE EMAILS
# ============================================================
def collect_email_accounts() -> List[Dict]:
    """Liste TOUS les comptes email"""
    accounts = []
    seen = set()

    # Dovecot
    dovecot_files = ["/etc/dovecot/users", "/etc/dovecot/passwd", "/etc/dovecot/passwd-file"]
    for df in dovecot_files:
        if Path(df).exists():
            try:
                content = Path(df).read_text()
                for line in content.splitlines():
                    if ":" in line and "@" in line:
                        email = line.split(":")[0]
                        if email not in seen:
                            seen.add(email)
                            accounts.append({"email": email, "domain": email.split("@")[1], "type": "dovecot"})
            except Exception:
                pass

    # FastPanel
    fastpanel_mail = "/usr/local/fastpanel/data/mail.json"
    if Path(fastpanel_mail).exists():
        try:
            data = json.loads(Path(fastpanel_mail).read_text())
            for email, info in data.items():
                if email not in seen:
                    seen.add(email)
                    accounts.append({
                        "email": email,
                        "domain": email.split("@")[1],
                        "quota_mb": info.get("quota", 0),
                        "forward_to": info.get("forwarding"),
                        "type": "fastpanel"
                    })
        except Exception:
            pass

    # Scanner /var/vmail
    vmail_paths = ["/var/vmail", "/var/mail", "/home/vmail"]
    for pattern in vmail_paths:
        for path in Path("/").glob(pattern):
            if path.exists() and path.is_dir():
                for domain in path.iterdir():
                    if domain.is_dir():
                        for user in domain.iterdir():
                            if user.is_dir() and "@" not in user.name:
                                email = f"{user.name}@{domain.name}"
                                if email not in seen:
                                    seen.add(email)
                                    size_mb = 0
                                    try:
                                        result = subprocess.run(["du", "-sm", str(user)],
                                                               capture_output=True, text=True, timeout=10)
                                        if result.returncode == 0:
                                            size_mb = int(result.stdout.split()[0])
                                    except Exception:
                                        pass
                                    accounts.append({
                                        "email": email,
                                        "domain": domain.name,
                                        "used_mb": size_mb,
                                        "type": "maildir"
                                    })

    return accounts


def collect_email_queue() -> dict:
    """État de la queue email"""
    queue = {"incoming": 0, "active": 0, "deferred": 0, "hold": 0, "oldest_age": 0}
    try:
        result = subprocess.run(["mailq"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "deferred" in line.lower():
                    queue["deferred"] += 1
                elif "hold" in line.lower():
                    queue["hold"] += 1
                elif "active" in line.lower():
                    queue["active"] += 1
                elif "Mail queue is empty" in line:
                    break
                elif line.strip() and not line.startswith("-"):
                    queue["incoming"] += 1
            age_match = re.search(r'(\d+) days', result.stdout)
            if age_match:
                queue["oldest_age"] = int(age_match.group(1))
    except Exception:
        pass
    return queue


# ============================================================
# COLLECTE CERTIFICATS SSL
# ============================================================
def collect_ssl_certificates() -> List[Dict]:
    """Liste TOUS les certificats SSL"""
    certificates = []
    cert_paths = set()

    for conf_file in Path("/etc/nginx").glob("**/*.conf"):
        try:
            content = conf_file.read_text()
            cert_matches = re.findall(r'ssl_certificate\s+([^;]+);', content)
            for cert_path in cert_matches:
                cert_path = cert_path.strip().strip('"').strip("'")
                if cert_path in cert_paths:
                    continue
                cert_paths.add(cert_path)

                if Path(cert_path).exists():
                    result = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-dates"],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        not_after = re.search(r'notAfter=(.+)', result.stdout)
                        if not_after:
                            expiry_str = not_after.group(1).strip()
                            try:
                                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                                days_left = (expiry_date - datetime.now()).days
                                certificates.append({
                                    "domain": conf_file.stem,
                                    "cert_path": cert_path,
                                    "expiry_date": expiry_date.isoformat(),
                                    "days_left": days_left,
                                    "status": "valid" if days_left > 30 else ("expiring" if days_left > 0 else "expired")
                                })
                            except Exception:
                                pass
        except Exception:
            pass
    return certificates


# ============================================================
# COLLECTE RCLONE
# ============================================================
def collect_rclone_remotes() -> List[Dict]:
    """Liste TOUS les remotes Rclone"""
    remotes = []
    seen = set()

    rclone_configs = ["/root/.config/rclone/rclone.conf", "/home/*/.config/rclone/rclone.conf"]
    for pattern in rclone_configs:
        for conf_path in Path("/").glob(pattern):
            if conf_path.exists():
                config = configparser.ConfigParser()
                try:
                    config.read(conf_path)
                    for section in config.sections():
                        if section not in seen:
                            seen.add(section)
                            remotes.append({
                                "name": section,
                                "type": config.get(section, "type", fallback="unknown"),
                                "path": str(conf_path)
                            })
                except Exception:
                    pass

    try:
        result = subprocess.run(["rclone", "listremotes"], capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            remote = line.strip().rstrip(':')
            if remote and remote not in seen:
                remotes.append({"name": remote, "type": "unknown"})
    except Exception:
        pass
    return remotes


def collect_rclone_mounts() -> List[Dict]:
    """Liste TOUS les montages Rclone"""
    mounts = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    device, mountpoint, fstype = parts[0], parts[1], parts[2]
                    if "rclone" in fstype or "fuse.rclone" in fstype:
                        try:
                            stat = os.statvfs(mountpoint)
                            total = stat.f_blocks * stat.f_frsize
                            free = stat.f_bfree * stat.f_frsize
                            used = total - free
                            mounts.append({
                                "mountpoint": mountpoint,
                                "remote": device,
                                "fstype": fstype,
                                "total_gb": round(total / 1024**3, 1),
                                "used_gb": round(used / 1024**3, 1),
                                "percent": round(100.0 * used / total, 1) if total > 0 else 0
                            })
                        except Exception:
                            mounts.append({"mountpoint": mountpoint, "remote": device, "fstype": fstype, "error": True})
    except Exception:
        pass
    return mounts


# ============================================================
# COLLECTE DOCKER
# ============================================================
def collect_docker_containers() -> List[Dict]:
    """Liste TOUS les conteneurs Docker"""
    containers = []
    try:
        result = subprocess.run(["docker", "ps", "-a", "--format", "json"],
                               capture_output=True, text=True, timeout=15)
        for line in result.stdout.splitlines():
            try:
                container = json.loads(line)
                containers.append({
                    "name": container.get("Names", "").lstrip('/'),
                    "image": container.get("Image"),
                    "status": container.get("State"),
                    "state": container.get("State"),
                    "created": container.get("CreatedAt", ""),
                    "last_check": datetime.now().isoformat()
                })
            except json.JSONDecodeError:
                continue
    except Exception:
        pass
    return containers


# ============================================================
# COLLECTE VPN & TUNNELS
# ============================================================
def collect_vpn_connections() -> List[Dict]:
    """Détecte TOUTES les connexions VPN"""
    vpns = []

    # WireGuard
    try:
        result = subprocess.run(["wg", "show", "all", "dump"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    vpns.append({
                        "type": "wireguard",
                        "interface": parts[0],
                        "peer": parts[1],
                        "endpoint": parts[2],
                        "status": "active"
                    })
    except Exception:
        pass

    # OpenVPN
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if "openvpn" in line and "grep" not in line:
                conf_match = re.search(r'--config\s+(\S+)', line)
                vpns.append({
                    "type": "openvpn",
                    "config": conf_match.group(1) if conf_match else "unknown",
                    "status": "active"
                })
    except Exception:
        pass

    # Tailscale
    try:
        result = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            self_data = data.get("Self", {})
            vpns.append({
                "type": "tailscale",
                "name": self_data.get("DNSName", "").split(".")[0],
                "ip": self_data.get("TailscaleIPs", [None])[0],
                "status": "connected"
            })
    except Exception:
        pass

    # Interfaces TUN/TAP
    try:
        result = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for iface in data:
                name = iface.get("ifname", "")
                if name.startswith(("tun", "tap", "wg", "zt")):
                    ips = [addr.get("local", "") for addr in iface.get("addr_info", [])]
                    vpns.append({
                        "type": "tun",
                        "name": name,
                        "ips": json.dumps(ips),
                        "state": iface.get("operstate", "unknown")
                    })
    except Exception:
        pass

    return vpns


def collect_cloudflare_tunnels() -> List[Dict]:
    """Détecte les tunnels Cloudflare"""
    tunnels = []
    try:
        result = subprocess.run(["ps", "aux", "|", "grep", "cloudflared"],
                               capture_output=True, text=True, shell=True, timeout=5)
        for line in result.stdout.splitlines():
            if "cloudflared" in line and "grep" not in line:
                tunnel_match = re.search(r'tunnel\s+--url\s+(\S+)', line)
                tunnels.append({
                    "type": "cloudflared",
                    "url": tunnel_match.group(1) if tunnel_match else "unknown",
                    "status": "active"
                })
    except Exception:
        pass
    return tunnels


def collect_ssh_tunnels() -> List[Dict]:
    """Détecte les tunnels SSH"""
    tunnels = []
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if "ssh" in line and "grep" not in line:
                local_fwd = re.search(r'-L\s+(\d+):([^\s]+)', line)
                remote_fwd = re.search(r'-R\s+(\d+):([^\s]+)', line)
                if local_fwd or remote_fwd:
                    tunnels.append({
                        "type": "ssh",
                        "local_forward": f"{local_fwd.group(1)} -> {local_fwd.group(2)}" if local_fwd else None,
                        "remote_forward": f"{remote_fwd.group(1)} -> {remote_fwd.group(2)}" if remote_fwd else None,
                        "status": "active"
                    })
    except Exception:
        pass
    return tunnels


def collect_ngrok_tunnels() -> List[Dict]:
    """Détecte les tunnels ngrok"""
    tunnels = []
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if "ngrok" in line and "grep" not in line:
                tunnels.append({"type": "ngrok", "status": "active"})
    except Exception:
        pass
    return tunnels


# ============================================================
# COLLECTE SYSTÈME & RÉSEAU
# ============================================================
def collect_active_sessions() -> List[Dict]:
    """Sessions actives (who)"""
    sessions = []
    try:
        result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                sessions.append({
                    "user": parts[0],
                    "tty": parts[1],
                    "login_time": f"{parts[2]} {parts[3]}",
                    "ip": parts[4] if parts[4] != '(:0)' else "local"
                })
    except Exception:
        pass
    return sessions


def collect_open_ports() -> List[Dict]:
    """Liste TOUS les ports ouverts"""
    ports = []
    try:
        result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                port_match = re.search(r':(\d+)', parts[4])
                if port_match:
                    process = parts[-1] if len(parts) > 5 else "unknown"
                    pid_match = re.search(r'pid=(\d+)', process)
                    pid = int(pid_match.group(1)) if pid_match else None
                    proc_name_match = re.search(r'"([^"]+)"', process)
                    proc_name = proc_name_match.group(1) if proc_name_match else process
                    ports.append({
                        "port": int(port_match.group(1)),
                        "protocol": parts[0],
                        "state": parts[1],
                        "process": proc_name[:50],
                        "pid": pid
                    })
    except Exception:
        pass
    return ports


def collect_network_hosts() -> List[Dict]:
    """Détecte les hôtes sur le réseau local (ARP)"""
    hosts = []
    try:
        result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2] != "incomplete":
                hosts.append({
                    "ip": parts[0],
                    "mac": parts[2],
                    "interface": parts[4] if len(parts) > 4 else "unknown",
                    "reachable": 1
                })
    except Exception:
        pass
    return hosts


def collect_system_mounts() -> List[Dict]:
    """Liste TOUS les points de montage"""
    mounts = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    device, mountpoint, fstype = parts[0], parts[1], parts[2]
                    try:
                        stat = os.statvfs(mountpoint)
                        total = stat.f_blocks * stat.f_frsize
                        free = stat.f_bfree * stat.f_frsize
                        used = total - free
                        mounts.append({
                            "device": device,
                            "mountpoint": mountpoint,
                            "fstype": fstype,
                            "total_gb": round(total / 1024**3, 1),
                            "used_gb": round(used / 1024**3, 1),
                            "percent": round(100.0 * used / total, 1) if total > 0 else 0
                        })
                    except Exception:
                        mounts.append({"device": device, "mountpoint": mountpoint, "fstype": fstype, "error": True})
    except Exception:
        pass
    return mounts


def collect_cron_jobs() -> List[Dict]:
    """Liste TOUTES les tâches cron"""
    jobs = []
    for user in ["root", "fastuser", "www-data"]:
        try:
            result = subprocess.run(["crontab", "-u", user, "-l"],
                                   capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 6:
                            schedule = " ".join(parts[:5])
                            command = " ".join(parts[5:])
                            jobs.append({"user": user, "schedule": schedule, "command": command[:200]})
        except Exception:
            pass
    return jobs


# ============================================================
# SAUVEGARDE
# ============================================================
def save_metrics(metrics: dict):
    conn = get_conn()
    conn.execute("""
        INSERT INTO metrics_realtime
        (ts, cpu_pct, ram_pct, ram_total_gb, ram_used_gb, ram_free_gb,
         ram_buffers_gb, ram_cached_gb, disk_pct, disk_total_gb, disk_used_gb,
         disk_free_gb, load_1m, load_5m, load_15m, top_processes, services, alerts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        metrics["ts"], metrics["cpu_pct"], metrics["ram_pct"],
        metrics["ram_total_gb"], metrics["ram_used_gb"], metrics["ram_free_gb"],
        metrics["ram_buffers_gb"], metrics["ram_cached_gb"],
        metrics["disk_pct"], metrics["disk_total_gb"], metrics["disk_used_gb"],
        metrics["disk_free_gb"], metrics["load_1m"], metrics["load_5m"], metrics["load_15m"],
        json.dumps(metrics["top_processes"]), json.dumps(metrics["services"]), json.dumps(metrics["alerts"])
    ))
    conn.execute("DELETE FROM metrics_realtime WHERE id NOT IN (SELECT id FROM metrics_realtime ORDER BY id DESC LIMIT 500)")
    conn.commit()
    conn.close()


def save_web_sites(sites: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for site in sites:
        conn.execute("""
            INSERT OR REPLACE INTO web_sites (domain, document_root, php_version, ssl_enabled, config_file, status, last_check)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (site["domain"], site.get("document_root", ""), site.get("php_version", ""),
              site.get("ssl_enabled", 0), site.get("config_file", ""), "active", now))
    conn.commit()
    conn.close()


def save_cms_sites(cms_sites: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for cms in cms_sites:
        conn.execute("""
            INSERT OR REPLACE INTO cms_sites (domain, path, cms_type, version, theme, plugins, plugins_count, db_name, db_user, last_check)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (cms.get("domain", ""), cms.get("path", ""), cms["cms_type"], cms.get("version", ""),
              cms.get("theme", ""), cms.get("plugins", "[]"), cms.get("plugins_count", 0),
              cms.get("db_name"), cms.get("db_user"), now))
    conn.commit()
    conn.close()


def save_databases(databases: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for db in databases:
        conn.execute("""
            INSERT OR REPLACE INTO databases (name, type, size_mb, tables_count, host, last_check)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (db["name"], db["type"], db.get("size_mb", 0), db.get("tables_count", 0), db.get("host", "localhost"), now))
    conn.commit()
    conn.close()


def save_email_accounts(accounts: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for acc in accounts:
        conn.execute("""
            INSERT OR REPLACE INTO email_accounts (email, domain, quota_mb, used_mb, forward_to, status, last_check)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (acc["email"], acc.get("domain", ""), acc.get("quota_mb", 0), acc.get("used_mb", 0),
              acc.get("forward_to"), acc.get("status", "active"), now))
    conn.commit()
    conn.close()


def save_ssl_certificates(certs: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for cert in certs:
        conn.execute("""
            INSERT OR REPLACE INTO ssl_certificates (domain, cert_path, expiry_date, days_left, status, last_check)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (cert["domain"], cert.get("cert_path", ""), cert.get("expiry_date", ""),
              cert.get("days_left", 0), cert.get("status", "unknown"), now))
    conn.commit()
    conn.close()


def save_rclone_remotes(remotes: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for remote in remotes:
        conn.execute("""
            INSERT OR REPLACE INTO rclone_remotes (name, type, path, last_check)
            VALUES (?, ?, ?, ?)
        """, (remote["name"], remote.get("type", "unknown"), remote.get("path", ""), now))
    conn.commit()
    conn.close()


def save_rclone_mounts(mounts: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for mount in mounts:
        conn.execute("""
            INSERT OR REPLACE INTO rclone_mounts (mountpoint, remote, fstype, total_gb, used_gb, percent, last_check)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (mount["mountpoint"], mount.get("remote", ""), mount.get("fstype", ""),
              mount.get("total_gb", 0), mount.get("used_gb", 0), mount.get("percent", 0), now))
    conn.commit()
    conn.close()


def save_docker_containers(containers: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for container in containers:
        conn.execute("""
            INSERT OR REPLACE INTO docker_containers (name, image, status, state, created, last_check)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (container["name"], container.get("image", ""), container.get("status", ""),
              container.get("state", ""), container.get("created", ""), now))
    conn.commit()
    conn.close()


def save_vpn_connections(vpns: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for vpn in vpns:
        conn.execute("""
            INSERT OR REPLACE INTO vpn_connections (type, name, interface, ip, endpoint, status, last_check)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (vpn.get("type", "unknown"), vpn.get("name") or vpn.get("interface") or "",
              vpn.get("interface", ""), vpn.get("ip", ""), vpn.get("endpoint", ""),
              vpn.get("status", "active"), now))
    conn.commit()
    conn.close()


def save_tunnels(tunnels: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    for tunnel in tunnels:
        conn.execute("""
            INSERT OR REPLACE INTO tunnels (type, url, status, last_check)
            VALUES (?, ?, ?, ?)
        """, (tunnel.get("type", "unknown"), tunnel.get("url", ""), tunnel.get("status", "active"), now))
    conn.commit()
    conn.close()


def save_active_sessions(sessions: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    conn.execute("DELETE FROM active_sessions")
    for session in sessions:
        conn.execute("""
            INSERT INTO active_sessions (user, tty, login_time, ip, last_check)
            VALUES (?, ?, ?, ?, ?)
        """, (session["user"], session.get("tty", ""), session.get("login_time", ""), session.get("ip", ""), now))
    conn.commit()
    conn.close()


def save_open_ports(ports: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    conn.execute("DELETE FROM open_ports")
    for port in ports:
        conn.execute("""
            INSERT INTO open_ports (port, protocol, state, process, pid, last_check)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (port["port"], port.get("protocol", ""), port.get("state", ""),
              port.get("process", ""), port.get("pid"), now))
    conn.commit()
    conn.close()


def save_network_hosts(hosts: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    conn.execute("DELETE FROM network_hosts")
    for host in hosts:
        conn.execute("""
            INSERT INTO network_hosts (ip, mac, interface, reachable, last_seen)
            VALUES (?, ?, ?, ?, ?)
        """, (host["ip"], host.get("mac", ""), host.get("interface", ""), host.get("reachable", 1), now))
    conn.commit()
    conn.close()


def save_system_mounts(mounts: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    conn.execute("DELETE FROM system_mounts")
    for mount in mounts:
        conn.execute("""
            INSERT INTO system_mounts (device, mountpoint, fstype, total_gb, used_gb, percent, last_check)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (mount.get("device", ""), mount.get("mountpoint", ""), mount.get("fstype", ""),
              mount.get("total_gb", 0), mount.get("used_gb", 0), mount.get("percent", 0), now))
    conn.commit()
    conn.close()


def save_cron_jobs(jobs: List[Dict]):
    conn = get_conn()
    now = datetime.now().isoformat()
    conn.execute("DELETE FROM cron_jobs")
    for job in jobs:
        conn.execute("""
            INSERT INTO cron_jobs (user, schedule, command, last_check)
            VALUES (?, ?, ?, ?)
        """, (job["user"], job.get("schedule", ""), job.get("command", ""), now))
    conn.commit()
    conn.close()


# ============================================================
# COLLECTEUR PRINCIPAL
# ============================================================
class KnowledgeCollector:
    def __init__(self):
        self.running = True
        self.last_metrics = 0
        self.last_quick = 0
        self.last_full = 0
        self.metrics_interval = 5
        self.quick_interval = 30
        self.full_interval = 300

    def collect_quick(self):
        """Collecte rapide (sessions, ports, montages)"""
        print("[CASSANDRA] Collecte rapide...", file=sys.stderr)
        save_active_sessions(collect_active_sessions())
        save_open_ports(collect_open_ports())
        save_system_mounts(collect_system_mounts())
        save_network_hosts(collect_network_hosts())

    def collect_full(self):
        """Collecte complète"""
        print("[CASSANDRA] Collecte complète...", file=sys.stderr)

        # Sites et CMS
        sites = collect_nginx_sites()
        save_web_sites(sites)
        print(f"[CASSANDRA] {len(sites)} sites web détectés", file=sys.stderr)

        cms_sites = collect_cms_sites()
        save_cms_sites(cms_sites)
        print(f"[CASSANDRA] {len(cms_sites)} sites CMS détectés", file=sys.stderr)

        # Bases de données
        all_dbs = collect_mysql_databases() + collect_postgresql_databases()
        save_databases(all_dbs)
        print(f"[CASSANDRA] {len(all_dbs)} bases de données", file=sys.stderr)

        # Emails
        emails = collect_email_accounts()
        save_email_accounts(emails)
        print(f"[CASSANDRA] {len(emails)} comptes email", file=sys.stderr)

        # SSL
        certs = collect_ssl_certificates()
        save_ssl_certificates(certs)
        print(f"[CASSANDRA] {len(certs)} certificats SSL", file=sys.stderr)

        # Rclone
        remotes = collect_rclone_remotes()
        save_rclone_remotes(remotes)
        print(f"[CASSANDRA] {len(remotes)} remotes Rclone", file=sys.stderr)

        rclone_mounts = collect_rclone_mounts()
        save_rclone_mounts(rclone_mounts)
        print(f"[CASSANDRA] {len(rclone_mounts)} montages Rclone", file=sys.stderr)

        # Docker
        containers = collect_docker_containers()
        save_docker_containers(containers)
        print(f"[CASSANDRA] {len(containers)} conteneurs Docker", file=sys.stderr)

        # VPN et tunnels
        vpns = collect_vpn_connections()
        save_vpn_connections(vpns)
        tunnels = collect_cloudflare_tunnels() + collect_ssh_tunnels() + collect_ngrok_tunnels()
        save_tunnels(tunnels)
        print(f"[CASSANDRA] {len(vpns)} VPNs, {len(tunnels)} tunnels", file=sys.stderr)

        # Cron
        cron_jobs = collect_cron_jobs()
        save_cron_jobs(cron_jobs)
        print(f"[CASSANDRA] {len(cron_jobs)} tâches cron", file=sys.stderr)

    def run(self):
        init_all_tables()
        print("[CASSANDRA] Collecteur démarré", file=sys.stderr)

        while self.running:
            now = time.time()

            if now - self.last_metrics >= self.metrics_interval:
                save_metrics(collect_metrics())
                self.last_metrics = now

            if now - self.last_quick >= self.quick_interval:
                self.collect_quick()
                self.last_quick = now

            if now - self.last_full >= self.full_interval:
                self.collect_full()
                self.last_full = now

            time.sleep(1)

    def stop(self):
        self.running = False


# ============================================================
# DÉMARRAGE
# ============================================================
if __name__ == "__main__":
    print("=" * 60, file=sys.stderr)
    print("CASSANDRA — Knowledge Collector v4.0 (ULTIME)", file=sys.stderr)
    print("Scan exhaustif de l'infrastructure", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    collector = KnowledgeCollector()
    try:
        collector.run()
    except KeyboardInterrupt:
        print("\n[CASSANDRA] Arrêt demandé", file=sys.stderr)
        collector.stop()
    except Exception as e:
        print(f"[CASSANDRA] Erreur fatale: {e}", file=sys.stderr)
        sys.exit(1)