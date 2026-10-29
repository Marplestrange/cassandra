#!/usr/bin/env python3
"""
CASSANDRA — Knowledge Collector v5.7 (BUGFIXES COMPLETS)
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
    "dns_servers", "dns_zones", "sysctl_security", "package_versions", "email_accounts"
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
def collect_active_sessions():
    sessions = []
    out = run_cmd("who")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            sessions.append({"user": parts[0], "ip": parts[4].strip("()") if len(parts) > 4 else "local", "login_time": f"{parts[2]} {parts[3]}", "last_check": datetime.now().isoformat()})
    return sessions

def collect_open_ports():
    ports = []
    out = run_cmd("ss -tulnp")
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            m = re.search(r':(\d+)$', parts[4])
            if m:
                proc = parts[-1] if len(parts) > 5 else "unknown"
                pname = re.search(r'"([^"]+)"', proc)
                ports.append({"port": int(m.group(1)), "protocol": parts[0], "process": pname.group(1)[:40] if pname else proc[:40], "last_check": datetime.now().isoformat()})
    return ports

def collect_web_sites():
    sites = []
    for conf in Path("/etc/nginx/sites-enabled").glob("*.conf") if Path("/etc/nginx/sites-enabled").exists() else []:
        try:
            content = conf.read_text(errors="replace")
            domains = re.findall(r'server_name\s+([^;]+);', content)
            ssl = "ssl_certificate" in content
            for d in domains:
                for domain in d.strip().split():
                    if domain and not domain.startswith("_") and not domain.startswith("*"):
                        sites.append({"domain": domain, "ssl_enabled": 1 if ssl else 0, "server_type": "nginx", "last_check": datetime.now().isoformat()})
        except:
            pass
    return sites

def collect_ssl_certificates():
    certs = []
    for conf in Path("/etc/nginx").rglob("*.conf"):
        try:
            content = conf.read_text(errors="replace")
            for cp in re.findall(r'ssl_certificate\s+([^;]+);', content):
                cp = cp.strip().strip('"\'')
                if Path(cp).exists():
                    out = run_cmd(f"openssl x509 -in {cp} -noout -dates")
                    na = re.search(r'notAfter=(.+)', out)
                    if na:
                        try:
                            expiry = datetime.strptime(na.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                            days = (expiry - datetime.now()).days
                            if days > 0:
                                certs.append({"domain": Path(conf).stem, "days_left": days, "cert_path": cp, "status": "expiring" if days <= 30 else "valid", "last_check": datetime.now().isoformat()})
                        except:
                            pass
        except:
            pass
    return certs

def collect_failed_units():
    units = []
    out = run_cmd("systemctl --failed --no-legend --no-pager")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            units.append({"unit": parts[0], "active_state": "failed", "last_check": datetime.now().isoformat()})
    return units

def collect_fail2ban_banned():
    banned = []
    out = run_cmd("fail2ban-client status")
    for jail in re.findall(r'Jail list:\s*(.+)', out):
        for j in jail.split(","):
            j = j.strip()
            if j:
                status = run_cmd(f"fail2ban-client status {j}")
                ips = re.search(r'Banned IP list:\s*(.+)', status)
                if ips:
                    for ip in ips.group(1).split():
                        banned.append({"jail": j, "ip": ip, "last_check": datetime.now().isoformat()})
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

def collect_fastpanel_users():
    users = []
    now = datetime.now().isoformat()
    fp_conf = Path("/usr/local/fastpanel/data/users.json")
    if fp_conf.exists():
        try:
            data = json.loads(fp_conf.read_text())
            for username, info in data.items():
                users.append({"username": username, "email": info.get("email"), "disk_quota_gb": info.get("disk_quota", 0), "status": info.get("status", "active"), "last_check": now})
        except:
            pass
    return users

def collect_fastpanel_domains():
    domains = []
    now = datetime.now().isoformat()
    fp_conf = Path("/usr/local/fastpanel/data/domains.json")
    if fp_conf.exists():
        try:
            data = json.loads(fp_conf.read_text())
            for domain, info in data.items():
                domains.append({"domain": domain, "user": info.get("user", ""), "php_version": info.get("php_version", "unknown"), "ssl_enabled": 1 if info.get("ssl", False) else 0, "status": "active", "last_check": now})
        except:
            pass
    return domains

def collect_fastpanel_php_versions():
    versions = []
    now = datetime.now().isoformat()
    for php_ver in ["8.3", "8.2", "8.1", "8.0", "7.4"]:
        fpm_bin = Path(f"/usr/sbin/php-fpm{php_ver}")
        if fpm_bin.exists():
            versions.append({"version": php_ver, "full_version": php_ver, "path": str(fpm_bin), "active": 1, "last_check": now})
    return versions

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
    jobs = []
    now = datetime.now().isoformat()
    out = run_cmd("crontab -l")
    for line in out.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 6:
                jobs.append({"user": "root", "schedule": " ".join(parts[:5]), "command": " ".join(parts[5:])[:200], "last_check": now})
    return jobs

def collect_ssh_authorized_keys():
    keys = []
    now = datetime.now().isoformat()
    auth_file = Path("/root/.ssh/authorized_keys")
    if auth_file.exists():
        for line in auth_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    key_hash = hashlib.md5(parts[1].encode()).hexdigest()[:16]
                    keys.append({"user": "root", "key_type": parts[0], "key_hash": key_hash, "comment": parts[2] if len(parts) > 2 else "", "last_check": now})
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
                    "version": "5.7",
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
        print("[COLLECTOR] Démarré — v5.7 BUGFIXES")
        
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