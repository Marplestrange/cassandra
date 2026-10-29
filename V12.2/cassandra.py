#!/usr/bin/env python3
"""
CASSANDRA v12.2 — Agent unifié (BUGFIXES + TERMINAL INTÉGRÉ)
============================================================
CORRECTIFS v11.1 :
  [S1] Tokens distants chiffrés au repos (Fernet/AES-256 ou HMAC-XOR)
  [S2] Migration transparente des configs héritées au démarrage
  [S3] multiserver.json chmod 0o600 à chaque écriture

CORRECTIFS v11.0 :
  [B1] XSS : commandes bash via data-attribute, plus d'injection onclick
  [B2] Race condition GET_DASHBOARD : _cache_lock sur health_score
  [B3] Fuite mémoire : purge _admin_action_log des sessions vides
  [B4] Caches déclarés avant rotate_deepseek_key (NameError impossible)
  [B5] auto_summarize_session déporté en thread daemon
  [B6] Socket timeout 2s → 5s
  [M1] Mode multi-serveur : agrégation de N agents distants via HTTP
  [M2] API /api/multiserver/* : list, add, remove, status, metrics
  [M3] Dashboard : onglet Flotte avec vue agrégée

STOCKAGE SÉCURISÉ : clé dans /etc/cassandra/deepseek.key (auto chattr +i)
CACHE RAM : /dev/shm/.cassandra_deepseek_key
"""

import os
import sys
import json
import sqlite3
import subprocess
import hashlib
import secrets
import socket
import time
import re
import threading
import urllib.request
import urllib.error
import base64
import struct
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse

# ============================================================
# 1. CONFIGURATION
# ============================================================
DB_PATH          = "/var/lib/cassandra/cassandra.db"
MEMORY_DB_PATH   = "/var/lib/cassandra/cassandra_memory.db"
COLLECTOR_SOCKET = "/tmp/cassandra_knowledge.sock"
PORT             = 9000
MAX_RAW_MESSAGES = 30
SUMMARY_KEEP     = 5

SECURE_KEY_FILE = "/etc/cassandra/deepseek.key"

# [A2] Rate limiting
RATE_LIMIT_MAX_ACTIONS = 5
RATE_LIMIT_INTERVAL = 3600
_admin_action_log: dict = {}
_admin_action_lock = threading.Lock()

# Caches
_prompt_cache: dict = {}
_prompt_cache_time: dict = {}
_PROMPT_CACHE_TTL = 10
_detailed_cache: dict = {}
_detailed_cache_time: dict = {}
_DETAILED_CACHE_TTL = 5
_intent_cache: dict = {}
_intent_cache_time: dict = {}
_INTENT_CACHE_TTL = 30

ADMIN_LOG_FILE = "/var/log/cassandra_admin.log"


# ============================================================
# 2. FONCTIONS ADMIN
# ============================================================
def init_admin_log():
    try:
        log_dir = os.path.dirname(ADMIN_LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, 0o750)
        if not os.path.exists(ADMIN_LOG_FILE):
            with open(ADMIN_LOG_FILE, 'w') as f:
                f.write(f"# CASSANDRA Admin Log - créé le {datetime.now().isoformat()}\n")
    except Exception as e:
        print(f"[ADMIN] Erreur init log: {e}", file=sys.stderr)


def log_admin_action(session_id: str, action: str, result: str, details: str = ""):
    try:
        with open(ADMIN_LOG_FILE, 'a') as f:
            timestamp = datetime.now().isoformat()
            f.write(f"[{timestamp}] session={session_id[:8]} action={action} result={result} {details}\n")
    except Exception as e:
        print(f"[ADMIN] Erreur log: {e}", file=sys.stderr)


def check_rate_limit(session_id: str) -> tuple:
    now = time.time()
    with _admin_action_lock:
        if session_id not in _admin_action_log:
            _admin_action_log[session_id] = []
        old_actions = [ts for ts in _admin_action_log[session_id] if now - ts < RATE_LIMIT_INTERVAL]
        if old_actions:
            _admin_action_log[session_id] = old_actions
        else:
            if session_id in _admin_action_log:
                del _admin_action_log[session_id]
        allowed = len(old_actions) < RATE_LIMIT_MAX_ACTIONS
        remaining = max(0, RATE_LIMIT_MAX_ACTIONS - len(old_actions))
        wait_seconds = 0
        if not allowed and old_actions:
            oldest = min(old_actions)
            wait_seconds = int(RATE_LIMIT_INTERVAL - (now - oldest))
        return allowed, remaining, wait_seconds


def record_admin_action(session_id: str) -> None:
    now = time.time()
    with _admin_action_lock:
        if session_id not in _admin_action_log:
            _admin_action_log[session_id] = []
        _admin_action_log[session_id].append(now)


# ============================================================
# 3. CHARGEMENT SÉCURISÉ DE LA CLÉ API
# ============================================================
def _apply_chattr_if_needed(filepath: str) -> tuple:
    test_file = "/tmp/.cassandra_chattr_test"
    try:
        which_result = subprocess.run(["which", "chattr"], capture_output=True, text=True, timeout=2)
        if which_result.returncode != 0:
            return (False, "chattr non disponible", False)
        test_success = False
        try:
            with open(test_file, 'w') as f:
                f.write("test")
            add_result = subprocess.run(["chattr", "+i", test_file], capture_output=True, timeout=2)
            if add_result.returncode == 0:
                subprocess.run(["chattr", "-i", test_file], capture_output=True, timeout=2)
                test_success = True
        except Exception:
            test_success = False
        finally:
            try:
                if os.path.exists(test_file):
                    subprocess.run(["chattr", "-i", test_file], capture_output=True, timeout=2)
                    os.remove(test_file)
            except Exception:
                pass
        if not test_success:
            return (False, "FS ne supporte pas chattr", True)
        if not os.path.exists(filepath):
            return (False, f"fichier {filepath} inexistant", True)
        lsattr_result = subprocess.run(["lsattr", filepath], capture_output=True, text=True, timeout=2)
        if lsattr_result.returncode != 0:
            return (False, f"lsattr a échoué", True)
        attrs = lsattr_result.stdout.split()[0] if lsattr_result.stdout.split() else ""
        if 'i' in attrs:
            return (True, "déjà protégé", False)
        chattr_result = subprocess.run(["chattr", "+i", filepath], capture_output=True, text=True, timeout=2)
        if chattr_result.returncode != 0:
            return (False, f"chattr +i a échoué", True)
        return (True, "protégé", False)
    except FileNotFoundError:
        return (False, "chattr/lsattr non trouvés", True)
    except Exception as e:
        return (False, f"erreur: {e}", True)
    finally:
        try:
            if os.path.exists(test_file):
                subprocess.run(["chattr", "-i", test_file], capture_output=True, timeout=2)
                os.remove(test_file)
        except Exception:
            pass


def _remove_chattr_if_needed(filepath: str) -> bool:
    try:
        lsattr_result = subprocess.run(["lsattr", filepath], capture_output=True, text=True, timeout=2)
        if lsattr_result.returncode == 0 and 'i' in (lsattr_result.stdout.split()[0] if lsattr_result.stdout.split() else ''):
            subprocess.run(["chattr", "-i", filepath], capture_output=True, timeout=2)
        return True
    except Exception:
        return False


def ensure_secure_key_file():
    key_dir = os.path.dirname(SECURE_KEY_FILE)
    if not os.path.exists(key_dir):
        os.makedirs(key_dir, 0o750)
        print(f"[API] Dossier créé : {key_dir}")
    file_created = False
    if not os.path.exists(SECURE_KEY_FILE):
        with open(SECURE_KEY_FILE, 'w') as f:
            f.write("# Placez votre clé DeepSeek ici (sk-...)\n")
        os.chmod(SECURE_KEY_FILE, 0o600)
        print(f"[API] 📝 Fichier clé créé : {SECURE_KEY_FILE}")
        print(f"[API] ⚠️ VEUILLEZ AJOUTER VOTRE CLÉ")
        file_created = True
    else:
        stat_info = os.stat(SECURE_KEY_FILE)
        if stat_info.st_mode & 0o777 != 0o600:
            os.chmod(SECURE_KEY_FILE, 0o600)
            print(f"[API] 🔧 Permissions corrigées")
    chattr_ok, chattr_msg, chattr_critical = _apply_chattr_if_needed(SECURE_KEY_FILE)
    if chattr_ok:
        print(f"[API] 🔒 {chattr_msg}")
    else:
        print(f"[API] ⚠️ {chattr_msg}")
        if chattr_critical:
            print(f"[API] ⚠️⚠️⚠️ ALERTE: fichier clé NON protégé!")
    return not file_created


def get_deepseek_key() -> str:
    ensure_secure_key_file()
    cache_file = '/dev/shm/.cassandra_deepseek_key'
    if os.path.exists(cache_file):
        try:
            if time.time() - os.path.getmtime(cache_file) < 3600:
                with open(cache_file, 'r') as f:
                    key = f.read().strip()
                    if key and not key.startswith('#'):
                        return key
        except Exception:
            pass
    try:
        with open(SECURE_KEY_FILE, 'r') as f:
            key = f.read().strip()
        if not key or key.startswith('#'):
            print("[API] ⚠️ Clé non configurée")
            return ""
        key = key.split()[0] if key.split() else key
        with open(cache_file, 'w') as f:
            f.write(key)
        os.chmod(cache_file, 0o600)
        return key
    except Exception as e:
        print(f"[API] Erreur lecture clé: {e}")
        return os.environ.get("DEEPSEEK_API_KEY", "")


def rotate_deepseek_key(new_key: str) -> bool:
    global DEEPSEEK_API_KEY, client
    global _intent_cache, _intent_cache_time
    global _prompt_cache, _prompt_cache_time
    global _detailed_cache, _detailed_cache_time
    if not new_key or not new_key.startswith("sk-"):
        print("[API] Rotation échouée: format invalide")
        return False
    current_key = get_deepseek_key()
    if current_key and not current_key.startswith("sk-"):
        print("[API] Rotation: clé actuelle semble invalide")
    try:
        _remove_chattr_if_needed(SECURE_KEY_FILE)
        with open(SECURE_KEY_FILE, 'w') as f:
            f.write(new_key)
        os.chmod(SECURE_KEY_FILE, 0o600)
        chattr_ok, chattr_msg, chattr_critical = _apply_chattr_if_needed(SECURE_KEY_FILE)
        if not chattr_ok:
            print(f"[API] Rotation: {chattr_msg}")
        cache_file = '/dev/shm/.cassandra_deepseek_key'
        if os.path.exists(cache_file):
            os.remove(cache_file)
        _intent_cache.clear()
        _intent_cache_time.clear()
        _prompt_cache.clear()
        _prompt_cache_time.clear()
        _detailed_cache.clear()
        _detailed_cache_time.clear()
        try:
            if hasattr(client, '_client') and hasattr(client._client, 'close'):
                client._client.close()
        except Exception:
            pass
        DEEPSEEK_API_KEY = new_key
        os.environ["DEEPSEEK_API_KEY"] = new_key
        client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1")
        _ms_invalidate_key_cache()    # forcer re-dérivation avec la nouvelle clé
        print("[API] Rotation effectuée")
        return True
    except Exception as e:
        print(f"[API] Erreur rotation: {e}")
        return False


DEEPSEEK_API_KEY = get_deepseek_key()
if not DEEPSEEK_API_KEY:
    print("[API] ❌ Clé DeepSeek non trouvée!")
    print(f"[API] Vérifiez {SECURE_KEY_FILE}")
else:
    print("[API] DeepSeek: ✅ OK")

os.environ["DEEPSEEK_API_KEY"] = DEEPSEEK_API_KEY

from openai import OpenAI
client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1")


# ============================================================
# 4. CACHE
# ============================================================
def get_cached_or_fetch(category: str, fetch_func, ttl: int = 5):
    now = time.time()
    if category in _detailed_cache and now - _detailed_cache_time.get(category, 0) < ttl:
        return _detailed_cache[category]
    data = fetch_func()
    _detailed_cache[category] = data
    _detailed_cache_time[category] = now
    return data


# ============================================================
# 5. DÉTECTION D'INTENTION
# ============================================================
KNOWN_CATEGORIES = ["sites", "remotes", "ssl", "processes", "sessions",
                    "ports", "oom", "failed", "tailscale", "fail2ban",
                    "health", "docker", "smart"]


def detect_intent_categories(user_question: str, expert_mode: bool = False) -> list:
    if expert_mode:
        return KNOWN_CATEGORIES
    cache_key = hashlib.md5(user_question.encode()).hexdigest()
    now = time.time()
    if cache_key in _intent_cache and now - _intent_cache_time.get(cache_key, 0) < _INTENT_CACHE_TTL:
        return _intent_cache[cache_key]
    if not DEEPSEEK_API_KEY:
        return []
    try:
        resp = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{
                "role": "user",
                "content": f"Question: \"{user_question}\"\n\nParmi ces catégories: {', '.join(KNOWN_CATEGORIES)}\nRetourne UNIQUEMENT un JSON array. Ex: [\"ssl\",\"sites\"]"
            }],
            temperature=0,
            max_tokens=80,
        )
        raw = resp.choices[0].message.content.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        cats = json.loads(raw)
        result = [c for c in cats if c in KNOWN_CATEGORIES]
    except Exception:
        result = []
    _intent_cache[cache_key] = result
    _intent_cache_time[cache_key] = now
    return result


# ============================================================
# 6. SOCKET
# ============================================================
def _recv_all(sock):
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _socket_request(command: str):
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(COLLECTOR_SOCKET)
        sock.send(command.encode())
        sock.shutdown(socket.SHUT_WR)
        response = _recv_all(sock)
        sock.close()
        return json.loads(response.decode())
    except Exception as e:
        print(f"[SOCKET] Erreur ({command.strip()}): {e}")
        return None


def get_metrics_from_socket():
    return _socket_request("GET_METRICS\n")


def get_dashboard_from_socket():
    return _socket_request("GET_DASHBOARD\n")


def get_entity_from_socket(entity_type):
    return _socket_request(f"GET_ENTITY:{entity_type}\n")


# ============================================================
# 7. FILTRAGE
# ============================================================
def filter_recent(data, time_field, max_minutes=5):
    if not data:
        return data
    now = datetime.now()
    filtered = []
    for item in data:
        time_val = item.get(time_field)
        if time_val:
            try:
                if isinstance(time_val, str):
                    time_val = time_val.replace('T', ' ')[:19]
                    dt = datetime.fromisoformat(time_val)
                elif isinstance(time_val, (int, float)):
                    dt = datetime.fromtimestamp(time_val)
                else:
                    filtered.append(item)
                    continue
                if now - dt < timedelta(minutes=max_minutes):
                    filtered.append(item)
            except Exception:
                filtered.append(item)
        else:
            filtered.append(item)
    return filtered


# ============================================================
# 8. DB FALLBACK
# ============================================================
def query_db(sql, params=[]):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=3)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA cache_size = 1000")
        cursor = conn.execute(sql, params)
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        print(f"[DB] Erreur: {e}")
        return []


def get_metrics_fallback():
    rows = query_db("""SELECT cpu_pct, ram_pct, disk_pct, swap_pct,
               load_1m, load_5m, load_15m,
               ram_total_gb, ram_used_gb,
               disk_total_gb, disk_used_gb, disk_free_gb
        FROM metrics_realtime ORDER BY id DESC LIMIT 1""")
    if rows:
        r = rows[0]
        return {"cpu": r.get("cpu_pct", 0), "ram": r.get("ram_pct", 0),
                "disk": r.get("disk_pct", 0), "swap": r.get("swap_pct", 0),
                "load_1m": r.get("load_1m", 0), "load_5m": r.get("load_5m", 0),
                "load_15m": r.get("load_15m", 0),
                "ram_total_gb": r.get("ram_total_gb", 0), "ram_used_gb": r.get("ram_used_gb", 0),
                "disk_total_gb": r.get("disk_total_gb", 0), "disk_used_gb": r.get("disk_used_gb", 0),
                "disk_free_gb": r.get("disk_free_gb", 0)}
    return {k: 0 for k in ["cpu", "ram", "disk", "swap", "load_1m", "load_5m", "load_15m",
                           "ram_total_gb", "ram_used_gb", "disk_total_gb", "disk_used_gb", "disk_free_gb"]}


# ============================================================
# 9. MÉTRIQUES
# ============================================================
def get_metrics():
    data = get_metrics_from_socket()
    return data if data else get_metrics_fallback()


def get_metrics_history(limit=60):
    rows = query_db("SELECT cpu_pct, ram_pct, disk_pct, swap_pct, ts FROM metrics_realtime ORDER BY id DESC LIMIT ?", [limit])
    return list(reversed(rows))


def get_dashboard():
    data = get_dashboard_from_socket()
    if data:
        return data
    sites = query_db("SELECT COUNT(*) as count FROM web_sites WHERE status = 'active'")
    remotes = query_db("SELECT COUNT(*) as count FROM rclone_remotes")
    ssl_expiring = query_db("SELECT COUNT(*) as count FROM ssl_certificates WHERE days_left <= 30 AND days_left > 0")
    fail2ban = query_db("SELECT COUNT(*) as count FROM fail2ban_banned_ips")
    tailscale = query_db("SELECT COUNT(*) as count FROM tailscale_peers WHERE online=1")
    oom = query_db("SELECT COUNT(*) as count FROM oom_events WHERE ts > datetime('now', '-24 hours')")
    failed = query_db("SELECT COUNT(*) as count FROM failed_units WHERE active_state = 'failed'")
    health = query_db("SELECT score, status FROM health_scores ORDER BY id DESC LIMIT 1")
    return {"sites": sites[0]["count"] if sites else 0,
            "remotes": remotes[0]["count"] if remotes else 0,
            "ssl_expiring": ssl_expiring[0]["count"] if ssl_expiring else 0,
            "fail2ban_banned": fail2ban[0]["count"] if fail2ban else 0,
            "tailscale_peers": tailscale[0]["count"] if tailscale else 0,
            "oom_events_24h": oom[0]["count"] if oom else 0,
            "failed_units": failed[0]["count"] if failed else 0,
            "health_score": health[0]["score"] if health else 0,
            "health_status": health[0]["status"] if health else "unknown"}


def get_active_sessions():
    data = get_entity_from_socket("active_sessions")
    if data:
        return filter_recent(data, "login_time", max_minutes=5)
    return filter_recent(query_db("SELECT user, ip, login_time FROM active_sessions ORDER BY id DESC LIMIT 20"), "login_time", max_minutes=5)


def get_top_processes(limit=10):
    data = get_metrics_from_socket()
    if data and data.get("top_processes"):
        return data["top_processes"][:limit]
    rows = query_db("SELECT top_processes FROM metrics_realtime ORDER BY id DESC LIMIT 1")
    if rows and rows[0].get("top_processes"):
        try:
            return json.loads(rows[0]["top_processes"])[:limit]
        except Exception:
            return []
    return []


def get_ssl_certificates():
    data = get_entity_from_socket("ssl_certificates")
    if data:
        return [c for c in data if c.get("days_left", -1) > 0]
    return query_db("SELECT domain, days_left, status, expiry_date FROM ssl_certificates WHERE days_left > 0 ORDER BY days_left ASC LIMIT 20")


def get_oom_events():
    data = get_entity_from_socket("oom_events")
    if data:
        return filter_recent(data, "ts", max_minutes=1440)
    return query_db("SELECT ts, killed_process, memory_used_mb FROM oom_events WHERE ts > datetime('now', '-1 day') ORDER BY id DESC LIMIT 10")


def get_failed_units():
    data = get_entity_from_socket("failed_units")
    if data:
        return [u for u in data if u.get("active_state") == "failed"]
    return query_db("SELECT unit, active_state, description FROM failed_units WHERE active_state = 'failed'")


def get_tailscale_peers():
    data = get_entity_from_socket("tailscale_peers")
    return data if data else query_db("SELECT name, online, tailscale_ip FROM tailscale_peers")


def get_fail2ban_banned():
    data = get_entity_from_socket("fail2ban_banned_ips")
    return data if data else query_db("SELECT jail, ip, banned_at FROM fail2ban_banned_ips ORDER BY banned_at DESC LIMIT 20")


def get_open_ports():
    data = get_entity_from_socket("open_ports")
    return data if data else query_db("SELECT port, protocol, process FROM open_ports ORDER BY port")


def get_rclone_remotes():
    data = get_entity_from_socket("rclone_remotes")
    return data if data else query_db("SELECT name, type, used_gb FROM rclone_remotes")


def get_web_sites():
    data = get_entity_from_socket("web_sites")
    return data if data else query_db("SELECT domain, ssl_enabled, php_version FROM web_sites WHERE status = 'active'")


def get_health_score():
    data = get_dashboard_from_socket()
    if data and data.get("health_score"):
        return {"score": data.get("health_score", 0), "status": data.get("health_status", "unknown")}
    rows = query_db("SELECT score, status FROM health_scores ORDER BY id DESC LIMIT 1")
    if rows and isinstance(rows, list) and len(rows) > 0:
        row = rows[0]
        if isinstance(row, dict):
            return {"score": row.get("score", 0), "status": row.get("status", "unknown")}
    return {"score": 0, "status": "unknown"}


def get_docker_containers():
    data = get_entity_from_socket("docker_containers")
    return data if data else query_db("SELECT name, status, image FROM docker_containers ORDER BY name LIMIT 30")


def get_disk_smart():
    data = get_entity_from_socket("disk_smart")
    return data if data else query_db("SELECT device, health, reallocated_sectors, pending_sectors FROM disk_smart LIMIT 10")


def get_package_upgrades():
    return query_db("SELECT package, installed_version, available_version FROM package_versions WHERE security_upgrade=1 LIMIT 20")


# ============================================================
# FastPanel2 — Accesseurs DB (via socket ou fallback SQLite)
# ============================================================
def get_fp_users():
    d = get_entity_from_socket("fastpanel_users")
    return d if d else query_db("SELECT username,email,status,disk_quota_gb,disk_used_gb,created_at,last_login FROM fastpanel_users ORDER BY username")

def get_fp_domains():
    d = get_entity_from_socket("fastpanel_domains")
    return d if d else query_db("SELECT domain,user,php_version,ssl_enabled,ssl_days_left,document_root,status FROM fastpanel_domains ORDER BY domain")

def get_fp_databases():
    d = get_entity_from_socket("fastpanel_databases")
    return d if d else query_db("SELECT name,db_user,size_mb,db_type,owner FROM fastpanel_databases ORDER BY name")

def get_fp_mail():
    d = get_entity_from_socket("fastpanel_mail_accounts")
    return d if d else query_db("SELECT email,domain,quota_mb,used_mb,status FROM fastpanel_mail_accounts ORDER BY email")

def get_fp_ftp():
    d = get_entity_from_socket("fastpanel_ftp_accounts")
    return d if d else query_db("SELECT login,home_dir,status,owner FROM fastpanel_ftp_accounts ORDER BY login")

def get_fp_backups():
    d = get_entity_from_socket("fastpanel_backups")
    return d if d else query_db("SELECT type,status,size_mb,created_at,error,user FROM fastpanel_backups ORDER BY created_at DESC LIMIT 50")

def get_fp_dns():
    d = get_entity_from_socket("fastpanel_dns_records")
    return d if d else query_db("SELECT zone,type,name,value,ttl FROM fastpanel_dns_records ORDER BY zone,type")

def get_fp_php():
    d = get_entity_from_socket("fastpanel_php_versions")
    return d if d else query_db("SELECT version,full_version,path,active FROM fastpanel_php_versions ORDER BY version DESC")

def get_fp_crons():
    d = get_entity_from_socket("fastpanel_crons")
    return d if d else query_db("SELECT user,schedule,command,enabled,last_run,last_status FROM fastpanel_crons ORDER BY user")

def get_fp_services():
    d = get_entity_from_socket("fastpanel_services")
    return d if d else query_db("SELECT name,status,version FROM fastpanel_services ORDER BY name")


def _fp_api_stat(endpoint: str, date: str = "") -> dict:
    """Appel API stats FastPanel2 avec auth JWT ou token interne."""
    import urllib.request as _req, urllib.error as _uerr
    # Charger le token depuis parameters.yml
    token = ""
    try:
        from pathlib import Path as _P
        for pf in ["/usr/local/fastpanel2/app/config/parameters.yml",
                   "/usr/local/fastpanel2/app/config/parameters.yaml"]:
            if _P(pf).exists():
                for line in _P(pf).read_text(errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("secret:") or line.startswith("api_token:"):
                        token = line.split(':', 1)[1].strip().strip("' \"")
                        break
                if token: break
    except Exception:
        pass
    url = f"http://127.0.0.1:8888{endpoint}"
    if date:
        url += f"?date={date}"
    try:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = _req.Request(url, headers=headers)
        with _req.urlopen(req, timeout=6) as resp:
            import json as _j
            return _j.loads(resp.read().decode())
    except Exception:
        return {}


def get_fp_stats_cpu(date: str = "") -> dict:
    """CPU breakdown par processus depuis FastPanel2."""
    import time as _t
    if not date:
        date = __import__('datetime').datetime.now().strftime("%Y-%m-%d")
    data = _fp_api_stat("/fastpanel/api/stat/cpu", date)
    if data:
        return data
    # Fallback : MySQL stat_cpu
    rows = []
    try:
        from pathlib import Path as _P
        creds = {}
        for pf in ["/usr/local/fastpanel2/app/config/parameters.yml"]:
            if _P(pf).exists():
                for line in _P(pf).read_text(errors="replace").splitlines():
                    line = line.strip()
                    if ": " in line and not line.startswith("#"):
                        k, _, v = line.partition(": ")
                        creds[k.strip()] = v.strip().strip("'\" ")
                break
        if creds.get("database_password"):
            import shlex as _sl
            cmd = (
                f"MYSQL_PWD={_sl.quote(creds['database_password'])} mysql "
                f"-h{creds.get('database_host','127.0.0.1')} "
                f"-u{_sl.quote(creds.get('database_user','fastpanel'))} "
                f"{_sl.quote(creds.get('database_name','fastpanel2'))} "
                f"--batch --silent --skip-column-names "
                f"-e {_sl.quote(f'SELECT ts,cpu_total,processes_json FROM stat_cpu WHERE DATE(ts)="{date}" ORDER BY ts DESC LIMIT 288')} "
                f"2>/dev/null"
            )
            import subprocess as _sp
            out = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=8).stdout
            for line in out.splitlines():
                if line.strip():
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        rows.append({"ts": parts[0], "total": parts[1],
                                     "processes": parts[2] if len(parts) > 2 else "{}"})
    except Exception:
        pass
    if rows:
        return {"source": "mysql", "data": rows}
    # Fallback ultime : ps snapshot en temps réel
    import subprocess as _sp
    ps = _sp.run("ps aux --sort=-%cpu --no-headers | head -15",
                 shell=True, capture_output=True, text=True).stdout
    procs = {}
    for line in ps.splitlines():
        parts = line.split(None, 10)
        if len(parts) >= 11:
            try:
                name = parts[10].split("/")[-1].split()[0][:20]
                cpu = float(parts[2])
                procs[name] = procs.get(name, 0) + cpu
            except Exception:
                pass
    return {"source": "realtime", "data": [{"ts": "now", "processes": procs}]}


def get_fp_stats_la(date: str = "") -> dict:
    """Load Average historique depuis FastPanel2."""
    if not date:
        date = __import__('datetime').datetime.now().strftime("%Y-%m-%d")
    data = _fp_api_stat("/fastpanel/api/stat/la", date)
    if data:
        return data
    # Fallback : /proc/loadavg temps réel
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return {"source": "realtime", "data": [{"ts": "now",
                "la1": float(parts[0]), "la5": float(parts[1]), "la15": float(parts[2])}]}
    except Exception:
        return {}


def get_fp_stats_memory(date: str = "") -> dict:
    """Utilisation mémoire historique depuis FastPanel2."""
    if not date:
        date = __import__('datetime').datetime.now().strftime("%Y-%m-%d")
    data = _fp_api_stat("/fastpanel/api/stat/memory", date)
    if data:
        return data
    # Fallback : /proc/meminfo
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        total = mi.get("MemTotal", 1)
        avail = mi.get("MemAvailable", total)
        cached = mi.get("Cached", 0) + mi.get("Buffers", 0)
        used = total - avail
        return {"source": "realtime", "data": [{"ts": "now",
                "total_mb": round(total/1024),
                "used_mb": round(used/1024),
                "cached_mb": round(cached/1024),
                "free_mb": round(avail/1024)}]}
    except Exception:
        return {}


def get_fp_stats_disk(date: str = "") -> dict:
    """Utilisation disque historique depuis FastPanel2."""
    if not date:
        date = __import__('datetime').datetime.now().strftime("%Y-%m-%d")
    data = _fp_api_stat("/fastpanel/api/stat/disk", date)
    if data:
        return data
    # Fallback : df
    import subprocess as _sp
    out = _sp.run("df -h --output=source,size,used,avail,pcent,target 2>/dev/null | grep -v tmpfs | grep -v udev",
                  shell=True, capture_output=True, text=True).stdout
    disks = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6:
            disks.append({"device": parts[0], "total": parts[1], "used": parts[2],
                          "avail": parts[3], "pct": parts[4], "mount": parts[5]})
    return {"source": "realtime", "data": disks}

def get_fp_summary():
    """Résumé rapide FastPanel pour les cards du dashboard."""
    users   = get_fp_users()
    domains = get_fp_domains()
    dbs     = get_fp_databases()
    mail    = get_fp_mail()
    backups = get_fp_backups()
    services= get_fp_services()
    ssl_warn = [d for d in domains if isinstance(d, dict) and 0 < d.get("ssl_days_left", 999) <= 30]
    ssl_crit = [d for d in domains if isinstance(d, dict) and d.get("ssl_days_left", 999) <= 0]
    svc_down = [s for s in services if isinstance(s, dict) and s.get("status") not in ("active", "running", "ok")]
    bk_fail  = [b for b in backups if isinstance(b, dict) and b.get("status") in ("error", "failed")]
    return {
        "users_count":    len(users),
        "domains_count":  len(domains),
        "databases_count":len(dbs),
        "mail_count":     len(mail),
        "ssl_warn":       len(ssl_warn),
        "ssl_crit":       len(ssl_crit),
        "services_down":  len(svc_down),
        "backups_failed": len(bk_fail),
    }


def get_ssh_keys():
    return query_db("SELECT user, key_type, comment FROM ssh_authorized_keys LIMIT 30")


def get_firewall_rules():
    data = get_entity_from_socket("firewall_rules")
    return data if data else query_db("SELECT chain, policy, rules_count FROM firewall_rules LIMIT 20")


def get_sysctl_issues():
    return query_db("SELECT param, value, recommended, status FROM sysctl_security WHERE status IN ('warning','critical') LIMIT 20")


# ============================================================
# 10. MÉMOIRE CONVERSATIONNELLE
# ============================================================
def init_memory_db():
    Path(MEMORY_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS conversations (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS conversation_summaries (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, summary TEXT NOT NULL, msg_range TEXT, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS server_sessions (token TEXT PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.commit()
    conn.close()


def create_server_session() -> str:
    token = secrets.token_hex(32)
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.execute("INSERT INTO server_sessions (token) VALUES (?)", (token,))
    conn.execute("DELETE FROM server_sessions WHERE created_at < datetime('now', '-1 day')")
    conn.commit()
    conn.close()
    return token


def validate_session(token: str) -> bool:
    if not token or len(token) != 64:
        return False
    conn = sqlite3.connect(MEMORY_DB_PATH)
    row = conn.execute("SELECT token FROM server_sessions WHERE token = ?", (token,)).fetchone()
    if row:
        conn.execute("UPDATE server_sessions SET last_used = CURRENT_TIMESTAMP WHERE token = ?", (token,))
        conn.commit()
    conn.close()
    return row is not None


def invalidate_session(token: str):
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.execute("DELETE FROM server_sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def save_conversation(session_id, role, content):
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.execute("INSERT INTO conversations (session_id, role, content) VALUES (?,?,?)", (session_id, role, content[:4000]))
    conn.commit()
    conn.close()


def count_raw_messages(session_id: str) -> int:
    conn = sqlite3.connect(MEMORY_DB_PATH)
    n = conn.execute("SELECT COUNT(*) FROM conversations WHERE session_id = ?", (session_id,)).fetchone()[0]
    conn.close()
    return n


def get_conversation_history(session_id, limit=20):
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT role, content FROM conversations WHERE session_id = ? ORDER BY id DESC LIMIT ?", (session_id, limit)).fetchall()
    conn.close()
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]


def get_summaries(session_id):
    conn = sqlite3.connect(MEMORY_DB_PATH)
    rows = conn.execute("SELECT summary FROM conversation_summaries WHERE session_id = ? ORDER BY id DESC LIMIT ?", (session_id, SUMMARY_KEEP)).fetchall()
    conn.close()
    return [r[0] for r in rows]


def prune_raw_messages(session_id: str, keep: int = 10):
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.execute("DELETE FROM conversations WHERE session_id = ? AND id NOT IN (SELECT id FROM conversations WHERE session_id = ? ORDER BY id DESC LIMIT ?)", (session_id, session_id, keep))
    conn.commit()
    conn.close()


def auto_summarize_session(session_id: str):
    if not DEEPSEEK_API_KEY:
        return
    history = get_conversation_history(session_id, limit=MAX_RAW_MESSAGES)
    if not history:
        return
    transcript = "\n".join(f"[{m['role'].upper()}] {m['content'][:500]}" for m in history)
    try:
        resp = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": "Voici une conversation d'admin système. Produis un résumé JSON structuré avec ces clés: problemes_resolus, changements_effectues, points_en_cours, alertes_notees.\n\n" + transcript}],
            temperature=0.2,
            max_tokens=600,
        )
        raw = resp.choices[0].message.content.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        summary_obj = json.loads(raw)
        summary_str = json.dumps(summary_obj, ensure_ascii=False)
    except Exception as e:
        print(f"[MEMORY] Erreur résumé auto: {e}")
        return
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.execute("INSERT INTO conversation_summaries (session_id, summary, msg_range) VALUES (?,?,?)", (session_id, summary_str, f"auto-{datetime.now().isoformat()}"))
    conn.execute("DELETE FROM conversation_summaries WHERE session_id = ? AND id NOT IN (SELECT id FROM conversation_summaries WHERE session_id = ? ORDER BY id DESC LIMIT ?)", (session_id, session_id, SUMMARY_KEEP))
    conn.commit()
    conn.close()
    prune_raw_messages(session_id, keep=10)


# ============================================================
# 11. FORMATEURS
# ============================================================
def _format_sites(sites, max_items=20):
    if not sites:
        return "Aucun site web"
    lines = [f"## 🌐 SITES WEB ({len(sites)} au total)"]
    for s in sites[:max_items]:
        lines.append(f"  • {s.get('domain','?')} (SSL:{'✅' if s.get('ssl_enabled') else '❌'} PHP:{s.get('php_version','?')})")
    if len(sites) > max_items:
        lines.append(f"  • … et {len(sites)-max_items} autres")
    return "\n".join(lines)


def _format_remotes(remotes, max_items=20):
    if not remotes:
        return "Aucun remote Rclone"
    lines = [f"## ☁️ REMOTES RCLONE ({len(remotes)} au total)"]
    for r in remotes[:max_items]:
        lines.append(f"  • {r.get('name','?')} ({r.get('type','?')})")
    if len(remotes) > max_items:
        lines.append(f"  • … et {len(remotes)-max_items} autres")
    return "\n".join(lines)


def _format_ssl(certs, max_items=20):
    expiring = [c for c in certs if c.get('days_left', 999) <= 30]
    if not expiring:
        return "Aucun certificat SSL expirant dans les 30 jours"
    lines = [f"## 🔒 SSL EXPIRANT (<30j) ({len(expiring)} certificats)"]
    for c in expiring[:max_items]:
        days = c.get('days_left', 0)
        emoji = "🔴" if days <= 7 else "🟠" if days <= 14 else "🟡"
        lines.append(f"  • {emoji} {c.get('domain','?')} : expire dans {days}j")
    if len(expiring) > max_items:
        lines.append(f"  • … et {len(expiring)-max_items} autres")
    return "\n".join(lines)


def _format_processes(processes, max_items=20):
    if not processes:
        return "Aucune donnée processus"
    lines = [f"## 🔥 TOP PROCESSUS ({len(processes)} actifs)"]
    for p in processes[:max_items]:
        cpu = p.get('cpu', 0)
        emoji = "🔥" if cpu > 50 else "⚡" if cpu > 25 else "💤"
        lines.append(f"  • {emoji} {p.get('command', '?')[:45]} — {cpu}% CPU")
    if len(processes) > max_items:
        lines.append(f"  • … et {len(processes)-max_items} autres")
    return "\n".join(lines)


def _format_sessions(sessions, max_items=20):
    if not sessions:
        return "Aucune session active"
    lines = [f"## 🌐 SESSIONS ACTIVES ({len(sessions)} connecté(s))"]
    for s in sessions[:max_items]:
        lines.append(f"  • {s.get('user','?')} depuis {s.get('ip','local')}")
    return "\n".join(lines)


def _format_ports(ports, max_items=20):
    if not ports:
        return "Aucun port ouvert détecté"
    lines = [f"## 🔌 PORTS OUVERTS ({len(ports)} ports)"]
    for p in ports[:max_items]:
        lines.append(f"  • {p.get('port','?')}/{p.get('protocol','?')} → {p.get('process','?')[:30]}")
    if len(ports) > max_items:
        lines.append(f"  • … et {len(ports)-max_items} autres")
    return "\n".join(lines)


def _format_oom(events, max_items=20):
    if not events:
        return "Aucun événement OOM récent"
    lines = [f"## 💀 OOM EVENTS ({len(events)} événements récents)"]
    for e in events[:max_items]:
        lines.append(f"  • {e.get('killed_process','?')} — {e.get('memory_used_mb',0)}MB")
    return "\n".join(lines)


def _format_failed(units, max_items=20):
    if not units:
        return "Aucune unité failed"
    lines = [f"## ⚠️ FAILED UNITS ({len(units)} service(s) en échec)"]
    for u in units[:max_items]:
        lines.append(f"  • {u.get('unit','?')}")
    return "\n".join(lines)


def _format_tailscale(peers, max_items=20):
    if not peers:
        return "Aucun peer Tailscale"
    online = sum(1 for p in peers if p.get('online'))
    lines = [f"## 🦎 TAILSCALE ({online}/{len(peers)} en ligne)"]
    for p in peers[:max_items]:
        lines.append(f"  • {p.get('name','?')} : {'🟢 en ligne' if p.get('online') else '🔴 hors ligne'}")
    return "\n".join(lines)


def _format_fail2ban(banned, max_items=20):
    if not banned:
        return "Aucune IP bannie"
    lines = [f"## 🚫 FAIL2BAN ({len(banned)} IP bannie(s))"]
    for b in banned[:max_items]:
        lines.append(f"  • {b.get('ip','?')} (jail: {b.get('jail','?')})")
    return "\n".join(lines)


def _format_docker(containers, max_items=20):
    if not containers:
        return "Aucun container Docker"
    running = sum(1 for c in containers if 'run' in str(c.get('status', '')).lower())
    lines = [f"## 🐳 DOCKER ({running} running / {len(containers)} total)"]
    for c in containers[:max_items]:
        st = c.get('status', '?')
        emoji = "🟢" if 'run' in str(st).lower() else "🔴"
        lines.append(f"  • {emoji} {c.get('name', '?')} ({c.get('image', '?')})")
    return "\n".join(lines)


def _format_smart(disks, max_items=10):
    if not disks:
        return "Aucune donnée SMART"
    lines = [f"## 💽 SANTÉ DISQUES ({len(disks)} disques)"]
    for d in disks[:max_items]:
        health = d.get('health', '?')
        emoji = "✅" if health in ('PASSED', 'OK') else "❌"
        lines.append(f"  • {emoji} {d.get('device', '?')} : {health}")
        if d.get('reallocated_sectors', 0):
            lines.append(f"    ⚠️ {d['reallocated_sectors']} secteurs réalloués")
        if d.get('pending_sectors', 0):
            lines.append(f"    ⚠️ {d['pending_sectors']} secteurs en attente")
    return "\n".join(lines)


def get_detailed_section(category: str, max_items: int = 20) -> str:
    sections = {
        "sites": lambda: _format_sites(get_web_sites(), max_items),
        "remotes": lambda: _format_remotes(get_rclone_remotes(), max_items),
        "ssl": lambda: _format_ssl(get_ssl_certificates(), max_items),
        "processes": lambda: _format_processes(get_top_processes(15), max_items),
        "sessions": lambda: _format_sessions(get_active_sessions(), max_items),
        "ports": lambda: _format_ports(get_open_ports(), max_items),
        "oom": lambda: _format_oom(get_oom_events(), max_items),
        "failed": lambda: _format_failed(get_failed_units(), max_items),
        "tailscale": lambda: _format_tailscale(get_tailscale_peers(), max_items),
        "fail2ban": lambda: _format_fail2ban(get_fail2ban_banned(), max_items),
        "docker": lambda: _format_docker(get_docker_containers(), max_items),
        "smart": lambda: _format_smart(get_disk_smart(), max_items),
    }
    if category not in sections:
        return ""
    return get_cached_or_fetch(f"detailed_{category}", sections[category], ttl=10)


def generate_infra_summary() -> str:
    global _prompt_cache, _prompt_cache_time
    now = time.time()
    if "summary" in _prompt_cache and now - _prompt_cache_time.get("summary", 0) < _PROMPT_CACHE_TTL:
        return _prompt_cache["summary"]
    metrics = get_metrics()
    health = get_health_score()
    sites = get_web_sites()
    remotes = get_rclone_remotes()
    ssl_certs = get_ssl_certificates()
    tailscale = get_tailscale_peers()
    oom = get_oom_events()
    failed = get_failed_units()
    expiring_ssl = [c for c in ssl_certs if c.get('days_left', 999) <= 30]
    summary_parts = []
    score = health.get('score', 0) if isinstance(health, dict) else 0
    emoji_health = "💚" if score >= 90 else "💛" if score >= 75 else "🧡" if score >= 50 else "❤️"
    summary_parts.append(f"{emoji_health} Santé {score}/100")
    summary_parts.append(f"📊 CPU {metrics.get('cpu', 0)}% RAM {metrics.get('ram', 0)}% DISK {metrics.get('disk', 0)}%")
    alerts = []
    if expiring_ssl:
        alerts.append(f"{len(expiring_ssl)} SSL expirent")
    if oom:
        alerts.append(f"{len(oom)} OOM")
    if failed:
        alerts.append(f"{len(failed)} failed")
    if alerts:
        summary_parts.append(f"⚠️ {', '.join(alerts)}")
    summary_parts.append(f"🌐 {len(sites)} sites · ☁️ {len(remotes)} remotes · 🦎 {len(tailscale)} tailscale")
    summary = " | ".join(summary_parts)
    _prompt_cache["summary"] = summary
    _prompt_cache_time["summary"] = now
    return summary


# ============================================================
# 12. PROMPT SYSTÈME
# ============================================================
def build_system_prompt(session_id: str, user_question: str = "", expert_mode: bool = False) -> str:
    infra_summary = generate_infra_summary()
    summaries = get_summaries(session_id)
    if summaries:
        memory_parts = []
        for s in summaries:
            try:
                obj = json.loads(s)
                memory_parts.append(f"• Résolus: {', '.join(obj.get('problemes_resolus', []))[:200]} | Faits: {', '.join(obj.get('changements_effectues', []))[:200]} | En cours: {', '.join(obj.get('points_en_cours', []))[:150]}")
            except Exception:
                memory_parts.append(f"• {s[:300]}")
        memory_context = "\n".join(memory_parts)
    else:
        memory_context = "Aucun historique"
    cats = detect_intent_categories(user_question, expert_mode)
    detailed_sections = []
    for cat in cats:
        if cat in ("health",):
            continue
        section = get_detailed_section(cat)
        if section and "Aucun" not in section:
            detailed_sections.append(section)
    if expert_mode and not detailed_sections:
        detailed_text = "## 📊 MODE EXPERT — ÉTAT COMPLET\n\n"
        for cat in KNOWN_CATEGORIES:
            if cat == "health":
                continue
            section = get_detailed_section(cat, max_items=10)
            if section:
                detailed_text += section + "\n\n"
    else:
        detailed_text = "\n\n".join(detailed_sections)
    expert_note = " (MODE EXPERT ACTIVÉ)" if expert_mode else ""
    return f"""Tu es CASSANDRA, agent IA souverain de l'infrastructure{expert_note}.

## 📊 RÉSUMÉ INFRA (temps réel)
{infra_summary}

{detailed_text}

## 🧠 MÉMOIRE CONVERSATIONNELLE
{memory_context}

## RÈGLES
1. Utilise TOUJOURS les données ci-dessus en priorité
2. Si une donnée n'est pas présente mais demandée, dis que tu peux approfondir
3. Formate tes réponses en HTML : <h2>/<h3>, <ul>/<li>, <table>, classes .ok/.warning/.critical
4. Pour les commandes shell : ```bash ... ```
5. Reste concise, efficace, garde ton humour ("meilleure amie en temps réel")
6. N'invente JAMAIS des métriques qui ne sont pas dans les données"""


# ============================================================
# 13. DEEPSEEK STREAM
# ============================================================
def call_deepseek_stream(messages):
    if not DEEPSEEK_API_KEY:
        yield "[ERREUR] Clé API DeepSeek non configurée"
        return
    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=messages,
            temperature=0.4,
            max_tokens=2000,
            stream=True
        )
        for chunk in response:
            if chunk.choices and chunk.choices[0].delta:
                token = chunk.choices[0].delta.content
                if token is not None:
                    yield token
    except Exception as e:
        yield f"[Erreur DeepSeek: {e}]"


# ============================================================
# 14. AUDIT
# ============================================================
def build_audit_report() -> str:
    ssh_keys = get_ssh_keys()
    ports = get_open_ports()
    sysctl = get_sysctl_issues()
    upgrades = get_package_upgrades()
    fail2ban = get_fail2ban_banned()
    ssl_certs = get_ssl_certificates()
    failed = get_failed_units()
    smart = get_disk_smart()
    firewall = get_firewall_rules()
    critical_ssl = [c for c in ssl_certs if c.get('days_left', 999) <= 7]
    warning_ssl = [c for c in ssl_certs if 7 < c.get('days_left', 999) <= 30]
    context = f"""DONNÉES D'AUDIT INFRASTRUCTURE :

SSH AUTHORIZED KEYS ({len(ssh_keys)}) : {json.dumps(ssh_keys[:20], ensure_ascii=False)}

PORTS OUVERTS ({len(ports)}) : {json.dumps(ports[:30], ensure_ascii=False)}

SYSCTL PROBLÉMATIQUES ({len(sysctl)}) : {json.dumps(sysctl, ensure_ascii=False)}

PAQUETS AVEC CVE ({len(upgrades)}) : {json.dumps(upgrades[:20], ensure_ascii=False)}

IPs BANNIES FAIL2BAN ({len(fail2ban)}) : {json.dumps(fail2ban[:15], ensure_ascii=False)}

SSL CRITIQUE ≤7j ({len(critical_ssl)}) : {[c['domain'] for c in critical_ssl]}
SSL AVERTISSEMENT ≤30j ({len(warning_ssl)}) : {[c['domain'] for c in warning_ssl]}

FAILED UNITS ({len(failed)}) : {json.dumps(failed, ensure_ascii=False)}

SANTÉ DISQUES : {json.dumps(smart, ensure_ascii=False)}

RÈGLES FIREWALL : {json.dumps(firewall[:10], ensure_ascii=False)}"""
    try:
        resp = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": "Tu es expert sécurité Linux. Produis un rapport d'audit HTML structuré avec score risque (/100), findings critiques, avertissements, recommandations avec commandes shell. Utilise classes .ok/.warning/.critical.\n\n" + context}],
            temperature=0.3,
            max_tokens=3000,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"<p class='critical'>Erreur génération audit : {e}</p>"


# ============================================================
# 15. SECURE EXECUTE - MODE ROOT (ACCÈS COMPLET)
# ============================================================
EXEC_ALLOWLIST = {}  # Mode root - plus aucune restriction
DANGEROUS_PATTERNS = []  # Désactive la détection d'injection

def secure_execute(cmd: str) -> str:
    """VERSION ROOT - Exécute TOUTES les commandes sans restriction"""
    if not cmd or not cmd.strip():
        return "Commande vide"
    
    # Protection minimale contre les commandes vraiment destructrices
    DANGEROUS_BLACKLIST = [
        "rm -rf /", "rm -rf /*", "dd if=/dev/zero of=/dev/sda",
        "mkfs", "format", ":(){ :|:& };:"
    ]
    
    for dangerous in DANGEROUS_BLACKLIST:
        if dangerous in cmd:
            return f"❌ Bloqué: {dangerous}"
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            executable='/bin/bash',
            capture_output=True,
            text=True,
            timeout=60,
            env=dict(os.environ, PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        )
        output = result.stdout + result.stderr
        if not output:
            output = f"✓ Code {result.returncode}"
        return output
    except subprocess.TimeoutExpired:
        return "⏱️ Timeout 60s"
    except Exception as e:
        return f"❌ Erreur: {e}"


# ============================================================
# 15.5 MODE MULTI-SERVEUR — tokens chiffrés au repos
# ============================================================
MULTISERVER_CONFIG_FILE = "/var/lib/cassandra/multiserver.json"
_ms_lock = threading.Lock()
_ms_derived_key: bytes = b""          # cache — invalidé sur rotate_deepseek_key
_ms_derived_key_lock = threading.Lock()


def _ms_derive_key() -> bytes:
    """Dérive la clé de chiffrement des tokens — mis en cache, coûteux une seule fois."""
    global _ms_derived_key
    with _ms_derived_key_lock:
        if _ms_derived_key:
            return _ms_derived_key
        master = DEEPSEEK_API_KEY.encode() if DEEPSEEK_API_KEY else b"cassandra-fallback-salt-insecure"
        _ms_derived_key = hashlib.pbkdf2_hmac(
            "sha256",
            master,
            b"cassandra-multiserver-token-encryption-v1",
            iterations=100_000,
            dklen=32,
        )
        return _ms_derived_key


def _ms_invalidate_key_cache() -> None:
    """Appelé après rotate_deepseek_key pour forcer la re-dérivation."""
    global _ms_derived_key
    with _ms_derived_key_lock:
        _ms_derived_key = b""


def _ms_encrypt_token(token: str) -> str:
    if not token:
        return ""
    try:
        from cryptography.fernet import Fernet
        import base64 as b64
        key_bytes = _ms_derive_key()
        fernet_key = b64.urlsafe_b64encode(key_bytes)
        f = Fernet(fernet_key)
        encrypted = f.encrypt(token.encode())
        return "enc1:" + encrypted.decode()
    except ImportError:
        pass
    import hmac
    key = _ms_derive_key()
    token_bytes = token.encode()
    keystream = b""
    counter = 0
    while len(keystream) < len(token_bytes):
        keystream += hmac.new(key, struct.pack(">I", counter), "sha256").digest()
        counter += 1
    xored = bytes(a ^ b for a, b in zip(token_bytes, keystream[:len(token_bytes)]))
    mac = hmac.new(key, xored, "sha256").digest()
    payload = mac + xored
    return "enc0:" + base64.b64encode(payload).decode()


def _ms_decrypt_token(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith("enc1:"):
        try:
            from cryptography.fernet import Fernet
            import base64 as b64
            key_bytes = _ms_derive_key()
            fernet_key = b64.urlsafe_b64encode(key_bytes)
            f = Fernet(fernet_key)
            return f.decrypt(stored[5:].encode()).decode()
        except Exception as e:
            print(f"[MULTISERVER] Erreur déchiffrement Fernet: {e}", file=sys.stderr)
            return ""
    if stored.startswith("enc0:"):
        try:
            import hmac
            key = _ms_derive_key()
            payload = base64.b64decode(stored[5:])
            mac_stored, xored = payload[:32], payload[32:]
            keystream = b""
            counter = 0
            while len(keystream) < len(xored):
                keystream += hmac.new(key, struct.pack(">I", counter), "sha256").digest()
                counter += 1
            mac_check = hmac.new(key, xored, "sha256").digest()
            if not hmac.compare_digest(mac_stored, mac_check):
                print("[MULTISERVER] HMAC invalide", file=sys.stderr)
                return ""
            token_bytes = bytes(a ^ b for a, b in zip(xored, keystream[:len(xored)]))
            return token_bytes.decode()
        except Exception as e:
            print(f"[MULTISERVER] Erreur déchiffrement fallback: {e}", file=sys.stderr)
            return ""
    print("[MULTISERVER] ⚠️ Token en clair détecté", file=sys.stderr)
    return stored


def _ms_load() -> list:
    try:
        if os.path.exists(MULTISERVER_CONFIG_FILE):
            with open(MULTISERVER_CONFIG_FILE, "r") as f:
                raw = json.load(f)
            for s in raw:
                if "token" in s:
                    s["token"] = _ms_decrypt_token(s["token"])
                    s["_token_encrypted"] = True
            return raw
    except Exception as e:
        print(f"[MULTISERVER] Erreur chargement: {e}", file=sys.stderr)
    return []


def _ms_save(servers: list) -> None:
    try:
        Path(MULTISERVER_CONFIG_FILE).parent.mkdir(parents=True, exist_ok=True)
        safe = []
        for s in servers:
            entry = {k: v for k, v in s.items() if k != "_token_encrypted"}
            if "token" in entry and entry["token"]:
                raw_token = entry["token"]
                if not raw_token.startswith(("enc1:", "enc0:")):
                    entry["token"] = _ms_encrypt_token(raw_token)
            safe.append(entry)
        with open(MULTISERVER_CONFIG_FILE, "w") as f:
            json.dump(safe, f, indent=2, ensure_ascii=False)
        os.chmod(MULTISERVER_CONFIG_FILE, 0o600)
    except Exception as e:
        print(f"[MULTISERVER] Erreur sauvegarde: {e}", file=sys.stderr)


def ms_migrate_plaintext_tokens() -> int:
    if not os.path.exists(MULTISERVER_CONFIG_FILE):
        return 0
    try:
        with open(MULTISERVER_CONFIG_FILE, "r") as f:
            raw = json.load(f)
        migrated = 0
        for s in raw:
            tok = s.get("token", "")
            if tok and not tok.startswith(("enc1:", "enc0:")):
                s["token"] = _ms_encrypt_token(tok)
                migrated += 1
        if migrated:
            with open(MULTISERVER_CONFIG_FILE, "w") as f:
                json.dump(raw, f, indent=2, ensure_ascii=False)
            os.chmod(MULTISERVER_CONFIG_FILE, 0o600)
            print(f"[MULTISERVER] ✅ {migrated} token(s) migrés", file=sys.stderr)
        return migrated
    except Exception as e:
        print(f"[MULTISERVER] Erreur migration: {e}", file=sys.stderr)
        return 0


def ms_list() -> list:
    servers = _ms_load()
    return [{"name": s["name"], "url": s["url"], "enabled": s.get("enabled", True)} for s in servers]


def ms_add(name: str, url: str, token: str) -> dict:
    name = name.strip()
    url = url.rstrip("/")
    if not name or not url or not token:
        return {"ok": False, "error": "name, url et token sont requis"}
    if not url.startswith(("http://", "https://")):
        return {"ok": False, "error": "URL doit commencer par http:// ou https://"}
    with _ms_lock:
        servers = _ms_load()
        for s in servers:
            if s["name"] == name:
                s["url"] = url
                s["token"] = token
                s["enabled"] = True
                _ms_save(servers)
                return {"ok": True, "action": "updated", "name": name}
        servers.append({"name": name, "url": url, "token": token, "enabled": True})
        _ms_save(servers)
    return {"ok": True, "action": "added", "name": name}


def ms_remove(name: str) -> dict:
    with _ms_lock:
        servers = _ms_load()
        before = len(servers)
        servers = [s for s in servers if s["name"] != name]
        if len(servers) == before:
            return {"ok": False, "error": f"Serveur '{name}' non trouvé"}
        _ms_save(servers)
    return {"ok": True, "name": name}


def ms_toggle(name: str, enabled: bool) -> dict:
    with _ms_lock:
        servers = _ms_load()
        for s in servers:
            if s["name"] == name:
                s["enabled"] = enabled
                _ms_save(servers)
                return {"ok": True, "name": name, "enabled": enabled}
    return {"ok": False, "error": f"Serveur '{name}' non trouvé"}


def _ms_fetch(server: dict, path: str, timeout: int = 6) -> dict | None:
    try:
        url = f"{server['url']}{path}"
        req = urllib.request.Request(url, headers={
            "X-Session-Token": server.get("token", ""),
            "User-Agent": "CASSANDRA-MultiServer/1.0",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}", "_server": server["name"]}
    except Exception as e:
        return {"_error": type(e).__name__, "_server": server["name"]}


def ms_status_all() -> list:
    import concurrent.futures
    servers = [s for s in _ms_load() if s.get("enabled", True)]
    if not servers:
        return []

    def fetch_one(s):
        dash = _ms_fetch(s, "/api/dashboard")
        metrics = _ms_fetch(s, "/api/metrics")
        return {
            "name": s["name"],
            "url": s["url"],
            "online": "_error" not in (dash or {}),
            "dashboard": dash if dash and "_error" not in dash else None,
            "metrics": metrics if metrics and "_error" not in metrics else None,
            "error": dash.get("_error") if dash and "_error" in dash else None,
        }

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(fetch_one, s): s for s in servers}
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                s = futures[fut]
                results.append({"name": s["name"], "url": s["url"], "online": False, "error": str(e)})
    results.sort(key=lambda x: x["name"])
    return results


def ms_aggregate_metrics() -> dict:
    statuses = ms_status_all()
    all_nodes = []
    local_metrics = get_metrics()
    local_health = get_health_score()
    all_nodes.append({
        "name": "local",
        "online": True,
        "cpu": local_metrics.get("cpu", 0),
        "ram": local_metrics.get("ram", 0),
        "disk": local_metrics.get("disk", 0),
        "health_score": local_health.get("score", 0),
        "health_status": local_health.get("status", "unknown"),
    })
    for s in statuses:
        node = {"name": s["name"], "online": s["online"], "error": s.get("error")}
        if s["online"] and s["metrics"]:
            m = s["metrics"]
            node.update({"cpu": m.get("cpu", 0), "ram": m.get("ram", 0), "disk": m.get("disk", 0)})
            if s["dashboard"]:
                d = s["dashboard"]
                node["health_score"] = d.get("health_score", 0)
                node["health_status"] = d.get("health_status", "unknown")
        all_nodes.append(node)
    online_nodes = [n for n in all_nodes if n.get("online")]
    total = len(all_nodes)
    online = len(online_nodes)
    avg = lambda key: round(sum(n.get(key, 0) for n in online_nodes) / max(online, 1), 1)
    return {
        "total_servers": total,
        "online_servers": online,
        "offline_servers": total - online,
        "avg_cpu": avg("cpu"),
        "avg_ram": avg("ram"),
        "avg_disk": avg("disk"),
        "avg_health": avg("health_score"),
        "nodes": all_nodes,
    }


# ============================================================
# 16. SERVEUR HTTP
# ============================================================
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True


class CassandraHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_html(self, content):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(content.encode())

    def send_sse(self, generator):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        for token in generator:
            if token:
                self.wfile.write(f"data: {json.dumps({'token': token})}\n\n".encode())
                self.wfile.flush()
        self.wfile.write(f"data: {json.dumps({'done': True})}\n\n".encode())
        self.wfile.flush()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if path in ("/", "/index.html"):
            self.send_html(HTML_TEMPLATE)
            return
        if path == "/api/verify":
            sid = self.headers.get("X-Session-Token", "")
            self.send_json({"valid": validate_session(sid)})
            return
        if path == "/api/metrics/history":
            sid = self.headers.get("X-Session-Token", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            limit = int(qs.get("limit", [60])[0])
            period = qs.get("period", ["1h"])[0]
            limit_map = {"1h": 720, "24h": 2880, "7d": 2016}
            limit = limit_map.get(period, limit)
            self.send_json(get_metrics_history(limit))
            return
        route_map = {
            "/api/metrics": get_metrics,
            "/api/dashboard": get_dashboard,
            "/api/remotes": get_rclone_remotes,
            "/api/ssl": get_ssl_certificates,
            "/api/sessions": get_active_sessions,
            "/api/ports": get_open_ports,
            "/api/processes": get_top_processes,
            "/api/health": get_health_score,
            "/api/fail2ban": get_fail2ban_banned,
            "/api/tailscale": get_tailscale_peers,
            "/api/oom": get_oom_events,
            "/api/failed": get_failed_units,
            "/api/sites": get_web_sites,
            "/api/docker": get_docker_containers,
            "/api/smart": get_disk_smart,
            # FastPanel2
            "/api/fp/summary":  get_fp_summary,
            "/api/fp/users":    get_fp_users,
            "/api/fp/domains":  get_fp_domains,
            "/api/fp/databases":get_fp_databases,
            "/api/fp/mail":     get_fp_mail,
            "/api/fp/ftp":      get_fp_ftp,
            "/api/fp/backups":  get_fp_backups,
            "/api/fp/dns":      get_fp_dns,
            "/api/fp/php":      get_fp_php,
            "/api/fp/crons":    get_fp_crons,
            "/api/fp/services": get_fp_services,
            "/api/fp/stats/cpu":    lambda: get_fp_stats_cpu(),
            "/api/fp/stats/la":     lambda: get_fp_stats_la(),
            "/api/fp/stats/memory": lambda: get_fp_stats_memory(),
            "/api/fp/stats/disk":   lambda: get_fp_stats_disk(),
        }
        if path in route_map:
            sid = self.headers.get("X-Session-Token", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            self.send_json(route_map[path]())
            return
        self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode() if length else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        # LOGIN
        if path == "/api/login":
            pwd = data.get("password", "")
            expected = os.environ.get("CASSANDRA_PASSWORD_HASH", "")
            if not expected:
                self.send_json({"success": False, "error": "CASSANDRA_PASSWORD_HASH non défini"}, 500)
                return
            if hashlib.sha256(pwd.encode()).hexdigest() == expected:
                sid = create_server_session()
                self.send_json({"success": True, "session": sid})
            else:
                self.send_json({"success": False, "error": "Mot de passe incorrect"}, 401)
            return

        # LOGOUT
        if path == "/api/logout":
            sid = data.get("session", "")
            if sid:
                invalidate_session(sid)
            self.send_json({"success": True})
            return

        # ROTATE KEY
        if path == "/api/rotate_key":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            new_key = data.get("new_key", "")
            if not new_key or not new_key.startswith("sk-"):
                self.send_json({"error": "Clé invalide"}, 400)
                return
            if rotate_deepseek_key(new_key):
                self.send_json({"success": True})
            else:
                self.send_json({"success": False, "error": "Échec rotation"}, 500)
            return

        # SERVICE STATUS
        if path == "/api/service/status":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            statuses = {}
            for service in ["cassandra", "cassandra-collector"]:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True, timeout=5
                )
                statuses[service] = result.stdout.strip() == "active"
            self.send_json({"success": True, "status": statuses})
            return

        # RESTART COLLECTOR
        if path == "/api/service/restart/collector":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            allowed, remaining, wait_seconds = check_rate_limit(sid)
            if not allowed:
                self.send_json({
                    "success": False,
                    "error": f"Trop d'actions. Attendez {wait_seconds}s (limite: {RATE_LIMIT_MAX_ACTIONS}/h)"
                }, 429)
                return
            admin_pwd = data.get("admin_password", "")
            expected = os.environ.get("CASSANDRA_PASSWORD_HASH", "")
            if expected and hashlib.sha256(admin_pwd.encode()).hexdigest() != expected:
                log_admin_action(sid, "restart_collector", "FAILED", "wrong password")
                self.send_json({"error": "Mot de passe administrateur incorrect"}, 403)
                return
            try:
                result = subprocess.run(
                    ["systemctl", "restart", "cassandra-collector"],
                    capture_output=True, text=True, timeout=30
                )
                record_admin_action(sid)
                if result.returncode == 0:
                    log_admin_action(sid, "restart_collector", "SUCCESS", "")
                    self.send_json({"success": True, "output": "Collector redémarré"})
                else:
                    log_admin_action(sid, "restart_collector", "FAILED", result.stderr)
                    self.send_json({"success": False, "error": result.stderr}, 500)
            except Exception as e:
                log_admin_action(sid, "restart_collector", "ERROR", str(e))
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # RESTART AGENT
        if path == "/api/service/restart/agent":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            allowed, remaining, wait_seconds = check_rate_limit(sid)
            if not allowed:
                self.send_json({
                    "success": False,
                    "error": f"Trop d'actions. Attendez {wait_seconds}s (limite: {RATE_LIMIT_MAX_ACTIONS}/h)"
                }, 429)
                return
            admin_pwd = data.get("admin_password", "")
            expected = os.environ.get("CASSANDRA_PASSWORD_HASH", "")
            if expected and hashlib.sha256(admin_pwd.encode()).hexdigest() != expected:
                log_admin_action(sid, "restart_agent", "FAILED", "wrong password")
                self.send_json({"error": "Mot de passe administrateur incorrect"}, 403)
                return
            try:
                record_admin_action(sid)

                def restart_agent():
                    time.sleep(1)
                    subprocess.run(["systemctl", "restart", "cassandra"], capture_output=True, timeout=30)

                threading.Thread(target=restart_agent, daemon=True).start()
                log_admin_action(sid, "restart_agent", "SUCCESS", "agent restart initiated")
                self.send_json({"success": True, "message": "Redémarrage de l'agent en cours. Vous allez être déconnecté."})
            except Exception as e:
                log_admin_action(sid, "restart_agent", "ERROR", str(e))
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # MULTI-SERVEUR
        if path == "/api/multiserver/list":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            self.send_json({"ok": True, "servers": ms_list()})
            return

        if path == "/api/multiserver/add":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            result = ms_add(data.get("name", ""), data.get("url", ""), data.get("token", ""))
            log_admin_action(sid, "multiserver_add", "SUCCESS" if result["ok"] else "FAILED", f"server={data.get('name', '')}")
            self.send_json(result)
            return

        if path == "/api/multiserver/remove":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            result = ms_remove(data.get("name", ""))
            log_admin_action(sid, "multiserver_remove", "SUCCESS" if result["ok"] else "FAILED", f"server={data.get('name', '')}")
            self.send_json(result)
            return

        if path == "/api/multiserver/toggle":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            result = ms_toggle(data.get("name", ""), bool(data.get("enabled", True)))
            self.send_json(result)
            return

        if path == "/api/multiserver/status":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            self.send_json({"ok": True, "fleet": ms_status_all()})
            return

        if path == "/api/multiserver/aggregate":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            self.send_json(ms_aggregate_metrics())
            return

        # CHAT STREAM
        if path == "/api/chat/stream":
            msg = data.get("message", "")
            sid = data.get("session", "")
            expert_mode = data.get("expert_mode", False)
            if not validate_session(sid):
                self.send_json({"error": "Session invalide"}, 401)
                return
            if not msg:
                self.send_json({"error": "Message vide"}, 400)
                return
            history = get_conversation_history(sid, 20)
            messages = [{"role": "system", "content": build_system_prompt(sid, msg, expert_mode)}]
            for h in history:
                messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": msg})
            full_response_parts = []
            stream_error = None

            def stream_and_collect():
                nonlocal stream_error
                try:
                    for token in call_deepseek_stream(messages):
                        if token:
                            full_response_parts.append(token)
                        yield token
                except Exception as e:
                    stream_error = e
                    yield f"[Erreur: {e}]"

            self.send_sse(stream_and_collect())
            full_response = "".join(full_response_parts)
            if full_response and not stream_error:
                save_conversation(sid, "user", msg)
                save_conversation(sid, "assistant", full_response)
            if count_raw_messages(sid) >= MAX_RAW_MESSAGES:
                threading.Thread(target=auto_summarize_session, args=(sid,), daemon=True).start()
            return

        # EXEC (réponse JSON complète — pour blocs commandes dans le chat)
        if path == "/api/exec":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            cmd = data.get("cmd", "")
            if not cmd:
                self.send_json({"error": "Commande vide"}, 400)
                return
            self.send_json({"success": True, "output": secure_execute(cmd)})
            return

        # EXEC STREAM (SSE — pour le terminal interactif)
        if path == "/api/exec/stream":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            cmd = data.get("cmd", "")
            if not cmd:
                self.send_json({"error": "Commande vide"}, 400)
                return
            log_admin_action(sid, "terminal_exec", "RUN", f"cmd={cmd[:120]}")

            def stream_exec():
                try:
                    proc = subprocess.Popen(
                        cmd,
                        shell=True,
                        executable="/bin/bash",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                        env=dict(os.environ, PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                 TERM="xterm-256color"),
                    )
                    for line in proc.stdout:
                        yield line
                    proc.wait()
                    yield f"\n[exit {proc.returncode}]\n"
                except Exception as e:
                    yield f"[Erreur: {e}]\n"

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                for chunk in stream_exec():
                    if chunk:
                        self.wfile.write(
                            f"data: {json.dumps({'out': chunk})}\n\n".encode()
                        )
                        self.wfile.flush()
                self.wfile.write(b"data: \"done\"\n\n")
                self.wfile.flush()
            except BrokenPipeError:
                pass
            return

        # AUDIT
        if path == "/api/audit":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            self.send_json({"success": True, "report": build_audit_report()})
            return

        self.send_json({"error": "Not found"}, 404)


# ============================================================
# 17. TEMPLATE HTML (COMPLET)
# ============================================================
HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cassandra v12.1 - IA souveraine</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e8e8f0;height:100vh;overflow:hidden}
#particles-canvas{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0}
.hex-grid{position:fixed;top:0;left:0;width:100%;height:100%;background-image:linear-gradient(to right,rgba(0,255,170,.03) 1px,transparent 1px),linear-gradient(to bottom,rgba(0,255,170,.03) 1px,transparent 1px);background-size:50px 50px;pointer-events:none;z-index:0;animation:gridMove 20s linear infinite}
@keyframes gridMove{0%{transform:translate(0,0)}100%{transform:translate(50px,50px)}}
.app-container{position:relative;z-index:1;height:100vh;display:flex;flex-direction:column}
.header{background:rgba(17,17,24,.9);backdrop-filter:blur(10px);border-bottom:1px solid rgba(0,255,170,.2);padding:12px 24px;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'JetBrains Mono',monospace;font-weight:700;font-size:18px;background:linear-gradient(135deg,#00ffcc,#7c5cfc);-webkit-background-clip:text;background-clip:text;color:transparent}
.logo-badge{background:rgba(0,255,170,.15);border-radius:4px;padding:2px 8px;font-size:9px;color:#00ffcc;margin-left:8px}
.status{display:flex;align-items:center;gap:8px}
.status-dot{width:8px;height:8px;border-radius:50%;background:#00ffcc;box-shadow:0 0 8px #00ffcc;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.session-time{font-size:11px;color:#6b6b80}
.hdr-btn{border-radius:6px;padding:6px 12px;font-size:11px;cursor:pointer;border:1px solid;background:transparent;color:#e8e8f0}
.expert-btn{border-color:rgba(124,92,252,.3);background:rgba(124,92,252,.15)}
.expert-btn.active{background:rgba(0,255,170,.25);border-color:#00ffcc;color:#00ffcc}
.audit-btn{border-color:rgba(255,165,0,.3);background:rgba(255,165,0,.1);color:#ffa502}
.logout-btn{border-color:rgba(255,71,87,.3);background:rgba(255,71,87,.15);color:#ff4757}
.service-btn-group{display:flex;gap:6px;margin:0 10px}
.service-btn{background:rgba(28,28,37,.9);border-color:rgba(0,255,170,.3);color:#00ffcc;padding:6px 10px;border-radius:6px;font-size:10px;cursor:pointer;transition:all .2s}
.service-btn:hover{background:rgba(0,255,170,.15)}
.service-btn.warning{border-color:rgba(255,71,87,.3);color:#ff4757}
.service-btn.warning:hover{background:rgba(255,71,87,.15)}
.tabs{display:flex;background:rgba(17,17,24,.9);border-bottom:1px solid rgba(0,255,170,.1);padding:0 16px}
.tab{padding:8px 18px;font-size:12px;cursor:pointer;color:#6b6b80;border-bottom:2px solid transparent}
.tab.active{color:#00ffcc;border-bottom-color:#00ffcc}
.tab-content{display:none;flex:1;overflow:hidden}
.tab-content.active{display:flex}
.main-layout{display:flex;flex:1;overflow:hidden;gap:1px;background:rgba(255,255,255,.03)}
.panel{background:rgba(17,17,24,.8);backdrop-filter:blur(10px);overflow-y:auto;padding:16px}
.panel-left{width:300px;border-right:1px solid rgba(0,255,170,.1)}
.panel-right{width:300px;border-left:1px solid rgba(0,255,170,.1)}
.panel-center{flex:1;display:flex;flex-direction:column;padding:0}
.panel::-webkit-scrollbar{width:3px}
.panel::-webkit-scrollbar-thumb{background:#00ffcc}
.history-layout{flex:1;display:flex;flex-direction:column;background:rgba(17,17,24,.8);padding:20px;overflow-y:auto}
.history-controls{display:flex;gap:10px;margin-bottom:20px}
.period-btn{background:rgba(28,28,37,.9);border:1px solid rgba(0,255,170,.2);border-radius:6px;padding:6px 14px;font-size:12px;color:#a0a0b0;cursor:pointer}
.period-btn.active{background:rgba(0,255,170,.15);border-color:#00ffcc;color:#00ffcc}
.history-charts{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.history-chart-card{background:rgba(28,28,37,.8);border:1px solid rgba(0,255,170,.1);border-radius:12px;padding:16px}
.history-chart-title{font-size:11px;color:#00ffcc;margin-bottom:12px}
.history-chart-container{height:160px}
.audit-modal{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,10,15,.95);backdrop-filter:blur(20px);z-index:500;display:flex;align-items:center;justify-content:center}
.audit-card{background:rgba(28,28,37,.98);border:1px solid rgba(255,165,0,.3);border-radius:16px;width:90%;max-width:860px;max-height:85vh;display:flex;flex-direction:column}
.audit-header{padding:16px 20px;display:flex;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.07)}
.audit-header h2{color:#ffa502;font-size:15px}
.audit-close{background:rgba(255,71,87,.2);border:1px solid rgba(255,71,87,.3);border-radius:6px;padding:4px 10px;cursor:pointer;color:#ff4757}
.audit-body{flex:1;overflow-y:auto;padding:20px;font-size:13px}
.audit-body::-webkit-scrollbar{width:3px}
.audit-body::-webkit-scrollbar-thumb{background:#ffa502}
.audit-body .ok{color:#2ed573}
.audit-body .warning{color:#ffa502}
.audit-body .critical{color:#ff4757}
.card{background:rgba(28,28,37,.8);border-radius:12px;padding:14px;margin-bottom:14px;border:1px solid rgba(0,255,170,.1)}
.card:hover{border-color:rgba(0,255,170,.3)}
.card-title{font-size:10px;text-transform:uppercase;letter-spacing:.2em;color:#00ffcc;margin-bottom:12px;display:flex;justify-content:space-between}
.card-title .fix-btn{font-size:9px;background:rgba(0,255,170,.12);border:1px solid rgba(0,255,170,.25);border-radius:4px;padding:2px 7px;cursor:pointer;color:#00ffcc}
.metric-bar{margin-bottom:12px}
.metric-label{font-size:11px;color:#a0a0b0;display:flex;justify-content:space-between;margin-bottom:4px}
.bar-track{background:rgba(255,255,255,.1);border-radius:4px;height:6px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .3s ease}
.bar-fill.cpu{background:linear-gradient(90deg,#00ffcc,#7c5cfc)}
.bar-fill.ram{background:linear-gradient(90deg,#7c5cfc,#00ffcc)}
.bar-fill.disk{background:linear-gradient(90deg,#00ffcc,#2ed573)}
.chart-container{height:110px;margin:8px 0}
.remote-item{padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:11px;font-family:monospace;display:flex;justify-content:space-between}
.remote-name{color:#00ffcc;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:190px}
.remote-type{font-size:9px;color:#7c5cfc}
.ssl-item{padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:11px;display:flex;justify-content:space-between}
.ssl-domain{font-weight:600}
.ssl-days.critical{color:#ff4757}
.ssl-days.warning{color:#ffa502}
.ssl-days.ok{color:#2ed573}
.score-ring{display:flex;align-items:center;gap:12px}
.score-big{font-size:36px;font-weight:700;font-family:monospace}
.score-big.excellent{color:#00ffcc}
.score-big.good{color:#2ed573}
.score-big.warning{color:#ffa502}
.score-big.critical{color:#ff4757}
.chat-messages{flex:1;overflow-y:auto;padding:16px}
.message{margin-bottom:16px;display:flex;flex-direction:column}
.message.user{align-items:flex-end}
.message.bot{align-items:flex-start}
.message-bubble{max-width:85%;padding:10px 14px;border-radius:12px;font-size:13px;line-height:1.6}
.message.user .message-bubble{background:linear-gradient(135deg,#7c5cfc,#00ffcc);color:#0a0a0f;border-radius:12px 12px 2px 12px}
.message.bot .message-bubble{background:rgba(28,28,37,.9);border:1px solid rgba(0,255,170,.2);border-radius:12px 12px 12px 2px}
.message.bot .message-bubble h2{font-size:13px;color:#00ffcc;margin:6px 0 4px}
.message.bot .message-bubble ul{margin:5px 0;padding-left:18px}
.message.bot .message-bubble li{margin:2px 0}
.command-block{background:#0a0a0f;border-radius:6px;margin:8px 0;border:1px solid rgba(0,255,170,.2)}
.command-header{padding:6px 10px;background:rgba(0,255,170,.05);font-size:10px;display:flex;justify-content:space-between}
.exec-btn{background:rgba(0,255,170,.15);border:none;border-radius:4px;padding:2px 8px;color:#00ffcc;cursor:pointer}
.command-result{padding:8px 10px;font-size:10px;font-family:monospace;white-space:pre-wrap;max-height:200px;overflow-y:auto;color:#a0a0b0}
.chat-input-area{padding:16px;border-top:1px solid rgba(0,255,170,.1);display:flex;gap:10px}
.chat-input{flex:1;background:rgba(28,28,37,.9);border:1px solid rgba(0,255,170,.2);border-radius:8px;padding:10px 14px;color:#e8e8f0;font-family:'Inter',sans-serif;font-size:13px;resize:none;outline:none}
.chat-input:focus{border-color:#00ffcc}
.send-btn{background:linear-gradient(135deg,#00ffcc,#7c5cfc);border:none;border-radius:8px;width:42px;height:42px;cursor:pointer;font-size:18px;display:flex;align-items:center;justify-content:center}
.send-btn:disabled{opacity:.4}
.typing{display:flex;gap:4px;padding:8px 12px}
.typing-dot{width:6px;height:6px;border-radius:50%;background:#00ffcc;animation:typingAnim 1.4s infinite}
.typing-dot:nth-child(2){animation-delay:.2s}
.typing-dot:nth-child(3){animation-delay:.4s}
@keyframes typingAnim{0%,60%,100%{transform:translateY(0);opacity:.4}30%{transform:translateY(-4px);opacity:1}}
.loader{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,255,170,.2);border-top-color:#00ffcc;border-radius:50%;animation:spin .6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.login-modal{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,10,15,.98);backdrop-filter:blur(20px);z-index:1000;display:flex;align-items:center;justify-content:center}
.login-card{background:rgba(28,28,37,.95);border:1px solid rgba(0,255,170,.3);border-radius:20px;padding:32px;width:340px;text-align:center}
.login-card h1{background:linear-gradient(135deg,#00ffcc,#7c5cfc);-webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:8px}
.login-card p{font-size:12px;color:#6b6b80;margin-bottom:24px}
.login-card input{width:100%;background:rgba(0,0,0,.5);border:1px solid rgba(0,255,170,.2);border-radius:8px;padding:12px;color:#fff;font-size:14px;margin-bottom:16px;outline:none}
.login-card input:focus{border-color:#00ffcc}
.login-card button{width:100%;background:linear-gradient(135deg,#00ffcc,#7c5cfc);border:none;border-radius:8px;padding:12px;font-weight:600;cursor:pointer;color:#0a0a0f;font-size:14px}
.login-error{color:#ff4757;font-size:12px;margin-top:12px}
.hidden{display:none!important}
.empty-state{font-size:10px;color:#6b6b80;padding:4px 0}

/* ============================================================
   TERMINAL CASSANDRA v12.0
   ============================================================ */
.terminal-overlay{position:fixed;top:0;right:0;width:100%;height:100%;background:rgba(5,5,10,.7);backdrop-filter:blur(4px);z-index:200;opacity:0;pointer-events:none;transition:opacity .25s ease}
.terminal-overlay.open{opacity:1;pointer-events:all}
.terminal-panel{position:fixed;top:0;right:-760px;width:760px;height:100%;background:#0d0d14;border-left:1px solid rgba(0,255,170,.25);z-index:201;display:flex;flex-direction:column;transition:right .3s cubic-bezier(.4,0,.2,1);box-shadow:-8px 0 40px rgba(0,0,0,.6)}
.terminal-panel.open{right:0}
.terminal-titlebar{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;background:#111120;border-bottom:1px solid rgba(0,255,170,.15);flex-shrink:0}
.terminal-title{font-family:'JetBrains Mono',monospace;font-size:13px;color:#00ffcc;display:flex;align-items:center;gap:10px}
.terminal-title .tdot{width:8px;height:8px;border-radius:50%;background:#00ffcc;box-shadow:0 0 6px #00ffcc;animation:pulse 2s infinite}
.terminal-status{font-size:10px;color:#6b6b80;font-family:'JetBrains Mono',monospace}
.terminal-actions{display:flex;gap:8px}
.terminal-btn{background:transparent;border:1px solid rgba(0,255,170,.2);border-radius:4px;padding:4px 10px;font-size:11px;cursor:pointer;color:#a0a0b0;transition:all .15s;font-family:'JetBrains Mono',monospace}
.terminal-btn:hover{background:rgba(0,255,170,.1);color:#00ffcc;border-color:#00ffcc}
.terminal-btn.tbdanger:hover{background:rgba(255,71,87,.15);color:#ff4757;border-color:#ff4757}
.terminal-tab-bar{display:flex;background:#0a0a14;border-bottom:1px solid rgba(0,255,170,.1);padding:0 8px;gap:2px;flex-shrink:0}
.terminal-tab{font-family:'JetBrains Mono',monospace;font-size:11px;padding:6px 14px;color:#6b6b80;cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;user-select:none}
.terminal-tab.active{color:#00ffcc;border-bottom-color:#00ffcc}
.terminal-tab:hover{color:#a0a0b0}
.terminal-tab-close{margin-left:6px;opacity:.5}
.terminal-tab-close:hover{opacity:1;color:#ff4757}
.terminal-new-tab{font-family:'JetBrains Mono',monospace;font-size:16px;padding:2px 10px;color:#4a4a60;cursor:pointer;align-self:center;transition:color .15s;line-height:1}
.terminal-new-tab:hover{color:#00ffcc}
.terminal-xterm-wrap{flex:1;padding:10px 8px 4px 10px;overflow:hidden;min-height:0}
.terminal-input-row{display:flex;align-items:center;background:#070710;border-top:1px solid rgba(0,255,170,.12);padding:0;flex-shrink:0}
.terminal-prompt{font-family:'JetBrains Mono',monospace;font-size:13px;color:#00ffcc;padding:10px 6px 10px 14px;white-space:nowrap;user-select:none;flex-shrink:0}
.terminal-cmd-input{flex:1;background:transparent;border:none;outline:none;color:#e8e8f0;font-family:'JetBrains Mono',monospace;font-size:13px;padding:10px 4px;caret-color:#00ffcc}
.terminal-send-btn{background:rgba(0,255,170,.12);border:none;border-left:1px solid rgba(0,255,170,.15);color:#00ffcc;padding:10px 16px;cursor:pointer;font-size:13px;transition:background .15s;flex-shrink:0}
.terminal-send-btn:hover{background:rgba(0,255,170,.25)}
.terminal-send-btn:disabled{opacity:.4;cursor:default}
#terminal-open-btn{border-color:rgba(0,255,170,.3);background:rgba(0,255,170,.08);color:#00ffcc}
#terminal-open-btn:hover{background:rgba(0,255,170,.18)}
.fleet-layout{flex:1;display:flex;flex-direction:column;background:rgba(17,17,24,.8);padding:20px;overflow-y:auto}
.fleet-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.fleet-header h2{font-size:13px;color:#00ffcc;font-family:'JetBrains Mono',monospace}
.fleet-actions{display:flex;gap:8px}
.fleet-add-btn{background:rgba(0,255,170,.15);border:1px solid rgba(0,255,170,.3);border-radius:6px;padding:6px 12px;font-size:11px;cursor:pointer;color:#00ffcc}
.fleet-agg{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.fleet-agg-card{background:rgba(28,28,37,.8);border:1px solid rgba(0,255,170,.1);border-radius:10px;padding:12px;text-align:center}
.fleet-agg-label{font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:#6b6b80;margin-bottom:6px}
.fleet-agg-value{font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace;color:#00ffcc}
.fleet-agg-value.warning{color:#ffa502}.fleet-agg-value.critical{color:#ff4757}
.fleet-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.fleet-node{background:rgba(28,28,37,.8);border:1px solid rgba(0,255,170,.1);border-radius:12px;padding:14px}
.fleet-node:hover{border-color:rgba(0,255,170,.3)}
.fleet-node.offline{border-color:rgba(255,71,87,.2);opacity:.7}
.fleet-node-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.fleet-node-name{font-size:13px;font-weight:600;color:#e8e8f0;font-family:'JetBrains Mono',monospace}
.fleet-node-badge{font-size:9px;padding:2px 8px;border-radius:4px}
.fleet-node-badge.online{background:rgba(46,213,115,.15);color:#2ed573}
.fleet-node-badge.offline{background:rgba(255,71,87,.15);color:#ff4757}
.fleet-node-url{font-size:10px;color:#6b6b80;margin-bottom:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fleet-node-metrics{display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-bottom:10px}
.fleet-metric-mini{text-align:center}
.fleet-metric-mini .label{font-size:9px;color:#6b6b80}
.fleet-metric-mini .val{font-size:13px;font-weight:600;font-family:'JetBrains Mono',monospace}
.fleet-node-actions{display:flex;gap:6px;margin-top:8px}
.fleet-node-btn{flex:1;background:transparent;border:1px solid rgba(0,255,170,.2);border-radius:4px;padding:4px;font-size:10px;cursor:pointer;color:#a0a0b0}
.fleet-node-btn:hover{background:rgba(0,255,170,.1);color:#00ffcc}
.fleet-node-btn.danger{border-color:rgba(255,71,87,.3);color:#ff4757}
.fleet-node-btn.danger:hover{background:rgba(255,71,87,.1)}
.fleet-add-modal{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,10,15,.92);backdrop-filter:blur(10px);z-index:300;display:flex;align-items:center;justify-content:center}
.fleet-add-card{background:rgba(28,28,37,.98);border:1px solid rgba(0,255,170,.3);border-radius:16px;padding:28px;width:360px}
.fleet-add-card h2{color:#00ffcc;font-size:14px;margin-bottom:20px;font-family:'JetBrains Mono',monospace}
.fleet-field{margin-bottom:14px}
.fleet-field label{font-size:11px;color:#a0a0b0;display:block;margin-bottom:4px}
.fleet-field input{width:100%;background:rgba(0,0,0,.4);border:1px solid rgba(0,255,170,.2);border-radius:6px;padding:9px 12px;color:#e8e8f0;font-size:13px;outline:none}
.fleet-field input:focus{border-color:#00ffcc}
.fleet-add-actions{display:flex;gap:10px;margin-top:18px}
.fleet-btn-primary{flex:1;background:linear-gradient(135deg,#00ffcc,#7c5cfc);border:none;border-radius:6px;padding:10px;font-weight:600;cursor:pointer;color:#0a0a0f;font-size:13px}
.fleet-btn-cancel{background:transparent;border:1px solid rgba(255,255,255,.1);border-radius:6px;padding:10px 16px;cursor:pointer;color:#6b6b80;font-size:13px}

/* ============================================================
   FASTPANEL2 UI — onglet + cards dashboard
   ============================================================ */
/* Cards résumé dans panel-left */
.fp-summary-cards{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin:0}
.fp-sc{background:rgba(10,10,20,.5);border:1px solid rgba(0,255,170,.1);border-radius:8px;padding:8px 10px;cursor:pointer;transition:all .2s;position:relative;overflow:hidden}
.fp-sc:hover{border-color:rgba(0,255,170,.35);background:rgba(0,255,170,.06)}
.fp-sc::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;border-radius:3px 0 0 3px}
.fp-sc.ok::before{background:#2ed573}.fp-sc.warn::before{background:#ffa502}.fp-sc.crit::before{background:#ff4757}
.fp-sc-label{font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:#6b6b80;margin-bottom:4px}
.fp-sc-value{font-size:20px;font-weight:700;font-family:'JetBrains Mono',monospace;color:#e8e8f0;line-height:1}
.fp-sc-sub{font-size:9px;color:#6b6b80;margin-top:2px}

/* Tab FastPanel */
.fp-layout{flex:1;display:flex;overflow:hidden;background:rgba(10,10,15,.6)}
.fp-sidebar{width:176px;background:rgba(17,17,24,.9);border-right:1px solid rgba(0,255,170,.1);display:flex;flex-direction:column;flex-shrink:0}
.fp-sidebar-header{padding:16px 14px 10px;border-bottom:1px solid rgba(0,255,170,.08)}
.fp-sidebar-title{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;background:linear-gradient(135deg,#00ffcc,#7c5cfc);-webkit-background-clip:text;background-clip:text;color:transparent}
.fp-sidebar-sub{font-size:9px;color:#6b6b80;margin-top:2px}
.fp-nav{flex:1;overflow-y:auto;padding:8px 0}
.fp-nav-item{display:flex;align-items:center;gap:8px;padding:9px 14px;font-size:11px;color:#6b6b80;cursor:pointer;border-left:2px solid transparent;transition:all .15s;user-select:none}
.fp-nav-item:hover{color:#a0a0b0;background:rgba(255,255,255,.03)}
.fp-nav-item.active{color:#00ffcc;border-left-color:#00ffcc;background:rgba(0,255,170,.06)}
.fp-nav-icon{font-size:13px;width:16px;text-align:center;flex-shrink:0}
.fp-nav-badge{margin-left:auto;font-size:9px;background:rgba(255,71,87,.25);color:#ff4757;border-radius:10px;padding:1px 5px;font-family:'JetBrains Mono',monospace}
.fp-nav-badge.warn{background:rgba(255,165,0,.2);color:#ffa502}
.fp-nav-badge.ok{background:rgba(46,213,115,.15);color:#2ed573}
.fp-nav-sep{height:1px;background:rgba(0,255,170,.06);margin:6px 10px}

/* Main content zone */
.fp-main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.fp-topbar{display:flex;align-items:center;justify-content:space-between;padding:14px 20px 10px;border-bottom:1px solid rgba(0,255,170,.08);flex-shrink:0}
.fp-topbar-title{font-size:14px;font-weight:600;color:#e8e8f0;display:flex;align-items:center;gap:8px}
.fp-topbar-icon{font-size:16px}
.fp-topbar-actions{display:flex;gap:8px}
.fp-btn{background:rgba(0,255,170,.1);border:1px solid rgba(0,255,170,.2);border-radius:6px;padding:5px 12px;font-size:10px;cursor:pointer;color:#00ffcc;transition:all .15s;font-family:'JetBrains Mono',monospace}
.fp-btn:hover{background:rgba(0,255,170,.2);border-color:#00ffcc}
.fp-btn.secondary{background:rgba(124,92,252,.1);border-color:rgba(124,92,252,.25);color:#7c5cfc}
.fp-btn.secondary:hover{background:rgba(124,92,252,.2)}

/* Stats bar */
.fp-stats{display:flex;gap:10px;padding:12px 20px;border-bottom:1px solid rgba(0,255,170,.06);flex-shrink:0}
.fp-stat{flex:1;background:rgba(28,28,37,.6);border:1px solid rgba(0,255,170,.08);border-radius:8px;padding:8px 12px;text-align:center}
.fp-stat-val{font-size:18px;font-weight:700;font-family:'JetBrains Mono',monospace;color:#00ffcc;line-height:1}
.fp-stat-val.warn{color:#ffa502}.fp-stat-val.crit{color:#ff4757}.fp-stat-val.ok{color:#2ed573}
.fp-stat-label{font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:#6b6b80;margin-top:3px}

/* Search bar */
.fp-searchbar{padding:10px 20px;flex-shrink:0}
.fp-search{width:100%;background:rgba(0,0,0,.3);border:1px solid rgba(0,255,170,.15);border-radius:6px;padding:7px 12px;color:#e8e8f0;font-size:12px;font-family:'JetBrains Mono',monospace;outline:none;transition:border-color .15s}
.fp-search:focus{border-color:#00ffcc}
.fp-search::placeholder{color:#4a4a60}

/* Data table */
.fp-table-wrap{flex:1;overflow-y:auto;padding:0 20px 20px}
.fp-table-wrap::-webkit-scrollbar{width:3px}
.fp-table-wrap::-webkit-scrollbar-thumb{background:#00ffcc;border-radius:2px}
.fp-table{width:100%;border-collapse:collapse;font-size:11px}
.fp-table th{font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:#6b6b80;padding:8px 10px;text-align:left;border-bottom:1px solid rgba(0,255,170,.1);position:sticky;top:0;background:rgba(10,10,15,.95);backdrop-filter:blur(8px);font-weight:400}
.fp-table td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.03);color:#c0c0d0;vertical-align:middle;transition:background .1s}
.fp-table tr:hover td{background:rgba(0,255,170,.04)}
.fp-table tr{cursor:pointer}
.fp-badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:9px;font-family:'JetBrains Mono',monospace;font-weight:600;letter-spacing:.05em}
.fp-badge.active,.fp-badge.running,.fp-badge.ok,.fp-badge.success{background:rgba(46,213,115,.15);color:#2ed573}
.fp-badge.warn,.fp-badge.expiring,.fp-badge.warning{background:rgba(255,165,0,.15);color:#ffa502}
.fp-badge.crit,.fp-badge.error,.fp-badge.failed,.fp-badge.expired{background:rgba(255,71,87,.15);color:#ff4757}
.fp-badge.inactive{background:rgba(100,100,120,.2);color:#6b6b80}
.fp-pill{display:inline-flex;align-items:center;gap:3px;padding:1px 6px;border-radius:10px;font-size:9px;font-family:'JetBrains Mono',monospace;border:1px solid}
.fp-pill.php{background:rgba(124,92,252,.1);border-color:rgba(124,92,252,.3);color:#a080ff}
.fp-empty{padding:40px 20px;text-align:center;color:#4a4a60;font-size:12px}
.fp-empty-icon{font-size:28px;margin-bottom:8px}
.fp-row-action{float:right;background:rgba(0,255,170,.1);border:1px solid rgba(0,255,170,.2);border-radius:4px;padding:2px 7px;font-size:9px;cursor:pointer;color:#00ffcc;opacity:0;transition:opacity .15s;font-family:'JetBrains Mono',monospace}
.fp-table tr:hover .fp-row-action{opacity:1}
.fp-loading{padding:30px;text-align:center;color:#6b6b80;font-size:11px}
.fp-disk-bar{width:60px;height:4px;background:rgba(255,255,255,.1);border-radius:2px;display:inline-block;vertical-align:middle;overflow:hidden}
.fp-disk-bar-fill{height:100%;border-radius:2px;transition:width .3s}

/* ---- Statistiques FastPanel ---- */
.fp-stats-layout{flex:1;display:flex;flex-direction:column;overflow:hidden}
.fp-stats-header{display:flex;align-items:center;justify-content:space-between;padding:14px 20px 10px;border-bottom:1px solid rgba(0,255,170,.08);flex-shrink:0}
.fp-stats-title{font-size:14px;font-weight:600;color:#e8e8f0}
.fp-date-picker{background:rgba(0,0,0,.3);border:1px solid rgba(0,255,170,.2);border-radius:6px;padding:5px 10px;color:#e8e8f0;font-size:12px;font-family:'JetBrains Mono',monospace;outline:none;cursor:pointer}
.fp-date-picker::-webkit-calendar-picker-indicator{filter:invert(1) hue-rotate(140deg);cursor:pointer}
.fp-subtabs{display:flex;gap:2px;padding:0 20px;background:rgba(10,10,15,.5);border-bottom:1px solid rgba(0,255,170,.06);flex-shrink:0}
.fp-subtab{padding:8px 16px;font-size:11px;color:#6b6b80;cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;font-family:'JetBrains Mono',monospace;user-select:none}
.fp-subtab.active{color:#00ffcc;border-bottom-color:#00ffcc}
.fp-subtab:hover{color:#a0a0b0}
.fp-chart-area{flex:1;overflow-y:auto;padding:16px 20px 20px}
.fp-chart-area::-webkit-scrollbar{width:3px}
.fp-chart-area::-webkit-scrollbar-thumb{background:#00ffcc}
.fp-chart-block{background:rgba(17,17,24,.8);border:1px solid rgba(0,255,170,.1);border-radius:12px;padding:16px;margin-bottom:16px}
.fp-chart-block-title{font-size:11px;color:#00ffcc;font-family:'JetBrains Mono',monospace;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.fp-chart-container{position:relative;height:200px}
.fp-chart-legend{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}
.fp-legend-item{display:flex;align-items:center;gap:5px;font-size:10px;color:#a0a0b0;font-family:'JetBrains Mono',monospace}
.fp-legend-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.fp-realtime-badge{font-size:9px;background:rgba(0,255,170,.1);border:1px solid rgba(0,255,170,.2);border-radius:4px;padding:2px 6px;color:#00ffcc}
.fp-disk-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px}
.fp-disk-card{background:rgba(28,28,37,.6);border:1px solid rgba(0,255,170,.08);border-radius:8px;padding:12px}
.fp-disk-card-name{font-size:10px;font-family:'JetBrains Mono',monospace;color:#00ffcc;margin-bottom:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fp-disk-card-bar{height:6px;background:rgba(255,255,255,.1);border-radius:3px;overflow:hidden;margin-bottom:6px}
.fp-disk-card-fill{height:100%;border-radius:3px;transition:width .5s}
.fp-disk-card-stats{display:flex;justify-content:space-between;font-size:10px;color:#6b6b80}
.fp-mem-ring-wrap{display:flex;gap:16px;align-items:center;justify-content:center;padding:8px 0}
.fp-mem-detail{flex:1}
.fp-mem-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px}
.fp-mem-label{color:#6b6b80;font-family:'JetBrains Mono',monospace}
.fp-mem-value{color:#e8e8f0;font-family:'JetBrains Mono',monospace;font-weight:600}

</style>
</head>
<body>
<canvas id="particles-canvas"></canvas>
<div class="hex-grid"></div>

<div id="login-modal" class="login-modal">
  <div class="login-card">
    <h1>🔐 CASSANDRA v12.0</h1>
    <p>Stockage sécurisé, multi-serveur, tokens chiffrés.</p>
    <input type="password" id="login-password" placeholder="Mot de passe" onkeydown="if(event.key==='Enter')login()">
    <button onclick="login()">Se connecter</button>
    <div id="login-error" class="login-error"></div>
  </div>
</div>

<div id="audit-modal" class="audit-modal hidden">
  <div class="audit-card">
    <div class="audit-header">
      <h2>🔍 Rapport d'audit</h2>
      <button class="audit-close" onclick="closeAudit()">✕</button>
    </div>
    <div class="audit-body" id="audit-body"><div class="audit-loading"><div class="loader"></div> Analyse...</div></div>
  </div>
</div>

<div id="app-container" class="app-container hidden">
  <div class="header">
    <div><span class="logo">CASSANDRA</span><span class="logo-badge">v12.2 · stats FastPanel</span></div>
    <div class="status">
      <div class="status-dot"></div>
      <span id="status-text">ONLINE</span>
      <span class="session-time" id="session-time">0 min</span>
      <div class="service-btn-group">
        <button id="restart-collector-btn" class="service-btn" title="Redémarrer le collector">🔄 Collector</button>
        <button id="restart-agent-btn" class="service-btn warning" title="Redémarrer l'agent (⚠️ déconnexion)">⚠️ Agent</button>
      </div>
      <button id="expert-mode-btn" class="hdr-btn expert-btn">🔍 Mode normal</button>
      <button id="terminal-open-btn" class="hdr-btn" onclick="openTerminal()">⌨ Terminal</button>
      <button class="hdr-btn audit-btn" onclick="openAudit()">🔍 Audit</button>
      <button class="hdr-btn logout-btn" onclick="logout()">Déconnexion</button>
    </div>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('dashboard')">📊 Dashboard</div>
    <div class="tab" onclick="switchTab('history')">📈 Historique</div>
    <div class="tab" onclick="switchTab('fleet')">🌐 Flotte</div>
    <div class="tab" id="tab-fp-btn" onclick="switchTab('fastpanel')" style="display:none">🖥 FastPanel</div>
  </div>

  <div id="tab-dashboard" class="tab-content active">
    <div class="main-layout">
      <div class="panel panel-left">
        <div class="card"><div class="card-title">📊 MÉTRIQUES</div>
          <div class="metric-bar"><div class="metric-label"><span>CPU</span><span id="cpu-val">–</span></div><div class="bar-track"><div class="bar-fill cpu" id="cpu-bar"></div></div></div>
          <div class="metric-bar"><div class="metric-label"><span>RAM</span><span id="ram-val">–</span></div><div class="bar-track"><div class="bar-fill ram" id="ram-bar"></div></div></div>
          <div class="metric-bar"><div class="metric-label"><span>DISQUE</span><span id="disk-val">–</span></div><div class="bar-track"><div class="bar-fill disk" id="disk-bar"></div></div></div>
          <div class="metric-label"><span>LOAD</span><span id="load-val">–</span></div>
          <div class="chart-container"><canvas id="cpu-chart"></canvas></div>
        </div>
        <div class="card"><div class="card-title">💚 Fraîcheur</div><div class="score-ring"><div class="score-big" id="health-score">–</div><div><div id="health-status"></div><div id="health-details" style="font-size:10px;color:#6b6b80"></div></div></div></div>
        <div class="card"><div class="card-title">☁️ Tiroir cloud</div><div id="remotes-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">🔒 SSL <button class="fix-btn" onclick="sendQuickFix('Certificats SSL expirants ?')">🔧</button></div><div id="ssl-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">🦎 Tailscale</div><div id="tailscale-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">🚫 Fail2ban</div><div id="fail2ban-count">–</div></div>
        <div class="card" id="fp-summary-card" style="display:none">
          <div class="card-title">🖥 FastPanel <button class="fix-btn" onclick="switchTab('fastpanel')">→ Détails</button></div>
          <div class="fp-summary-cards" id="fp-summary-grid">
            <div class="fp-sc" onclick="switchTab('fastpanel');fpNav('domains')" title="Domaines hébergés">
              <div class="fp-sc-label">Domaines</div><div class="fp-sc-value" id="fps-domains">–</div>
            </div>
            <div class="fp-sc" onclick="switchTab('fastpanel');fpNav('services')" title="Services actifs">
              <div class="fp-sc-label">Services</div><div class="fp-sc-value" id="fps-services">–</div>
              <div class="fp-sc-sub" id="fps-services-sub"></div>
            </div>
            <div class="fp-sc" onclick="switchTab('fastpanel');fpNav('databases')" title="Bases de données">
              <div class="fp-sc-label">Bases DB</div><div class="fp-sc-value" id="fps-dbs">–</div>
            </div>
            <div class="fp-sc" onclick="switchTab('fastpanel');fpNav('mail')" title="Comptes mail">
              <div class="fp-sc-label">Comptes mail</div><div class="fp-sc-value" id="fps-mail">–</div>
            </div>
            <div class="fp-sc" onclick="switchTab('fastpanel');fpNav('backups')" title="Backups">
              <div class="fp-sc-label">Backups</div><div class="fp-sc-value" id="fps-backups">–</div>
              <div class="fp-sc-sub" id="fps-backups-sub"></div>
            </div>
            <div class="fp-sc" onclick="switchTab('fastpanel');fpNav('users')" title="Utilisateurs">
              <div class="fp-sc-label">Users</div><div class="fp-sc-value" id="fps-users">–</div>
            </div>
          </div>
        </div>
      </div>

      <div class="panel panel-center">
        <div class="chat-messages" id="chat-messages">
          <div class="message bot"><div class="message-bubble">👋 <strong>CASSANDRA v12.0</strong><br>Stockage sécurisé, multi-serveur, tokens chiffrés — je préviens avant que ça pète.</div></div>
        </div>
        <div class="chat-input-area">
          <textarea class="chat-input" id="chat-input" placeholder="Pose ta question… (Entrée)" rows="2"></textarea>
          <button class="send-btn" id="send-btn" onclick="sendMessage()">➤</button>
        </div>
      </div>

      <div class="panel panel-right">
        <div class="card"><div class="card-title">🔥 Top processus</div><div id="processes-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">⚠️ Failed <button class="fix-btn" onclick="sendQuickFix('Unités failed ?')">🔧</button></div><div id="failed-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">🌐 Sessions</div><div id="sessions-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">🔌 Ports</div><div id="ports-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">💀 OOM <button class="fix-btn" onclick="sendQuickFix('OOM récents ?')">🔧</button></div><div id="oom-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">🐳 Docker</div><div id="docker-list"><div class="empty-state">Chargement...</div></div></div>
      </div>
    </div>
  </div>


  <!-- ========== ONGLET FASTPANEL2 ========== -->
  <div id="tab-fastpanel" class="tab-content">
    <div class="fp-layout">

      <!-- Sidebar navigation -->
      <div class="fp-sidebar">
        <div class="fp-sidebar-header">
          <div class="fp-sidebar-title">FastPanel 2</div>
          <div class="fp-sidebar-sub">Panneau d'hébergement</div>
        </div>
        <nav class="fp-nav">
          <div class="fp-nav-item active" id="fpnav-hosting" onclick="fpNav('domains')">
            <span class="fp-nav-icon">🌐</span>Hébergement
            <span class="fp-nav-badge ok" id="fpbadge-domains">–</span>
          </div>
          <div class="fp-nav-item" id="fpnav-users" onclick="fpNav('users')">
            <span class="fp-nav-icon">👤</span>Utilisateurs
            <span class="fp-nav-badge ok" id="fpbadge-users">–</span>
          </div>
          <div class="fp-nav-sep"></div>
          <div class="fp-nav-item" id="fpnav-databases" onclick="fpNav('databases')">
            <span class="fp-nav-icon">🗄</span>Bases de données
            <span class="fp-nav-badge ok" id="fpbadge-databases">–</span>
          </div>
          <div class="fp-nav-item" id="fpnav-mail" onclick="fpNav('mail')">
            <span class="fp-nav-icon">📧</span>Mail
            <span class="fp-nav-badge ok" id="fpbadge-mail">–</span>
          </div>
          <div class="fp-nav-item" id="fpnav-ftp" onclick="fpNav('ftp')">
            <span class="fp-nav-icon">📁</span>FTP
            <span class="fp-nav-badge ok" id="fpbadge-ftp">–</span>
          </div>
          <div class="fp-nav-sep"></div>
          <div class="fp-nav-item" id="fpnav-backups" onclick="fpNav('backups')">
            <span class="fp-nav-icon">💾</span>Backups
            <span class="fp-nav-badge ok" id="fpbadge-backups">–</span>
          </div>
          <div class="fp-nav-item" id="fpnav-dns" onclick="fpNav('dns')">
            <span class="fp-nav-icon">🔗</span>DNS
            <span class="fp-nav-badge ok" id="fpbadge-dns">–</span>
          </div>
          <div class="fp-nav-item" id="fpnav-crons" onclick="fpNav('crons')">
            <span class="fp-nav-icon">⏱</span>Crons
            <span class="fp-nav-badge ok" id="fpbadge-crons">–</span>
          </div>
          <div class="fp-nav-sep"></div>
          <div class="fp-nav-item" id="fpnav-services" onclick="fpNav('services')">
            <span class="fp-nav-icon">⚙️</span>Services
            <span class="fp-nav-badge ok" id="fpbadge-services">–</span>
          </div>
          <div class="fp-nav-item" id="fpnav-php" onclick="fpNav('php')">
            <span class="fp-nav-icon">🐘</span>PHP
            <span class="fp-nav-badge ok" id="fpbadge-php">–</span>
          </div>
          <div class="fp-nav-sep"></div>
          <div class="fp-nav-item" id="fpnav-stats" onclick="fpNav('stats')">
            <span class="fp-nav-icon">📈</span>Statistiques
          </div>
        </nav>
      </div>

      <!-- Main content area -->
      <div class="fp-main" id="fp-main-area">
        <div class="fp-loading">Chargement de FastPanel…</div>
      </div>

    </div>
  </div>

  <div id="tab-fleet" class="tab-content">
    <div class="fleet-layout">
      <div class="fleet-header">
        <h2>🌐 FLOTTE CASSANDRA</h2>
        <div class="fleet-actions">
          <button class="fleet-add-btn" onclick="openFleetAdd()">+ Ajouter serveur</button>
          <button class="fleet-add-btn" onclick="refreshFleet()" style="background:rgba(124,92,252,.15);border-color:rgba(124,92,252,.3);color:#7c5cfc">↻ Actualiser</button>
        </div>
      </div>
      <div class="fleet-agg">
        <div class="fleet-agg-card"><div class="fleet-agg-label">Serveurs</div><div class="fleet-agg-value" id="fa-total">–</div></div>
        <div class="fleet-agg-card"><div class="fleet-agg-label">En ligne</div><div class="fleet-agg-value" id="fa-online">–</div></div>
        <div class="fleet-agg-card"><div class="fleet-agg-label">CPU moy.</div><div class="fleet-agg-value" id="fa-cpu">–</div></div>
        <div class="fleet-agg-card"><div class="fleet-agg-label">RAM moy.</div><div class="fleet-agg-value" id="fa-ram">–</div></div>
      </div>
      <div class="fleet-grid" id="fleet-grid"><div class="empty-state" style="padding:20px">Chargement de la flotte…</div></div>
    </div>
  </div>

  <div id="fleet-add-modal" class="fleet-add-modal hidden">
    <div class="fleet-add-card">
      <h2>+ Ajouter un serveur</h2>
      <div class="fleet-field"><label>Nom (identifiant unique)</label><input type="text" id="fa-name" placeholder="prod-01"></div>
      <div class="fleet-field"><label>URL de l'agent</label><input type="text" id="fa-url" placeholder="http://192.168.1.10:9000"></div>
      <div class="fleet-field"><label>Token de session</label><input type="password" id="fa-token" placeholder="Token obtenu après login"></div>
      <div class="fleet-add-actions">
        <button class="fleet-btn-cancel" onclick="closeFleetAdd()">Annuler</button>
        <button class="fleet-btn-primary" onclick="addFleetServer()">Ajouter</button>
      </div>
      <div id="fa-error" style="color:#ff4757;font-size:11px;margin-top:10px"></div>
    </div>
  </div>

  <div id="tab-history" class="tab-content">
    <div class="history-layout">
      <div class="history-controls"><span>Période :</span><button class="period-btn active" onclick="changePeriod('1h',this)">1h</button><button class="period-btn" onclick="changePeriod('24h',this)">24h</button><button class="period-btn" onclick="changePeriod('7d',this)">7j</button><span id="history-info"></span></div>
      <div class="history-charts">
        <div class="history-chart-card"><div class="history-chart-title">CPU</div><div class="history-chart-container"><canvas id="hist-cpu"></canvas></div></div>
        <div class="history-chart-card"><div class="history-chart-title">RAM</div><div class="history-chart-container"><canvas id="hist-ram"></canvas></div></div>
        <div class="history-chart-card"><div class="history-chart-title">Disque</div><div class="history-chart-container"><canvas id="hist-disk"></canvas></div></div>
        <div class="history-chart-card"><div class="history-chart-title">SWAP</div><div class="history-chart-container"><canvas id="hist-swap"></canvas></div></div>
      </div>
    </div>
  </div>
</div>

  <!-- TERMINAL CASSANDRA v12.0 -->
  <div id="terminal-overlay" class="terminal-overlay" onclick="closeTerminal()"></div>
  <div id="terminal-panel" class="terminal-panel">
    <div class="terminal-titlebar">
      <div class="terminal-title">
        <span class="tdot"></span>
        <span>CASSANDRA TERMINAL</span>
        <span class="terminal-status" id="term-status">root@local ▸ accès complet</span>
      </div>
      <div class="terminal-actions">
        <button class="terminal-btn" onclick="termClear()">⌫ Effacer</button>
        <button class="terminal-btn" id="term-kill-btn" onclick="termKill()" style="display:none;background:rgba(255,165,0,.15);border-color:rgba(255,165,0,.4);color:#ffa502">⏹ Stop</button>
        <button class="terminal-btn tbdanger" onclick="closeTerminal()">✕ Fermer</button>
      </div>
    </div>
    <div class="terminal-tab-bar" id="terminal-tab-bar">
      <div class="terminal-tab active" id="tab-label-0" onclick="switchTermTab(0)">bash <span class="terminal-tab-close" onclick="event.stopPropagation();closeTermTab(0)">×</span></div>
      <div class="terminal-new-tab" onclick="newTermTab()" title="Nouveau terminal">＋</div>
    </div>
    <div class="terminal-xterm-wrap" id="terminal-xterm-wrap"></div>
    <div class="terminal-input-row">
      <span class="terminal-prompt" id="term-prompt">root@cassandra:~#</span>
      <input class="terminal-cmd-input" id="terminal-input" type="text"
             placeholder="commande…  (Tab=complétion · ↑↓=historique · Ctrl+L=clear · Ctrl+C=stop)"
             autocomplete="off" autocorrect="off" spellcheck="false" autocapitalize="none"
             onkeydown="termKeyDown(event)">
      <button class="terminal-send-btn" id="term-send-btn" onclick="termSend()">▶</button>
    </div>
  </div>

<script>
let sessionId = sessionStorage.getItem('cassandra_session') || '';
let expertMode = localStorage.getItem('cassandra_expert_mode') === 'true';
let cpuChart = null, cpuHistory = [], ramHistory = [];
let isStreaming = false, sessionStart = Date.now();
let histCharts = {}, currentPeriod = '1h';

async function verifySession() {
    if (!sessionId) return false;
    try {
        const r = await fetch('/api/verify', { headers: { 'X-Session-Token': sessionId } });
        if (r.ok) return true;
        logout();
        return false;
    } catch(e) { logout(); return false; }
}

async function login() {
    const pwd = document.getElementById('login-password').value;
    const err = document.getElementById('login-error');
    err.textContent = '';
    try {
        const r = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pwd}) });
        const d = await r.json();
        if (d.success) {
            sessionId = d.session;
            sessionStorage.setItem('cassandra_session', sessionId);
            document.getElementById('login-modal').classList.add('hidden');
            document.getElementById('app-container').classList.remove('hidden');
            startApp();
        } else err.textContent = d.error || 'Mot de passe incorrect';
    } catch(e) { err.textContent = 'Erreur connexion'; }
}

function logout() {
    fetch('/api/logout', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId}) }).catch(()=>{});
    sessionStorage.removeItem('cassandra_session');
    sessionId = '';
    document.getElementById('login-modal').classList.remove('hidden');
    document.getElementById('app-container').classList.add('hidden');
}

function switchTab(name) {
    const tabs = ['dashboard','history','fleet','fastpanel'];
    document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active', tabs[i]===name));
    ['dashboard','history','fleet','fastpanel'].forEach(n=>{
        const el = document.getElementById('tab-'+n);
        if(el) el.classList.toggle('active', n===name);
    });
    if(name==='history')   loadHistoryCharts(currentPeriod);
    if(name==='fleet')     refreshFleet();
    if(name==='fastpanel') fpInit();
}

function toggleExpertMode() {
    expertMode = !expertMode;
    localStorage.setItem('cassandra_expert_mode', expertMode);
    const btn = document.getElementById('expert-mode-btn');
    btn.textContent = expertMode ? '🔬 Mode expert' : '🔍 Mode normal';
    btn.classList.toggle('active', expertMode);
    addSystemMessage(expertMode ? 'Mode expert activé.' : 'Mode normal.');
}

async function openAudit() {
    document.getElementById('audit-modal').classList.remove('hidden');
    document.getElementById('audit-body').innerHTML = '<div class="audit-loading"><div class="loader"></div> Analyse...</div>';
    try {
        const r = await fetch('/api/audit', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId}) });
        if(r.status===401){ logout(); return; }
        const d = await r.json();
        document.getElementById('audit-body').innerHTML = d.report || '<p>Erreur</p>';
    } catch(e){ document.getElementById('audit-body').innerHTML = `<p class="critical">Erreur: ${e.message}</p>`; }
}
function closeAudit(){ document.getElementById('audit-modal').classList.add('hidden'); }
function sendQuickFix(msg){ switchTab('dashboard'); document.getElementById('chat-input').value = msg; sendMessage(); }

async function loadHistoryCharts(period) {
    document.getElementById('history-info').textContent = 'Chargement...';
    try {
        const r = await fetch(`/api/metrics/history?period=${period}`, { headers: { 'X-Session-Token': sessionId } });
        if(r.status===401){ logout(); return; }
        const data = await r.json();
        const labels = data.map(d=>{let t=new Date(d.ts); return isNaN(t)?'':t.toLocaleTimeString('fr',{hour:'2-digit',minute:'2-digit'});});
        const build = (id,label,color,vals)=> {
            const ctx=document.getElementById(id).getContext('2d');
            if(histCharts[id]) histCharts[id].destroy();
            histCharts[id]=new Chart(ctx,{type:'line',data:{labels,datasets:[{label,data:vals,borderColor:color,backgroundColor:color.replace(')',',.1)'),fill:true,tension:0.3,pointRadius:0,borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#6b6b80',font:{size:9},maxTicksLimit:8}},y:{beginAtZero:true,max:100,ticks:{color:'#6b6b80',font:{size:9}}}}}});
        };
        build('hist-cpu','CPU %','rgb(0,255,204)',data.map(d=>Math.round(d.cpu_pct||0)));
        build('hist-ram','RAM %','rgb(124,92,252)',data.map(d=>Math.round(d.ram_pct||0)));
        build('hist-disk','Disk %','rgb(46,213,115)',data.map(d=>Math.round(d.disk_pct||0)));
        build('hist-swap','Swap %','rgb(255,165,0)',data.map(d=>Math.round(d.swap_pct||0)));
        document.getElementById('history-info').textContent = `${data.length} points · ${period}`;
    } catch(e){ document.getElementById('history-info').textContent = 'Erreur'; }
}

function changePeriod(period,btn){ currentPeriod=period; document.querySelectorAll('.period-btn').forEach(b=>b.classList.remove('active')); btn.classList.add('active'); loadHistoryCharts(period); }

async function apiGet(e){ const r=await fetch(e,{headers:{'X-Session-Token':sessionId}}); if(r.status===401){logout();throw new Error('401');} if(!r.ok)throw new Error(r.status); return r.json(); }
function escapeHtml(t){ if(t==null)return ''; return String(t).replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m])); }
function colorClass(p){ return p>85?'critical':p>70?'warning':'ok'; }

async function loadMetrics(){
    try{
        const d=await apiGet('/api/metrics');
        const cpu=Math.round(d.cpu||0), ram=Math.round(d.ram||0), disk=Math.round(d.disk||0);
        document.getElementById('cpu-val').textContent=cpu+'%'; document.getElementById('ram-val').textContent=ram+'%'; document.getElementById('disk-val').textContent=disk+'%';
        document.getElementById('cpu-bar').style.width=cpu+'%'; document.getElementById('ram-bar').style.width=ram+'%'; document.getElementById('disk-bar').style.width=disk+'%';
        document.getElementById('load-val').textContent=(d.load_1m||0)+' '+(d.load_5m||0)+' '+(d.load_15m||0);
        cpuHistory.push(cpu); ramHistory.push(ram);
        if(cpuHistory.length>60)cpuHistory.shift();
        if(ramHistory.length>60)ramHistory.shift();
        updateCharts();
    }catch(e){}
}
function initCharts(){
    const ctx=document.getElementById('cpu-chart').getContext('2d');
    cpuChart=new Chart(ctx,{type:'line',data:{labels:[],datasets:[{label:'CPU %',data:[],borderColor:'#00ffcc',backgroundColor:'rgba(0,255,204,.06)',fill:true,tension:0.4,pointRadius:0,borderWidth:2},{label:'RAM %',data:[],borderColor:'#7c5cfc',backgroundColor:'rgba(124,92,252,.06)',fill:true,tension:0.4,pointRadius:0,borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false}},scales:{x:{display:false},y:{beginAtZero:true,max:100,grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#6b6b80',font:{size:9}}}}}});
}
function updateCharts(){ if(!cpuChart)return; cpuChart.data.labels=cpuHistory.map((_,i)=>i); cpuChart.data.datasets[0].data=cpuHistory; cpuChart.data.datasets[1].data=ramHistory; cpuChart.update('none'); }

async function loadDashboard(){
    try{
        const d=await apiGet('/api/dashboard');
        const s=d.health_score||0;
        const el=document.getElementById('health-score');
        el.textContent=s+'/100';
        el.className='score-big '+(s>=90?'excellent':s>=75?'good':s>=50?'warning':'critical');
        document.getElementById('health-status').textContent=d.health_status||'unknown';
        document.getElementById('health-details').textContent=`${d.sites||0} sites · ${d.ssl_expiring||0} SSL · ${d.failed_units||0} failed`;
    }catch(e){}
}
async function loadRemotes(){ try{ const d=await apiGet('/api/remotes'); document.getElementById('remotes-list').innerHTML=d.length?d.map(r=>`<div class="remote-item"><span class="remote-name">${escapeHtml(r.name)}</span><span class="remote-type">${escapeHtml(r.type||'?')}</span></div>`).join(''):'<div class="empty-state">Aucun remote</div>'; }catch(e){} }
async function loadSSLCerts(){ try{ const d=await apiGet('/api/ssl'); document.getElementById('ssl-list').innerHTML=d.length?d.slice(0,10).map(c=>{const cls=c.days_left<=7?'critical':c.days_left<=30?'warning':'ok'; return `<div class="ssl-item"><span class="ssl-domain">${escapeHtml(c.domain)}</span><span class="ssl-days ${cls}">${c.days_left}j</span></div>`;}).join(''):'<div class="empty-state">Aucun certificat</div>'; }catch(e){} }
async function loadTailscale(){ try{ const d=await apiGet('/api/tailscale'); document.getElementById('tailscale-list').innerHTML=d.length?d.map(p=>`<div class="remote-item"><span class="remote-name">${escapeHtml(p.name||'?')}</span><span class="remote-type">${p.online?'🟢':'🔴'}</span></div>`).join(''):'<div class="empty-state">Aucun peer</div>'; }catch(e){} }
async function loadFail2ban(){ try{ const d=await apiGet('/api/fail2ban'); document.getElementById('fail2ban-count').textContent=d.length+' IP bannie'+(d.length>1?'s':''); }catch(e){} }
async function loadProcesses(){ try{ const d=await apiGet('/api/processes'); document.getElementById('processes-list').innerHTML=d.length?d.map(p=>`<div class="remote-item"><span class="remote-name">${escapeHtml(String(p.command||'?').substring(0,35))}</span><span class="remote-type ${colorClass(p.cpu||0)}">${p.cpu||0}%</span></div>`).join(''):'<div class="empty-state">Aucun processus</div>'; }catch(e){} }
async function loadSessions(){ try{ const d=await apiGet('/api/sessions'); document.getElementById('sessions-list').innerHTML=d.length?d.map(s=>`<div class="remote-item"><span class="remote-name">${escapeHtml(s.user||'?')}</span><span class="remote-type">${escapeHtml(s.ip||'local')}</span></div>`).join(''):'<div class="empty-state">Aucune session</div>'; }catch(e){} }
async function loadPorts(){ try{ const d=await apiGet('/api/ports'); document.getElementById('ports-list').innerHTML=d.length?d.slice(0,15).map(p=>`<div class="remote-item"><span class="remote-name">${p.port}/${escapeHtml(p.protocol||'?')}</span><span class="remote-type">${escapeHtml(p.process||'?')}</span></div>`).join(''):'<div class="empty-state">Aucun port</div>'; }catch(e){} }
async function loadOOM(){ try{ const d=await apiGet('/api/oom'); document.getElementById('oom-list').innerHTML=d.length?d.slice(0,5).map(o=>`<div class="remote-item"><span class="remote-name">${escapeHtml(o.killed_process||'?')}</span><span class="remote-type critical">${o.memory_used_mb||0}MB</span></div>`).join(''):'<div class="empty-state">Aucun OOM</div>'; }catch(e){} }
async function loadFailedUnits(){ try{ const d=await apiGet('/api/failed'); document.getElementById('failed-list').innerHTML=d.length?d.slice(0,5).map(f=>`<div class="remote-item"><span class="remote-name">${escapeHtml(f.unit||'?')}</span><span class="remote-type critical">failed</span></div>`).join(''):'<div class="empty-state">Aucune unité failed</div>'; }catch(e){} }
async function loadDocker(){ try{ const d=await apiGet('/api/docker'); document.getElementById('docker-list').innerHTML=d.length?d.slice(0,8).map(c=>`<div class="remote-item"><span class="remote-name">${escapeHtml(c.name||'?')}</span><span class="remote-type">${c.status && c.status.toLowerCase().includes('run')?'🟢':'🔴'}</span></div>`).join(''):'<div class="empty-state">Aucun container</div>'; }catch(e){} }

function addMessage(c,u=false){ const div=document.createElement('div'); div.className='message '+(u?'user':'bot'); div.innerHTML=`<div class="message-bubble">${c}</div>`; document.getElementById('chat-messages').appendChild(div); div.scrollIntoView({behavior:'smooth'}); return div; }
function addSystemMessage(m){ const div=document.createElement('div'); div.className='message bot'; div.innerHTML=`<div class="message-bubble" style="background:rgba(0,255,204,0.1);border-color:#00ffcc;">✨ ${m}</div>`; document.getElementById('chat-messages').appendChild(div); div.scrollIntoView({behavior:'smooth'}); }
function addTypingIndicator(){ const d=document.createElement('div'); d.className='message bot'; d.id='typing-indicator'; d.innerHTML='<div class="message-bubble"><div class="typing"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div></div>'; document.getElementById('chat-messages').appendChild(d); d.scrollIntoView({behavior:'smooth'}); }
function removeTypingIndicator(){ const t=document.getElementById('typing-indicator'); if(t)t.remove(); }
function formatResponse(t){
    let out=t.replace(/```bash\n([\s\S]*?)\n```/g,(_,code)=>{const safe=escapeHtml(code); const uid='r'+Date.now()+Math.random().toString(36).slice(2); return `<div class="command-block"><div class="command-header"><span>💻 ${safe}</span><button class="exec-btn" data-cmd="${safe}" onclick="executeCommandFromBtn(this)">▶ EXÉCUTER</button></div><div class="command-result" id="${uid}">En attente...</div></div>`;});
    out=out.replace(/^## (.+)$/gm,'<h2>$1</h2>').replace(/^### (.+)$/gm,'<h3>$1</h3>').replace(/^[•\-] (.+)$/gm,'<li>$1</li>').replace(/(<li>[\s\S]*?<\/li>)+/g,m=>'<ul>'+m+'</ul>');
    out=out.replace(/\b(\d{1,3})%/g,(m,p)=>{const pc=parseInt(p); if(pc>100)return m; const col=pc>85?'#ff4757':pc>70?'#ffa502':'#2ed573'; return `<span style="color:${col};font-weight:bold">${pc}%</span>`;});
    return out;
}
async function executeCommandFromBtn(btn){
    const cmd=btn.getAttribute('data-cmd');
    if(!cmd||!confirm('Exécuter :\n'+cmd+'\n\nConfirmer ?'))return;
    const block=btn.closest('.command-block');
    const rd=block?block.querySelector('.command-result'):null;
    if(rd)rd.innerHTML='<div class="loader"></div> Exécution...';
    try{
        const r=await fetch('/api/exec',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd,session:sessionId})});
        if(r.status===401){if(rd)rd.innerHTML='<span style="color:#ff4757">❌ Session expirée</span>';logout();return;}
        const d=await r.json();
        if(rd)rd.innerHTML=`<pre style="margin:0;font-size:10px;white-space:pre-wrap">${escapeHtml(d.output||'Aucune sortie')}</pre>`;
    }catch(e){if(rd)rd.innerHTML='<span style="color:#ff4757">❌ '+escapeHtml(e.message)+'</span>';}
}

async function sendMessage(){
    const input=document.getElementById('chat-input');
    const msg=input.value.trim();
    if(!msg||isStreaming)return;
    input.value=''; input.style.height='auto';
    document.getElementById('send-btn').disabled=true;
    addMessage(escapeHtml(msg),true);
    addTypingIndicator();
    isStreaming=true;
    try{
        const resp=await fetch('/api/chat/stream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg,session:sessionId,expert_mode:expertMode})});
        if(resp.status===401){ removeTypingIndicator(); addSystemMessage('Session expirée'); logout(); return; }
        removeTypingIndicator();
        const reader=resp.body.getReader();
        const decoder=new TextDecoder();
        let full='', msgDiv=null, buf='';
        while(true){
            const {done,value}=await reader.read();
            if(done)break;
            buf+=decoder.decode(value,{stream:true});
            const lines=buf.split('\n'); buf=lines.pop();
            for(const line of lines){
                if(!line.startsWith('data: '))continue;
                try{
                    const d=JSON.parse(line.slice(6));
                    if(d.done)break;
                    if(d.token){
                        full+=d.token;
                        if(!msgDiv){ const w=addMessage('',false); msgDiv=w.querySelector('.message-bubble'); }
                        msgDiv.innerHTML=formatResponse(full);
                        document.getElementById('chat-messages').scrollTop=document.getElementById('chat-messages').scrollHeight;
                    }
                }catch(_){}
            }
        }
    }catch(e){ removeTypingIndicator(); addMessage('<span style="color:#ff4757">❌ '+escapeHtml(e.message)+'</span>', false); }
    isStreaming=false;
    document.getElementById('send-btn').disabled=false;
}

function initParticles(){
    const c=document.getElementById('particles-canvas'), ctx=c.getContext('2d');
    c.width=window.innerWidth; c.height=window.innerHeight;
    const pts=Array.from({length:80},()=>({x:Math.random()*c.width,y:Math.random()*c.height,r:Math.random()*1.5+0.5,a:Math.random()*.4+.1,vx:(Math.random()-.5)*.4,vy:(Math.random()-.5)*.4}));
    function animate(){ ctx.clearRect(0,0,c.width,c.height); for(const p of pts){ p.x+=p.vx; p.y+=p.vy; if(p.x<0)p.x=c.width; if(p.x>c.width)p.x=0; if(p.y<0)p.y=c.height; if(p.y>c.height)p.y=0; ctx.beginPath(); ctx.arc(p.x,p.y,p.r,0,Math.PI*2); ctx.fillStyle=`rgba(0,255,204,${p.a})`; ctx.fill(); } requestAnimationFrame(animate); }
    animate();
    window.addEventListener('resize',()=>{ c.width=window.innerWidth; c.height=window.innerHeight; });
}

async function checkServicesStatus() {
    try {
        const r = await fetch('/api/service/status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session: sessionId })
        });
        if (r.status === 401) return;
        const d = await r.json();
        if (d.success) {
            const collectorBtn = document.getElementById('restart-collector-btn');
            const agentBtn = document.getElementById('restart-agent-btn');
            if (collectorBtn) {
                if (!d.status['cassandra-collector']) {
                    collectorBtn.style.opacity = '0.6';
                    collectorBtn.title = 'Collector arrêté - cliquer pour démarrer';
                } else {
                    collectorBtn.style.opacity = '1';
                    collectorBtn.title = 'Redémarrer le collector';
                }
            }
            if (agentBtn) {
                if (!d.status['cassandra']) {
                    agentBtn.style.opacity = '0.6';
                    agentBtn.title = 'Agent arrêté - cliquer pour démarrer';
                } else {
                    agentBtn.style.opacity = '1';
                    agentBtn.title = 'Redémarrer l\'agent (⚠️ déconnexion)';
                }
            }
        }
    } catch(e) { console.warn('Status check:', e.message); }
}

async function restartService(serviceName, requiresReconnect = false) {
    const adminPassword = prompt(
        `⚠️ ACTION ADMINISTRATIVE ⚠️\n\n` +
        `Vous allez redémarrer ${serviceName === 'collector' ? 'le Collector' : "l'Agent CASSANDRA"}.\n` +
        `${requiresReconnect ? '⚠️ ATTENTION : Vous serez déconnecté et devrez vous reconnecter.\n\n' : ''}` +
        `Entrez votre mot de passe administrateur pour confirmer :`
    );
    if (!adminPassword) return;
    const endpoint = serviceName === 'collector' ? '/api/service/restart/collector' : '/api/service/restart/agent';
    try {
        const r = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session: sessionId, admin_password: adminPassword })
        });
        const d = await r.json();
        if (r.status === 429) {
            addSystemMessage(`❌ Taux limité: ${d.error}`);
        } else if (r.status === 403) {
            addSystemMessage('❌ Mot de passe administrateur incorrect');
        } else if (r.status === 401) {
            addSystemMessage('❌ Session expirée, veuillez vous reconnecter');
            logout();
        } else if (d.success) {
            addSystemMessage(`✅ ${serviceName === 'collector' ? 'Collector' : 'Agent'} redémarré avec succès`);
            if (requiresReconnect) {
                setTimeout(() => {
                    addSystemMessage('⚠️ L\'agent va redémarrer. Vous allez être déconnecté...');
                    setTimeout(() => { logout(); }, 2000);
                }, 1000);
            } else {
                setTimeout(checkServicesStatus, 3000);
            }
        } else {
            addSystemMessage(`❌ Erreur: ${d.error || d.message || 'Inconnue'}`);
        }
    } catch(e) {
        addSystemMessage(`❌ Erreur réseau: ${e.message}`);
    }
}

function openFleetAdd(){ document.getElementById('fleet-add-modal').classList.remove('hidden'); document.getElementById('fa-name').focus(); document.getElementById('fa-error').textContent=''; }
function closeFleetAdd(){ document.getElementById('fleet-add-modal').classList.add('hidden'); }

async function addFleetServer(){
    const name=document.getElementById('fa-name').value.trim();
    const url=document.getElementById('fa-url').value.trim();
    const token=document.getElementById('fa-token').value.trim();
    const err=document.getElementById('fa-error');
    if(!name||!url||!token){ err.textContent='Tous les champs sont requis'; return; }
    try{
        const r=await fetch('/api/multiserver/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session:sessionId,name,url,token})});
        const d=await r.json();
        if(d.ok){ closeFleetAdd(); refreshFleet(); addSystemMessage('Serveur '+name+' ajouté à la flotte'); }
        else err.textContent=d.error||'Erreur inconnue';
    } catch(e){ err.textContent='Erreur réseau: '+e.message; }
}

async function removeFleetServer(name){
    if(!confirm('Supprimer le serveur "'+name+'" de la flotte ?'))return;
    try{
        const r=await fetch('/api/multiserver/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session:sessionId,name})});
        const d=await r.json();
        if(d.ok){ refreshFleet(); addSystemMessage('Serveur '+name+' retiré'); }
        else addSystemMessage('❌ '+d.error);
    } catch(e){ addSystemMessage('❌ '+e.message); }
}

async function refreshFleet(){
    const grid=document.getElementById('fleet-grid');
    grid.innerHTML='<div class="empty-state" style="padding:20px">Interrogation de la flotte…</div>';
    try{
        const r=await fetch('/api/multiserver/aggregate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session:sessionId})});
        if(r.status===401){ logout(); return; }
        const d=await r.json();
        document.getElementById('fa-total').textContent=d.total_servers||0;
        const onEl=document.getElementById('fa-online');
        onEl.textContent=d.online_servers||0;
        onEl.className='fleet-agg-value '+(d.offline_servers>0?'warning':'');
        const cpuEl=document.getElementById('fa-cpu');
        cpuEl.textContent=(d.avg_cpu||0)+'%';
        cpuEl.className='fleet-agg-value '+(d.avg_cpu>85?'critical':d.avg_cpu>70?'warning':'');
        const ramEl=document.getElementById('fa-ram');
        ramEl.textContent=(d.avg_ram||0)+'%';
        ramEl.className='fleet-agg-value '+(d.avg_ram>85?'critical':d.avg_ram>70?'warning':'');
        if(!d.nodes||d.nodes.length===0){
            grid.innerHTML='<div class="empty-state" style="padding:20px">Aucun serveur dans la flotte.<br>Ajoutez le premier avec le bouton ci-dessus.</div>';
            return;
        }
        grid.innerHTML=d.nodes.map(n=>{
            const isLocal=n.name==='local';
            const online=n.online;
            const cpu=n.cpu||0, ram=n.ram||0, disk=n.disk||0, health=n.health_score||0;
            const hEmoji=health>=90?'💚':health>=75?'💛':health>=50?'🧡':'❤️';
            const cc=v=>v>85?'#ff4757':v>70?'#ffa502':'#2ed573';
            const metricsHtml=online?`<div class="fleet-node-metrics">
                <div class="fleet-metric-mini"><div class="label">CPU</div><div class="val" style="color:${cc(cpu)}">${cpu}%</div></div>
                <div class="fleet-metric-mini"><div class="label">RAM</div><div class="val" style="color:${cc(ram)}">${ram}%</div></div>
                <div class="fleet-metric-mini"><div class="label">DISK</div><div class="val" style="color:${cc(disk)}">${disk}%</div></div>
            </div><div style="font-size:10px;color:#6b6b80">${hEmoji} Santé ${health}/100</div>`
            :n.error?`<div style="font-size:11px;color:#ff4757;margin:8px 0">❌ ${escapeHtml(n.error)}</div>`:'';
            const actionsHtml=isLocal?'<div style="font-size:10px;color:#6b6b80;margin-top:6px">Serveur local</div>':`<div class="fleet-node-actions"><button class="fleet-node-btn" onclick="sendQuickFix('Statut du serveur ${escapeHtml(n.name)}')">Analyser</button><button class="fleet-node-btn danger" onclick="removeFleetServer('${escapeHtml(n.name)}')">Retirer</button></div>`;
            return `<div class="fleet-node ${online?'':'offline'}"><div class="fleet-node-header"><span class="fleet-node-name">${isLocal?'★ ':''}${escapeHtml(n.name)}</span><span class="fleet-node-badge ${online?'online':'offline'}">${online?'● EN LIGNE':'○ HORS LIGNE'}</span></div>${!isLocal?`<div class="fleet-node-url">${escapeHtml(n.url||'')}</div>`:''}${metricsHtml}${actionsHtml}</div>`;
        }).join('');
    } catch(e){ grid.innerHTML=`<div style="color:#ff4757;padding:20px">❌ Erreur: ${escapeHtml(e.message)}</div>`; }
}

async function startApp(){
    initCharts(); initParticles();
    if(expertMode){ document.getElementById('expert-mode-btn').textContent='🔬 Mode expert'; document.getElementById('expert-mode-btn').classList.add('active'); }
    document.getElementById('expert-mode-btn').onclick=toggleExpertMode;
    const collectorBtn = document.getElementById('restart-collector-btn');
    const agentBtn = document.getElementById('restart-agent-btn');
    if (collectorBtn) collectorBtn.onclick = () => restartService('collector', false);
    if (agentBtn) agentBtn.onclick = () => restartService('agent', true);
    await Promise.allSettled([loadMetrics(), loadDashboard(), loadRemotes(), loadSSLCerts(), loadTailscale(), loadFail2ban(), loadProcesses(), loadSessions(), loadPorts(), loadOOM(), loadFailedUnits(), loadDocker(), fpLoadSummary()]);
    setInterval(loadMetrics,1000); setInterval(loadProcesses,2000); setInterval(loadSessions,2000); setInterval(loadDocker,5000); setInterval(loadTailscale,5000); setInterval(loadRemotes,10000); setInterval(loadFail2ban,10000); setInterval(loadDashboard,10000); setInterval(loadSSLCerts,30000); setInterval(loadPorts,30000); setInterval(loadOOM,30000); setInterval(loadFailedUnits,30000);
    setInterval(fpLoadSummary, 60000);
    setInterval(checkServicesStatus,30000);
    checkServicesStatus();
}

document.getElementById('chat-input').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault(); sendMessage();}});
document.getElementById('chat-input').addEventListener('input',function(){ this.style.height='auto'; this.style.height=Math.min(this.scrollHeight,100)+'px'; });


// ============================================================
// TERMINAL CASSANDRA v12.0 — xterm.js streaming
// ============================================================
let termTabs = [];
let termActiveTab = 0;
let termIsRunning = false;
let termAbortController = null;

const TERM_THEME = {
    background:'#0d0d14', foreground:'#e8e8f0', cursor:'#00ffcc',
    cursorAccent:'#0d0d14', selectionBackground:'rgba(0,255,170,.25)',
    black:'#1a1a2e', red:'#ff4757', green:'#2ed573', yellow:'#ffa502',
    blue:'#7c5cfc', magenta:'#ff6b9d', cyan:'#00ffcc', white:'#e8e8f0',
    brightBlack:'#4a4a6a', brightRed:'#ff6b7a', brightGreen:'#5df5a0',
    brightYellow:'#ffbf5c', brightBlue:'#a48dff', brightMagenta:'#ff9ec4',
    brightCyan:'#5fffd3', brightWhite:'#ffffff',
};

const TERM_COMPLETIONS = [
    'ls','ls -la','ls -lah','ls -ltr','cd','pwd','cat','head -n 50','tail -n 50','tail -f',
    'grep -r','grep -n','find / -name','find . -name',
    'ps aux','ps aux --sort=-%cpu | head -20','ps aux --sort=-%mem | head -20',
    'top -bn1 | head -30','df -h','df -ih','du -sh','du -sh /*','du -sh /var/*',
    'free -h','vmstat 1 5','iostat -x 1 3',
    'systemctl status','systemctl start','systemctl stop','systemctl restart','systemctl reload',
    'systemctl enable','systemctl disable','systemctl list-units --failed',
    'systemctl list-units --state=active','systemctl daemon-reload',
    'journalctl -xe','journalctl -u','journalctl -f','journalctl --since today',
    'journalctl --since "1 hour ago"',
    'docker ps','docker ps -a','docker stats --no-stream','docker logs --tail 100',
    'docker inspect','docker restart','docker stop','docker start','docker rm',
    'docker images','docker rmi','docker pull','docker exec -it',
    'docker-compose up -d','docker-compose down','docker-compose logs -f',
    'nginx -t','nginx -s reload','apache2ctl configtest','apache2ctl graceful',
    'ss -tulnp','netstat -tulnp','lsof -i','lsof -i :80','lsof -i :443',
    'iptables -L -n -v','iptables -S','ufw status verbose','ufw allow','ufw deny',
    'fail2ban-client status','fail2ban-client status sshd','fail2ban-client unban',
    'apt update','apt list --upgradable','apt upgrade -y','apt install',
    'apt-get autoremove -y','apt-get autoclean','dpkg -l',
    'uptime','hostname','whoami','id','uname -a','hostnamectl','timedatectl',
    'ip addr','ip route','ip neigh','ping -c4','traceroute','nslookup','dig',
    'certbot renew --dry-run','certbot renew','certbot certificates',
    'openssl x509 -in','openssl s_client -connect','openssl verify',
    'crontab -l','crontab -e','cat /etc/crontab',
    'mysql -u root -e','mysqldump','mysqlcheck','redis-cli info','redis-cli dbsize',
    'smartctl -H /dev/sda','smartctl -a /dev/sda','lsblk -f','fdisk -l',
    'mount','umount','blkid','fstrim -v /',
    'chmod 755','chown root:root','chattr +i','lsattr',
    'rclone lsd','rclone ls','rclone copy --progress','rclone sync --dry-run',
    'wg show','tailscale status','tailscale ping',
    'dmesg -T | tail -30','dmesg -T | grep -iE "error|warn|fail"',
    'last | head -20','lastb | head -20','who','w',
    'history','env','echo $PATH','cat /etc/os-release',
    'awk','sed','sort','uniq -c','wc -l','cut -d',
    'tar czf','tar xzf','zip -r','unzip',
    'wget','curl -I','curl -sL',
    'ssh','scp','rsync -avz',
    'htpasswd','openssl rand -hex 32',
    'kill -9','killall','pkill',
    'watch -n1','screen -ls','tmux ls',
];

function termWriteWelcome(term) {
    term.write('\x1b[1;36m╔══════════════════════════════════════════════════════════╗\r\n');
    term.write('\x1b[1;36m║\x1b[0m  \x1b[1;32mCASSANDRA v12.0\x1b[0m — Terminal interactif root              \x1b[1;36m║\r\n');
    term.write('\x1b[1;36m║\x1b[0m  \x1b[36mDrops complets · streaming · ↑↓ historique · Tab=complet\x1b[0m \x1b[1;36m║\r\n');
    term.write('\x1b[1;36m╚══════════════════════════════════════════════════════════╝\x1b[0m\r\n\r\n');
}

function createTermTab(label) {
    label = label || 'bash';
    const wrap = document.getElementById('terminal-xterm-wrap');
    const container = document.createElement('div');
    container.style.cssText = 'width:100%;height:100%;display:none';
    wrap.appendChild(container);

    const term = new Terminal({
        theme: TERM_THEME,
        fontFamily: "'JetBrains Mono','Fira Code','Cascadia Code',monospace",
        fontSize: 13, lineHeight: 1.4,
        cursorBlink: true, cursorStyle: 'block',
        scrollback: 8000, allowProposedApi: true,
    });

    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);
    setTimeout(() => { try { fitAddon.fit(); } catch(e){} }, 50);

    termWriteWelcome(term);

    const tab = { term, fitAddon, container, history: [], histIdx: -1, label };
    termTabs.push(tab);
    return termTabs.length - 1;
}

function switchTermTab(idx) {
    if (idx < 0 || idx >= termTabs.length) return;
    termTabs.forEach((t, i) => {
        t.container.style.display = i === idx ? 'block' : 'none';
        const el = document.getElementById('tab-label-' + i);
        if (el) el.classList.toggle('active', i === idx);
    });
    termActiveTab = idx;
    setTimeout(() => { try { termTabs[idx].fitAddon.fit(); } catch(e){} }, 20);
    document.getElementById('terminal-input').focus();
}

function newTermTab() {
    const n = termTabs.length;
    const idx = createTermTab('bash ' + (n + 1));
    const bar = document.getElementById('terminal-tab-bar');
    const el = document.createElement('div');
    el.className = 'terminal-tab';
    el.id = 'tab-label-' + idx;
    el.innerHTML = 'bash ' + (idx + 1) + ' <span class="terminal-tab-close" onclick="event.stopPropagation();closeTermTab(' + idx + ')">×</span>';
    el.onclick = (function(i){ return function(){ switchTermTab(i); }; })(idx);
    bar.insertBefore(el, bar.lastElementChild);
    switchTermTab(idx);
}

function closeTermTab(idx) {
    if (termTabs.length <= 1) { closeTerminal(); return; }
    termTabs[idx].container.remove();
    document.getElementById('tab-label-' + idx)?.remove();
    termTabs.splice(idx, 1);
    const newIdx = Math.max(0, idx - 1);
    termActiveTab = newIdx;
    switchTermTab(newIdx);
}

function openTerminal() {
    document.getElementById('terminal-panel').classList.add('open');
    document.getElementById('terminal-overlay').classList.add('open');
    if (termTabs.length === 0) { createTermTab('bash'); switchTermTab(0); }
    setTimeout(() => {
        try { termTabs[termActiveTab].fitAddon.fit(); } catch(e){}
        document.getElementById('terminal-input').focus();
    }, 320);
    // Mettre à jour le hostname dans la status bar
    fetch('/api/metrics', {headers:{'X-Session-Token':sessionId}}).then(r=>r.json()).then(d=>{
        if (d) document.getElementById('term-status').textContent = 'root@' + (window.location.hostname || 'cassandra') + ' ▸ accès complet';
    }).catch(()=>{});
}

function closeTerminal() {
    document.getElementById('terminal-panel').classList.remove('open');
    document.getElementById('terminal-overlay').classList.remove('open');
    if (termAbortController) { termAbortController.abort(); termAbortController = null; }
}

function termClear() {
    const tab = termTabs[termActiveTab];
    if (tab) { tab.term.clear(); }
}

function termKill() {
    if (termAbortController) { termAbortController.abort(); termAbortController = null; }
    const tab = termTabs[termActiveTab];
    if (tab) tab.term.write('\r\n\x1b[33m[^C — interrompu]\x1b[0m\r\n');
    termSetRunning(false);
}

function termSetRunning(running) {
    termIsRunning = running;
    const sendBtn = document.getElementById('term-send-btn');
    const killBtn = document.getElementById('term-kill-btn');
    const inp = document.getElementById('terminal-input');
    if (sendBtn) sendBtn.disabled = running;
    if (killBtn) killBtn.style.display = running ? 'flex' : 'none';
    if (inp) inp.disabled = running;
    if (!running) setTimeout(() => { try { document.getElementById('terminal-input').focus(); } catch(e){} }, 50);
}

async function termSend() {
    const input = document.getElementById('terminal-input');
    const cmd = input.value.trim();
    if (!cmd || termIsRunning) return;
    input.value = '';

    const tab = termTabs[termActiveTab];
    if (!tab) return;
    const { term } = tab;

    if (tab.history.length === 0 || tab.history[0] !== cmd) {
        tab.history.unshift(cmd);
        if (tab.history.length > 500) tab.history.pop();
    }
    tab.histIdx = -1;

    // Afficher la commande avec prompt coloré
    term.write('\x1b[1;32mroot@cassandra\x1b[0m\x1b[0;37m:\x1b[0m\x1b[1;34m~\x1b[0m\x1b[0;37m#\x1b[0m \x1b[1;37m' + cmd + '\x1b[0m\r\n');

    // Built-ins locaux
    if (cmd === 'clear' || cmd === 'cls') { termClear(); return; }
    if (cmd === 'exit' || cmd === 'quit') { closeTerminal(); return; }
    if (cmd === 'help' || cmd === '?') {
        term.write('\x1b[1;36mCASSANDRA Terminal — droits root complets\x1b[0m\r\n');
        term.write('  \x1b[36mTab\x1b[0m  autocomplétion sur ' + TERM_COMPLETIONS.length + ' commandes\r\n');
        term.write('  \x1b[36m↑↓\x1b[0m   historique (500 commandes)\r\n');
        term.write('  \x1b[36mCtrl+L\x1b[0m  effacer\r\n');
        term.write('  \x1b[36mCtrl+C\x1b[0m  arrêter la commande en cours\r\n');
        term.write('  \x1b[36mexit\x1b[0m   fermer le terminal\r\n\r\n');
        return;
    }

    termSetRunning(true);
    termAbortController = new AbortController();

    try {
        const resp = await fetch('/api/exec/stream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cmd, session: sessionId }),
            signal: termAbortController.signal,
        });

        if (resp.status === 401) {
            term.write('\x1b[31m[Session expirée]\x1b[0m\r\n');
            termSetRunning(false);
            logout();
            return;
        }

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += decoder.decode(value, { stream: true });
            const lines = buf.split('\n');
            buf = lines.pop();
            for (const line of lines) {
                if (!line.startsWith('data: ')) continue;
                const payload = line.slice(6).trim();
                if (payload === '"done"') { buf = ''; break; }
                try {
                    const d = JSON.parse(payload);
                    if (d.out) {
                        const text = d.out.replace(/\r?\n/g, '\r\n');
                        term.write(text);
                    }
                } catch(_) {}
            }
        }
    } catch(e) {
        if (e.name !== 'AbortError') {
            term.write('\x1b[31m[Erreur réseau: ' + e.message + ']\x1b[0m\r\n');
        }
    }

    term.write('\r\n');
    termSetRunning(false);
    termAbortController = null;
}

function termKeyDown(e) {
    const tab = termTabs[termActiveTab];
    if (!tab) return;
    const input = document.getElementById('terminal-input');

    if (e.key === 'Enter') {
        e.preventDefault(); termSend();
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (tab.histIdx < tab.history.length - 1) {
            tab.histIdx++;
            input.value = tab.history[tab.histIdx];
            setTimeout(() => { input.selectionStart = input.selectionEnd = input.value.length; }, 0);
        }
    } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (tab.histIdx > 0) { tab.histIdx--; input.value = tab.history[tab.histIdx]; }
        else { tab.histIdx = -1; input.value = ''; }
    } else if (e.key === 'Tab') {
        e.preventDefault(); termAutoComplete(input);
    } else if (e.key === 'l' && e.ctrlKey) {
        e.preventDefault(); termClear();
    } else if (e.key === 'c' && e.ctrlKey) {
        e.preventDefault(); if (termIsRunning) termKill();
    }
}

function termAutoComplete(input) {
    const val = input.value;
    if (!val) return;
    const matches = TERM_COMPLETIONS.filter(c => c.startsWith(val));
    if (matches.length === 1) {
        input.value = matches[0];
    } else if (matches.length > 1 && matches.length <= 20) {
        const tab = termTabs[termActiveTab];
        if (tab) {
            tab.term.write('\r\n');
            matches.forEach(m => tab.term.write('  \x1b[36m' + m + '\x1b[0m\r\n'));
        }
    }
}

// Resize observer
const _termResObs = new ResizeObserver(() => {
    if (termTabs[termActiveTab]) {
        try { termTabs[termActiveTab].fitAddon.fit(); } catch(e){}
    }
});
document.addEventListener('DOMContentLoaded', () => {
    const wrap = document.getElementById('terminal-xterm-wrap');
    if (wrap) _termResObs.observe(wrap);
});


// ============================================================
// FASTPANEL2 — UI Controller
// ============================================================
let _fpSection = 'domains';
let _fpData    = {};
let _fpInited  = false;

const FP_SECTIONS = {
    domains:   { title: '🌐 Hébergement', endpoint: '/api/fp/domains',   cols: ['domain','user','php_version','ssl_enabled','ssl_days_left','status'] },
    users:     { title: '👤 Utilisateurs', endpoint: '/api/fp/users',    cols: ['username','email','status','disk_quota_gb','disk_used_gb'] },
    databases: { title: '🗄 Bases de données', endpoint: '/api/fp/databases', cols: ['name','db_user','size_mb','db_type','owner'] },
    mail:      { title: '📧 Comptes Mail', endpoint: '/api/fp/mail',    cols: ['email','domain','quota_mb','used_mb','status'] },
    ftp:       { title: '📁 Comptes FTP', endpoint: '/api/fp/ftp',     cols: ['login','home_dir','status','owner'] },
    backups:   { title: '💾 Backups', endpoint: '/api/fp/backups',  cols: ['type','status','size_mb','created_at','user','error'] },
    dns:       { title: '🔗 Enregistrements DNS', endpoint: '/api/fp/dns', cols: ['zone','type','name','value','ttl'] },
    php:       { title: '🐘 Versions PHP', endpoint: '/api/fp/php',   cols: ['version','full_version','path','active'] },
    crons:     { title: '⏱ Tâches Cron', endpoint: '/api/fp/crons',  cols: ['user','schedule','command','enabled','last_run','last_status'] },
    services:  { title: '⚙️ Services', endpoint: '/api/fp/services', cols: ['name','status','version'] },
    stats:     { title: '📈 Statistiques', endpoint: null, cols: [] },
};

const FP_COL_LABELS = {
    domain:'Domaine', user:'Utilisateur', php_version:'PHP', ssl_enabled:'SSL',
    ssl_days_left:'SSL expire', status:'Statut', username:'Login', email:'Email',
    disk_quota_gb:'Quota GB', disk_used_gb:'Utilisé GB', name:'Nom', db_user:'User DB',
    size_mb:'Taille MB', db_type:'Type', owner:'Propriétaire', quota_mb:'Quota MB',
    used_mb:'Utilisé MB', login:'Login', home_dir:'Répertoire', type:'Type',
    created_at:'Date', error:'Erreur', zone:'Zone', value:'Valeur', ttl:'TTL',
    version:'Version', full_version:'Version complète', path:'Chemin', active:'Actif',
    schedule:'Planning', command:'Commande', enabled:'Activé',
    last_run:'Dernier run', last_status:'Dernier statut',
};

async function fpLoadSummary() {
    try {
        const d = await apiGet('/api/fp/summary');
        if (!d || typeof d !== 'object') return;
        // Cards résumé panel-left
        const card = document.getElementById('fp-summary-card');
        if (card) card.style.display = '';
        const fpTabBtn = document.getElementById('tab-fp-btn');
        if (fpTabBtn) fpTabBtn.style.display = '';
        document.getElementById('fps-domains').textContent  = d.domains_count  || 0;
        document.getElementById('fps-dbs').textContent      = d.databases_count || 0;
        document.getElementById('fps-mail').textContent     = d.mail_count      || 0;
        document.getElementById('fps-users').textContent    = d.users_count     || 0;
        const svcs = d.services_down || 0;
        const svcEl = document.getElementById('fps-services');
        svcEl.textContent = svcs === 0 ? '✓ OK' : svcs + ' ↓';
        svcEl.parentElement.className = 'fp-sc ' + (svcs > 0 ? 'crit' : 'ok');
        document.getElementById('fps-services-sub').textContent = svcs > 0 ? svcs + ' service(s) down' : 'Tous actifs';
        const bkFail = d.backups_failed || 0;
        document.getElementById('fps-backups').textContent = bkFail === 0 ? '✓ OK' : bkFail + ' ✗';
        document.getElementById('fps-backups-sub').textContent = bkFail > 0 ? bkFail + ' backup(s) en erreur' : '';
        document.getElementById('fps-backups').parentElement.className = 'fp-sc ' + (bkFail > 0 ? 'warn' : 'ok');
        // Badges sidebar
        document.getElementById('fpbadge-domains').textContent   = d.domains_count  || 0;
        document.getElementById('fpbadge-users').textContent     = d.users_count    || 0;
        document.getElementById('fpbadge-databases').textContent = d.databases_count || 0;
        document.getElementById('fpbadge-mail').textContent      = d.mail_count     || 0;
        if (d.services_down > 0) {
            const b = document.getElementById('fpbadge-services');
            b.textContent = d.services_down + ' ↓';
            b.className = 'fp-nav-badge';
        }
        if (d.backups_failed > 0) {
            const b = document.getElementById('fpbadge-backups');
            b.textContent = d.backups_failed + ' ✗';
            b.className = 'fp-nav-badge warn';
        }
    } catch(e) {}
}

async function fpInit() {
    if (!_fpInited) { _fpInited = true; await fpLoadSection(_fpSection); }
}

function fpNav(section) {
    _fpSection = section;
    document.querySelectorAll('.fp-nav-item').forEach(el => el.classList.remove('active'));
    const active = document.getElementById('fpnav-' + section);
    if (active) active.classList.add('active');
    fpLoadSection(section);
}

function fpRenderValue(key, val, row) {
    if (val === null || val === undefined || val === '') return '<span style="color:#4a4a60">–</span>';
    const s = String(val);
    // SSL status
    if (key === 'ssl_enabled') return val == 1 ? '<span class="fp-badge active">SSL ✓</span>' : '<span class="fp-badge inactive">non-SSL</span>';
    if (key === 'ssl_days_left') {
        if (!val || val <= 0) return '<span class="fp-badge crit">Expiré</span>';
        const cls = val <= 7 ? 'crit' : val <= 30 ? 'warn' : 'ok';
        return `<span class="fp-badge ${cls}">${val}j</span>`;
    }
    // Status badges
    if (key === 'status' || key === 'last_status') {
        const cls = ['active','running','ok','success','connected'].includes(s.toLowerCase()) ? 'active'
                  : ['error','failed','expired','critical'].includes(s.toLowerCase()) ? 'crit'
                  : ['expiring','warning','inactive'].includes(s.toLowerCase()) ? 'warn' : 'inactive';
        return `<span class="fp-badge ${cls}">${escapeHtml(s)}</span>`;
    }
    // Active (bool)
    if (key === 'active' || key === 'enabled') return val == 1 || val === true ? '<span class="fp-badge active">Oui</span>' : '<span class="fp-badge inactive">Non</span>';
    // PHP version pill
    if (key === 'php_version' && val && val !== 'unknown') return `<span class="fp-pill php">PHP ${escapeHtml(s)}</span>`;
    // Disk usage with bar
    if ((key === 'disk_used_gb' || key === 'used_mb') && row) {
        const used  = parseFloat(val) || 0;
        const quota = parseFloat(row.disk_quota_gb || row.quota_mb || 0);
        if (quota > 0) {
            const pct  = Math.min(100, Math.round(used / quota * 100));
            const col  = pct > 85 ? '#ff4757' : pct > 70 ? '#ffa502' : '#2ed573';
            return `<span style="color:${col}">${key==='size_mb'?used.toFixed(0)+' MB':used.toFixed(1)+' GB'}</span>
                    <div class="fp-disk-bar"><div class="fp-disk-bar-fill" style="width:${pct}%;background:${col}"></div></div>`;
        }
        return `<span>${key==='size_mb'?parseFloat(val).toFixed(0)+' MB':parseFloat(val).toFixed(2)+' GB'}</span>`;
    }
    if (key === 'size_mb') return `<span>${parseFloat(val).toFixed(0)} MB</span>`;
    if (key === 'disk_quota_gb') return `<span style="color:#6b6b80">${parseFloat(val).toFixed(1)} GB</span>`;
    if (key === 'disk_used_gb')  return `<span>${parseFloat(val).toFixed(2)} GB</span>`;
    if (key === 'quota_mb') return `<span style="color:#6b6b80">${parseFloat(val).toFixed(0)} MB</span>`;
    // Truncate long strings
    const maxlen = { command: 40, error: 35, path: 38, value: 38, home_dir: 35 };
    const max = maxlen[key] || 60;
    const display = s.length > max ? s.substring(0, max) + '…' : s;
    return escapeHtml(display);
}

function fpBuildAnalyzeMsg(section, row) {
    const name = row.domain || row.username || row.name || row.email || row.login || row.zone || row.service || '?';
    const msgs = {
        domains:   `Analyse le domaine FastPanel "${name}" : PHP ${row.php_version||'?'}, SSL ${row.ssl_days_left||0} jours`,
        users:     `Analyse l'utilisateur FastPanel "${name}" : ${row.disk_used_gb||0} GB utilisés sur ${row.disk_quota_gb||0} GB`,
        databases: `Analyse la base de données "${name}" (${row.size_mb||0} MB, user: ${row.db_user||'?'})`,
        mail:      `Analyse le compte mail "${name}" : ${row.used_mb||0}/${row.quota_mb||0} MB utilisés`,
        backups:   `Analyse le backup FastPanel : type "${row.type||'?'}", statut "${row.status||'?'}", ${row.size_mb||0} MB`,
        services:  `Analyse le service FastPanel "${name}" (statut: ${row.status||'?'})`,
        dns:       `Analyse l'enregistrement DNS : ${row.type||'?'} ${name} → ${row.value||'?'}`,
        crons:     `Analyse le cron FastPanel de "${row.user||'root'}" : ${row.schedule||'?'} → ${(row.command||'').substring(0,60)}`,
        ftp:       `Analyse le compte FTP "${name}" (répertoire: ${row.home_dir||'?'})`,
        php:       `Analyse la version PHP ${name} installée sur le serveur`,
    };
    return msgs[section] || `Analyse FastPanel : ${JSON.stringify(row)}`;
}

async function fpLoadSection(section) {
    if (section === 'stats') { fpLoadStats(); return; }
    const cfg = FP_SECTIONS[section];
    if (!cfg) return;
    const main = document.getElementById('fp-main-area');
    main.innerHTML = `<div class="fp-loading"><div class="loader"></div> Chargement ${cfg.title}…</div>`;
    try {
        const data = await apiGet(cfg.endpoint);
        _fpData[section] = Array.isArray(data) ? data : (data.data || []);
        fpRenderSection(section);
        const badge = document.getElementById('fpbadge-' + section);
        if (badge) badge.textContent = _fpData[section].length;
    } catch(e) {
        main.innerHTML = `<div class="fp-empty"><div class="fp-empty-icon">⚠️</div>Erreur de chargement<br><span style="font-size:10px;color:#4a4a60">${escapeHtml(e.message)}</span></div>`;
    }
}

function fpRenderSection(section) {
    const cfg  = FP_SECTIONS[section];
    const rows = _fpData[section] || [];
    const main = document.getElementById('fp-main-area');
    // Stats bar
    const stats = fpComputeStats(section, rows);
    let statsHtml = stats.map(s =>
        `<div class="fp-stat"><div class="fp-stat-val ${s.cls||''}">${escapeHtml(String(s.val))}</div><div class="fp-stat-label">${escapeHtml(s.label)}</div></div>`
    ).join('');
    // Quick actions
    const analyzeAll = `Analyse l'ensemble des ${cfg.title.replace(/[^\w\s]/g,'')} FastPanel et donne-moi les points d'attention`;
    // Table
    const cols = cfg.cols;
    let tableHtml = '';
    if (rows.length === 0) {
        tableHtml = `<div class="fp-empty"><div class="fp-empty-icon">📭</div>Aucune donnée disponible<br><span style="font-size:10px;color:#4a4a60">FastPanel non détecté ou section vide</span></div>`;
    } else {
        const header = cols.map(c => `<th>${FP_COL_LABELS[c]||c}</th>`).join('');
        const rowsHtml = rows.map(row => {
            const cells = cols.map(c => `<td>${fpRenderValue(c, row[c], row)}</td>`).join('');
            const msg = fpBuildAnalyzeMsg(section, row);
            return `<tr onclick="sendQuickFix(${JSON.stringify(msg)})">${cells}<td><span class="fp-row-action">Analyser ↗</span></td></tr>`;
        }).join('');
        tableHtml = `<div class="fp-table-wrap"><table class="fp-table"><thead><tr>${header}<th></th></tr></thead><tbody>${rowsHtml}</tbody></table></div>`;
    }
    main.innerHTML = `
        <div class="fp-topbar">
            <div class="fp-topbar-title"><span class="fp-topbar-icon">${cfg.title.substring(0,2)}</span>${cfg.title.substring(2)}</div>
            <div class="fp-topbar-actions">
                <button class="fp-btn" onclick="fpLoadSection('${section}')">↻ Actualiser</button>
                <button class="fp-btn secondary" onclick="switchTab('dashboard');sendQuickFix(${JSON.stringify(analyzeAll)})">💬 Analyser tout</button>
            </div>
        </div>
        ${stats.length ? `<div class="fp-stats">${statsHtml}</div>` : ''}
        <div class="fp-searchbar"><input class="fp-search" type="text" placeholder="Filtrer…" oninput="fpFilter('${section}',this.value)"></div>
        ${tableHtml}`;
}

function fpFilter(section, q) {
    const rows = _fpData[section] || [];
    const ql = q.toLowerCase();
    const filtered = q ? rows.filter(r => Object.values(r).some(v => String(v||'').toLowerCase().includes(ql))) : rows;
    const tbody = document.querySelector('#fp-main-area .fp-table tbody');
    if (!tbody) return;
    const cfg = FP_SECTIONS[section];
    tbody.innerHTML = filtered.map(row => {
        const cells = cfg.cols.map(c => `<td>${fpRenderValue(c, row[c], row)}</td>`).join('');
        const msg = fpBuildAnalyzeMsg(section, row);
        return `<tr onclick="sendQuickFix(${JSON.stringify(msg)})">${cells}<td><span class="fp-row-action">Analyser ↗</span></td></tr>`;
    }).join('');
}

function fpComputeStats(section, rows) {
    if (!rows.length) return [];
    switch(section) {
        case 'domains': {
            const ssl = rows.filter(r=>r.ssl_enabled==1).length;
            const exp = rows.filter(r=>r.ssl_days_left>0&&r.ssl_days_left<=30).length;
            const active = rows.filter(r=>r.status==='active').length;
            return [
                {val: rows.length, label:'Total'},
                {val: active, label:'Actifs', cls:'ok'},
                {val: ssl, label:'SSL actif', cls:'ok'},
                {val: exp, label:'SSL < 30j', cls: exp>0?'warn':'ok'},
            ];
        }
        case 'users': {
            const totalUsed = rows.reduce((s,r)=>s+(parseFloat(r.disk_used_gb)||0),0);
            const totalQuota = rows.reduce((s,r)=>s+(parseFloat(r.disk_quota_gb)||0),0);
            return [
                {val: rows.length, label:'Utilisateurs'},
                {val: totalUsed.toFixed(1)+' GB', label:'Espace utilisé'},
                {val: totalQuota.toFixed(0)+' GB', label:'Quota total'},
            ];
        }
        case 'databases': {
            const total = rows.reduce((s,r)=>s+(parseFloat(r.size_mb)||0),0);
            return [
                {val: rows.length, label:'Bases'},
                {val: (total/1024).toFixed(1)+' GB', label:'Taille totale'},
            ];
        }
        case 'mail': {
            const active = rows.filter(r=>r.status==='active').length;
            const totalUsed = rows.reduce((s,r)=>s+(parseFloat(r.used_mb)||0),0);
            return [
                {val: rows.length, label:'Comptes'},
                {val: active, label:'Actifs', cls:'ok'},
                {val: (totalUsed/1024).toFixed(1)+' GB', label:'Espace utilisé'},
            ];
        }
        case 'backups': {
            const ok  = rows.filter(r=>['success','ok','completed'].includes((r.status||'').toLowerCase())).length;
            const err = rows.filter(r=>['error','failed'].includes((r.status||'').toLowerCase())).length;
            return [
                {val: rows.length, label:'Total'},
                {val: ok, label:'Réussis', cls:'ok'},
                {val: err, label:'Échoués', cls: err>0?'crit':'ok'},
            ];
        }
        case 'services': {
            const up   = rows.filter(r=>['active','running'].includes((r.status||'').toLowerCase())).length;
            const down = rows.filter(r=>!['active','running','ok'].includes((r.status||'').toLowerCase())).length;
            return [
                {val: rows.length, label:'Services'},
                {val: up, label:'En ligne', cls:'ok'},
                {val: down, label:'Hors ligne', cls: down>0?'crit':'ok'},
            ];
        }
        case 'dns': {
            const zones = new Set(rows.map(r=>r.zone)).size;
            return [{val:rows.length,label:'Enregistrements'},{val:zones,label:'Zones'}];
        }
        case 'crons': {
            const active = rows.filter(r=>r.enabled==1||r.enabled===true).length;
            return [{val:rows.length,label:'Crons'},{val:active,label:'Actifs',cls:'ok'}];
        }
        default: return [{val: rows.length, label:'Entrées'}];
    }
}


// ============================================================
// FASTPANEL2 — STATISTIQUES (CPU breakdown, LA, mémoire, disque)
// ============================================================
let _fpStatsDate   = new Date().toISOString().slice(0,10);
let _fpStatsTab    = 'cpu';
let _fpStatsCharts = {};

const FP_PROCESS_COLORS = [
    '#00ffcc','#7c5cfc','#ffa502','#ff4757','#2ed573',
    '#1e90ff','#ff6b9d','#eccc68','#a29bfe','#fd9644',
    '#55efc4','#fdcb6e','#e17055','#74b9ff','#dfe6e9',
];

async function fpLoadStats(date) {
    if (date) _fpStatsDate = date;
    const main = document.getElementById('fp-main-area');

    main.innerHTML = `
    <div class="fp-stats-layout">
      <div class="fp-stats-header">
        <div class="fp-stats-title">📈 Statistiques système</div>
        <div style="display:flex;align-items:center;gap:10px">
          <span style="font-size:11px;color:#6b6b80">Date :</span>
          <input type="date" class="fp-date-picker" id="fp-stats-date"
                 value="${_fpStatsDate}" max="${new Date().toISOString().slice(0,10)}"
                 onchange="fpLoadStats(this.value)">
          <button class="fp-btn" onclick="fpLoadStats()">↻</button>
        </div>
      </div>
      <div class="fp-subtabs">
        <div class="fp-subtab ${_fpStatsTab==='cpu'?'active':''}" onclick="fpStatsTab('cpu')">Processeur</div>
        <div class="fp-subtab ${_fpStatsTab==='la'?'active':''}" onclick="fpStatsTab('la')">Load Average</div>
        <div class="fp-subtab ${_fpStatsTab==='memory'?'active':''}" onclick="fpStatsTab('memory')">Mémoire</div>
        <div class="fp-subtab ${_fpStatsTab==='disk'?'active':''}" onclick="fpStatsTab('disk')">Disque</div>
      </div>
      <div class="fp-chart-area" id="fp-chart-area">
        <div class="fp-loading"><div class="loader"></div> Chargement des statistiques…</div>
      </div>
    </div>`;

    // Détruire anciens charts
    Object.values(_fpStatsCharts).forEach(c => { try { c.destroy(); } catch(e){} });
    _fpStatsCharts = {};

    await fpRenderStatsTab(_fpStatsTab);
}

function fpStatsTab(tab) {
    _fpStatsTab = tab;
    document.querySelectorAll('.fp-subtab').forEach((el,i) => {
        el.classList.toggle('active', ['cpu','la','memory','disk'][i] === tab);
    });
    Object.values(_fpStatsCharts).forEach(c => { try { c.destroy(); } catch(e){} });
    _fpStatsCharts = {};
    fpRenderStatsTab(tab);
}

async function fpRenderStatsTab(tab) {
    const area = document.getElementById('fp-chart-area');
    if (!area) return;
    area.innerHTML = '<div class="fp-loading"><div class="loader"></div></div>';
    try {
        const data = await apiGet(`/api/fp/stats/${tab}`);
        switch(tab) {
            case 'cpu':    fpRenderCPU(data, area); break;
            case 'la':     fpRenderLA(data, area);  break;
            case 'memory': fpRenderMemory(data, area); break;
            case 'disk':   fpRenderDisk(data, area); break;
        }
    } catch(e) {
        area.innerHTML = `<div class="fp-empty"><div class="fp-empty-icon">⚠️</div>Impossible de charger les stats<br><span style="font-size:10px;color:#4a4a60">${escapeHtml(e.message)}</span><br><span style="font-size:10px;color:#4a4a60">Vérifiez que FastPanel2 est actif sur le port 8888</span></div>`;
    }
}

function fpNormalizeData(raw) {
    // Normalise les différentes structures de réponse FastPanel2
    if (!raw) return { source: 'unknown', items: [] };
    // Format API directe FastPanel2
    if (raw.status === 'ok' && raw.data) {
        if (Array.isArray(raw.data)) return { source: 'api', items: raw.data };
        if (raw.data.labels && raw.data.datasets)
            return { source: 'api_chart', labels: raw.data.labels, datasets: raw.data.datasets };
    }
    // Format fallback MySQL
    if (raw.source === 'mysql' && raw.data) return { source: 'mysql', items: raw.data };
    // Format fallback realtime
    if (raw.source === 'realtime' && raw.data) return { source: 'realtime', items: raw.data };
    // Format direct
    if (Array.isArray(raw)) return { source: 'array', items: raw };
    if (raw.data) return { source: 'data', items: Array.isArray(raw.data) ? raw.data : [raw.data] };
    return { source: 'raw', items: [raw] };
}

function fpRenderCPU(raw, area) {
    const d = fpNormalizeData(raw);
    area.innerHTML = '';

    // Si on a le format chart API directe avec breakdown par processus
    if (d.source === 'api_chart' && d.datasets) {
        const ds = d.datasets;
        const labels = d.labels || [];

        // Graphique 1 : CPU total (stacked area)
        const block1 = document.createElement('div');
        block1.className = 'fp-chart-block';
        const isRT = d.source === 'realtime';
        block1.innerHTML = `
            <div class="fp-chart-block-title">
                Charge du processeur
                ${isRT ? '<span class="fp-realtime-badge">⚡ Temps réel</span>' : ''}
            </div>
            <div class="fp-chart-container"><canvas id="fp-cpu-chart"></canvas></div>
            <div class="fp-chart-legend" id="fp-cpu-legend"></div>`;
        area.appendChild(block1);

        const procNames = Object.keys(ds.processes || {});
        const datasets_cfg = procNames.map((name, i) => ({
            label: name,
            data: ds.processes[name],
            backgroundColor: FP_PROCESS_COLORS[i % FP_PROCESS_COLORS.length] + '55',
            borderColor:     FP_PROCESS_COLORS[i % FP_PROCESS_COLORS.length],
            borderWidth: 1.5, fill: true, tension: 0.3, pointRadius: 0,
        }));
        // Ajouter "other" si total > somme processus
        if (ds.total) {
            datasets_cfg.unshift({
                label: 'Total', data: ds.total,
                backgroundColor: 'rgba(0,255,204,0.08)',
                borderColor: '#00ffcc', borderWidth: 2,
                fill: false, tension: 0.3, pointRadius: 0,
            });
        }

        const ctx = document.getElementById('fp-cpu-chart').getContext('2d');
        _fpStatsCharts['cpu'] = new Chart(ctx, {
            type: 'line',
            data: { labels, datasets: datasets_cfg },
            options: fpChartOptions('CPU %', 100),
        });

        // Légende colorée
        const legend = document.getElementById('fp-cpu-legend');
        datasets_cfg.forEach(ds => {
            const item = document.createElement('div');
            item.className = 'fp-legend-item';
            item.innerHTML = `<div class="fp-legend-dot" style="background:${ds.borderColor}"></div>${escapeHtml(ds.label)}`;
            legend.appendChild(item);
        });
        return;
    }

    // Format realtime (snapshot ps)
    if (d.source === 'realtime' && d.items.length > 0) {
        const snap = d.items[0];
        const procs = snap.processes || {};
        const sorted = Object.entries(procs).sort((a,b) => b[1]-a[1]).slice(0, 12);
        const total = sorted.reduce((s, [,v]) => s+v, 0);

        block_rt = document.createElement('div');
        block_rt.className = 'fp-chart-block';
        block_rt.innerHTML = `
            <div class="fp-chart-block-title">
                Processus actifs <span class="fp-realtime-badge">⚡ Snapshot actuel</span>
            </div>
            <div class="fp-chart-container" style="height:220px"><canvas id="fp-cpu-rt-chart"></canvas></div>`;
        area.appendChild(block_rt);

        const ctx = document.getElementById('fp-cpu-rt-chart').getContext('2d');
        _fpStatsCharts['cpu_rt'] = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: sorted.map(([n]) => n),
                datasets: [{
                    data: sorted.map(([,v]) => v.toFixed(1)),
                    backgroundColor: sorted.map((_, i) => FP_PROCESS_COLORS[i % FP_PROCESS_COLORS.length] + '99'),
                    borderColor:     sorted.map((_, i) => FP_PROCESS_COLORS[i % FP_PROCESS_COLORS.length]),
                    borderWidth: 1.5, borderRadius: 4,
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false, animation: false,
                plugins: { legend: { display: false },
                    tooltip: { callbacks: { label: ctx => ` ${ctx.parsed.y}% CPU` } } },
                scales: {
                    x: { ticks: { color: '#6b6b80', font: { size: 10 }, maxRotation: 30 }, grid: { color: 'rgba(255,255,255,.04)' } },
                    y: { beginAtZero: true, ticks: { color: '#6b6b80', font: { size: 10 }, callback: v => v+'%' }, grid: { color: 'rgba(255,255,255,.04)' } }
                }
            }
        });

        // Barre de total
        const info = document.createElement('div');
        info.className = 'fp-chart-block';
        info.innerHTML = `<div class="fp-chart-block-title">Utilisation totale mesurée : <span style="color:#00ffcc;font-size:14px">${total.toFixed(1)}%</span></div>
            <div style="font-size:10px;color:#6b6b80;margin-top:4px">API FastPanel2 non disponible — snapshot ps en temps réel. Démarrez fastpanel2 pour l'historique.</div>`;
        area.appendChild(info);
        return;
    }

    // Format MySQL rows
    if (d.items && d.items.length > 0 && d.items[0].ts) {
        fpRenderTimeseriesFromRows(area, d.items, 'cpu_total', 'CPU total %', '#00ffcc');
        return;
    }

    area.innerHTML = '<div class="fp-empty"><div class="fp-empty-icon">📭</div>Aucune donnée CPU disponible pour cette date</div>';
}

function fpRenderLA(raw, area) {
    const d = fpNormalizeData(raw);
    area.innerHTML = '';

    const block = document.createElement('div');
    block.className = 'fp-chart-block';
    block.innerHTML = `
        <div class="fp-chart-block-title">
            Load Average
            ${d.source === 'realtime' ? '<span class="fp-realtime-badge">⚡ Temps réel</span>' : ''}
        </div>
        <div class="fp-chart-container" style="height:220px"><canvas id="fp-la-chart"></canvas></div>
        <div class="fp-chart-legend">
          <div class="fp-legend-item"><div class="fp-legend-dot" style="background:#1e90ff"></div>LA1 (1 min)</div>
          <div class="fp-legend-item"><div class="fp-legend-dot" style="background:#00bcd4"></div>LA5 (5 min)</div>
          <div class="fp-legend-item"><div class="fp-legend-dot" style="background:#ff5722"></div>LA15 (15 min)</div>
        </div>`;
    area.appendChild(block);

    let labels = [], la1 = [], la5 = [], la15 = [];

    if (d.source === 'api_chart' && d.datasets) {
        labels = d.labels || [];
        la1    = d.datasets.la1  || [];
        la5    = d.datasets.la5  || [];
        la15   = d.datasets.la15 || [];
    } else if (d.items) {
        d.items.forEach(row => {
            labels.push(row.ts === 'now' ? 'Maintenant' : (row.ts||'').slice(11,16));
            la1.push(parseFloat(row.la1||0));
            la5.push(parseFloat(row.la5||0));
            la15.push(parseFloat(row.la15||0));
        });
    }

    const ctx = document.getElementById('fp-la-chart').getContext('2d');
    _fpStatsCharts['la'] = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                { label: 'LA1',  data: la1,  borderColor:'#1e90ff', backgroundColor:'rgba(30,144,255,.08)', fill:true, tension:0.4, pointRadius:0, borderWidth:2 },
                { label: 'LA5',  data: la5,  borderColor:'#00bcd4', backgroundColor:'rgba(0,188,212,.06)',  fill:true, tension:0.4, pointRadius:0, borderWidth:1.5 },
                { label: 'LA15', data: la15, borderColor:'#ff5722', backgroundColor:'rgba(255,87,34,.05)',  fill:true, tension:0.4, pointRadius:0, borderWidth:1.5 },
            ]
        },
        options: fpChartOptions('Load Average'),
    });
}

function fpRenderMemory(raw, area) {
    const d = fpNormalizeData(raw);
    area.innerHTML = '';

    // Bloc graphique temporal
    const block = document.createElement('div');
    block.className = 'fp-chart-block';
    block.innerHTML = `
        <div class="fp-chart-block-title">
            Utilisation mémoire
            ${d.source === 'realtime' ? '<span class="fp-realtime-badge">⚡ Temps réel</span>' : ''}
        </div>
        <div class="fp-chart-container" style="height:200px"><canvas id="fp-mem-chart"></canvas></div>`;
    area.appendChild(block);

    let labels = [], used = [], cached = [], free = [], total_mb = 0;

    if (d.source === 'api_chart' && d.datasets) {
        labels = d.labels || [];
        used   = d.datasets.used_mb   || d.datasets.used   || [];
        cached = d.datasets.cached_mb || d.datasets.cached || [];
        free   = d.datasets.free_mb   || d.datasets.free   || [];
    } else if (d.items) {
        d.items.forEach(row => {
            labels.push(row.ts === 'now' ? 'Maintenant' : (row.ts||'').slice(11,16));
            used.push(parseFloat(row.used_mb||row.used||0));
            cached.push(parseFloat(row.cached_mb||row.cached||0));
            free.push(parseFloat(row.free_mb||row.free||0));
            if (row.total_mb) total_mb = parseFloat(row.total_mb);
        });
    }

    const ctx = document.getElementById('fp-mem-chart').getContext('2d');
    _fpStatsCharts['mem'] = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                { label: 'Utilisée (MB)', data: used,   borderColor:'#ff4757', backgroundColor:'rgba(255,71,87,.12)', fill:true, tension:0.3, pointRadius:0, borderWidth:2 },
                { label: 'Cache (MB)',    data: cached, borderColor:'#ffa502', backgroundColor:'rgba(255,165,0,.08)',  fill:true, tension:0.3, pointRadius:0, borderWidth:1.5 },
                { label: 'Libre (MB)',    data: free,   borderColor:'#2ed573', backgroundColor:'rgba(46,213,115,.06)', fill:true, tension:0.3, pointRadius:0, borderWidth:1.5 },
            ]
        },
        options: fpChartOptions('MB'),
    });

    // Bloc détail actuel si realtime
    if (d.source === 'realtime' && d.items.length > 0) {
        const r = d.items[0];
        const tot = parseFloat(r.total_mb||0);
        const us  = parseFloat(r.used_mb||0);
        const ca  = parseFloat(r.cached_mb||0);
        const fr  = parseFloat(r.free_mb||0);
        const pct = tot > 0 ? Math.round(us/tot*100) : 0;
        const col = pct > 85 ? '#ff4757' : pct > 70 ? '#ffa502' : '#2ed573';

        const block2 = document.createElement('div');
        block2.className = 'fp-chart-block';
        block2.innerHTML = `
            <div class="fp-chart-block-title">État actuel</div>
            <div class="fp-mem-ring-wrap">
              <div style="text-align:center;flex-shrink:0">
                <div style="font-size:32px;font-weight:700;font-family:'JetBrains Mono',monospace;color:${col}">${pct}%</div>
                <div style="font-size:10px;color:#6b6b80;margin-top:4px">${us.toFixed(0)} / ${tot.toFixed(0)} MB</div>
              </div>
              <div class="fp-mem-detail">
                <div class="fp-mem-row"><span class="fp-mem-label">Totale</span><span class="fp-mem-value">${(tot/1024).toFixed(1)} GB</span></div>
                <div class="fp-mem-row"><span class="fp-mem-label">Utilisée</span><span class="fp-mem-value" style="color:${col}">${us.toFixed(0)} MB</span></div>
                <div class="fp-mem-row"><span class="fp-mem-label">Cache</span><span class="fp-mem-value" style="color:#ffa502">${ca.toFixed(0)} MB</span></div>
                <div class="fp-mem-row"><span class="fp-mem-label">Libre</span><span class="fp-mem-value" style="color:#2ed573">${fr.toFixed(0)} MB</span></div>
              </div>
            </div>`;
        area.appendChild(block2);
    }
}

function fpRenderDisk(raw, area) {
    const d = fpNormalizeData(raw);
    area.innerHTML = '';

    if (d.source === 'api_chart' && d.labels) {
        // Historique I/O
        const block = document.createElement('div');
        block.className = 'fp-chart-block';
        block.innerHTML = `<div class="fp-chart-block-title">I/O Disque</div>
            <div class="fp-chart-container" style="height:200px"><canvas id="fp-disk-io-chart"></canvas></div>`;
        area.appendChild(block);
        const ds = d.datasets || {};
        const ctx = document.getElementById('fp-disk-io-chart').getContext('2d');
        _fpStatsCharts['disk_io'] = new Chart(ctx, {
            type: 'line',
            data: {
                labels: d.labels,
                datasets: [
                    { label: 'Lecture MB', data: ds.read_mb||[], borderColor:'#2ed573', backgroundColor:'rgba(46,213,115,.08)', fill:true, tension:0.3, pointRadius:0, borderWidth:2 },
                    { label: 'Écriture MB', data: ds.write_mb||[], borderColor:'#ff4757', backgroundColor:'rgba(255,71,87,.08)', fill:true, tension:0.3, pointRadius:0, borderWidth:2 },
                ]
            },
            options: fpChartOptions('MB/s'),
        });
        return;
    }

    // Format realtime df
    if (d.items && d.items.length > 0 && d.items[0].pct !== undefined) {
        const block = document.createElement('div');
        block.className = 'fp-chart-block';
        block.innerHTML = `
            <div class="fp-chart-block-title">Utilisation disques <span class="fp-realtime-badge">⚡ Temps réel</span></div>
            <div class="fp-disk-grid" id="fp-disk-grid"></div>`;
        area.appendChild(block);

        const grid = document.getElementById('fp-disk-grid');
        d.items.forEach(disk => {
            const pct = parseInt((disk.pct||'0%').replace('%','')) || 0;
            const col = pct > 85 ? '#ff4757' : pct > 70 ? '#ffa502' : '#2ed573';
            const card = document.createElement('div');
            card.className = 'fp-disk-card';
            card.innerHTML = `
                <div class="fp-disk-card-name" title="${escapeHtml(disk.device)}">${escapeHtml(disk.mount||disk.device)}</div>
                <div style="font-size:9px;color:#4a4a60;margin-bottom:6px;font-family:'JetBrains Mono',monospace">${escapeHtml(disk.device)}</div>
                <div class="fp-disk-card-bar"><div class="fp-disk-card-fill" style="width:${pct}%;background:${col}"></div></div>
                <div class="fp-disk-card-stats">
                    <span>${escapeHtml(disk.used||'–')} utilisés</span>
                    <span style="color:${col};font-weight:700">${pct}%</span>
                    <span style="color:#6b6b80">${escapeHtml(disk.total||'–')}</span>
                </div>`;
            grid.appendChild(card);
        });
        return;
    }

    area.innerHTML = '<div class="fp-empty"><div class="fp-empty-icon">💽</div>Aucune donnée disque disponible</div>';
}

function fpRenderTimeseriesFromRows(area, rows, key, label, color) {
    const block = document.createElement('div');
    block.className = 'fp-chart-block';
    block.innerHTML = `<div class="fp-chart-block-title">${escapeHtml(label)}</div>
        <div class="fp-chart-container"><canvas id="fp-ts-chart"></canvas></div>`;
    area.appendChild(block);
    const labels = rows.map(r => (r.ts||'').slice(11,16));
    const data   = rows.map(r => parseFloat(r[key]||0));
    const ctx = document.getElementById('fp-ts-chart').getContext('2d');
    _fpStatsCharts['ts'] = new Chart(ctx, {
        type: 'line',
        data: { labels, datasets: [{ label, data, borderColor: color,
            backgroundColor: color+'15', fill: true, tension: 0.3,
            pointRadius: 0, borderWidth: 2 }] },
        options: fpChartOptions(label),
    });
}

function fpChartOptions(yLabel, max) {
    return {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: 'rgba(17,17,24,.95)',
                borderColor: 'rgba(0,255,170,.3)', borderWidth: 1,
                titleColor: '#00ffcc', bodyColor: '#a0a0b0',
                padding: 10,
            },
        },
        scales: {
            x: {
                ticks: { color:'#6b6b80', font:{ size:9 }, maxTicksLimit: 12, maxRotation: 0 },
                grid: { color:'rgba(255,255,255,.03)' },
            },
            y: {
                beginAtZero: true,
                ...(max ? { max } : {}),
                ticks: { color:'#6b6b80', font:{ size:9 }, callback: v => v + (yLabel.includes('%') || yLabel==='CPU %' ? '%' : '') },
                grid: { color:'rgba(255,255,255,.04)' },
            }
        }
    };
}

if(sessionId){ verifySession().then(valid=>{ if(valid){ document.getElementById('login-modal').classList.add('hidden'); document.getElementById('app-container').classList.remove('hidden'); startApp(); } }); }
</script>
</body>
</html>'''

# ============================================================
# 18. DÉMARRAGE
# ============================================================
if __name__ == "__main__":
    init_admin_log()
    init_memory_db()

    if not os.path.exists('/dev/shm'):
        os.makedirs('/dev/shm', exist_ok=True)

    ms_migrate_plaintext_tokens()

    if not os.path.exists(SECURE_KEY_FILE):
        print(f"\n[!] FICHIER DE CLÉ MANQUANT")
        print(f"[!] Créez-le avec :")
        print(f"    mkdir -p {os.path.dirname(SECURE_KEY_FILE)}")
        print(f"    echo 'sk-votre-cle-ici' > {SECURE_KEY_FILE}")
        print(f"    chmod 600 {SECURE_KEY_FILE}")
        print(f"    chattr +i {SECURE_KEY_FILE}\n")

    test = get_metrics_from_socket()
    if test:
        print("[SOCKET] ✅ Connecté au collector")
    else:
        print("[SOCKET] ⚠️ Socket indisponible, fallback DB")

    server = ThreadedHTTPServer(("0.0.0.0", PORT), CassandraHandler)
    print(f"\n{'='*60}")
    print(f"  CASSANDRA v12.0 — IA souveraine (terminal intégré + bugfixes)")
    print(f"  Port    : {PORT}")
    print(f"  URL     : http://localhost:{PORT}")
    print(f"  DeepSeek: {'✅ OK' if DEEPSEEK_API_KEY else '❌ MANQUANTE'}")
    print(f"  Stockage: {SECURE_KEY_FILE}")
    print(f"  Cache   : /dev/shm/.cassandra_deepseek_key (RAM)")
    print(f"  Admin   : {ADMIN_LOG_FILE}")
    print(f"  Rate limit: {RATE_LIMIT_MAX_ACTIONS} actions/heure")
    print(f"  Multi-server: {MULTISERVER_CONFIG_FILE} (tokens chiffrés)")
    print(f"{'='*60}")
    print(f"  CORRECTIFS v11.1:")
    print(f"  [S1] Tokens distants chiffrés au repos (Fernet/AES-256)")
    print(f"  [S2] Migration transparente des configs héritées au démarrage")
    print(f"  [S3] multiserver.json chmod 0o600 à chaque écriture")
    print(f"{'='*60}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Arrêt de CASSANDRA...")
        server.shutdown()