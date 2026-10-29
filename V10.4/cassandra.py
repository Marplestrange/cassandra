#!/usr/bin/env python3
"""
CASSANDRA v10.4 — Agent unifié (SÉCURITÉ RENFORCÉE + ADMIN)
============================================================
CORRECTIFS v10.4 :
  [A1] Endpoints admin : restart collector, restart agent, status services
  [A2] Rate limiting : 5 actions administratives par heure max
  [A3] Logging étendu : toutes les actions admin sont loggées
  [A4] Interface : boutons de contrôle des services (dashboard)

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
RATE_LIMIT_MAX_ACTIONS = 5  # 5 actions par intervalle
RATE_LIMIT_INTERVAL = 3600  # 1 heure
_admin_action_log: dict = {}  # {session_id: [timestamps]}
_admin_action_lock = threading.Lock()

# [A3] Logging étendu
ADMIN_LOG_FILE = "/var/log/cassandra_admin.log"

# ============================================================
# 2. FONCTIONS ADMIN (rate limiting + logging)
# ============================================================

def init_admin_log():
    """Initialise le fichier de log admin"""
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
    """Enregistre une action admin dans le fichier de log"""
    try:
        with open(ADMIN_LOG_FILE, 'a') as f:
            timestamp = datetime.now().isoformat()
            f.write(f"[{timestamp}] session={session_id[:8]} action={action} result={result} {details}\n")
    except Exception as e:
        print(f"[ADMIN] Erreur log: {e}", file=sys.stderr)


def check_rate_limit(session_id: str) -> tuple:
    """
    Vérifie le rate limiting pour une session.
    Retourne (is_allowed, remaining_actions, wait_seconds)
    """
    now = time.time()
    with _admin_action_lock:
        if session_id not in _admin_action_log:
            _admin_action_log[session_id] = []
        
        # Nettoyer les actions anciennes
        old_actions = [ts for ts in _admin_action_log[session_id] if now - ts < RATE_LIMIT_INTERVAL]
        _admin_action_log[session_id] = old_actions
        
        allowed = len(old_actions) < RATE_LIMIT_MAX_ACTIONS
        remaining = max(0, RATE_LIMIT_MAX_ACTIONS - len(old_actions))
        wait_seconds = 0
        if not allowed and old_actions:
            oldest = min(old_actions)
            wait_seconds = int(RATE_LIMIT_INTERVAL - (now - oldest))
        
        return allowed, remaining, wait_seconds


def record_admin_action(session_id: str) -> None:
    """Enregistre une action admin pour le rate limiting"""
    now = time.time()
    with _admin_action_lock:
        if session_id not in _admin_action_log:
            _admin_action_log[session_id] = []
        _admin_action_log[session_id].append(now)


# ============================================================
# 3. CHARGEMENT SÉCURISÉ DE LA CLÉ API (avec auto chattr +i)
# ============================================================

def _apply_chattr_if_needed(filepath: str) -> tuple:
    """
    Vérifie et applique chattr +i sur le fichier.
    Retourne (success, message, is_critical)
    """
    test_file = "/tmp/.cassandra_chattr_test"
    
    try:
        # Vérifier si chattr est disponible
        which_result = subprocess.run(["which", "chattr"], capture_output=True, text=True, timeout=2)
        if which_result.returncode != 0:
            return (False, "chattr non disponible (commande introuvable)", False)
        
        # Vérifier si le système supporte les attributs étendus
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
            return (False, "chattr présent mais FS ne supporte pas les attributs étendus", True)
        
        if not os.path.exists(filepath):
            return (False, f"fichier {filepath} n'existe pas", True)
        
        lsattr_result = subprocess.run(["lsattr", filepath], capture_output=True, text=True, timeout=2)
        if lsattr_result.returncode != 0:
            return (False, f"lsattr a échoué: {lsattr_result.stderr.strip()}", True)
        
        attrs = lsattr_result.stdout.split()[0] if lsattr_result.stdout.split() else ""
        if 'i' in attrs:
            return (True, "déjà protégé (chattr +i présent)", False)
        
        chattr_result = subprocess.run(["chattr", "+i", filepath], capture_output=True, text=True, timeout=2)
        if chattr_result.returncode != 0:
            return (False, f"chattr +i a échoué: {chattr_result.stderr.strip()}", True)
        
        return (True, "protégé (chattr +i appliqué)", False)
    except FileNotFoundError:
        return (False, "chattr/lsattr non trouvés (système minimal)", True)
    except subprocess.TimeoutExpired:
        return (False, "timeout sur chattr/lsattr", True)
    except Exception as e:
        return (False, f"erreur inattendue: {e}", True)
    finally:
        try:
            if os.path.exists(test_file):
                subprocess.run(["chattr", "-i", test_file], capture_output=True, timeout=2)
                os.remove(test_file)
        except Exception:
            pass


def _remove_chattr_if_needed(filepath: str) -> bool:
    """Retire l'attribut immutable si présent"""
    try:
        lsattr_result = subprocess.run(["lsattr", filepath], capture_output=True, text=True, timeout=2)
        if lsattr_result.returncode == 0 and 'i' in (lsattr_result.stdout.split()[0] if lsattr_result.stdout.split() else ''):
            subprocess.run(["chattr", "-i", filepath], capture_output=True, timeout=2)
        return True
    except Exception:
        return False


def ensure_secure_key_file():
    """Vérifie que le fichier de clé existe, le crée avec les bonnes permissions et chattr +i"""
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
        print(f"[API] ⚠️  VEUILLEZ AJOUTER VOTRE CLÉ DANS CE FICHIER")
        file_created = True
    else:
        stat_info = os.stat(SECURE_KEY_FILE)
        if stat_info.st_mode & 0o777 != 0o600:
            os.chmod(SECURE_KEY_FILE, 0o600)
            print(f"[API] 🔧 Permissions corrigées sur {SECURE_KEY_FILE}")
    
    chattr_ok, chattr_msg, chattr_critical = _apply_chattr_if_needed(SECURE_KEY_FILE)
    if chattr_ok:
        print(f"[API] 🔒 {chattr_msg}")
    else:
        print(f"[API] ⚠️  {chattr_msg}")
        if chattr_critical:
            print(f"[API] ⚠️⚠️⚠️ ALERTE SÉCURITÉ : Le fichier clé N'EST PAS protégé contre les modifications !")
            print(f"[API] ⚠️⚠️⚠️ Si possible, déplacez la clé vers un système avec support chattr.")
    
    return not file_created


def get_deepseek_key() -> str:
    """Récupère la clé DeepSeek - stockée en RAM uniquement après first load"""
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
            print("[API] ⚠️ Clé non configurée dans le fichier sécurisé")
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
    """Rotation de la clé DeepSeek avec gestion de l'attribut immutable et rechargement complet"""
    global DEEPSEEK_API_KEY, client
    global _intent_cache, _intent_cache_time
    global _prompt_cache, _prompt_cache_time
    global _detailed_cache, _detailed_cache_time
    
    if not new_key or not new_key.startswith("sk-"):
        print("[API] Rotation échouée : format de clé invalide")
        return False
    
    current_key = get_deepseek_key()
    if current_key and not current_key.startswith("sk-"):
        print("[API] Rotation : attention, la clé actuelle semble invalide")
    
    try:
        _remove_chattr_if_needed(SECURE_KEY_FILE)
        
        with open(SECURE_KEY_FILE, 'w') as f:
            f.write(new_key)
        os.chmod(SECURE_KEY_FILE, 0o600)
        
        chattr_ok, chattr_msg, chattr_critical = _apply_chattr_if_needed(SECURE_KEY_FILE)
        if not chattr_ok:
            print(f"[API] Rotation : {chattr_msg}")
            if chattr_critical:
                print(f"[API] Rotation : ⚠️ Clé écrite mais NON protégée !")
        
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
        
        print("[API] Rotation effectuée avec succès (caches invalidés, client rechargé)")
        return True
    except Exception as e:
        print(f"[API] Erreur rotation: {e}")
        return False


# Chargement initial
DEEPSEEK_API_KEY = get_deepseek_key()
if not DEEPSEEK_API_KEY:
    print("[API] ❌ Clé DeepSeek non trouvée !")
    print(f"[API] Vérifiez que {SECURE_KEY_FILE} contient votre clé (sans #)")
else:
    print("[API] DeepSeek: ✅ OK (clé chargée depuis stockage sécurisé)")

os.environ["DEEPSEEK_API_KEY"] = DEEPSEEK_API_KEY

from openai import OpenAI
client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1")

# ============================================================
# 4. CACHE
# ============================================================
_prompt_cache = {}
_prompt_cache_time = {}
_PROMPT_CACHE_TTL = 10

_detailed_cache = {}
_detailed_cache_time = {}
_DETAILED_CACHE_TTL = 5


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
_intent_cache = {}
_intent_cache_time = {}
_INTENT_CACHE_TTL = 30

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
                "content": f"Question: \"{user_question}\"\n\nParmi ces catégories : {', '.join(KNOWN_CATEGORIES)}\nRetourne UNIQUEMENT un JSON array des catégories pertinentes. Ex: [\"ssl\",\"sites\"]"
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
        sock.settimeout(2)
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
    return {k: 0 for k in ["cpu","ram","disk","swap","load_1m","load_5m","load_15m",
                            "ram_total_gb","ram_used_gb","disk_total_gb","disk_used_gb","disk_free_gb"]}


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
# 11. FORMATEURS (COMPLETS)
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
    running = sum(1 for c in containers if 'run' in str(c.get('status','')).lower())
    lines = [f"## 🐳 DOCKER ({running} running / {len(containers)} total)"]
    for c in containers[:max_items]:
        st = c.get('status','?')
        emoji = "🟢" if 'run' in str(st).lower() else "🔴"
        lines.append(f"  • {emoji} {c.get('name','?')} ({c.get('image','?')})")
    return "\n".join(lines)

def _format_smart(disks, max_items=10):
    if not disks:
        return "Aucune donnée SMART"
    lines = [f"## 💽 SANTÉ DISQUES ({len(disks)} disques)"]
    for d in disks[:max_items]:
        health = d.get('health','?')
        emoji = "✅" if health in ('PASSED','OK') else "❌"
        lines.append(f"  • {emoji} {d.get('device','?')} : {health}")
        if d.get('reallocated_sectors',0):
            lines.append(f"    ⚠️ {d['reallocated_sectors']} secteurs réalloués")
        if d.get('pending_sectors',0):
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
    summary_parts.append(f"📊 CPU {metrics.get('cpu',0)}% RAM {metrics.get('ram',0)}% DISK {metrics.get('disk',0)}%")

    alerts = []
    if expiring_ssl: alerts.append(f"{len(expiring_ssl)} SSL expirent")
    if oom: alerts.append(f"{len(oom)} OOM")
    if failed: alerts.append(f"{len(failed)} failed")
    if alerts: summary_parts.append(f"⚠️ {', '.join(alerts)}")

    summary_parts.append(f"🌐 {len(sites)} sites · ☁️ {len(remotes)} remotes · 🦎 {len(tailscale)} tailscale")

    summary = " | ".join(summary_parts)
    _prompt_cache["summary"] = summary
    _prompt_cache_time["summary"] = now
    return summary


# ============================================================
# 12. PROMPT SYSTÈME (COMPLET)
# ============================================================
def build_system_prompt(session_id: str, user_question: str = "", expert_mode: bool = False) -> str:
    infra_summary = generate_infra_summary()
    summaries = get_summaries(session_id)
    if summaries:
        memory_parts = []
        for s in summaries:
            try:
                obj = json.loads(s)
                memory_parts.append(f"• Résolus: {', '.join(obj.get('problemes_resolus',[]))[:200]} | Faits: {', '.join(obj.get('changements_effectues',[]))[:200]} | En cours: {', '.join(obj.get('points_en_cours',[]))[:150]}")
            except Exception:
                memory_parts.append(f"• {s[:300]}")
        memory_context = "\n".join(memory_parts)
    else:
        memory_context = "Aucun historique"

    cats = detect_intent_categories(user_question, expert_mode)
    detailed_sections = []
    for cat in cats:
        if cat in ("health",): continue
        section = get_detailed_section(cat)
        if section and "Aucun" not in section:
            detailed_sections.append(section)

    if expert_mode and not detailed_sections:
        detailed_text = "## 📊 MODE EXPERT — ÉTAT COMPLET\n\n"
        for cat in KNOWN_CATEGORIES:
            if cat == "health": continue
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
# 15. SECURE EXECUTE
# ============================================================
EXEC_ALLOWLIST = {
    "df": ["-h", "-H", "--human"],
    "free": ["-h", "-m", "-g", "-b"],
    "uptime": [None],
    "who": [None],
    "ps": ["aux", "-ef", "-p", "axo"],
    "systemctl": ["status ", "list-units", "is-active", "is-failed", "show "],
    "journalctl": ["-u ", "-n ", "--since", "-xe", "-p"],
    "tail": ["-n ", "-f /var/log/"],
    "ls": ["-la ", "-lh ", "/var/", "/etc/", "/home/", "/tmp/"],
    "du": ["-sh ", "-h --max-depth"],
    "ss": ["-tlnp", "-tnp", "-ulnp"],
    "netstat": ["-tlnp", "-tnp"],
    "ping": ["-c "],
    "rclone": ["listremotes", "ls ", "lsd ", "size "],
    "nginx": ["-t", "-v", "-T"],
    "php": ["-v", "-m", "--version"],
    "docker": ["ps", "stats --no-stream", "images", "logs --tail"],
    "mysql": ["--version"],
}

DANGEROUS_PATTERNS = [r"[&|;`$]", r"\$\([^)]+\)", r"`[^`]+`", r"\\x[0-9a-fA-F]{2}", r"\|\|", r"&&"]

def is_safe_command(cmd: str) -> bool:
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd):
            return False
    return True

def secure_execute(cmd: str) -> str:
    parts = cmd.strip().split()
    if not parts:
        return "Commande vide"
    binary = parts[0]
    if "/" in binary or "\\" in binary:
        return "Chemin absolu non autorisé"
    if binary not in EXEC_ALLOWLIST:
        return f"Commande '{binary}' non autorisée"
    if not is_safe_command(cmd):
        return "Injection détectée"
    allowed_prefixes = EXEC_ALLOWLIST[binary]
    if allowed_prefixes != [None] and len(parts) > 1:
        args_str = " ".join(parts[1:])
        if not any(args_str.startswith(p) for p in allowed_prefixes if p):
            return f"Arguments non autorisés pour '{binary}'"
    try:
        result = subprocess.run(parts, capture_output=True, text=True, timeout=15)
        return result.stdout + result.stderr
    except Exception as e:
        return f"Erreur: {e}"


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
        }
        if path in route_map:
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

        # SERVICE STATUS [A1]
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

        # RESTART COLLECTOR [A1] avec rate limiting [A2]
        if path == "/api/service/restart/collector":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            
            # Rate limiting
            allowed, remaining, wait_seconds = check_rate_limit(sid)
            if not allowed:
                self.send_json({
                    "success": False, 
                    "error": f"Trop d'actions administratives. Veuillez attendre {wait_seconds} secondes. (limite: {RATE_LIMIT_MAX_ACTIONS}/h)"
                }, 429)
                return
            
            # Vérification mot de passe admin
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
                    self.send_json({"success": True, "output": "Collector redémarré avec succès"})
                else:
                    log_admin_action(sid, "restart_collector", "FAILED", result.stderr)
                    self.send_json({"success": False, "error": result.stderr}, 500)
            except Exception as e:
                log_admin_action(sid, "restart_collector", "ERROR", str(e))
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # RESTART AGENT [A1] avec rate limiting [A2]
        if path == "/api/service/restart/agent":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            
            # Rate limiting
            allowed, remaining, wait_seconds = check_rate_limit(sid)
            if not allowed:
                self.send_json({
                    "success": False, 
                    "error": f"Trop d'actions administratives. Veuillez attendre {wait_seconds} secondes. (limite: {RATE_LIMIT_MAX_ACTIONS}/h)"
                }, 429)
                return
            
            # Vérification mot de passe admin
            admin_pwd = data.get("admin_password", "")
            expected = os.environ.get("CASSANDRA_PASSWORD_HASH", "")
            if expected and hashlib.sha256(admin_pwd.encode()).hexdigest() != expected:
                log_admin_action(sid, "restart_agent", "FAILED", "wrong password")
                self.send_json({"error": "Mot de passe administrateur incorrect"}, 403)
                return
            
            try:
                record_admin_action(sid)
                
                # Redémarrage en arrière-plan
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
                auto_summarize_session(sid)
            return

        # EXEC
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
# 17. TEMPLATE HTML (COMPLET avec boutons service)
# ============================================================
HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cassandra v10.4 - IA souveraine</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
</style>
</head>
<body>
<canvas id="particles-canvas"></canvas>
<div class="hex-grid"></div>

<div id="login-modal" class="login-modal">
  <div class="login-card">
    <h1>🔐 CASSANDRA v10.4</h1>
    <p>Stockage sécurisé, temps réel, contrôle services.</p>
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
    <div><span class="logo">CASSANDRA</span><span class="logo-badge">v10.4 · contrôle services</span></div>
    <div class="status">
      <div class="status-dot"></div>
      <span id="status-text">ONLINE</span>
      <span class="session-time" id="session-time">0 min</span>
      <div class="service-btn-group">
        <button id="restart-collector-btn" class="service-btn" title="Redémarrer le collector">🔄 Collector</button>
        <button id="restart-agent-btn" class="service-btn warning" title="Redémarrer l'agent (⚠️ déconnexion)">⚠️ Agent</button>
      </div>
      <button id="expert-mode-btn" class="hdr-btn expert-btn">🔍 Mode normal</button>
      <button class="hdr-btn audit-btn" onclick="openAudit()">🔍 Audit</button>
      <button class="hdr-btn logout-btn" onclick="logout()">Déconnexion</button>
    </div>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('dashboard')">📊 Dashboard</div>
    <div class="tab" onclick="switchTab('history')">📈 Historique</div>
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
      </div>

      <div class="panel panel-center">
        <div class="chat-messages" id="chat-messages">
          <div class="message bot"><div class="message-bubble">👋 <strong>CASSANDRA v10.4</strong><br>Stockage sécurisé, temps réel, contrôle services — je préviens avant que ça pète.</div></div>
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
    document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active',['dashboard','history'][i]===name));
    document.getElementById('tab-dashboard').classList.toggle('active',name==='dashboard');
    document.getElementById('tab-history').classList.toggle('active',name==='history');
    if(name==='history') loadHistoryCharts(currentPeriod);
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

async function apiGet(e){ const r=await fetch(e); if(!r.ok)throw new Error(); return r.json(); }
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
    let out=t.replace(/```bash\n([\s\S]*?)\n```/g,(_,code)=>{const safe=escapeHtml(code); const esc=code.replace(/\\/g,'\\\\').replace(/'/g,"\\'"); return `<div class="command-block"><div class="command-header"><span>💻 ${safe}</span><button class="exec-btn" onclick="executeCommand('${esc}')">▶ EXÉCUTER</button></div><div class="command-result" id="res-${Date.now()}">En attente...</div></div>`;});
    out=out.replace(/^## (.+)$/gm,'<h2>$1</h2>').replace(/^### (.+)$/gm,'<h3>$1</h3>').replace(/^[•\-] (.+)$/gm,'<li>$1</li>').replace(/(<li>[\s\S]*?<\/li>)+/g,m=>'<ul>'+m+'</ul>');
    out=out.replace(/\b(\d{1,3})%/g,(m,p)=>{const pc=parseInt(p); if(pc>100)return m; const col=pc>85?'#ff4757':pc>70?'#ffa502':'#2ed573'; return `<span style="color:${col};font-weight:bold">${pc}%</span>`;});
    return out;
}
async function executeCommand(cmd){ if(!confirm('Exécuter :\n'+cmd+'\n\nConfirmer ?'))return; const rdiv=document.querySelectorAll('.command-result'); const rd=rdiv[rdiv.length-1]; if(rd)rd.innerHTML='<div class="loader"></div> Exécution...'; try{ const r=await fetch('/api/exec',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd,session:sessionId})}); if(r.status===401){ if(rd)rd.innerHTML='<span style="color:#ff4757">❌ Session expirée</span>'; logout(); return; } const d=await r.json(); if(rd)rd.innerHTML=`<pre style="margin:0;font-size:10px;white-space:pre-wrap">${escapeHtml(d.output||'Aucune sortie')}</pre>`; }catch(e){ if(rd)rd.innerHTML='<span style="color:#ff4757">❌ '+e.message+'</span>'; } }
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

// [A4] Service control functions
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
    
    const endpoint = serviceName === 'collector' 
        ? '/api/service/restart/collector' 
        : '/api/service/restart/agent';
    
    try {
        const r = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                session: sessionId, 
                admin_password: adminPassword 
            })
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

async function startApp(){
    initCharts(); initParticles();
    if(expertMode){ document.getElementById('expert-mode-btn').textContent='🔬 Mode expert'; document.getElementById('expert-mode-btn').classList.add('active'); }
    document.getElementById('expert-mode-btn').onclick=toggleExpertMode;
    
    // Attacher les événements des boutons service
    const collectorBtn = document.getElementById('restart-collector-btn');
    const agentBtn = document.getElementById('restart-agent-btn');
    if (collectorBtn) collectorBtn.onclick = () => restartService('collector', false);
    if (agentBtn) agentBtn.onclick = () => restartService('agent', true);
    
    await Promise.allSettled([loadMetrics(), loadDashboard(), loadRemotes(), loadSSLCerts(), loadTailscale(), loadFail2ban(), loadProcesses(), loadSessions(), loadPorts(), loadOOM(), loadFailedUnits(), loadDocker()]);
    
    setInterval(loadMetrics,1000); setInterval(loadProcesses,2000); setInterval(loadSessions,2000); setInterval(loadDocker,5000); setInterval(loadTailscale,5000); setInterval(loadRemotes,10000); setInterval(loadFail2ban,10000); setInterval(loadDashboard,10000); setInterval(loadSSLCerts,30000); setInterval(loadPorts,30000); setInterval(loadOOM,30000); setInterval(loadFailedUnits,30000);
    setInterval(checkServicesStatus, 30000);
    checkServicesStatus();
}

document.getElementById('chat-input').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault(); sendMessage();}});
document.getElementById('chat-input').addEventListener('input',function(){ this.style.height='auto'; this.style.height=Math.min(this.scrollHeight,100)+'px'; });

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

    # Vérification initiale du fichier de clé
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
    print(f"  CASSANDRA v10.4 — IA souveraine (contrôle services)")
    print(f"  Port    : {PORT}")
    print(f"  URL     : http://localhost:{PORT}")
    print(f"  DeepSeek: {'✅ OK' if DEEPSEEK_API_KEY else '❌ MANQUANTE'}")
    print(f"  Stockage: {SECURE_KEY_FILE}")
    print(f"  Cache   : /dev/shm/.cassandra_deepseek_key (RAM)")
    print(f"  Admin   : {ADMIN_LOG_FILE}")
    print(f"  Rate limit: {RATE_LIMIT_MAX_ACTIONS} actions/heure")
    print(f"{'='*60}")
    print(f"  CORRECTIFS v10.4:")
    print(f"  [A1] Endpoints admin : restart collector, restart agent, status services")
    print(f"  [A2] Rate limiting : 5 actions par heure max par session")
    print(f"  [A3] Logging étendu : {ADMIN_LOG_FILE}")
    print(f"  [A4] Interface : boutons de contrôle des services")
    print(f"{'='*60}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Arrêt de CASSANDRA...")
        server.shutdown()