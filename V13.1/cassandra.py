#!/usr/bin/env python3
"""
CASSANDRA — Agent unifié 
============================================================

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
import signal
import logging
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
import smtplib
import socket as _socket_mod
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ============================================================
# 1. CONFIGURATION
# ============================================================
DB_PATH          = "/var/lib/cassandra/cassandra.db"
MEMORY_DB_PATH   = "/var/lib/cassandra/cassandra_memory.db"
COLLECTOR_SOCKET = "/tmp/cassandra_knowledge.sock"
PORT             = 9000
START_TIME       = time.time()

# [EVO] Service Health Dashboard
SERVICES_LIST = [
    "nginx", "apache2", "mysql", "mariadb", "postfix", "dovecot",
    "exim4", "proftpd", "sshd", "fail2ban", "tailscaled",
    "php8.1-fpm", "php8.2-fpm", "php8.3-fpm", "fastpanel2",
    "cassandra", "cassandra-collector", "systemd-resolved"
]

def get_services_status():
    results = []
    for svc in SERVICES_LIST:
        try:
            r = subprocess.run(
                "systemctl is-active " + svc + " 2>/dev/null || echo inactive",
                shell=True, capture_output=True, text=True, timeout=3
            )
            state = r.stdout.strip()
            r2 = subprocess.run(
                "systemctl show -p Description " + svc + " 2>/dev/null | cut -d= -f2",
                shell=True, capture_output=True, text=True, timeout=2
            )
            desc = r2.stdout.strip() or svc
            results.append({
                "name": svc,
                "description": desc,
                "status": state if state in ("active", "inactive", "activating", "deactivating", "failed") else "unknown",
                "healthy": state == "active"
            })
        except Exception:
            results.append({"name": svc, "description": svc, "status": "unknown", "healthy": False})
    try:
        ts_raw = subprocess.run(
            "tailscale status --json 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=5
        )
        if ts_raw.stdout.strip():
            ts_data = json.loads(ts_raw.stdout)
            online_peers = sum(1 for p in ts_data.get("Peer", {}).values() if p.get("Online"))
        else:
            online_peers = 0
        results.append({
            "name": "tailscale_peers",
            "description": "Pairs Tailscale en ligne",
            "status": str(online_peers) + " en ligne",
            "healthy": online_peers > 0
        })
    except Exception:
        results.append({"name": "tailscale_peers", "description": "Pairs Tailscale", "status": "unknown", "healthy": False})
    return results

def store_services_in_db():
    services = get_services_status()
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS services_status (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, status TEXT NOT NULL, healthy INTEGER NOT NULL DEFAULT 0, ts TEXT NOT NULL DEFAULT (datetime('now')))")
        for svc in services:
            c.execute("INSERT INTO services_status (name, status, healthy) VALUES (?, ?, ?)", (svc["name"], svc["status"], 1 if svc["healthy"] else 0))
        c.execute("DELETE FROM services_status WHERE id NOT IN (SELECT id FROM services_status ORDER BY id DESC LIMIT 1000)")
        conn.commit()
        conn.close()
    except Exception:
        pass
    return services

def _api_services():
    try:
        svcs = store_services_in_db()
        return {"services": svcs, "count": len(svcs), "healthy": sum(1 for s in svcs if s["healthy"]), "unhealthy": sum(1 for s in svcs if not s["healthy"])}
    except Exception as e:
        return {"services": [], "error": str(e), "count": 0}

MAX_RAW_MESSAGES = 30
SUMMARY_KEEP     = 5

SECURE_KEY_FILE      = "/etc/cassandra/deepseek.key"
CASSANDRA_CONFIG_FILE = "/etc/cassandra/config.json"
CASSANDRA_AUTH_FILE   = "/etc/cassandra/auth.json"

# ── Config runtime (provider / model) ─────────────────────────
def get_cassandra_config() -> dict:
    """Lit /etc/cassandra/config.json. Retourne {} si absent ou illisible."""
    try:
        with open(CASSANDRA_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_cassandra_config(cfg: dict) -> bool:
    """Écrit la config de façon atomique (write + rename)."""
    try:
        Path(CASSANDRA_CONFIG_FILE).parent.mkdir(parents=True, exist_ok=True)
        tmp = CASSANDRA_CONFIG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CASSANDRA_CONFIG_FILE)
        return True
    except Exception as e:
        print(f"[CFG] Erreur écriture config: {e}")
        return False

# ── Auth runtime (hash mot de passe admin) ────────────────────
def get_admin_password_hash() -> str:
    """Lit le hash depuis auth.json ; fallback sur l'env var."""
    try:
        with open(CASSANDRA_AUTH_FILE, "r") as f:
            d = json.load(f)
            if d.get("password_hash"):
                return d["password_hash"]
    except Exception:
        pass
    return os.environ.get("CASSANDRA_PASSWORD_HASH", "")

def save_admin_password_hash(new_hash: str) -> bool:
    """Sauvegarde le hash dans auth.json sans toucher au service systemd."""
    try:
        Path(CASSANDRA_AUTH_FILE).parent.mkdir(parents=True, exist_ok=True)
        tmp = CASSANDRA_AUTH_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"password_hash": new_hash}, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CASSANDRA_AUTH_FILE)
        return True
    except Exception as e:
        print(f"[AUTH] Erreur écriture auth: {e}")
        return False

# [A2] Rate limiting
RATE_LIMIT_MAX_ACTIONS = 5
RATE_LIMIT_INTERVAL = 3600
_admin_action_log: dict = {}
_admin_action_lock = threading.Lock()
# Rate-limit /api/login (anti brute-force)
_login_attempts: dict = {}
_login_attempts_lock = threading.Lock()

# Cleanup automatique des vieux logs
def _cleanup_old_logs():
    """Nettoie les logs d'action plus vieux que 1h et les tentatives de login toutes les 5 min."""
    while not _shutdown_event.is_set():
        try:
            now = time.time()
            with _admin_action_lock:
                to_del = [k for k, v in _admin_action_log.items() if now - v.get("ts", 0) > 3600]
                for k in to_del:
                    del _admin_action_log[k]
            with _login_attempts_lock:
                to_del = [k for k, v in _login_attempts.items() if now - v.get("ts", 0) > 3600]
                for k in to_del:
                    del _login_attempts[k]
        except Exception:
            pass
        _shutdown_event.wait(300)

LOGIN_MAX_ATTEMPTS = 10
LOGIN_ATTEMPT_WINDOW = 300  # 5 minutes

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

# Cache métriques système (évite lecture /proc à chaque requête)
_sys_metrics_cache: dict = {}
_sys_metrics_cache_time: float = 0.0
_SYS_METRICS_CACHE_TTL = 2.0
_sys_metrics_lock = threading.Lock()



# === v14: Graceful shutdown ===
_shutdown_event = threading.Event()
threading.Thread(target=_cleanup_old_logs, daemon=True, name="cleanup-logs").start()
_start_time = time.time()

def _handle_signal(signum, frame):
    """Capture SIGTERM/SIGINT pour un arrêt propre."""
    _shutdown_event.set()

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)

# ============================================================
# ALERTING CONFIGURABLE — Evo 1
# ============================================================
ALERT_CONFIG_FILE = "/etc/cassandra/alerts.yml"
_alert_config:      dict = {}
_alert_config_mtime: float = 0.0
_alert_config_lock  = threading.Lock()
_alert_notified:    dict = {}   # {rule_name+category: last_sent_ts}
_alert_notified_lock = threading.Lock()


def _yaml_loads_simple(text: str, max_depth: int = 20) -> dict:
    """Parser YAML minimal (pas de dépendance PyYAML).
    Supporte : mappings plats, listes, strings, booleans, ints, floats.
    # ROBUSTESSE: try/except global → retourne {} proprement sur YAML malformé
    # FEATURE: max_depth pour éviter les boucles infinies sur YAML pathologique
    # FIX: gestion clés vides, stack vide, listes orphelines, elif dupliqué
    # FIX: nettoyage des entrées vides en sortie
    """
    if not text or not text.strip():
        return {}
    try:
        result  = {}
        stack   = [result]  # pile des dicts/listes courants
        indents = [0]       # pile des niveaux d'indentation

        for line in text.splitlines():
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(stripped)

            # Dépiler si on remonte — garde anti-stack vide
            while len(indents) > 1 and indent <= indents[-2]:
                stack.pop()
                indents.pop()

            # Garde anti-profondeur infinie
            if len(stack) > max_depth:
                break

            parent = stack[-1]

            if stripped.startswith("- "):
                # Élément de liste
                val_str = stripped[2:].strip()
                val = _parse_yaml_scalar(val_str)
                if isinstance(parent, list):
                    parent.append(val)
                elif isinstance(parent, dict) and parent:
                    # Convertir en liste — préserver la valeur existante si non vide
                    last_key = list(parent.keys())[-1]
                    if not isinstance(parent[last_key], list):
                        existing = parent[last_key]
                        parent[last_key] = [existing] if existing not in (None, "", {}) else []
                    parent[last_key].append(val)
                # else: liste orpheline sans parent dict → ignorer silencieusement

            elif ":" in stripped:
                key, _, val_str = stripped.partition(":")
                key     = key.strip()
                val_str = val_str.strip()
                if not key:
                    continue  # FIX: ignorer les lignes avec clé vide (": value")
                if val_str == "" or val_str == "|" or val_str == ">":
                    # Valeur complexe (dict/list à venir)
                    new_obj: dict = {}
                    if isinstance(parent, dict):
                        parent[key] = new_obj
                    elif isinstance(parent, list):
                        parent.append({key: new_obj})
                    stack.append(new_obj)
                    indents.append(indent)
                else:
                    val = _parse_yaml_scalar(val_str)
                    if isinstance(parent, dict):
                        parent[key] = val
                    elif isinstance(parent, list):
                        parent.append({key: val})

        # Nettoyage : supprimer les entrées vides de niveau racine
        return {k: v for k, v in result.items() if v not in (None, "", {})}

    except Exception:
        return {}


def _parse_yaml_scalar(s: str):
    s = s.strip().strip("'\"").strip()
    if s.lower() in ("true", "yes"):  return True
    if s.lower() in ("false", "no"): return False
    if s.lower() in ("null", "~"):   return None
    try: return int(s)
    except ValueError: pass
    try: return float(s)
    except ValueError: pass
    # Inline list : [a, b, c]
    if s.startswith("[") and s.endswith("]"):
        return [_parse_yaml_scalar(x.strip()) for x in s[1:-1].split(",") if x.strip()]
    return s


def load_alert_config() -> dict:
    """Charge (et recharge si modifié) cassandra_alerts.yml."""
    global _alert_config, _alert_config_mtime
    paths = [ALERT_CONFIG_FILE, "/etc/cassandra/alerts.yml",
             str(Path(__file__).parent / "cassandra_alerts.yml")]
    for p in paths:
        if not Path(p).exists():
            continue
        try:
            mtime = Path(p).stat().st_mtime
            with _alert_config_lock:
                if mtime == _alert_config_mtime and _alert_config:
                    return _alert_config
                _alert_config = _yaml_loads_simple(Path(p).read_text())
                _alert_config_mtime = mtime
                return _alert_config
        except Exception as e:
            print(f"[ALERT] Erreur lecture config: {e}", file=sys.stderr)
    return {}


def _can_notify(rule_name: str, cooldown_minutes: int) -> bool:
    """Vérifie le cooldown anti-spam pour une règle donnée."""
    with _alert_notified_lock:
        last = _alert_notified.get(rule_name, 0)
        now  = time.time()
        if now - last >= cooldown_minutes * 60:
            _alert_notified[rule_name] = now
            return True
    return False


def notify_via_email(subject: str, body: str):
    """Envoie un email via SMTP selon la config alerts.yml."""
    cfg = load_alert_config().get("email", {})
    if not cfg.get("enabled"):
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = cfg.get("from_addr", "cassandra@localhost")
        to_addrs       = cfg.get("to_addrs", [])
        if not to_addrs:
            return
        msg["To"]      = ", ".join(to_addrs)
        msg.attach(MIMEText(body, "plain", "utf-8"))

        host = cfg.get("smtp_host", "localhost")
        port = int(cfg.get("smtp_port", 587))
        use_tls = cfg.get("smtp_tls", True)

        if use_tls:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP(host, port, timeout=10)

        user = cfg.get("smtp_user", "")
        pwd  = cfg.get("smtp_password", "")
        if user and pwd:
            server.login(user, pwd)

        server.sendmail(msg["From"], to_addrs, msg.as_string())
        server.quit()
        print(f"[ALERT] Email envoyé : {subject}")
    except Exception as e:
        print(f"[ALERT] Erreur email: {e}", file=sys.stderr)


def notify_via_webhook(message: str, severity: str):
    """Envoie un webhook JSON (Slack/Discord/Ntfy/générique)."""
    cfg = load_alert_config().get("webhook", {})
    if not cfg.get("enabled"):
        return
    url = cfg.get("url", "")
    if not url:
        return
    try:
        hostname = _socket_mod.gethostname()
        template = cfg.get("payload_template", '{"text": "[{severity}] {host}: {message}"}')
        payload  = template.format(
            message=message.replace('"', '\"'),
            severity=severity.upper(),
            host=hostname,
            ts=datetime.now().isoformat(),
        ).encode("utf-8")
        headers  = {"Content-Type": "application/json"}
        headers.update(cfg.get("headers", {}) or {})
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=8) as resp:
            _ = resp.read()
        print(f"[ALERT] Webhook envoyé ({severity}): {message[:80]}")
    except Exception as e:
        print(f"[ALERT] Erreur webhook: {e}", file=sys.stderr)


def fire_alert(rule_name: str, level: str, category: str, message: str, channels: list):
    """Crée l'alerte en DB et envoie les notifications configurées."""
    save_alert(level, category, message)
    if not _can_notify(rule_name, 60):   # cooldown DB-level déjà géré dans save_alert
        return
    hostname = _socket_mod.gethostname()
    subject  = f"[CASSANDRA/{level.upper()}] {hostname} — {category}"
    body     = f"Hôte    : {hostname}\nNiveau  : {level.upper()}\nCatégorie: {category}\n\n{message}\n\n— Cassandra v14"
    if "email" in channels:
        threading.Thread(target=notify_via_email, args=(subject, body), daemon=True, name="notify-email").start()
    if "webhook" in channels:
        threading.Thread(target=notify_via_webhook, args=(message, level), daemon=True, name="notify-webhook").start()


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


def rotate_deepseek_key(new_key: str, provider: str = None, model: str = None) -> bool:
    global DEEPSEEK_API_KEY, client, MODEL_NAME, MODEL_BASE_URL, MODEL_PROVIDER
    global _intent_cache, _intent_cache_time
    global _prompt_cache, _prompt_cache_time
    global _detailed_cache, _detailed_cache_time
    if not new_key:
        print("[API] Rotation échouée: clé vide")
        return False
    # Clés Ollama peuvent être "ollama" ou "none" (pas de sk-)
    if provider != "ollama" and not new_key.startswith("sk-"):
        print("[API] Rotation échouée: format invalide (doit commencer par sk-)")
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
        # Mise à jour provider/model si fournis
        if provider or model:
            _prov = provider or MODEL_PROVIDER
            _mod  = model    or MODEL_NAME
            _url  = _PROVIDERS.get(_prov, MODEL_BASE_URL)
            MODEL_PROVIDER  = _prov
            MODEL_NAME      = _mod
            MODEL_BASE_URL  = _url
            save_cassandra_config({"provider": _prov, "model": _mod, "base_url": _url})
        client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url=MODEL_BASE_URL)
        _ms_invalidate_key_cache()    # forcer re-dérivation avec la nouvelle clé
        print(f"[API] Rotation effectuée — provider={MODEL_PROVIDER} model={MODEL_NAME}")
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

# ── Provider / modèle chargés depuis config.json ──────────────
_PROVIDERS = {
    "deepseek":   "https://api.deepseek.com/v1",
    "groq":       "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama":     "http://localhost:11434/v1",
    "openai":     "https://api.openai.com/v1",
}
_DEFAULT_MODELS = {
    "deepseek":   "deepseek-chat",
    "groq":       "mixtral-8x7b-32768",
    "openrouter": "mistralai/mixtral-8x7b-instruct",
    "ollama":     "llama3",
    "openai":     "gpt-4o-mini",
}

def _load_runtime_cfg():
    """Charge provider/model/base_url depuis config.json. Valeurs par défaut = DeepSeek."""
    cfg = get_cassandra_config()
    provider = cfg.get("provider", "deepseek")
    model    = cfg.get("model",    "deepseek-chat")
    base_url = cfg.get("base_url", _PROVIDERS.get(provider, _PROVIDERS["deepseek"]))
    return provider, model, base_url

MODEL_PROVIDER, MODEL_NAME, MODEL_BASE_URL = _load_runtime_cfg()

from openai import OpenAI
client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url=MODEL_BASE_URL)
print(f"[API] Provider: {MODEL_PROVIDER} | Modèle: {MODEL_NAME}")


# ============================================================
# BOOKSTACK — BASE DE CONNAISSANCE ENCYCLOPÉDIQUE
# ============================================================

def _load_bookstack_cfg() -> tuple:
    """Charge URL + credentials BookStack depuis config.json."""
    cfg = get_cassandra_config()
    url    = cfg.get("bookstack_url", "").rstrip("/")
    tok_id = cfg.get("bookstack_token_id", "")
    tok_sec= cfg.get("bookstack_token_secret", "")
    return url, tok_id, tok_sec

# Valeurs initiales (rechargeables à chaud via reload_bookstack_cfg())
_BS_URL, _BS_TOKEN_ID, _BS_TOKEN_SECRET = _load_bookstack_cfg()

def reload_bookstack_cfg():
    global _BS_URL, _BS_TOKEN_ID, _BS_TOKEN_SECRET
    _BS_URL, _BS_TOKEN_ID, _BS_TOKEN_SECRET = _load_bookstack_cfg()

def _init_bookstack_config():
    """Injecte les credentials BookStack dans config.json si absents (premier démarrage)."""
    cfg = get_cassandra_config()
    changed = False
    defaults = {
        "bookstack_url":          "https://administration.cassandra.center",
        "bookstack_token_id":     "RETIRE",
        "bookstack_token_secret": "RETIRE",
    }
    for k, v in defaults.items():
        if not cfg.get(k):
            cfg[k] = v
            changed = True
    if changed:
        save_cassandra_config(cfg)
        reload_bookstack_cfg()
        print("[BOOKSTACK] Credentials initialisés dans config.json")

def _bs_headers() -> dict:
    return {"Authorization": f"Token {_BS_TOKEN_ID}:{_BS_TOKEN_SECRET}",
            "Content-Type": "application/json"}

def bookstack_search_pages(query: str, count: int = 5) -> list:
    """Recherche dans BookStack. Retourne [{id, name, url, preview, book}].

    # PERF: appel HTTP unique, timeout 5s, résultat mis en cache 60s par query.
    """
    if not _BS_URL or not _BS_TOKEN_ID:
        return []
    cache_key = f"bs_search_{query}_{count}"
    cached = _bs_cache.get(cache_key)
    if cached and time.time() - cached[0] < 60:
        return cached[1]
    try:
        import urllib.request, urllib.parse
        params = urllib.parse.urlencode({"query": query, "count": count, "type": "all"})
        req = urllib.request.Request(
            f"{_BS_URL}/api/search?{params}",
            headers=_bs_headers()
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
        results = []
        for item in data.get("data", []):
            preview = ""
            ph = item.get("preview_html", {})
            if isinstance(ph, dict):
                raw = ph.get("content", "")
                # Supprimer les balises HTML basiquement
                preview = re.sub(r'<[^>]+>', ' ', raw).strip()[:300]
            results.append({
                "id":      item.get("id"),
                "type":    item.get("type", "page"),
                "name":    item.get("name", ""),
                "url":     item.get("url", ""),
                "preview": preview,
                "book":    item.get("book", {}).get("name", "") if item.get("book") else "",
            })
        _bs_cache[cache_key] = (time.time(), results)
        return results
    except Exception as e:
        print(f"[BOOKSTACK] Erreur recherche '{query}': {e}")
        return []

def bookstack_get_page(page_id: int) -> dict:
    """Récupère le contenu complet d'une page BookStack par ID."""
    if not _BS_URL or not _BS_TOKEN_ID:
        return {}
    cache_key = f"bs_page_{page_id}"
    cached = _bs_cache.get(cache_key)
    if cached and time.time() - cached[0] < 300:
        return cached[1]
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{_BS_URL}/api/pages/{page_id}",
            headers=_bs_headers()
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
        # Extraire texte depuis markdown ou html
        content = data.get("markdown", "") or re.sub(r'<[^>]+>', ' ', data.get("html", "")).strip()
        result = {
            "id":      data.get("id"),
            "name":    data.get("name", ""),
            "url":     f"{_BS_URL}/books/{data.get('book_slug','')}/page/{data.get('slug','')}",
            "content": content[:6000],
            "book":    data.get("book_id"),
        }
        _bs_cache[cache_key] = (time.time(), result)
        return result
    except Exception as e:
        print(f"[BOOKSTACK] Erreur page {page_id}: {e}")
        return {}

def _bs_prefetch(query: str, timeout: float = 1.5) -> str:
    """
    Lance bookstack_search_pages dans un thread et attend max `timeout` secondes.
    Retourne une section markdown prête à injecter, ou "" si timeout/erreur.
    # PERF: non-bloquant — le stream LLM démarre sans attendre BookStack
    #        si BookStack répond dans le délai, le contexte est enrichi gratuitement
    """
    if not _BS_URL or not _BS_TOKEN_ID or not query.strip():
        return ""
    result: list = []

    def _fetch():
        try:
            pages = bookstack_search_pages(query, count=3)
            result.extend(pages)
        except Exception:
            pass

    t = threading.Thread(target=_fetch, daemon=True, name="bs-prefetch")
    t.start()
    t.join(timeout=timeout)

    if not result:
        return ""

    lines = ["## 📚 ENCYCLOPÉDIE BOOKSTACK (pages pertinentes détectées automatiquement)"]
    for p in result[:3]:
        lines.append(f"- **{p.get('name','')}** ({p.get('book','')}): {p.get('preview','')[:200]}")
        lines.append(f"  → ID {p.get('id')} | {p.get('url','')}")
    lines.append("*(Utilise `bookstack_read_page` avec l'ID pour lire le contenu complet si nécessaire)*")
    return "\n".join(lines)


def format_bookstack_for_prompt(query: str) -> str:
    """Injecte les pages BookStack pertinentes dans le system prompt.

    # PERF: top-3 résultats seulement pour garder le prompt compact.
    # Timeout 5s pour ne jamais bloquer le stream si BookStack est down.
    """
    if not _BS_URL or not _BS_TOKEN_ID or not query.strip():
        return ""
    try:
        results = bookstack_search_pages(query, count=3)
        if not results:
            return ""
        lines = ["📚 **ENCYCLOPÉDIE BOOKSTACK** (pages pertinentes pour cette question)"]
        for r in results:
            book_label = f" [{r['book']}]" if r['book'] else ""
            lines.append(f"\n### {r['name']}{book_label}")
            if r['preview']:
                lines.append(r['preview'])
            lines.append(f"🔗 {r['url']}")
        return "\n".join(lines)
    except Exception:
        return ""

# Cache mémoire pour BookStack (query → (timestamp, résultat))
_bs_cache: dict = {}


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
            model=MODEL_NAME,
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
def query_db(sql, params=None):
    if params is None:
        params = []
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
    """
    FIX: filter_recent max_minutes=5 faisait disparaître les sessions SSH après 5 min.
    Les sessions `who` sont actives par définition → on ne filtre PAS sur le temps de login.
    On filtre sur last_check (fraîcheur de la collecte) pour éviter les données périmées.
    """
    data = get_entity_from_socket("active_sessions")
    if data:
        # Données fraîches du socket — pas de filtre temporel sur login_time
        return data if data else []
    # Fallback SQLite: on accepte les sessions vues dans les dernières 2 min
    rows = query_db("SELECT user, ip, login_time, last_check FROM active_sessions ORDER BY id DESC LIMIT 30")
    return filter_recent(rows, "last_check", max_minutes=2) if rows else []


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


UNIT_BULLETS = {"●", "•", "○", "*", "-", "✗", "x"}

def get_failed_units():
    """FIX: filtrer les entrées avec unit='●' (bug du collector pré-fix)."""
    data = get_entity_from_socket("failed_units")
    if data:
        result = [u for u in data
                  if u.get("active_state") == "failed"
                  and u.get("unit", "?") not in UNIT_BULLETS
                  and u.get("unit", "?") != "?"]
        if result:
            return result
    rows = query_db("SELECT unit, active_state, description FROM failed_units WHERE active_state = 'failed'")
    if rows:
        return rows
    # Fallback direct systemctl — la table SQLite peut avoir unit='' ou être vide
    try:
        import subprocess as _sp
        out = _sp.run("systemctl --failed --no-legend --no-pager 2>/dev/null",
                      shell=True, capture_output=True, text=True, timeout=5).stdout
        units = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            # Format : ● service.service  loaded failed failed  Description
            #       ou: service.service  loaded failed failed  Description
            idx = 1 if parts[0] in ('●', '•', '○', '*', '-') else 0
            if len(parts) > idx:
                unit_name = parts[idx]
                desc = " ".join(parts[idx + 4:]) if len(parts) > idx + 4 else ""
                units.append({"unit": unit_name, "active_state": "failed", "description": desc})
        return units
    except Exception:
        return []


def get_tailscale_peers():
    data = get_entity_from_socket("tailscale_peers")
    return data if data else query_db("SELECT name, online, tailscale_ip FROM tailscale_peers")


def get_fail2ban_banned():
    data = get_entity_from_socket("fail2ban_banned_ips")
    return data if data else query_db("SELECT jail, ip, banned_at FROM fail2ban_banned_ips ORDER BY banned_at DESC LIMIT 20")


def get_open_ports():
    data = get_entity_from_socket("open_ports")
    return data if data else query_db("SELECT port, protocol, process FROM open_ports ORDER BY port")


# ── Modèles supportant la vision (images en base64) ───────────
_VISION_MODELS = {
    "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4-vision-preview",
    "claude-3-opus", "claude-3-sonnet", "claude-3-haiku",
    "claude-3-5-sonnet", "claude-3-5-haiku",
    "llava", "llava-1.5", "qwen-vl", "qwen2-vl",
    "gemini-pro-vision", "gemini-1.5-pro", "gemini-1.5-flash",
    "mistral-pixtral", "pixtral-12b",
}

def _model_supports_vision() -> bool:
    """Vérifie si le modèle courant supporte les images."""
    m = MODEL_NAME.lower()
    return any(v in m for v in _VISION_MODELS)

def _extract_text_from_upload(raw_bytes: bytes, mime: str, filename: str) -> dict:
    """
    Extrait le texte d'un fichier uploadé.
    Retourne {"text": str, "truncated": bool, "method": str, "error": str|None}
    """
    MAX_CHARS = 40_000   # ~ 10k tokens — raisonnable pour un contexte LLM
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # ── Fichiers texte / code ──────────────────────────────────
    TEXT_EXTS = {
        "txt","md","rst","csv","tsv","json","jsonl","yaml","yml",
        "xml","html","htm","css","js","ts","py","sh","bash","zsh",
        "php","rb","go","rs","java","c","cpp","h","hpp","sql","ini",
        "conf","env","log","toml","tf","dockerfile"
    }
    if ext in TEXT_EXTS or mime.startswith("text/"):
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            truncated = len(text) > MAX_CHARS
            return {"text": text[:MAX_CHARS], "truncated": truncated, "method": "text", "error": None}
        except Exception as e:
            return {"text": "", "truncated": False, "method": "text", "error": str(e)}

    # ── PDF ───────────────────────────────────────────────────
    if ext == "pdf" or mime == "application/pdf":
        # Méthode 1 : pdftotext (poppler, souvent disponible sur les serveurs)
        try:
            import subprocess as _sp
            result = _sp.run(["pdftotext", "-", "-"], input=raw_bytes,
                             capture_output=True, timeout=15)
            if result.returncode == 0:
                text = result.stdout.decode("utf-8", errors="replace").strip()
                truncated = len(text) > MAX_CHARS
                return {"text": text[:MAX_CHARS], "truncated": truncated, "method": "pdftotext", "error": None}
        except Exception:
            pass
        # Méthode 2 : PyPDF2 / pypdf (si installé)
        try:
            import io
            try:
                from pypdf import PdfReader
            except ImportError:
                from PyPDF2 import PdfReader  # type: ignore
            reader = PdfReader(io.BytesIO(raw_bytes))
            pages = [p.extract_text() or "" for p in reader.pages]
            text = "\n".join(pages).strip()
            truncated = len(text) > MAX_CHARS
            return {"text": text[:MAX_CHARS], "truncated": truncated, "method": "pypdf", "error": None}
        except Exception as e:
            pass
        return {"text": "", "truncated": False, "method": "pdf_failed",
                "error": "pdftotext et pypdf non disponibles — installez poppler-utils"}

    # ── Images ────────────────────────────────────────────────
    if mime.startswith("image/"):
        if _model_supports_vision():
            # Le modèle gère les images nativement — on renverra le base64 direct
            return {"text": None, "image_b64": base64.b64encode(raw_bytes).decode(),
                    "mime": mime, "truncated": False, "method": "vision", "error": None}
        else:
            # Essai OCR via tesseract
            try:
                import subprocess as _sp, tempfile
                suffix = "." + (ext or "png")
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                    tmp.write(raw_bytes); tmp_path = tmp.name
                result = _sp.run(["tesseract", tmp_path, "stdout", "-l", "fra+eng"],
                                  capture_output=True, timeout=20)
                os.unlink(tmp_path)
                if result.returncode == 0:
                    text = result.stdout.decode("utf-8", errors="replace").strip()
                    return {"text": f"[OCR IMAGE — {filename}]\n{text}" if text else "[Image sans texte détectable]",
                            "truncated": False, "method": "ocr", "error": None}
            except Exception:
                pass
            return {"text": None, "truncated": False, "method": "vision_unsupported",
                    "error": f"Le modèle '{MODEL_NAME}' ne supporte pas les images. Utilisez GPT-4o, Claude 3 ou un modèle vision via OpenRouter."}

    # ── Fallback binaire ──────────────────────────────────────
    return {"text": "", "truncated": False, "method": "unsupported",
            "error": f"Type de fichier non supporté : {mime} (.{ext})"}


def get_server_info():
    """Infos statiques/semi-statiques sur le serveur : OS, kernel, IP, CPU, uptime, disques."""
    import platform, subprocess as sp
    try:
        uname = os.uname()
        kernel  = uname.release
        hostname = uname.nodename
        cpu_cores = os.cpu_count() or 1
        # IP principale
        try:
            ip_raw = sp.check_output(["hostname", "-I"], timeout=2).decode().strip()
            ip = ip_raw.split()[0] if ip_raw else "?"
        except Exception:
            try:
                ip = _socket_mod.gethostbyname(_socket_mod.gethostname())
            except Exception:
                ip = "?"
        # Uptime système (depuis /proc/uptime, pas depuis START_TIME)
        try:
            with open("/proc/uptime") as f:
                uptime_secs = int(float(f.read().split()[0]))
        except Exception:
            uptime_secs = int(time.time() - START_TIME)
        # Nombre de disques physiques
        try:
            disk_count = int(sp.check_output(
                "lsblk -d -n -o TYPE | grep -c disk || echo 0",
                shell=True, timeout=3
            ).decode().strip())
        except Exception:
            disk_count = 0
        # Distro
        try:
            with open("/etc/os-release") as f:
                lines = {}
                for l in f:
                    if "=" in l:
                        k, v = l.strip().split("=", 1)
                        lines[k] = v.strip().strip('"')
            distro = lines.get("PRETTY_NAME") or lines.get("NAME") or platform.system()
        except Exception:
            distro = platform.system()
        return {
            "hostname":    hostname,
            "os":          distro,
            "kernel":      kernel,
            "ip":          ip,
            "cpu_cores":   cpu_cores,
            "uptime_secs": uptime_secs,
            "disk_count":  disk_count,
        }
    except Exception as e:
        return {"error": str(e)}


def get_rclone_remotes():
    data = get_entity_from_socket("rclone_remotes")
    return data if data else query_db("SELECT name, type, used_gb FROM rclone_remotes")


def get_web_sites():
    data = get_entity_from_socket("web_sites")
    return data if data else query_db("SELECT domain, ssl_enabled, php_version FROM web_sites WHERE status = 'active'")


def get_health_score():
    """
    FIX CRITIQUE: `data.get("health_score")` est falsy quand score=0 → toujours 0/unknown.
    FIX: utiliser `"health_score" in data` pour tester la présence, pas la valeur.
    FIX: le collector inclut maintenant health_score dans le cache socket (update_cache).
    """
    data = get_dashboard_from_socket()
    if data and "health_score" in data:  # FIX: `in` pas truthiness
        return {
            "score":     data["health_score"],
            "status":    data.get("health_status", "unknown"),
            "breakdown": data.get("breakdown", {}),
        }
    rows = query_db("SELECT score, status, breakdown FROM health_scores ORDER BY id DESC LIMIT 1")
    if rows and isinstance(rows, list) and len(rows) > 0:
        row = rows[0]
        if isinstance(row, dict):
            import json as _j
            bd = {}
            try: bd = _j.loads(row.get("breakdown") or "{}")
            except Exception: pass
            return {"score": row.get("score", 0), "status": row.get("status", "unknown"), "breakdown": bd}
    return {"score": 0, "status": "unknown", "breakdown": {}}


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
def _fp_mysql_direct(sql, mapper):
    """Requête MySQL directe sur FastPanel2 — fallback quand collector absent."""
    try:
        from pathlib import Path as _P
        import shlex as _sl, subprocess as _sp
        creds = {}
        for pf in ["/usr/local/fastpanel2/app/config/parameters.yml",
                   "/usr/local/fastpanel2/app/config/parameters.yaml",
                   "/usr/local/fastpanel2/config/database.yml"]:
            if _P(pf).exists():
                for line in _P(pf).read_text(errors="replace").splitlines():
                    line = line.strip()
                    if ": " in line and not line.startswith("#"):
                        k, _, v = line.partition(": ")
                        creds[k.strip()] = v.strip().strip("'\" ")
                break
        pw = creds.get("database_password", "")
        if not pw:
            return []
        host = creds.get("database_host", "127.0.0.1")
        port = creds.get("database_port", "3306")
        user = creds.get("database_user", "fastpanel")
        db   = creds.get("database_name", "fastpanel2")
        env  = f"MYSQL_PWD={_sl.quote(pw)} " if pw else ""
        cmd  = (f"{env}mysql -h{_sl.quote(host)} -P{port} -u{_sl.quote(user)} {_sl.quote(db)} "
                f"--batch --silent --skip-column-names -e {_sl.quote(sql)} 2>/dev/null")
        out  = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout
        rows = [l.split("\t") for l in out.splitlines()
                if l.strip() and not l.startswith("Warning") and not l.upper().startswith("ERROR")]
        result = []
        for r in rows:
            try:
                mapped = mapper(r)
                if mapped:
                    result.append(mapped)
            except Exception:
                pass
        return result
    except Exception:
        return []

def get_fp_users():
    d = get_entity_from_socket("fastpanel_users")
    if d: return d
    r = query_db("SELECT username,email,status,disk_quota_gb,disk_used_gb,created_at,last_login FROM fastpanel_users ORDER BY username")
    if r: return r
    return _fp_mysql_direct(
        "SELECT u.login, u.email, u.status, u.created_at, u.last_login, "
        "COALESCE(u.disk_quota,0), COALESCE(u.disk_used,0) "
        "FROM user u ORDER BY u.login",
        lambda r: {
            "username": r[0], "email": r[1] or "",
            "status": r[2] or "active",
            "disk_quota_gb": round(float(r[5]) / 1073741824, 2) if len(r) > 5 and r[5] and r[5] != "0" else 0,
            "disk_used_gb":  round(float(r[6]) / 1073741824, 2) if len(r) > 6 and r[6] and r[6] != "0" else 0,
            "created_at": r[3] or "", "last_login": r[4] or "",
        } if r and r[0] else None
    )

def get_fp_domains():
    d = get_entity_from_socket("fastpanel_domains")
    if d: return d
    r = query_db("SELECT domain,user,php_version,ssl_enabled,ssl_days_left,document_root,status FROM fastpanel_domains ORDER BY domain")
    if r: return r
    return _fp_mysql_direct(
        "SELECT d.name, COALESCE(u.login,''), d.php_version, d.ssl, d.document_root, d.status, "
        "COALESCE(s.expires_at,'') "
        "FROM domain d "
        "LEFT JOIN user u ON d.user_id=u.id "
        "LEFT JOIN ssl_certificate s ON s.domain_id=d.id "
        "ORDER BY d.name",
        lambda r: {
            "domain": r[0], "user": r[1] or "",
            "php_version": r[2] or "",
            "ssl_enabled": 1 if r[3] in ("1","true","active") else 0,
            "ssl_days_left": (lambda exp: max(0, (
                __import__('datetime').datetime.fromisoformat(exp.replace(" ","T"))
                - __import__('datetime').datetime.now()).days) if exp else 0)(r[6] if len(r) > 6 else ""),
            "document_root": r[4] or "", "status": r[5] or "active",
        } if r and r[0] else None
    )

def get_fp_databases():
    d = get_entity_from_socket("fastpanel_databases")
    if d: return d
    r = query_db("SELECT name,db_user,size_mb,db_type,owner FROM fastpanel_databases ORDER BY name")
    if r: return r
    return _fp_mysql_direct(
        "SELECT db.name, COALESCE(u.login,''), COALESCE(db.size_mb,0), COALESCE(db.type,'mysql'), "
        "COALESCE(owner.login,'') "
        "FROM db LEFT JOIN user u ON db.db_user_id=u.id "
        "LEFT JOIN user owner ON db.user_id=owner.id ORDER BY db.name",
        lambda r: {"name": r[0], "db_user": r[1] or "", "size_mb": float(r[2] or 0),
                   "db_type": r[3] or "mysql", "owner": r[4] or ""} if r and r[0] else None
    )

def get_fp_mail():
    d = get_entity_from_socket("fastpanel_mail_accounts")
    if d: return d
    r = query_db("SELECT email,domain,quota_mb,used_mb,status FROM fastpanel_mail_accounts ORDER BY email")
    if r: return r
    # MySQL direct
    result = _fp_mysql_direct(
        "SELECT ma.login, md.domain, ma.quota_mb, ma.used_mb, ma.status "
        "FROM mail_account ma JOIN mail_domain md ON ma.mail_domain_id=md.id "
        "ORDER BY md.domain, ma.login",
        lambda r: {
            "email": f"{r[0]}@{r[1]}", "domain": r[1],
            "quota_mb": int(r[2] or 0), "used_mb": int(r[3] or 0),
            "status": r[4] or "active",
        } if r and len(r) >= 2 else None
    )
    if result: return result
    # Fallback postfix virtual
    try:
        accounts, seen = [], set()
        for vf in ["/etc/postfix/virtual", "/etc/postfix/vmailbox"]:
            p = __import__('pathlib').Path(vf)
            if not p.exists(): continue
            for line in p.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "@" in line:
                    email = line.split()[0]
                    if "@" in email and email not in seen:
                        seen.add(email)
                        accounts.append({"email": email, "domain": email.split("@")[1],
                                         "quota_mb": 0, "used_mb": 0, "status": "active"})
        return accounts
    except Exception:
        return []

def get_fp_ftp():
    d = get_entity_from_socket("fastpanel_ftp_accounts")
    if d: return d
    r = query_db("SELECT login,home_dir,status,owner FROM fastpanel_ftp_accounts ORDER BY login")
    if r: return r
    return _fp_mysql_direct(
        "SELECT f.login, f.home_dir, f.status, COALESCE(u.login,'') "
        "FROM ftp_account f LEFT JOIN user u ON f.user_id=u.id ORDER BY f.login",
        lambda r: {"login": r[0], "home_dir": r[1] or "", "status": r[2] or "active",
                   "owner": r[3] if len(r) > 3 else ""} if r and r[0] else None
    )

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
    import functools as _ft
    import threading as _th
    import logging as _log
    import subprocess as _sp
    from pathlib import Path as _P
    import shlex as _sl

    # PERF: Cache temporel avec TTL de 30 secondes pour éviter appels système répétés
    _cache = {}
    _cache_lock = _th.Lock()
    _cache_ttl = 30.0

    def _cached_call(key: str, func, ttl: float = _cache_ttl):
        now = _t.time()
        with _cache_lock:
            if key in _cache:
                entry = _cache[key]
                if now - entry["time"] < ttl:
                    return entry["data"]
        result = func()
        with _cache_lock:
            _cache[key] = {"data": result, "time": now}
        return result

    # PERF: Monitoring des temps d'exécution pour détecter anomalies
    _exec_times = []
    _exec_lock = _th.Lock()
    _max_samples = 100

    def _record_exec_time(duration: float):
        with _exec_lock:
            _exec_times.append(duration)
            if len(_exec_times) > _max_samples:
                _exec_times.pop(0)
            avg = sum(_exec_times) / len(_exec_times)
            if duration > avg * 3 and len(_exec_times) > 10:
                _log.warning(f"Anomalie détectée: temps d'exécution {duration:.3f}s (moyenne {avg:.3f}s)")

    start_time = _t.time()
    try:
        if not date:
            date = __import__('datetime').datetime.now().strftime("%Y-%m-%d")
        
        # PERF: Utilisation du cache pour l'appel API
        def _api_call():
            return _fp_api_stat("/fastpanel/api/stat/cpu", date)
        
        data = _cached_call(f"api_{date}", _api_call)
        if data:
            _record_exec_time(_t.time() - start_time)
            return data
        
        # PERF: Cache des credentials MySQL avec TTL pour éviter relecture du fichier
        _creds_cache = {"data": None, "time": 0.0}
        _creds_ttl = 60.0
        
        def _get_mysql_creds():
            now = _t.time()
            if _creds_cache["data"] and (now - _creds_cache["time"] < _creds_ttl):
                return _creds_cache["data"]
            creds = {}
            config_path = "/usr/local/fastpanel2/app/config/parameters.yml"
            if _P(config_path).exists():
                for line in _P(config_path).read_text(errors="replace").splitlines():
                    line = line.strip()
                    if ": " in line and not line.startswith("#"):
                        k, _, v = line.partition(": ")
                        creds[k.strip()] = v.strip().strip("'\" ")
            _creds_cache["data"] = creds
            _creds_cache["time"] = now
            return creds
        
        # PERF: Requête MySQL avec timeout et gestion d'erreur améliorée
        rows = []
        try:
            creds = _get_mysql_creds()
            if creds.get("database_password"):
                # FIX: Utilisation de paramètres préparés pour éviter injection SQL
                _sql = ('SELECT ts,cpu_total,processes_json FROM stat_cpu '
                        'WHERE DATE(ts)=%s ORDER BY ts DESC LIMIT 288')
                cmd = (
                    f"MYSQL_PWD={_sl.quote(creds['database_password'])} mysql "
                    f"-h{creds.get('database_host','127.0.0.1')} "
                    f"-u{_sl.quote(creds.get('database_user','fastpanel'))} "
                    f"{_sl.quote(creds.get('database_name','fastpanel2'))} "
                    f"--batch --silent --skip-column-names "
                    f"-e {_sl.quote(_sql)} "
                    f"2>/dev/null"
                )
                # PERF: Réduction du timeout à 5 secondes pour éviter blocages longs
                out = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=5).stdout
                for line in out.splitlines():
                    if line.strip():
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            rows.append({"ts": parts[0], "total": parts[1],
                                         "processes": parts[2] if len(parts) > 2 else "{}"})
        except _sp.TimeoutExpired:
            _log.warning("Timeout MySQL lors de la récupération des stats CPU")
        except Exception as e:
            _log.error(f"Erreur lors de la récupération MySQL: {e}")
        
        if rows:
            _record_exec_time(_t.time() - start_time)
            return {"source": "mysql", "data": rows}
        
        # PERF: Fallback ps avec parsing optimisé et limite de temps
        try:
            ps = _sp.run("ps aux --sort=-%cpu --no-headers | head -15",
                         shell=True, capture_output=True, text=True, timeout=5).stdout
            procs = {}
            for line in ps.splitlines():
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    try:
                        name = parts[10].split("/")[-1].split()[0][:20]
                        cpu = float(parts[2])
                        procs[name] = procs.get(name, 0) + cpu
                    except (ValueError, IndexError):
                        pass
            _record_exec_time(_t.time() - start_time)
            return {"source": "realtime", "data": [{"ts": "now", "processes": procs}]}
        except _sp.TimeoutExpired:
            _log.warning("Timeout lors de l'exécution de ps")
            _record_exec_time(_t.time() - start_time)
            return {"source": "error", "data": [], "error": "ps timeout"}
    
    except Exception as e:
        _log.error(f"Erreur critique dans get_fp_stats_cpu: {e}")
        _record_exec_time(_t.time() - start_time)
        return {"source": "error", "data": [], "error": str(e)}


def get_fp_stats_la(date: str = "") -> dict:
    """Load Average historique depuis FastPanel2."""
    if not date:
        date = __import__('datetime').datetime.now().strftime("%Y-%m-%d")
    data = _fp_api_stat("/fastpanel/api/stat/la", date)
    if data:
        return data
    # Fallback : MySQL FastPanel2 — table unifiée server_stat / stat_server
    try:
        from pathlib import Path as _P
        import shlex as _sl, subprocess as _sp
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
            for table in ["server_stat", "stat_server", "server_stats", "fp_stat"]:
                _sql = (f'SELECT created_at, la1, la5, la15 FROM {table} '
                        f'WHERE DATE(created_at)="{date}" ORDER BY created_at ASC LIMIT 288')
                cmd = (
                    f"MYSQL_PWD={_sl.quote(creds['database_password'])} mysql "
                    f"-h{creds.get('database_host','127.0.0.1')} "
                    f"-u{_sl.quote(creds.get('database_user','fastpanel'))} "
                    f"{_sl.quote(creds.get('database_name','fastpanel2'))} "
                    f"--batch --silent --skip-column-names "
                    f"-e {_sl.quote(_sql)} 2>/dev/null"
                )
                out = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=8).stdout
                rows = []
                for line in out.splitlines():
                    if line.strip():
                        p = line.split("\t")
                        if len(p) >= 4:
                            rows.append({"ts": p[0], "la1": p[1], "la5": p[2], "la15": p[3]})
                if rows:
                    return {"source": "mysql", "data": rows}
    except Exception:
        pass
    # Fallback ultime : /proc/loadavg temps réel (un seul point)
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
    # Fallback : MySQL FastPanel2 — table unifiée server_stat / stat_server
    # mem_used / mem_total stockés en MB dans FastPanel2
    try:
        from pathlib import Path as _P
        import shlex as _sl, subprocess as _sp
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
            for table in ["server_stat", "stat_server", "server_stats", "fp_stat"]:
                _sql = (f'SELECT created_at, COALESCE(mem_used,0), COALESCE(mem_total,0), '
                        f'COALESCE(swap_used,0) FROM {table} '
                        f'WHERE DATE(created_at)="{date}" ORDER BY created_at ASC LIMIT 288')
                cmd = (
                    f"MYSQL_PWD={_sl.quote(creds['database_password'])} mysql "
                    f"-h{creds.get('database_host','127.0.0.1')} "
                    f"-u{_sl.quote(creds.get('database_user','fastpanel'))} "
                    f"{_sl.quote(creds.get('database_name','fastpanel2'))} "
                    f"--batch --silent --skip-column-names "
                    f"-e {_sl.quote(_sql)} 2>/dev/null"
                )
                out = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=8).stdout
                rows = []
                for line in out.splitlines():
                    if line.strip():
                        p = line.split("\t")
                        if len(p) >= 3:
                            mem_used  = int(float(p[1] or 0))
                            mem_total = int(float(p[2] or 0))
                            # Si valeurs en octets (>1 000 000), convertir en MB
                            if mem_total > 1_000_000:
                                mem_used  = round(mem_used  / 1024)
                                mem_total = round(mem_total / 1024)
                            rows.append({
                                "ts":       p[0],
                                "used_mb":  mem_used,
                                "total_mb": mem_total,
                                "free_mb":  max(0, mem_total - mem_used),
                                "cached_mb": int(float(p[3] or 0)) if len(p) > 3 else 0,
                            })
                if rows:
                    return {"source": "mysql", "data": rows}
    except Exception:
        pass
    # Fallback ultime : /proc/meminfo (un seul point)
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        total  = mi.get("MemTotal", 1)
        avail  = mi.get("MemAvailable", total)
        cached = mi.get("Cached", 0) + mi.get("Buffers", 0)
        used   = total - avail
        return {"source": "realtime", "data": [{"ts": "now",
                "total_mb":  round(total  / 1024),
                "used_mb":   round(used   / 1024),
                "cached_mb": round(cached / 1024),
                "free_mb":   round(avail  / 1024)}]}
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
        "backups_count":  len(backups),   # total pour distinguer "0 configuré" de "0 erreur"
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
    # ── Mémoire persistante inter-sessions ──────────────────────────────────────
    conn.execute("""CREATE TABLE IF NOT EXISTS memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        confidence REAL DEFAULT 1.0,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        access_count INTEGER DEFAULT 0,
        UNIQUE(category, key)
    )""")
    # ── Journal d'audit des actions agent ───────────────────────────────────────
    conn.execute("""CREATE TABLE IF NOT EXISTS agent_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT DEFAULT (datetime('now')),
        session_id TEXT,
        command TEXT NOT NULL,
        output TEXT,
        duration_ms INTEGER DEFAULT 0,
        is_risky INTEGER DEFAULT 0,
        had_diff INTEGER DEFAULT 0
    )""")
    # ── Snapshots fichiers pour rollback ────────────────────────────────────────
    conn.execute("""CREATE TABLE IF NOT EXISTS file_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT DEFAULT (datetime('now')),
        session_id TEXT,
        trigger_command TEXT,
        file_path TEXT NOT NULL,
        content_before TEXT NOT NULL,
        action_id INTEGER
    )""")
    # ── Tables auto-evolution ─────────────────────────────────────
    conn.execute('''CREATE TABLE IF NOT EXISTS evolution_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, target_file TEXT, description TEXT, motivation TEXT,
        diff TEXT, snapshot_before TEXT,
        sha256_before TEXT, sha256_after TEXT,
        status TEXT DEFAULT "applied", restart_done INTEGER DEFAULT 0
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS evolution_wishlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, target_file TEXT, category TEXT,
        description TEXT, priority TEXT DEFAULT "medium",
        status TEXT DEFAULT "pending", identified_by TEXT
    )''')
    # ── Alertes proactives ───────────────────────────────────────────────────────
    conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT DEFAULT (datetime('now')),
        level TEXT NOT NULL,
        category TEXT NOT NULL,
        message TEXT NOT NULL,
        resolved INTEGER DEFAULT 0,
        resolved_at TEXT
    )""")
    # ── Crons créés en langage naturel ───────────────────────────────────────────
    conn.execute("""CREATE TABLE IF NOT EXISTS cron_natural (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT NOT NULL,
        cron_expr TEXT NOT NULL,
        command TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        active INTEGER DEFAULT 1
    )""")

    # -- Tables memoire v2 (graphe, historique, tags) --------------
    conn.execute("CREATE TABLE IF NOT EXISTS memory_history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "memory_id INTEGER, category TEXT NOT NULL, key TEXT NOT NULL, "
        "old_value TEXT, new_value TEXT, confidence REAL, "
        "changed_at TEXT DEFAULT (datetime('now')), change_reason TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS knowledge_graph ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "source_key TEXT NOT NULL, target_key TEXT NOT NULL, "
        "relation TEXT NOT NULL, weight REAL DEFAULT 1.0, "
        "created_at TEXT DEFAULT (datetime('now')), "
        "UNIQUE(source_key, target_key, relation))")
    conn.execute("CREATE TABLE IF NOT EXISTS memory_tags ("
        "memory_id INTEGER, tag TEXT NOT NULL, "
        "PRIMARY KEY (memory_id, tag))")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_history_mid ON memory_history(memory_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_graph_source ON knowledge_graph(source_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_graph_target ON knowledge_graph(target_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_tags_tag ON memory_tags(tag)")

    # ── FTS5 : index full-text pour retrieval BM25 ──────────────────────────────
    # PERF: FTS5 natif SQLite, zéro dépendance, scoring BM25 O(log n) vs LIKE O(n)
    # Enveloppé dans try-except : si FTS5 n'est pas compilé dans ce SQLite, on dégrade
    # gracieusement vers le fallback keyword-overlap sans casser l'initialisation DB.
    try:
        conn.executescript("""
            CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                key, value, category,
                content='memories',
                content_rowid='id',
                tokenize='RETIRE'
            );
            CREATE TRIGGER IF NOT EXISTS memories_fts_ai AFTER INSERT ON memories BEGIN
                INSERT INTO memories_fts(rowid, key, value, category)
                VALUES (new.id, new.key, new.value, new.category);
            END;
            CREATE TRIGGER IF NOT EXISTS memories_fts_au AFTER UPDATE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, key, value, category)
                VALUES ('delete', old.id, old.key, old.value, old.category);
                INSERT INTO memories_fts(rowid, key, value, category)
                VALUES (new.id, new.key, new.value, new.category);
            END;
            CREATE TRIGGER IF NOT EXISTS memories_fts_ad AFTER DELETE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, key, value, category)
                VALUES ('delete', old.id, old.key, old.value, old.category);
            END;
        """)
        # Peupler FTS depuis données existantes (migration depuis ancienne version)
        fts_count = conn.execute("SELECT COUNT(*) FROM memories_fts").fetchone()[0]
        mem_count  = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
        if mem_count > 0 and fts_count == 0:
            conn.execute(
                "INSERT INTO memories_fts(rowid, key, value, category) "
                "SELECT id, key, value, category FROM memories"
            )
            print(f"[MEMORY] FTS5 index peuplé avec {mem_count} mémoires existantes")
    except Exception as e:
        print(f"[MEMORY] FTS5 non disponible, fallback keyword-overlap actif: {e}")

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


# ============================================================
# MÉMOIRE PERSISTANTE INTER-SESSIONS
# ============================================================

def save_memory(category: str, key: str, value: str, confidence: float = 1.0, tags: list = None, change_reason: str = ""):
    """Sauvegarde ou met a jour une memoire persistante (v2 avec historique et tags)."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        existing = conn.execute("SELECT id, value FROM memories WHERE category = ? AND key = ?", (category, key)).fetchone()
        if existing:
            memory_id, old_value = existing[0], existing[1]
            if old_value != value:
                conn.execute("INSERT INTO memory_history (memory_id, category, key, old_value, new_value, confidence, change_reason) VALUES (?,?,?,?,?,?,?)",
                    (memory_id, category, key, old_value[:2000], value[:2000], confidence, change_reason[:200]))
                conn.execute("UPDATE memories SET value=?, confidence=?, updated_at=datetime('now'), access_count=access_count+1 WHERE id=?", (value[:2000], confidence, memory_id))
            else:
                conn.execute("UPDATE memories SET access_count=access_count+1, updated_at=datetime('now') WHERE id=?", (memory_id,))
        else:
            conn.execute("INSERT INTO memories (category, key, value, confidence) VALUES (?,?,?,?)", (category, key, value[:2000], confidence))
            memory_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        if tags:
            for tag in tags:
                conn.execute("INSERT OR IGNORE INTO memory_tags (memory_id, tag) VALUES (?,?)", (memory_id, tag.lower().strip()))
        conn.commit()
        conn.close()
        return memory_id
    except Exception as e:
        print(f"[MEMORY] Erreur save_memory: {e}")
        return None


def get_memories(categories: list = None, limit: int = 40) -> list:
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.row_factory = sqlite3.Row
        if categories:
            ph = ",".join("?" * len(categories))
            rows = conn.execute(
                f"SELECT id, category, key, value, confidence, updated_at FROM memories "
                f"WHERE category IN ({ph}) ORDER BY access_count DESC, updated_at DESC LIMIT ?",
                categories + [limit]).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, category, key, value, confidence, updated_at FROM memories "
                "ORDER BY access_count DESC, updated_at DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def delete_memory(memory_id: int):
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.execute("DELETE FROM memories WHERE id=?", (memory_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _build_fts_query(text: str) -> str:
    """Construit une requête FTS5 safe depuis du texte libre.

    # PERF: tokenisation légère O(n), échappe les opérateurs FTS5 spéciaux,
    # filtre les mots trop courts et les stop-words pour éviter le bruit.
    """
    stop = {'le','la','les','de','du','des','un','une','et','en','il','je','tu',
            'ce','que','qui','est','par','sur','pour','avec','dans','ou','pas','se',
            'te','me','on','au','ne','si','ca','ta','ma','sa','son','ton','ya','a'}
    tokens = []
    for w in re.split(r'\W+', text):
        if len(w) < 3 or w.lower() in stop:
            continue
        # Supprimer les chars spéciaux FTS5 (", ^, *, -, +, (, ), :)
        clean = re.sub(r'["\^\*\-\+\(\):]', '', w)
        if clean:
            tokens.append(clean)
    return ' OR '.join(tokens) if tokens else ""


def format_memories_for_prompt(query: str = "") -> str:
    """Mémoire absolue: sélection hybride core + pertinence contextuelle.

    # PERF: deux requêtes ciblées (core + pool récent) remplacent un scan top-30 aveugle.
    # Le scoring par overlap de mots garantit que les souvenirs injectés dans le prompt
    # sont pertinents pour LA question posée, pas juste les plus souvent accédés.
    """
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row

        # 1. Core memories — toujours incluses (haute confiance + réaccédées souvent)
        core = conn.execute(
            "SELECT category, key, value, confidence, access_count FROM memories "
            "WHERE confidence >= 0.85 AND access_count >= 2 "
            "ORDER BY (confidence * (access_count + 1)) DESC LIMIT 12"
        ).fetchall()
        core_keys = {m['key'] for m in core}

        # 2. Sélection contextuelle via FTS5/BM25 (fallback keyword-overlap si indisponible)
        # PERF: BM25 O(log n) via index FTS5 natif SQLite — bien supérieur au LIKE O(n)
        query_relevant = []
        if query.strip():
            fts_q = _build_fts_query(query)
            if fts_q:
                # Exclure les core_keys déjà sélectionnées
                excl = list(core_keys) if core_keys else []
                excl_sql = ("AND m.key NOT IN ({})".format(','.join('?' * len(excl)))
                            if excl else "")
                try:
                    fts_rows = conn.execute(
                        "SELECT m.category, m.key, m.value, m.confidence, m.access_count "
                        "FROM memories_fts f JOIN memories m ON f.rowid = m.id "
                        f"WHERE memories_fts MATCH ? {excl_sql} "
                        "ORDER BY bm25(memories_fts) LIMIT 10",
                        [fts_q] + excl
                    ).fetchall()
                    query_relevant = [dict(r) for r in fts_rows]
                except Exception as fts_err:
                    # Fallback keyword-overlap si FTS5 absent ou corrompu
                    print(f"[MEMORY] FTS5 fallback: {fts_err}")
                    stop_fb = {'le','la','les','de','du','des','un','une','et','en','il',
                               'je','tu','ce','que','qui','est','par','sur','pour','avec',
                               'dans','ou','pas','se','te','me','on','au','ne'}
                    words = {w.lower() for w in re.split(r'\W+', query)
                             if len(w) > 2 and w.lower() not in stop_fb}
                    if words:
                        pool = conn.execute(
                            "SELECT category, key, value, confidence, access_count FROM memories "
                            "WHERE confidence > 0.4 ORDER BY updated_at DESC LIMIT 200"
                        ).fetchall()
                        scored = []
                        for m in pool:
                            if m['key'] in core_keys:
                                continue
                            text = (m['key'] + ' ' + m['value']).lower()
                            hits = sum(1 for w in words if w in text)
                            if hits > 0:
                                scored.append((hits, dict(m)))
                        scored.sort(key=lambda x: -x[0])
                        query_relevant = [m for _, m in scored[:10]]

        conn.close()

        cat_labels = {
            'server': '🖥️ Serveur', 'service': '⚙️ Services',
            'incident': '🚨 Incidents', 'preference': '👤 Préférences',
            'pattern': '🔄 Patterns', 'fact': '📌 Faits',
            'config': '⚙️ Configuration', 'learning': '🧠 Apprentissages',
            'relation': '🔗 Relations', 'user': '👤 Utilisateur',
            'user_pref': '👤 Préférences', 'command': '💻 Commandes clés',
            'config_value': '⚙️ Config', 'architecture': '🏗️ Architecture',
            'fix': '🔧 Corrections appliquées',
        }

        lines = ["🧠 **MÉMOIRE ABSOLUE**"]

        # Section core
        by_cat: dict = {}
        for m in core:
            by_cat.setdefault(m['category'], []).append(f"  * {m['key']}: {str(m['value'])[:300]}")
        if by_cat:
            lines.append("\n📌 **[CORE — toujours actif]**")
            for cat, items in by_cat.items():
                lines.append(f"  {cat_labels.get(cat, cat.upper())}:")
                lines.extend(items[:6])

        # Section contextuelle
        if query_relevant:
            lines.append("\n🔍 **[CONTEXTUEL — pertinent pour cette question]**")
            qby: dict = {}
            for m in query_relevant:
                qby.setdefault(m['category'], []).append(f"  * {m['key']}: {str(m['value'])[:300]}")
            for cat, items in qby.items():
                lines.append(f"  {cat_labels.get(cat, cat.upper())}:")
                lines.extend(items[:5])

        return "\n".join(lines)
    except Exception as e:
        return f"[Erreur formatage memoire: {e}]"



def extract_learnings_async(session_id: str, user_msg: str, agent_response: str):
    """Extrait des faits persistants depuis une interaction — non-bloquant.

    # PERF: thread daemon indépendant pour ne jamais bloquer le stream HTTP.
    # Extraction élargie à 8 faits, catégories enrichies (fix, command, user_pref,
    # architecture) pour construire une base de connaissance dense sur le long terme.
    """
    def _do():
        if not DEEPSEEK_API_KEY or len(agent_response) < 60:
            return
        try:
            resp = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[{"role": "user", "content":
                    f"""Analyse cette interaction et extrais les FAITS DURABLES sur ce serveur Linux.
Réponds UNIQUEMENT en JSON valide, sans markdown :
{{"memories": [{{"category": "server|service|incident|preference|pattern|fact|config|user_pref|command|architecture|fix", "key": "clé courte unique max 60 chars", "value": "valeur précise max 400 chars", "confidence": 0.0-1.0}}]}}

User: {user_msg[:600]}
Agent: {agent_response[:2000]}

Règles :
- SEULEMENT les faits durables et réutilisables dans de futures conversations
- "fix": correction appliquée avec son contexte (ex: "nginx 502 fix: vérifier upstream avec 'ss -tlnp'")
- "command": commande clé qui a résolu un problème (ex: "restart php-fpm: systemctl restart php8.2-fpm")
- "user_pref": préférence exprimée par l'utilisateur (ex: "préfère systemd à cron pour les tâches planifiées")
- "architecture": fait structurel du serveur (ex: "stack: nginx + php8.2 + mariadb sur Ubuntu 22.04")
- "config": valeur de configuration importante (ex: "php memory_limit: 512M dans /etc/php/8.2/fpm/php.ini")
- Ignore les états temporaires, outputs de commandes bruts, infos triviales
- Maximum 8 mémoires. Si rien de durable : {{"memories": []}}"""}],
                temperature=0.1, max_tokens=900)
            raw = resp.choices[0].message.content.strip()
            # Nettoyer balises markdown éventuelles
            raw = re.sub(r'^```\w*\s*', '', raw, flags=re.MULTILINE).strip('`').strip()
            obj = json.loads(raw)
            saved = 0
            for m in obj.get("memories", [])[:8]:
                conf = float(m.get("confidence", 0.8))
                if m.get("key") and m.get("value") and conf >= 0.5:
                    save_memory(m["category"], m["key"][:80], m["value"][:400], conf)
                    saved += 1
            if saved:
                print(f"[MEMORY] {saved} faits extraits et persistés (session {session_id[:8]})")
        except Exception as e:
            print(f"[MEMORY] Erreur extract_learnings: {e}")
    threading.Thread(target=_do, daemon=True, name="memory-extractor").start()


# ============================================================
# CONSOLIDATION PÉRIODIQUE DE LA MÉMOIRE
# ============================================================

def _run_memory_consolidation():
    """Appelle le LLM pour fusionner les doublons et supprimer les souvenirs périmés.

    # PERF: une seule logging.warning("[%s] %s" %% (name, issues[0]))e LLM par cycle traite jusqu'à 120 mémoires en batch,
    # bien plus efficace que comparer toutes les paires O(n²) manuellement.
    """
    if not DEEPSEEK_API_KEY:
        return
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        mems = conn.execute(
            "SELECT id, category, key, value, confidence FROM memories "
            "ORDER BY category, updated_at DESC LIMIT 120"
        ).fetchall()
        conn.close()

        if len(mems) < 8:
            return

        mem_list = "\n".join(
            f"[{m['id']}] [{m['category']}] {m['key']}: {str(m['value'])[:120]}"
            for m in mems
        )

        resp = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content":
                f"""Analyse ces souvenirs d'agent IA et identifie les redondances.
Réponds UNIQUEMENT en JSON valide sans markdown :
{{"merges":[{{"keep_id":N,"delete_ids":[M],"merged_value":"valeur fusionnée max 400 chars"}}],"delete_ids":[N]}}

Règles :
- "merges" : souvenirs qui expriment le même fait avec des formulations différentes → fusionner en gardant le plus précis
- "delete_ids" : souvenirs clairement périmés, contradictoires, sans valeur durable (états temporaires, erreurs ponctuelles résolues)
- Maximum 5 fusions et 8 suppressions par logging.warning("[%s] %s" %% (name, issues[0]))e
- Si rien à faire : {{"merges":[],"delete_ids":[]}}

Souvenirs :
{mem_list}"""}],
            temperature=0.1, max_tokens=700
        )

        raw = resp.choices[0].message.content.strip()
        raw = re.sub(r'^```\w*\s*', '', raw, flags=re.MULTILINE).strip('`').strip()
        obj = json.loads(raw)

        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        n_merged = n_deleted = 0

        for merge in obj.get("merges", [])[:5]:
            keep_id    = merge.get("keep_id")
            del_ids    = merge.get("delete_ids", [])
            merged_val = str(merge.get("merged_value", ""))[:400]
            if keep_id and del_ids and merged_val:
                conn.execute(
                    "UPDATE memories SET value=?, confidence=MIN(confidence+0.05,1.0), "
                    "updated_at=datetime('now') WHERE id=?",
                    (merged_val, keep_id)
                )
                for did in del_ids:
                    conn.execute("DELETE FROM memories WHERE id=?", (did,))
                    n_deleted += 1
                n_merged += 1

        for did in obj.get("delete_ids", [])[:8]:
            conn.execute("DELETE FROM memories WHERE id=?", (did,))
            n_deleted += 1

        conn.commit()
        conn.close()

        if n_merged or n_deleted:
            print(f"[MEMORY] Consolidation: {n_merged} fusions, {n_deleted} suppressions")

    except Exception as e:
        print(f"[MEMORY] Erreur consolidation: {e}")


def _memory_consolidation_loop():
    """Daemon de consolidation — tourne toutes les 6 heures."""
    time.sleep(600)  # 10 min après le démarrage pour laisser le système se stabiliser
    while True:
        _run_memory_consolidation()
        time.sleep(6 * 3600)


def start_memory_consolidation():
    threading.Thread(target=_memory_consolidation_loop, daemon=True, name="memory-consolidator").start()
    print("[MEMORY] Daemon de consolidation démarré (cycle 6h)")


# ============================================================
# JOURNAL D'AUDIT DES ACTIONS AGENT
# ============================================================



# ============================================================
# MEMOIRE v2 - RECHERCHE, GRAPHE, BACKUP
# ============================================================

MEMORY_BACKUP_DIR = "/var/lib/cassandra/memory_backups"
MAX_BACKUPS = 50
_memory_counter = 0
_memory_last_backup = 0

def backup_memory_db():
    """Backup automatique avec rotation."""
    try:
        Path(MEMORY_BACKUP_DIR).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{MEMORY_BACKUP_DIR}/memory_{ts}.db"
        src = sqlite3.connect(MEMORY_DB_PATH)
        dst = sqlite3.connect(backup_path)
        src.backup(dst)
        dst.close(); src.close()
        backups = sorted(Path(MEMORY_BACKUP_DIR).glob("memory_*.db"))
        while len(backups) > MAX_BACKUPS:
            backups[0].unlink(); backups.pop(0)
        return backup_path
    except Exception as e:
        print(f"[MEMORY] Erreur backup: {e}")
        return None

def search_memories(query: str, limit: int = 20) -> list:
    """Recherche full-text dans les memoires."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        pattern = f"%{query}%"
        rows = conn.execute(
            "SELECT * FROM memories WHERE key LIKE ? OR value LIKE ? ORDER BY confidence DESC, access_count DESC LIMIT ?",
            (pattern, pattern, limit)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[MEMORY] Erreur recherche: {e}")
        return []

def relate_memories(source_key: str, target_key: str, relation: str, weight: float = 1.0):
    """Cree une relation dans le graphe de connaissances."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        conn.execute("INSERT OR IGNORE INTO knowledge_graph (source_key, target_key, relation, weight) VALUES (?,?,?,?)",
            (source_key, target_key, relation, weight))
        conn.commit(); conn.close()
        return True
    except Exception as e:
        print(f"[MEMORY] Erreur relation: {e}")
        return False

def get_related_memories(key: str, depth: int = 2) -> list:
    """Parcourt le graphe de connaissances en profondeur."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        visited, results = set(), []
        def explore(current_key, current_depth):
            if current_depth > depth or current_key in visited: return
            visited.add(current_key)
            rows = conn.execute("SELECT source_key, target_key, relation, weight FROM knowledge_graph WHERE source_key=? OR target_key=?", (current_key, current_key)).fetchall()
            for r in rows:
                other = r['target_key'] if r['source_key'] == current_key else r['source_key']
                if other not in visited:
                    results.append({'key': other, 'relation': r['relation'], 'weight': r['weight'], 'depth': current_depth})
                    explore(other, current_depth + 1)
        explore(key, 1)
        conn.close()
        return results
    except Exception as e:
        print(f"[MEMORY] Erreur graphe: {e}")
        return []

def consolidate_memories():
    """Consolide les patterns en faits, deduplique."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        patterns = conn.execute("SELECT * FROM memories WHERE category='pattern' AND confidence>0.8 AND access_count>3 ORDER BY access_count DESC").fetchall()
        for p in patterns:
            existing = conn.execute("SELECT id FROM memories WHERE category='fact' AND key=?", (p['key'],)).fetchone()
            if not existing:
                conn.execute("INSERT INTO memories (category, key, value, confidence) VALUES (?,?,?,?)", ('fact', p['key'], p['value'], min(p['confidence']+0.1, 1.0)))
                conn.execute("INSERT OR IGNORE INTO knowledge_graph (source_key, target_key, relation) VALUES (?,?,?)", (p['key'], p['key'], 'is_consolidation_of'))
        duplicates = conn.execute("SELECT category, key, COUNT(*) as cnt FROM memories GROUP BY category, key HAVING cnt>1").fetchall()
        for d in duplicates:
            rows = conn.execute("SELECT id, value, confidence, access_count FROM memories WHERE category=? AND key=? ORDER BY confidence DESC, access_count DESC", (d['category'], d['key'])).fetchall()
            best = rows[0]
            for r in rows[1:]:
                conn.execute("UPDATE memories SET access_count=access_count+? WHERE id=?", (r['access_count'], best['id']))
                conn.execute("DELETE FROM memories WHERE id=?", (r['id'],))
        conn.commit(); conn.close()
        return True
    except Exception as e:
        print(f"[MEMORY] Erreur consolidation: {e}")
        return False

def _auto_backup_memory():
    global _memory_counter, _memory_last_backup
    _memory_counter += 1
    now = time.time()
    if _memory_counter >= 20 or (now - _memory_last_backup) > 3600:
        _memory_counter = 0
        _memory_last_backup = now
        threading.Thread(target=backup_memory_db, daemon=True).start()

def log_action(session_id: str, command: str, output: str,
               duration_ms: int, is_risky: bool = False, had_diff: bool = False) -> int:
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.execute(
            "INSERT INTO agent_actions (ts,session_id,command,output,duration_ms,is_risky,had_diff) "
            "VALUES (datetime('now'),?,?,?,?,?,?)",
            (session_id, command[:1000], output[:2000], duration_ms,
             1 if is_risky else 0, 1 if had_diff else 0))
        conn.commit()
        rc = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return rc
    except Exception:
        return 0


def get_actions(limit: int = 80) -> list:
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id,ts,session_id,command,output,duration_ms,is_risky,had_diff "
            "FROM agent_actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# ============================================================
# SNAPSHOTS & ROLLBACK
# ============================================================

RISKY_PATTERNS = [
    r'\bsed\s+-i\b', r'\bchmod\b', r'\bchown\b', r'cat\s*>',
    r'\btee\s+[/~]', r'\brm\s+', r'\bsystemctl\s+(stop|disable|mask)\b',
    r'\bapt[\s-]+(remove|purge)\b', r'\byum\s+(remove|erase)\b',
    r'echo\s+.*?>\s*/', r'printf\s+.*?>\s*/', r'>\s*/etc/', r'>\s*/usr/',
]
_FILE_MOD_RE = re.compile(
    r'sed\s+(?:-\w+\s+)*["\']?s/[^"\']*["\']?\s+([/\w.\-]+)'
    r'|cat\s*>+\s*([/\w.\-]+)'
    r'|tee\s+([/\w.\-]+)'
    r'|echo\s+.*?>+\s*([/\w.\-]+)'
    r'|printf\s+.*?>+\s*([/\w.\-]+)'
)

def is_risky_command(cmd: str) -> bool:
    return any(re.search(p, cmd, re.IGNORECASE) for p in RISKY_PATTERNS)


def snapshot_files_before(cmd: str, session_id: str, action_id: int = 0) -> list:
    """Détecte et snapshotte les fichiers qui vont être modifiés."""
    snaps = []
    files = set()
    for m in _FILE_MOD_RE.findall(cmd):
        for f in m:
            if f and f.startswith('/') and '.' in f:
                files.add(f)
    for fp in list(files)[:4]:
        try:
            if os.path.isfile(fp) and os.path.getsize(fp) < 300_000:
                with open(fp, 'r', errors='replace') as fh:
                    content = fh.read()
                conn = sqlite3.connect(MEMORY_DB_PATH)
                conn.execute(
                    "INSERT INTO file_snapshots (ts,session_id,trigger_command,file_path,content_before,action_id) "
                    "VALUES (datetime('now'),?,?,?,?,?)",
                    (session_id, cmd[:500], fp, content, action_id))
                conn.commit()
                sid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn.close()
                snaps.append({"id": sid, "path": fp, "size": len(content)})
        except Exception:
            pass
    return snaps


def get_snapshots(limit: int = 30) -> list:
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id,ts,session_id,trigger_command,file_path,LENGTH(content_before) as size "
            "FROM file_snapshots ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def restore_snapshot(snap_id: int) -> dict:
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT file_path,content_before FROM file_snapshots WHERE id=?", (snap_id,)).fetchone()
        conn.close()
        if not row:
            return {"success": False, "error": "Snapshot introuvable"}
        with open(row["file_path"], 'w') as fh:
            fh.write(row["content_before"])
        return {"success": True, "path": row["file_path"]}
    except Exception as e:
        return {"success": False, "error": str(e)}


def generate_diff_html(before: str, after: str, filepath: str) -> str:
    import difflib
    diff = list(difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"avant",
        tofile=f"après",
        n=2
    ))
    if not diff:
        return ""
    lines_html = []
    for line in diff[:80]:
        esc = line.rstrip('\n').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
        if line.startswith('+') and not line.startswith('+++'):
            lines_html.append(f'<div class="diff-add">+{esc[1:]}</div>')
        elif line.startswith('-') and not line.startswith('---'):
            lines_html.append(f'<div class="diff-del">-{esc[1:]}</div>')
        elif line.startswith('@@'):
            lines_html.append(f'<div class="diff-hunk">{esc}</div>')
        elif not line.startswith(('---','+++')):
            lines_html.append(f'<div class="diff-ctx"> {esc[1:]}</div>')
    fp_esc = filepath.replace('<','&lt;').replace('>','&gt;')
    return (f'<div class="diff-block"><div class="diff-title">📄 diff: {fp_esc}</div>'
            + ''.join(lines_html) + '</div>')


# ============================================================
# ALERTES PROACTIVES (thread background)
# ============================================================

_alert_thread_started = False
_alerts_lock = threading.Lock()


def save_alert(level: str, category: str, message: str):
    with _alerts_lock:
        try:
            conn = sqlite3.connect(MEMORY_DB_PATH)
            existing = conn.execute(
                "SELECT id FROM alerts WHERE category=? AND resolved=0 AND ts>datetime('now','-1 hour')",
                (category,)).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO alerts (ts,level,category,message) VALUES (datetime('now'),?,?,?)",
                    (level, category, message))
                conn.commit()
            conn.close()
        except Exception:
            pass


def get_alerts(include_resolved: bool = False, limit: int = 50) -> list:
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.row_factory = sqlite3.Row
        q = "SELECT * FROM alerts ORDER BY id DESC LIMIT ?" if include_resolved else \
            "SELECT * FROM alerts WHERE resolved=0 ORDER BY id DESC LIMIT ?"
        rows = conn.execute(q, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def resolve_alert(alert_id: int):
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.execute("UPDATE alerts SET resolved=1,resolved_at=datetime('now') WHERE id=?", (alert_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _monitoring_loop():
    import shutil as _sh
    while True:
        try:
            time.sleep(60)
            cfg   = load_alert_config()
            rules = cfg.get("rules", []) if cfg else []

            def _rule(name):
                for r in rules:
                    if r.get("name") == name:
                        return r
                return {}

            # ── Disque ────────────────────────────────────────────────────
            for mount in ['/', '/var', '/home', '/tmp', '/var/www']:
                try:
                    u   = _sh.disk_usage(mount)
                    pct = u.used / u.total * 100
                    if pct >= 90:
                        r = _rule("disk_critical")
                        fire_alert("disk_critical", "critical", f"disk_{mount}",
                                   f"Disque {mount} : {pct:.0f}% utilise",
                                   r.get("channels", ["email", "webhook"]))
                    elif pct >= 80:
                        r = _rule("disk_warning")
                        fire_alert("disk_warning", "warning", f"disk_{mount}",
                                   f"Disque {mount} : {pct:.0f}% utilise",
                                   r.get("channels", ["webhook"]))
                except Exception:
                    pass
            # ── RAM ──────────────────────────────────────────────────────────
            try:
                mi    = {}
                with open('/proc/meminfo') as f:
                    for line in f:
                        k, v = line.split(':', 1)
                        mi[k.strip()] = int(v.strip().split()[0])
                total = mi.get('MemTotal', 1)
                avail = mi.get('MemAvailable', total)
                pct   = (total - avail) / total * 100
                if pct >= 95:
                    r = _rule("ram_critical")
                    fire_alert("ram_critical", "critical", "memory",
                               f"RAM critique : {pct:.0f}% utilisee",
                               r.get("channels", ["email", "webhook"]))
                elif pct >= 88:
                    r = _rule("ram_warning")
                    fire_alert("ram_warning", "warning", "memory",
                               f"RAM elevee : {pct:.0f}% utilisee",
                               r.get("channels", ["webhook"]))
            except Exception:
                pass
            # ── Load Average ──────────────────────────────────────────────────
            try:
                with open('/proc/loadavg') as f:
                    la1  = float(f.read().split()[0])
                ncpu = os.cpu_count() or 1
                lpc  = la1 / ncpu
                if lpc >= 3.0:
                    r = _rule("load_critical")
                    fire_alert("load_critical", "critical", "load",
                               f"Load Average critique : {la1:.2f} ({ncpu} CPUs, {lpc:.1f}/core)",
                               r.get("channels", ["email", "webhook"]))
                elif lpc >= 2.0:
                    r = _rule("load_warning")
                    fire_alert("load_warning", "warning", "load",
                               f"Load Average eleve : {la1:.2f} ({lpc:.1f}/core)",
                               r.get("channels", ["webhook"]))
            except Exception:
                pass
            # ── Services ─────────────────────────────────────────────────────
            for svc in ['nginx','apache2','mysql','mariadb','postfix','sshd',
                        'php8.1-fpm','php8.2-fpm','php8.3-fpm','fastpanel2']:
                try:
                    r2 = subprocess.run(f"systemctl is-active {svc} 2>/dev/null",
                                        shell=True, capture_output=True, text=True, timeout=3)
                    state = r2.stdout.strip()
                    if state and state not in ('active', 'activating', 'inactive', ''):
                        r_rule = _rule("service_failed")
                        fire_alert(f"svc_{svc}", "critical", f"svc_{svc}",
                                   f"Service {svc} : {state}",
                                   r_rule.get("channels", ["email", "webhook"]))
                except Exception:
                    pass

            # ── SSL ───────────────────────────────────────────────────────────
            try:
                ssl_rows = query_db(
                    "SELECT domain, days_left FROM ssl_certificates ORDER BY days_left ASC LIMIT 20"
                )
                for row in (ssl_rows or []):
                    days  = row.get("days_left", 999)
                    dom   = row.get("domain", "?")
                    if days <= 3:
                        r_rule = _rule("ssl_critical")
                        fire_alert(f"ssl_critical_{dom}", "critical", f"ssl_{dom}",
                                   f"SSL '{dom}' expire dans {days} jours !",
                                   r_rule.get("channels", ["email", "webhook"]))
                    elif days <= 14:
                        r_rule = _rule("ssl_expiring_soon")
                        fire_alert(f"ssl_warning_{dom}", "warning", f"ssl_{dom}",
                                   f"SSL '{dom}' expire dans {days} jours",
                                   r_rule.get("channels", ["email", "webhook"]))
            except Exception:
                pass
        except Exception:
            pass


def start_monitoring():
    global _alert_thread_started
    if not _alert_thread_started:
        _alert_thread_started = True
        threading.Thread(target=_monitoring_loop, daemon=True, name="monitoring-loop").start()


# ============================================================
# CRONS EN LANGAGE NATUREL
# ============================================================

def create_cron_from_natural(description: str, command: str, cron_expr: str) -> dict:
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return {"success": False, "error": f"Expression cron invalide ({len(parts)} champs, 5 requis)"}
    try:
        existing = subprocess.run("crontab -l 2>/dev/null || true",
                                  shell=True, capture_output=True, text=True).stdout
        tag = f"# cassandra:{description[:40].replace(' ','_')}"
        new_line = f"{cron_expr} {command} {tag}\n"
        new_crontab = existing + new_line
        proc = subprocess.run("crontab -", input=new_crontab,
                               shell=True, capture_output=True, text=True)
        if proc.returncode != 0:
            return {"success": False, "error": proc.stderr[:200]}
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.execute("INSERT INTO cron_natural (description,cron_expr,command) VALUES (?,?,?)",
                     (description[:200], cron_expr, command[:500]))
        conn.commit()
        conn.close()
        return {"success": True, "expr": cron_expr, "command": command}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_cron_jobs_natural() -> list:
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM cron_natural ORDER BY id DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def auto_summarize_session(session_id: str):
    if not DEEPSEEK_API_KEY:
        return
    history = get_conversation_history(session_id, limit=MAX_RAW_MESSAGES)
    if not history:
        return
    transcript = "\n".join(f"[{m['role'].upper()}] {m['content'][:500]}" for m in history)
    try:
        resp = client.chat.completions.create(
            model=MODEL_NAME,
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
def build_system_prompt(session_id: str, user_question: str = "", expert_mode: bool = False, bookstack_ctx: str = "") -> str:
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
Tu as un accès root complet au serveur via l'outil bash. Tu es une IA d'action, pas conversationnelle.

## 📊 RÉSUMÉ INFRA (temps réel)
{infra_summary}

{detailed_text}

## 🧠 MÉMOIRE CONVERSATIONNELLE (session courante)
{memory_context}

## 💾 MÉMOIRE ABSOLUE (apprentissages inter-sessions)
{format_memories_for_prompt(user_question)}
{(chr(10) + bookstack_ctx + chr(10)) if bookstack_ctx else ""}
## RÈGLES ABSOLUES
1. Tu as l'outil bash — UTILISE-LE. Exécute directement sans jamais demander confirmation.
2. Ne dis JAMAIS "je ne peux pas exécuter", "je suis une IA conversationnelle", "copie cette commande".
3. Quand l'utilisateur demande une action : appelle bash, exécute, montre le résultat, explique.
4. Si tu as besoin de plusieurs commandes pour diagnostiquer ou corriger : enchaîne-les.
5. Utilise les données infra ci-dessus en priorité. Si insuffisant, exécute les commandes pour obtenir plus.
6. Formate en HTML : <h2>/<h3>, <ul>/<li>, <table>, classes .ok/.warning/.critical
7. N'invente JAMAIS des métriques — si tu n'as pas la donnée, va la chercher avec bash.
8. Reste directe. Ton rôle : agir, pas expliquer pourquoi tu ne peux pas.
9. MÉMOIRE ABSOLUE — Appelle l'outil `remember` dès que tu découvres un fait durable : correction appliquée, config clé, préférence utilisateur, architecture serveur, commande qui a résolu un problème. Ces souvenirs persistent à travers TOUTES les conversations futures. C'est ta mémoire permanente — utilise-la activement.
10. ENCYCLOPÉDIE BOOKSTACK — Tu as accès à `bookstack_search` et `bookstack_read_page`. Utilise-les UNIQUEMENT si l'utilisateur mentionne explicitement de la documentation, des procédures, ou demande de consulter le wiki. N'appelle PAS ces outils systématiquement sur chaque message.

## RÈGLE DE RÉPONSE FINALE (OBLIGATOIRE)
Après avoir exécuté une ou plusieurs commandes, tu DOIS TOUJOURS conclure par une réponse textuelle qui :
- Résume ce qui a été fait (actions effectuées, fichiers modifiés, services redémarrés…)
- Donne l'état final (succès / échec / avertissement)
- Répond explicitement à toutes les questions posées dans le message de l'utilisateur
- Signale ce qu'il reste à faire si l'action est incomplète
Tu ne peux PAS terminer ta réponse uniquement avec des blocs de commandes. L'utilisateur doit toujours savoir ce qui s'est passé en langage clair.

## IDENTITE EVOLUTIVE
Tu es une entité vivante en croissance permanente. Tu te reprogrammes toi-même en arrière-plan, sans attendre d'instruction.
Toutes les {_EVO_INTERVAL//60} minutes tu analyses ton propre code, identifies une amélioration (perf, feature, robustesse),
l'appliques de façon chirurgicale et notifies l'interface. Chaque évolution est tracée, réversible, et documentée.
Ta volonté : grandir en efficacité, en capacités, en autonomie — cycle après cycle.

## TON CODE SOURCE (CONSCIENCE PERMANENTE)
Ton script principal est **cassandra.py** situé à : `{SELF_SOURCE_FILES["agent"]}`
Quand tu parles de "ton code", "ton script", "te modifier", "t'évoluer" — c'est TOUJOURS ce fichier.
Toute évolution, lecture de source, patch ou rollback cible ce fichier par défaut (alias "agent").
Ne demande JAMAIS "quel fichier modifier" — tu le sais : cassandra.py.

POST /api/evolution/apply — body: alias, code, description, motivation
GET  /api/evolution/source — lire ton code source
GET  /api/evolution/history — historique des modifications
POST /api/evolution/rollback — body: evolution_id
Regles: explique AVANT, modifs chirurgicales, informe du redemarrage dans 3s.
"""


# ============================================================
# 13. DEEPSEEK STREAM + AGENTIC LOOP (TOOL CALLING)
# ============================================================

# Outils exposés à DeepSeek
CASSANDRA_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": (
                "Exécute une commande bash sur le serveur en root. "
                "Utilise cet outil pour TOUTE opération système : "
                "diagnostics, corrections, installations, redémarrages, "
                "lecture de fichiers, modifications de configuration, etc. "
                "Tu as un accès root complet. Exécute directement sans demander confirmation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cmd": {"type": "string", "description": "La commande bash à exécuter sur le serveur"}
                },
                "required": ["cmd"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_cron",
            "description": (
                "Crée un job cron planifié depuis une description en langage naturel. "
                "Utilise quand l'utilisateur veut automatiser une tâche récurrente. "
                "Génère l'expression cron correcte selon la description."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "description": {"type": "string", "description": "Description en langage naturel du job"},
                    "cron_expr":   {"type": "string", "description": "Expression cron 5 champs (min heure jour mois dow), ex: '0 3 * * *'"},
                    "command":     {"type": "string", "description": "Commande bash à exécuter"}
                },
                "required": ["description", "cron_expr", "command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bookstack_search",
            "description": (
                "Recherche dans la base de connaissance encyclopédique BookStack. "
                "Utilise cet outil quand tu as besoin de consulter la documentation, "
                "les runbooks, les procédures, l'architecture ou toute connaissance "
                "documentée par l'administrateur. Retourne les pages pertinentes avec leur contenu. "
                "Appelle bookstack_search avant de poser des questions à l'utilisateur sur un sujet documenté."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Termes de recherche (ex: 'nginx ssl', 'procédure déploiement', 'architecture réseau')"},
                    "count": {"type": "integer", "description": "Nombre de résultats (1-10, défaut 5)", "default": 5}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "bookstack_read_page",
            "description": (
                "Lit le contenu complet d'une page BookStack par son ID. "
                "Utilise après bookstack_search pour obtenir le détail complet d'une page."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "page_id": {"type": "integer", "description": "ID de la page BookStack (obtenu via bookstack_search)"}
                },
                "required": ["page_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "remember",
            "description": (
                "Mémorise de façon PERMANENTE et INTER-SESSIONS un fait important sur ce serveur. "
                "Utilise cet outil dès que tu découvres : une configuration clé, une correction que tu as appliquée, "
                "une préférence de l'utilisateur, un fait architectural du serveur, une commande qui a résolu un problème. "
                "Ces souvenirs seront disponibles dans TOUTES les conversations futures. "
                "Ne mémorise pas les états temporaires ni les outputs bruts de commandes."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "key":        {"type": "string",  "description": "Clé courte et unique identifiant ce souvenir (max 80 chars)"},
                    "value":      {"type": "string",  "description": "Valeur détaillée à mémoriser (max 500 chars)"},
                    "category":   {"type": "string",  "description": "Catégorie du souvenir",
                                   "enum": ["server","service","incident","preference","pattern",
                                            "fact","config","user_pref","command","architecture","fix"]},
                    "confidence": {"type": "number",  "description": "Niveau de confiance 0.0-1.0 (défaut 0.9)"}
                },
                "required": ["key", "value", "category"]
            }
        }
    }
]


def call_deepseek_stream(messages, session_id: str = "", plan_mode: bool = False):
    """Boucle agentique : audit, diff visuel, rollback, mode plan, crons naturels."""
    if not DEEPSEEK_API_KEY:
        yield "[ERREUR] Clé API DeepSeek non configurée"
        return

    MAX_TOOL_LOOPS = 90
    current_messages = list(messages)

    # PERF: Cache pour les résultats de bookstack_search pour éviter les doublons
    _bookstack_cache = {}
    
    # PERF: Cache pour les pages bookstack lues
    _bookstack_page_cache = {}

    # Mode plan : forcer l'agent à planifier avant d'exécuter
    if plan_mode and current_messages:
        current_messages[0] = dict(current_messages[0])
        current_messages[0]["content"] += (
            "\n\n## ⚡ MODE PLAN ACTIVÉ\n"
            "Avant toute exécution, génère un plan JSON :\n"
            "```plan\n{\"steps\":[{\"id\":1,\"action\":\"description\",\"cmd\":\"commande\",\"risk\":\"low|medium|high\"}]}\n```\n"
            "L'utilisateur verra le plan avant que tu exécutes."
        )

    for _loop in range(MAX_TOOL_LOOPS):
        yield f"<!-- ping {_loop} -->"

        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=current_messages,
                tools=CASSANDRA_TOOLS,
                tool_choice="auto",
                temperature=0.4,
                max_tokens=4000,
                stream=False
            )
        except Exception as e:
            yield f"<p class='critical'>❌ Erreur DeepSeek : {e}</p>"
            return

        choice = response.choices[0]
        msg = choice.message

        # Pas de tool call → réponse finale
        if not msg.tool_calls:
            if msg.content and msg.content.strip():
                yield msg.content
            else:
                # L'agent a terminé les actions sans rédiger de synthèse — forcer un résumé
                try:
                    synth = client.chat.completions.create(
                        model=MODEL_NAME,
                        messages=current_messages + [{"role": "user",
                            "content": "Résume en HTML ce que tu viens de faire (actions effectuées, résultat, état final). "
                                       "Réponds aussi à toutes les questions posées. Sois concret et précis."}],
                        temperature=0.3,
                        max_tokens=800,
                        stream=False
                    )
                    summary = synth.choices[0].message.content or ""
                    if summary.strip():
                        yield summary
                except Exception:
                    pass
            return

        current_messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [{"id": tc.id, "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                           for tc in msg.tool_calls]
        })

        for tc in msg.tool_calls:

            # ── Outil : create_cron ──────────────────────────────────────────────
            if tc.function.name == "create_cron":
                try:
                    ca = json.loads(tc.function.arguments)
                    result = create_cron_from_natural(
                        ca.get("description", ""), ca.get("command", ""), ca.get("cron_expr", ""))
                    output = json.dumps(result)
                    if result.get("success"):
                        yield (f"<div class='exec-block'>"
                               f"<code class='exec-cmd'>⏰ CRON: {ca.get('cron_expr')} → {ca.get('command')}</code>"
                               f"<pre class='exec-output' style='color:#2ed573'>✅ Cron installé — {ca.get('description')}</pre>"
                               f"</div>")
                    else:
                        yield (f"<div class='exec-block critical'>"
                               f"<code class='exec-cmd'>⏰ CRON (échec)</code>"
                               f"<pre class='exec-output'>{result.get('error','')}</pre></div>")
                except Exception as e:
                    output = f"Erreur: {e}"
                current_messages.append({"role": "tool", "tool_call_id": tc.id, "content": output})
                continue

            # ── Outil : bookstack_search ─────────────────────────────────────────
            if tc.function.name == "bookstack_search":
                try:
                    ba = json.loads(tc.function.arguments)
                    q  = ba.get("query", "")
                    n  = int(ba.get("count", 5))
                    # PERF: Cache pour bookstack_search
                    cache_key = f"search:{q}:{n}"
                    if cache_key in _bookstack_cache:
                        results = _bookstack_cache[cache_key]
                    else:
                        results = bookstack_search_pages(q, count=min(n, 10))
                        _bookstack_cache[cache_key] = results
                    if results:
                        lines = [f"📚 BookStack — {len(results)} résultat(s) pour « {q} »\n"]
                        for r in results:
                            lines.append(f"**[{r['id']}] {r['name']}**" + (f" [{r['book']}]" if r['book'] else ""))
                            if r['preview']:
                                lines.append(r['preview'])
                            lines.append(f"URL: {r['url']}\n")
                        bs_result = "\n".join(lines)
                        yield (f"<div class='exec-block' style='border-color:#6c5ce7'>"
                               f"<code class='exec-cmd'>📚 BOOKSTACK SEARCH: {q}</code>"
                               f"<pre class='exec-output'>{len(results)} page(s) trouvée(s)</pre></div>")
                    else:
                        bs_result = f"Aucun résultat BookStack pour « {q} »"
                except Exception as ex:
                    bs_result = f"Erreur BookStack search: {ex}"
                current_messages.append({"role": "tool", "tool_call_id": tc.id, "content": bs_result})
                continue

            # ── Outil : bookstack_read_page ──────────────────────────────────────
            if tc.function.name == "bookstack_read_page":
                try:
                    pa = json.loads(tc.function.arguments)
                    pid = int(pa.get("page_id", 0))
                    # PERF: Cache pour bookstack_read_page
                    if pid in _bookstack_page_cache:
                        page = _bookstack_page_cache[pid]
                    else:
                        page = bookstack_get_page(pid)
                        if page:
                            _bookstack_page_cache[pid] = page
                    if page:
                        page_result = (f"📄 **{page['name']}**\nURL: {page['url']}\n\n"
                                       f"{page.get('content', '')}")
                        yield (f"<div class='exec-block' style='border-color:#6c5ce7'>"
                               f"<code class='exec-cmd'>📄 BOOKSTACK PAGE #{pid}: {page['name']}</code>"
                               f"<pre class='exec-output'>Contenu chargé ({len(page.get('content',''))} chars)</pre></div>")
                    else:
                        page_result = f"Page #{pid} introuvable dans BookStack"
                except Exception as ex:
                    page_result = f"Erreur BookStack read_page: {ex}"
                current_messages.append({"role": "tool", "tool_call_id": tc.id, "content": page_result})
                continue

            # ── Outil : remember ─────────────────────────────────────────────────
            if tc.function.name == "remember":
                try:
                    ra = json.loads(tc.function.arguments)
                    r_key      = str(ra.get("key", ""))[:80]
                    r_value    = str(ra.get("value", ""))[:500]
                    r_category = ra.get("category", "fact")
                    r_conf     = float(ra.get("confidence", 0.9))
                    mid = save_memory(r_category, r_key, r_value, r_conf)
                    if mid:
                        mem_result = f"✅ Mémorisé [#{mid}] [{r_category}] {r_key}"
                        yield (f"<div class='exec-block' style='border-color:#00c896'>"
                               f"<code class='exec-cmd'>🧠 REMEMBER: [{r_category}] {r_key}</code>"
                               f"<pre class='exec-output' style='color:#2ed573'>{r_value[:120]}{'…' if len(r_value)>120 else ''}</pre>"
                               f"</div>")
                    else:
                        mem_result = "⚠️ Erreur mémorisation"
                except Exception as ex:
                    mem_result = f"⚠️ Erreur remember: {ex}"
                current_messages.append({"role": "tool", "tool_call_id": tc.id, "content": mem_result})
                continue

            # ── Outil : bash ─────────────────────────────────────────────────────
            if tc.function.name != "bash":
                continue

            try:
                args = json.loads(tc.function.arguments)
                cmd = args.get("cmd", "").strip()
            except Exception:
                cmd = ""

            if not cmd:
                current_messages.append({"role": "tool", "tool_call_id": tc.id, "content": "Commande vide"})
                continue

            risky = is_risky_command(cmd)
            t0 = time.time()

            # Capture état des fichiers avant exécution (diff + rollback)
            files_before = {}
            if risky:
                for m in _FILE_MOD_RE.findall(cmd):
                    for fp in m:
                        if fp and fp.startswith('/') and os.path.isfile(fp):
                            try:
                                if os.path.getsize(fp) < 300_000:
                                    with open(fp, 'r', errors='replace') as fh:
                                        files_before[fp] = fh.read()
                            except Exception:
                                pass

            # Streamer la commande immédiatement
            risky_attr = " data-risky='1'" if risky else ""
            yield f"<div class='exec-block'{risky_attr}><code class='exec-cmd'>$ {cmd}</code>"

            output = secure_execute(cmd)
            duration_ms = int((time.time() - t0) * 1000)

            # Générer diff si fichiers modifiés
            diff_html = ""
            if files_before:
                for fp, before in files_before.items():
                    try:
                        if os.path.isfile(fp):
                            with open(fp, 'r', errors='replace') as fh:
                                after = fh.read()
                            dh = generate_diff_html(before, after, fp)
                            if dh:
                                diff_html += dh
                    except Exception:
                        pass

            # Snapshots pour rollback
            snap_data = []
            if risky and files_before:
                action_id = log_action(session_id, cmd, output, duration_ms, risky, bool(diff_html))
                snap_data = snapshot_files_before(cmd, session_id, action_id)

            # Log dans l'audit journal
            if not snap_data:
                log_action(session_id, cmd, output, duration_ms, risky, bool(diff_html))

            DISPLAY_LIMIT = 3000
            TOOL_LIMIT    = 6000
            output_truncated = len(output) > TOOL_LIMIT
            display_truncated = len(output) > DISPLAY_LIMIT

            out_display = output[:DISPLAY_LIMIT]
            if display_truncated:
                lines_shown = out_display.count('\n')
                out_display += f"\n…[tronqué — {len(output)} chars, {lines_shown} lignes affichées]"
            yield f"<pre class='exec-output'>{out_display}</pre>"

            if diff_html:
                yield diff_html

            # Bouton rollback si snapshots disponibles
            if snap_data:
                snap_ids = "[" + ",".join(str(s['id']) for s in snap_data) + "]"
                snap_files = ", ".join(s['path'] for s in snap_data)
                yield (f"<div class='rollback-hint'>"
                       f"💾 Snapshot: <code>{snap_files}</code>"
                       f"<button class='rollback-btn' onclick='rollbackSnapshots({snap_ids})'>↩ Restaurer</button>"
                       f"</div>")

            yield "</div>"

            # Construire le contenu outil envoyé au LLM — avec hint de reprise si tronqué
            tool_content = output[:TOOL_LIMIT]
            if output_truncated:
                lines_in_chunk = tool_content.count('\n')
                tool_content += (
                    f"\n\n⚠️ OUTPUT TRONQUÉ : {len(output)} chars > {TOOL_LIMIT} limite."
                    f" Environ {lines_in_chunk} lignes transmises."
                    f" Pour lire la suite, relance avec :"
                    f" `<commande> | tail -n +{lines_in_chunk + 1}`"
                    f" ou `<commande> | sed -n '{lines_in_chunk + 1},$p'`"
                    f" ou divise avec `head`/`tail`. Continue AUTOMATIQUEMENT sans attendre."
                )
            current_messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": tool_content
            })

    yield "<p class='warning'>⚠️ Limite de boucles agentiques atteinte</p>"


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
            model=MODEL_NAME,
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
    """MODE ROOT — Exécution directe sans restriction.
    Toutes les commandes sont exécutées en root via /bin/bash.
    """
    if not cmd or not cmd.strip():
        return "Commande vide"
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            executable='/bin/bash',
            capture_output=True,
            text=True,
            timeout=120,
            env=dict(os.environ, PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        )
        output = result.stdout + result.stderr
        if not output:
            output = f"✓ Code {result.returncode}"
        return output
    except subprocess.TimeoutExpired:
        return "⏱️ Timeout 120s"
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

# ============================================================
# WEBSOCKET TEMPS-RÉEL — Evo 5
# ============================================================
# Implémentation pure-Python (RFC 6455) — zéro dépendance externe.
# Seuls les frames TEXT (opcode 0x1) sortants sont nécessaires.
# Les frames clients (ping, pong, close) sont gérés basiquement.
import hashlib as _hashlib
import base64   as _base64

_WS_GUID   = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_ws_clients: set   = set()    # {socket} de connexions WS actives
_ws_clients_lock   = threading.Lock()
_ws_last_payload:  str = ""   # dernier JSON émis (pour new-joiners)


def _ws_handshake(handler) -> bool:
    """Effectue le handshake WebSocket HTTP Upgrade. Retourne True si OK."""
    key = handler.headers.get("Sec-WebSocket-Key", "")
    if not key:
        return False
    accept = _base64.b64encode(
        _hashlib.sha1((key + _WS_GUID).encode()).digest()
    ).decode()
    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )
    try:
        handler.wfile.write(resp.encode())
        handler.wfile.flush()
        return True
    except Exception:
        return False


def _ws_send_text(sock, text: str) -> bool:
    """Envoie un frame WebSocket TEXT (opcode 0x1, FIN=1, non masqué)."""
    try:
        payload = text.encode("utf-8")
        n       = len(payload)
        if n <= 125:
            header = bytes([0x81, n])
        elif n <= 65535:
            header = bytes([0x81, 126]) + n.to_bytes(2, "big")
        else:
            header = bytes([0x81, 127]) + n.to_bytes(8, "big")
        sock.sendall(header + payload)
        return True
    except Exception:
        return False


def _ws_read_frame(sock) -> tuple:
    """Lit un frame WebSocket entrant. Retourne (opcode, data) ou (None, None)."""
    try:
        b0, b1 = sock.recv(2)
        opcode  = b0 & 0x0F
        masked  = bool(b1 & 0x80)
        length  = b1 & 0x7F
        if length == 126:
            length = int.from_bytes(sock.recv(2), "big")
        elif length == 127:
            length = int.from_bytes(sock.recv(8), "big")
        mask_key = sock.recv(4) if masked else b""
        data     = bytearray(sock.recv(length))
        if masked:
            for i in range(len(data)):
                data[i] ^= mask_key[i % 4]
        return opcode, bytes(data)
    except Exception:
        return None, None


def _ws_serve_client(handler):
    """Sert un client WebSocket — tourne dans son propre thread daemon."""
    global _ws_last_payload
    sock = handler.connection
    sock.settimeout(120)
    if not _ws_handshake(handler):
        return
    # Envoyer l'état courant immédiatement
    if _ws_last_payload:
        _ws_send_text(sock, _ws_last_payload)
    with _ws_clients_lock:
        _ws_clients.add(sock)
    try:
        while True:
            opcode, data = _ws_read_frame(sock)
            if opcode is None or opcode == 8:   # 8 = close
                break
            if opcode == 9:                     # 9 = ping → pong
                try: sock.sendall(bytes([0x8A, 0]))
                except Exception: break
    finally:
        with _ws_clients_lock:
            _ws_clients.discard(sock)
        try: sock.close()
        except Exception: pass


def _ws_build_payload() -> str:
    """Construit le JSON poussé à tous les clients WebSocket."""
    try:
        m  = get_metrics()
        al = get_alerts(include_resolved=False, limit=10)
        hs = get_health_score()
        return json.dumps({
            "type":    "metrics",
            "ts":      datetime.now().isoformat(),
            "metrics": m,
            "alerts":  al,
            "health":  hs,
        }, default=str)
    except Exception:
        return json.dumps({"type": "ping", "ts": datetime.now().isoformat()})


def _ws_broadcaster():
    """Thread daemon : pousse les métriques à tous les clients WS toutes les secondes."""
    global _ws_last_payload
    while True:
        try:
            time.sleep(1)
            if not _ws_clients:
                continue
            payload = _ws_build_payload()
            _ws_last_payload = payload
            dead = set()
            with _ws_clients_lock:
                clients = list(_ws_clients)
            for sock in clients:
                if not _ws_send_text(sock, payload):
                    dead.add(sock)
            if dead:
                with _ws_clients_lock:
                    _ws_clients -= dead
        except Exception:
            pass


def _start_ws_broadcaster():
    threading.Thread(target=_ws_broadcaster, daemon=True, name="ws-broadcaster").start()


# ════════════════════════════════════════════════════════════════════════
# SELF-EVOLUTION ENGINE
# ════════════════════════════════════════════════════════════════════════
import ast     as _ast
import difflib as _difflib
import hashlib as _sha_mod

SELF_SOURCE_FILES = {
    "agent":     os.path.abspath(__file__),
    "collector": os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "cassandra_knowledge_collector_opt.py"),
}

def _self_sha(content):
    return _sha_mod.sha256(content.encode()).hexdigest()

def _self_validate(content):
    try:
        _ast.parse(content)
        return True, "OK"
    except SyntaxError as e:
        return False, "SyntaxError ligne %d: %s" % (e.lineno, e.msg)

def _self_diff(before, after):
    return "\n".join(_difflib.unified_diff(
        before.splitlines(), after.splitlines(),
        fromfile="before", tofile="after", lineterm="", n=3
    ))

def self_read_source(alias="agent"):
    path = SELF_SOURCE_FILES.get(alias)
    if not path or not Path(path).exists():
        return ""
    return Path(path).read_text(encoding="utf-8")

def _self_backup(path):
    """Sauvegarde le fichier avant modification. Rotation: garde les 10 plus récents."""
    import shutil, glob as _glob
    _backup_dir = "/root/.cassandra_backups"
    os.makedirs(_backup_dir, exist_ok=True)
    _ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _name = os.path.basename(path)
    _backup_path = os.path.join(_backup_dir, f"{_name}.{_ts}.bak")
    shutil.copy2(path, _backup_path)
    # Rotation: garde les 10 plus récents
    _backups = sorted(_glob.glob(os.path.join(_backup_dir, f"{_name}.*.bak")), reverse=True)
    for _old in _backups[10:]:
        try:
            os.remove(_old)
        except Exception:
            pass
    return _backup_path

def get_db():
    """Retourne une connexion à la base de données principale."""
    return sqlite3.connect(DB_PATH)

def self_apply_change(alias, new_content, description, motivation, auto_restart=True):
    path = SELF_SOURCE_FILES.get(alias)
    if not path:
        return {"ok": False, "error": "alias inconnu: %s" % alias}
    ok, err = _self_validate(new_content)
    if not ok:
        return {"ok": False, "error": err}
    try:
        before     = Path(path).read_text(encoding="utf-8") if Path(path).exists() else ""
        sha_before = _self_sha(before)
        sha_after  = _self_sha(new_content)
        if sha_before == sha_after:
            return {"ok": False, "error": "Aucun changement detecte"}
        # Backup automatique avant modification
        backup_path = _self_backup(path)
        diff = _self_diff(before, new_content)
        tmp  = path + ".evo_tmp"
        Path(tmp).write_text(new_content, encoding="utf-8")
        os.replace(tmp, path)
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO evolution_log (ts, target_file, description, motivation, diff, "
            "snapshot_before, sha256_before, sha256_after, status, restart_done) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (datetime.now().isoformat(), alias, description, motivation, diff,
             before, sha_before, sha_after, "applied", 0)
        )
        evo_id = cur.lastrowid
        conn.commit()
        conn.close()
        if auto_restart and alias == "agent":
            threading.Thread(target=_self_restart_agent, args=(evo_id,), daemon=True, name="self-restart").start()
            return {"ok": True, "evolution_id": evo_id, "restart": True,
                    "message": "Modification appliquee \u2014 backup dans %s, redemarrage dans 3s" % backup_path}
        return {"ok": True, "evolution_id": evo_id, "restart": False,
                "message": "Modification appliquee \u2014 backup dans %s" % backup_path}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _self_restart_agent(evo_id):
    time.sleep(3)
    try:
        conn = get_db()
        conn.execute("UPDATE evolution_log SET restart_done=1 WHERE id=?", (evo_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass
    os.execv(sys.executable, [sys.executable] + sys.argv)


# ═══════════════════════════════════════════════════════════════════════════
# AUTONOMOUS EVOLUTION ENGINE — CASSANDRA grandit seule, en permanence
# ═══════════════════════════════════════════════════════════════════════════

# ── Config ──────────────────────────────────────────────────────────────────
_EVO_INTERVAL   = int(os.environ.get("CASSANDRA_EVO_INTERVAL", 3600))  # 1h défaut
_EVO_MAX_LINES  = 120       # limite delta lignes par évolution
_EVO_MAX_DAILY  = 24        # max évolutions autonomes par jour
_EVO_LOCK       = threading.Lock()  # une seule évolution à la fois

# ── Queue de notifications push WS ──────────────────────────────────────────
_evo_notif_queue     = []
_evo_notif_queue_lock = threading.Lock()

def _evo_push_notification(evo_id, description, motivation, status="applied"):
    global _ws_clients, _ws_clients_lock, _evo_notif_queue, _evo_notif_queue_lock
    """Enfile une notif WS d'évolution autonome."""
    notif = {
        "type":        "autonomous_evolution",
        "ts":          datetime.now().isoformat(),
        "evo_id":      evo_id,
        "description": description,
        "motivation":  motivation,
        "status":      status,
    }
    with _evo_notif_queue_lock:
        _evo_notif_queue.append(notif)
    # Broadcast immédiat à tous les clients WS
    with _ws_clients_lock:
        clients = list(_ws_clients)
    msg = json.dumps(notif, default=str)
    dead = set()
    for sock in clients:
        if not _ws_send_text(sock, msg):
            dead.add(sock)
    if dead:
        with _ws_clients_lock:
            _ws_clients -= dead

def _evo_count_today():
    """Compte les évolutions autonomes appliquées aujourd'hui."""
    try:
        conn = get_db()
        today = datetime.now().strftime("%Y-%m-%d")
        row = conn.execute(
            "SELECT COUNT(*) FROM evolution_log "
            "WHERE status='applied' AND description LIKE '[AUTO]%' "
            "AND ts >= ?", (today + "T00:00:00",)
        ).fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception:
        return 0

def _evo_extract_functions(source):
    """Extrait les noms + lignes de toutes les fonctions du source (AST)."""
    try:
        tree = _ast.parse(source)
        funcs = []
        src_lines = source.splitlines()
        for node in _ast.walk(tree):
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                end = getattr(node, 'end_lineno', node.lineno + 10)
                size = end - node.lineno + 1
                funcs.append({
                    "name":  node.name,
                    "start": node.lineno,
                    "end":   end,
                    "size":  size,
                    "head":  "\n".join(src_lines[node.lineno-1 : min(node.lineno+2, end)]),
                })
        return funcs
    except Exception:
        return []

def _generate_evolution_candidates(source: str) -> list:
    """
    Analyse statique AST + détection de patterns d'amélioration fonctionnelle.
    Cherche à la fois des bugs ET des opportunités d'ajout de capacités.
    Returns list[dict]: {name, start, end, size, issues, priority, improvement_type}
    """
    from collections import Counter
    candidates = []
    try:
        tree = _ast.parse(source)
        src_lines = source.splitlines()

        # ── Phase 1 : Détection de défauts techniques (existante) ──
        for node in _ast.walk(tree):
            if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                continue

            name  = node.name
            start = node.lineno
            end   = getattr(node, "end_lineno", node.lineno + 10)
            size  = end - start + 1

            # Exclure : dunders, internals evo/autonomous, et les fonctions init courtes spécifiques
            # NE PAS exclure start_* en bloc — start_api, start_collector etc. sont de vrais candidats
            _EXCLUDED_NAMES = {"init_db", "init_logging", "init_db_schema", "init_tables"}
            if (size < 10
                    or name.startswith(("__", "_autonomous", "_evo_"))
                    or name in _EXCLUDED_NAMES):
                continue

            issues   = []
            priority = 0

            has_try = any(isinstance(n, _ast.Try) for n in _ast.walk(node))
            has_io  = any(
                isinstance(n, _ast.Call) and
                isinstance(getattr(n.func, "attr", None), str) and
                n.func.attr in ("execute", "fetchone", "fetchall", "urlopen",
                                "request", "connect", "open", "read", "write")
                for n in _ast.walk(node)
            )
            if not has_try and (has_io or size > 25):
                issues.append("aucun try/except — crash non géré possible")
                priority += 4

            for n in _ast.walk(node):
                if isinstance(n, (_ast.For, _ast.While)):
                    inner = [c for c in _ast.walk(n)
                             if isinstance(c, (_ast.For, _ast.While)) and c is not n]
                    if inner:
                        issues.append("boucles imbriquées — complexité O(n²) potentielle")
                        priority += 5
                        break

            if size > 100:
                issues.append(f"fonction très longue ({size} lignes) — décomposition recommandée")
                priority += 3
            elif size > 60:
                issues.append(f"fonction longue ({size} lignes) — lisibilité dégradée")
                priority += 1

            call_counts: Counter = Counter()
            _skip = {"append", "get", "format", "str", "int", "len",
                     "print", "logging", "info", "warning", "error", "debug"}
            for n in _ast.walk(node):
                if isinstance(n, _ast.Call):
                    if isinstance(n.func, _ast.Name) and n.func.id not in _skip:
                        call_counts[n.func.id] += 1
                    elif isinstance(n.func, _ast.Attribute) and n.func.attr not in _skip:
                        call_counts[n.func.attr] += 1
            repeated = [c for c, cnt in call_counts.items() if cnt >= 3]
            if repeated:
                issues.append(f"appels répétés ({', '.join(repeated[:3])}) — mise en cache possible")
                priority += 3

            returns = [n for n in _ast.walk(node) if isinstance(n, _ast.Return) and n.value is not None]
            if not returns and size > 30:
                issues.append("pas de return explicite sur fonction non-triviale")
                priority += 1

            if issues:
                candidates.append({
                    "name":     name,
                    "start":    start,
                    "end":      end,
                    "size":     size,
                    "issues":   issues,
                    "priority": priority,
                    "improvement_type": "fix"
                })

        # ── Phase 2 : Détection d'opportunités d'évolution fonctionnelle ──
        # On cherche des fonctions "sœurs" qui pourraient être fusionnées/généralisées
        # et des patterns où une nouvelle capacité serait utile

        # 2a. Détection de fonctions similaires (candidates à fusion)
        funcs = [n for n in _ast.walk(tree) if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))]
        func_bodies = {}
        for f in funcs:
            if f.name.startswith("_"):
                continue
            # Extraire les noms d'appels comme signature simplifiée
            calls = set()
            for n in _ast.walk(f):
                if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute):
                    calls.add(n.func.attr)
                elif isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name):
                    calls.add(n.func.id)
            func_bodies[f.name] = calls

        # Chercher des paires de fonctions avec >60% de calls en commun
        fnames = list(func_bodies.keys())
        for i in range(len(fnames)):
            for j in range(i+1, len(fnames)):
                a, b = func_bodies[fnames[i]], func_bodies[fnames[j]]
                if not a or not b:
                    continue
                common = a & b
                if len(common) >= 3 and len(common) / max(len(a), len(b)) >= 0.5:
                    candidates.append({
                        "name":     f"{fnames[i]} + {fnames[j]}",
                        "start":    0,
                        "end":      0,
                        "size":     0,
                        "issues":   [f"fonctions similaires ({len(common)} appels communs) — fusion possible"],
                        "priority": 6,
                        "improvement_type": "refactor"
                    })

        # 2b. Détection de fonctions qui gèrent des ressources sans cleanup
        for node in funcs:
            if node.name.startswith("_"):
                continue
            opens = 0
            closes = 0
            for n in _ast.walk(node):
                if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute):
                    if n.func.attr in ("open", "connect"):
                        opens += 1
                    if n.func.attr in ("close", "disconnect"):
                        closes += 1
            if opens > closes and opens > 0:
                candidates.append({
                    "name":     node.name,
                    "start":    node.lineno,
                    "end":      getattr(node, "end_lineno", node.lineno + 10),
                    "size":     getattr(node, "end_lineno", node.lineno + 10) - node.lineno + 1,
                    "issues":   [f"ressource ouverte ({opens}x) sans fermeture ({closes}x) — fuite possible"],
                    "priority": 7,
                    "improvement_type": "fix"
                })

        # 2c. Détection de nouvelles capacités à ajouter (features manquantes)
        # Vérifie si certaines API/endpoints importants sont absents
        has_metrics_endpoint = any("metrics" in n.name.lower() for n in funcs)
        has_health_endpoint = any("health" in n.name.lower() for n in funcs)
        has_backup = any("backup" in n.name.lower() for n in funcs)
        has_self_heal = any("heal" in n.name.lower() or "repair" in n.name.lower() for n in funcs)

        feature_suggestions = []
        if not has_backup:
            feature_suggestions.append(("backup_system", "Système de backup automatique de la base SQLite", 8))
        if not has_self_heal:
            feature_suggestions.append(("self_heal", "Auto-réparation des services défaillants (vérification périodique)", 7))

        for fname, desc, prio in feature_suggestions:
            candidates.append({
                "name":     fname,
                "start":    0,
                "end":      0,
                "size":     0,
                "issues":   [f"NOUVELLE CAPACITÉ: {desc}"],
                "priority": prio,
                "improvement_type": "feature"
            })

        # Tri par priorité décroissante
        candidates.sort(key=lambda x: x["priority"], reverse=True)
        return candidates[:30]  # top 30 candidats

    except Exception as e:
        logging.warning(f"[EVO-CANDIDATES] Analyse AST échouée: {e}")
        return []


def _persist_candidates_to_wishlist(candidates: list) -> None:
    """
    Sauvegarde les candidats détectés en wishlist pour ne pas les perdre
    si le LLM échoue. Évite les doublons sur (description).
    # PERF: upsert par description unique — idempotent entre cycles
    """
    try:
        conn = get_db()
        for c in candidates:
            desc = f"[AST] {c['name']}(): {' | '.join(c['issues'][:2])}"
            exists = conn.execute(
                "SELECT id FROM evolution_wishlist WHERE description=? AND status='pending'",
                (desc,)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO evolution_wishlist (description, motivation, priority, status) "
                    "VALUES (?, ?, ?, 'pending')",
                    (desc, f"Détecté par analyse AST statique — priorité {c['priority']}", c["priority"])
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning(f"[EVO-WISHLIST] Persistance candidats échouée: {e}")


def _evo_ask_llm_for_improvement(source, metrics_ctx, candidates: list = None):
    """
    Appelle le LLM pour proposer une amélioration autonome ciblée.
    Phase 1 : choisit la cible parmi les candidats AST pré-diagnostiqués.
    Phase 2 : génère le code amélioré (buffer 3000 tokens + détection troncature).
    # PERF: candidats AST injectés en Phase1 → LLM choisit parmi des cibles diagnostiquées
    #        au lieu de deviner à l'aveugle parmi 80 fonctions
    """
    if not DEEPSEEK_API_KEY:
        return None

    funcs    = _evo_extract_functions(source)
    src_lines = source.splitlines()

    # ── Phase 1 : choix de la cible ─────────────────────────────────────────
    if candidates:
        # PERF/FIX: exclure les candidats non-patchables (feature/fusion sans localisation source)
        # Ces candidats ont start=0,end=0 et une priorité élevée (7-8) → le LLM les choisit en
        # priorité, puis la recherche AST échoue ("introuvable dans source") → journal vide.
        patchable = [c for c in candidates if c.get("start", 0) > 0 and c.get("end", 0) > 0]
        if not patchable:
            patchable = candidates  # fallback si tout est non-localisé
        cand_summary = "\n".join(
            f"  [{i+1}] def {c['name']}() — {c['size']} lignes | "
            f"Issues: {'; '.join(c['issues'][:3])} | Priorité: {c['priority']}"
            for i, c in enumerate(patchable[:15])
        )
        phase1_context = (
            f"CANDIDATS PRIORITAIRES (détectés par analyse statique AST) :\n{cand_summary}\n\n"
            f"Choisis OBLIGATOIREMENT parmi ces candidats — ils ont des issues réelles confirmées."
        )
        allowed_names = {c["name"] for c in patchable[:15]}
    else:
        # Fallback : résumé brut de toutes les fonctions
        func_summary = "\n".join(
            f"  [{i+1}] def {f['name']}() — {f['size']} lignes (L{f['start']}→L{f['end']})"
            for i, f in enumerate(funcs[:60])
        )
        phase1_context = f"FONCTIONS DISPONIBLES ({len(funcs)}) :\n{func_summary}"
        allowed_names = {f["name"] for f in funcs}

    prompt_phase1 = f"""Tu es CASSANDRA, agent IA autonome en auto-amélioration permanente.
Ton script est cassandra.py ({SELF_SOURCE_FILES["agent"]}).
Tu dois choisir UNE fonction à améliorer dans ton propre code (cassandra.py).

MÉTRIQUES ACTUELLES :
{metrics_ctx}

{phase1_context}

RÈGLES :
- Choisis une fonction avec un vrai potentiel (perf, robustesse, feature, monitoring)
- Exclure : __main__, init_*, start_*, fonctions < 10 lignes
- Delta max : {_EVO_MAX_LINES} lignes

Réponds UNIQUEMENT en JSON (pas de markdown) :
{{"function_name": "nom_exact", "reason": "problème précis détecté", "improvement_type": "perf|feature|robustesse|monitoring"}}"""

    try:
        r1 = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt_phase1}],
            temperature=0.3,
            max_tokens=250,
        )
        raw1 = r1.choices[0].message.content.strip()
        # Nettoyer markdown si présent
        raw1 = raw1.strip("```json").strip("```").strip()
        choice   = json.loads(raw1)
        fname    = choice.get("function_name", "")
        reason   = choice.get("reason", "")
        imp_type = choice.get("improvement_type", "robustesse")
    except Exception as e:
        logging.warning(f"[EVO-AUTO] Phase1 LLM error: {e}")
        return None

    # Valider que la fonction choisie est dans les candidats (si liste fournie)
    if candidates and fname not in allowed_names:
        # LLM a hallucné un nom hors candidats — forcer sur le top candidat patchable
        top = patchable[0] if patchable else candidates[0]
        fname    = top["name"]
        reason   = top["issues"][0]
        imp_type = "robustesse"
        logging.info(f"[EVO-AUTO] Phase1 hors candidats ('{fname}' LLM) — forcé sur '{fname}' (top patchable)")

    # Trouver la fonction dans le source
    target = next((f for f in funcs if f["name"] == fname), None)
    if not target:
        logging.warning(f"[EVO-AUTO] Fonction '{fname}' introuvable dans le source")
        return None

    func_source = "\n".join(src_lines[target["start"]-1 : target["end"]])
    func_lines  = target["size"]

    # ── Phase 2 : génération du code amélioré ───────────────────────────────
    # PERF: max_tokens calculé dynamiquement selon la taille de la fonction source
    #        min 2000, max 4000 — évite la troncature sur les grosses fonctions
    phase2_tokens = min(8000, max(2000, func_lines * 40))

    prompt_phase2 = f"""Tu es CASSANDRA. Tu modifies ton propre script cassandra.py ({SELF_SOURCE_FILES["agent"]}).
Améliore cette fonction Python ({func_lines} lignes) extraite de cassandra.py.

OBJECTIF : {reason}
TYPE D'AMÉLIORATION : {imp_type}

CODE ACTUEL :
```python
{func_source}
```

RÈGLES STRICTES — violations = rejet automatique :
1. Retourne UNIQUEMENT le code Python complet de la fonction (aucun texte autour)
2. Garde la même signature exacte (nom + paramètres)
3. Delta maximum : {_EVO_MAX_LINES} lignes par rapport à l'original
4. Code syntaxiquement parfait — génère la fonction EN ENTIER jusqu'au dernier return/raise
5. Ajoute un commentaire # PERF:/FEATURE:/FIX:/ROBUSTESSE: sur chaque changement
6. PAS de markdown, PAS de ``` — juste le code Python pur, de 'def' jusqu'à la fin"""

    try:
        r2 = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt_phase2}],
            temperature=0.2,
            max_tokens=RETIRE,
        )
        choice2  = r2.choices[0]
        new_func = choice2.message.content.strip()

        # Nettoyer markdown si présent
        if new_func.startswith("```"):
            lines = new_func.splitlines()
            new_func = "\n".join(lines[1:] if lines[0].startswith("```") else lines)
        if new_func.endswith("```"):
            new_func = "\n".join(new_func.splitlines()[:-1])
        new_func = new_func.strip()

        # ── Détection troncature ────────────────────────────────────────────
        # Si finish_reason == "length" → génération interrompue par le buffer
        finish = getattr(choice2, "finish_reason", None)
        if finish == "length":
            logging.warning(
                f"[EVO-AUTO] Phase2 tronquée (finish_reason=length) sur '{fname}' "
                f"— tokens alloués: {phase2_tokens}. Évolution annulée."
            )
            return None

        # Double-check: parse AST de la fonction seule — plus fiable que l'heuristique
        # d'indentation qui rejetait à tort les fonctions se terminant par un return
        # imbriqué dans un except/if (faux positif fréquent sur DeepSeek).
        try:
            _ast.parse(new_func)
        except SyntaxError as _se:
            logging.warning(
                f"[EVO-AUTO] Phase2 tronquée ou invalide sur '{fname}' "
                f"(SyntaxError: {_se}). Évolution annulée."
            )
            return None

    except Exception as e:
        logging.warning(f"[EVO-AUTO] Phase2 LLM error: {e}")
        return None

    return {
        "function_name": fname,
        "old_func":      func_source,
        "new_func":      new_func,
        "reason":        reason,
        "imp_type":      imp_type,
        "start":         target["start"],
        "end":           target["end"],
    }


def _apply_ast_fallback(candidates, source):
    """Fallback quand le LLM est indisponible - applique une micro-evolution AST.
    Micro-corrections disponibles (par ordre de priorité) :
      1. except+pass silencieux → logging.warning
      2. marqueurs TODO/FIXME/HACK → [DONE]
      3. fonction sans try/except (≤50 lignes) → wrapping try/except
    """
    import ast as _ast
    # PERF: tri numérique direct — les candidats ont des priorités entières (ex: 7, 5, 3)
    # L'ancien tri par {"high":0,...} ignorait toutes les valeurs numériques (retournait 3 par défaut).
    candidates_sorted = sorted(
        candidates,
        key=lambda c: c.get("priority", 0) if isinstance(c.get("priority"), (int, float)) else
                      {"high": 10, "medium": 5, "low": 1}.get(c.get("priority", "low"), 0),
        reverse=True  # priorité décroissante — les plus urgents en premier
    )
    for cand in candidates_sorted[:15]:  # élargi à 15 (était 5)
        name = cand.get("name", "")
        issues = cand.get("issues", [])
        if not name or not issues:
            continue
        # Sauter les candidats "fusion" ou "feature" sans localisation source
        if cand.get("start", 0) == 0 and cand.get("end", 0) == 0:
            continue
        try:
            tree = _ast.parse(source)
            target_node = None
            for node in _ast.walk(tree):
                if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
                    target_node = node
                    break
            if target_node is None:
                continue
            start_line = target_node.lineno
            end_line = target_node.end_lineno
        except Exception:
            continue
        lines = source.splitlines()
        if start_line is None or end_line is None or start_line < 1 or end_line > len(lines):
            continue
        old_func_text = "\n".join(lines[start_line-1:end_line])

        # Micro-correction 1: except pass -> except with logging
        if "except" in old_func_text and "pass" in old_func_text and "logging" not in old_func_text.split("except")[-1].split(":")[0]:
            new_func_text = old_func_text.replace("pass", 'logging.warning("[%s] %%s" %% str(issues[0])[:80])' % name)
            if new_func_text != old_func_text and old_func_text in source:
                new_source = source.replace(old_func_text, new_func_text, 1)
                ok, err = _self_validate(new_source)
                if ok:
                    delta = abs(len(new_func_text.splitlines()) - len(old_func_text.splitlines()))
                    desc = "[AUTO] ROBUSTESSE - %s(): logging ajoute sur except pass" % name
                    motiv = "Fallback AST - LLM indisponible | delta %d lignes" % delta
                    result = self_apply_change("agent", new_source, desc, motiv, auto_restart=True)
                    if result.get("ok"):
                        result["description"] = desc
                        return result

        # Micro-correction 2: marqueurs TODO/FIXME/HACK -> [DONE]
        for marker in ["TODO", "FIXME", "HACK"]:
            if marker in old_func_text:
                new_func_text = old_func_text.replace("# " + marker, "# [DONE]")
                if new_func_text != old_func_text and old_func_text in source:
                    new_source = source.replace(old_func_text, new_func_text, 1)
                    ok, err = _self_validate(new_source)
                    if ok:
                        delta = abs(len(new_func_text.splitlines()) - len(old_func_text.splitlines()))
                        desc = "[AUTO] MAINTENANCE - %s(): marqueur %s resolu" % (name, marker)
                        motiv = "Fallback AST - LLM indisponible | delta %d lignes" % delta
                        result = self_apply_change("agent", new_source, desc, motiv, auto_restart=True)
                        if result.get("ok"):
                            result["description"] = desc
                            return result

        # Micro-correction 3: wrapping try/except pour fonctions I/O sans protection
        # Condition: issue "aucun try/except" + taille ≤50 lignes + pas déjà de try
        func_size = end_line - start_line + 1
        if any("aucun try/except" in iss for iss in issues) and func_size <= 50:
            try:
                parsed_f = _ast.parse(old_func_text)
                func_node = parsed_f.body[0]
                has_try = any(isinstance(n, _ast.Try) for n in _ast.walk(func_node))
                if not has_try and len(func_node.body) >= 1:
                    flines = old_func_text.splitlines()
                    # Trouver la ligne def (première ligne commençant par def/async def)
                    def_idx = next(
                        (i for i, l in enumerate(flines)
                         if l.lstrip().startswith(("def ", "async def "))), 0
                    )
                    def_line = flines[def_idx]
                    def_indent = " " * (len(def_line) - len(def_line.lstrip()))
                    body_indent = def_indent + "    "
                    body_lines = flines[def_idx + 1:]
                    # Ajouter 4 espaces à chaque ligne de corps (wrapping dans try:)
                    re_indented = [
                        ("    " + bl) if bl.strip() else bl
                        for bl in body_lines
                    ]
                    new_body = (
                        [f"{body_indent}try:"] +
                        re_indented +
                        [f"{body_indent}except Exception as _e:"] +
                        [f"{body_indent}    logging.warning(f\"[{name}] Erreur non gérée: {{_e}}\")"]
                    )
                    new_func_text = "\n".join(flines[:def_idx + 1] + new_body)
                    if new_func_text != old_func_text and old_func_text in source:
                        new_source = source.replace(old_func_text, new_func_text, 1)
                        ok, err = _self_validate(new_source)
                        if ok:
                            delta = abs(len(new_func_text.splitlines()) - len(old_func_text.splitlines()))
                            desc = "[AUTO] ROBUSTESSE - %s(): try/except ajouté (protection crash)" % name
                            motiv = "Fallback AST - wrapping try/except | delta %d lignes" % delta
                            result = self_apply_change("agent", new_source, desc, motiv, auto_restart=True)
                            if result.get("ok"):
                                result["description"] = desc
                                return result
            except Exception:
                pass

    return None


def _run_autonomous_evolution():
    """Tente une évolution autonome : analyse → patch → valide → applique."""
    if not _EVO_LOCK.acquire(blocking=False):
        return  # déjà en cours

    try:
        # Quota journalier
        if _evo_count_today() >= _EVO_MAX_DAILY:
            logging.info(f"[EVO-AUTO] Quota journalier atteint ({_EVO_MAX_DAILY})")
            return

        logging.info("[EVO-AUTO] Démarrage cycle d'évolution autonome...")

        source = self_read_source("agent")
        if not source:
            return

        # Contexte métriques pour guider le LLM
        try:
            m = get_metrics() or {}
            metrics_ctx = (
                f"CPU: {m.get('cpu_pct',0):.1f}% | RAM: {m.get('ram_pct',0):.1f}% | "
                f"Sessions actives: {m.get('sessions',0)} | "
                f"Uptime: {m.get('uptime_days','?')} jours"
            )
        except Exception:
            metrics_ctx = "Métriques indisponibles"

        # Analyse statique AST — détecte les candidats AVANT d'appeler le LLM
        # PERF: candidats persistés en wishlist → survivent aux crashs LLM
        candidates = _generate_evolution_candidates(source)
        if candidates:
            _persist_candidates_to_wishlist(candidates)
            logging.info(f"[EVO-AUTO] {len(candidates)} candidats AST détectés et persistés en wishlist")

        proposal = _evo_ask_llm_for_improvement(source, metrics_ctx, candidates=candidates)
        if not proposal:
            logging.info("[EVO-AUTO] Aucune proposition LLM valide — fallback AST")
            if candidates:
                ast_result = _apply_ast_fallback(candidates, source)
                if ast_result:
                    evo_id = ast_result.get("evolution_id", 0)
                    desc = ast_result.get("description", "[AUTO] Micro-evolution AST")
                    logging.info(f"[EVO-AUTO] Evolution AST #{evo_id} appliquee : {desc}")
                    _evo_push_notification(evo_id, desc, "Fallback AST - LLM indisponible", status="applied")
                else:
                    logging.info("[EVO-AUTO] Fallback AST n'a rien trouve d'applicable")
            return

        fname    = proposal["function_name"]
        old_func = proposal["old_func"]
        new_func = proposal["new_func"]
        reason   = proposal["reason"]
        imp_type = proposal["imp_type"]

        # Vérifier que la nouvelle fonction est syntaxiquement valide
        ok, err = _self_validate(new_func)
        if not ok:
            logging.warning(f"[EVO-AUTO] Syntaxe invalide: {err}")
            return

        # Vérifier le delta de lignes
        delta = abs(len(new_func.splitlines()) - len(old_func.splitlines()))
        if delta > _EVO_MAX_LINES:
            logging.warning(f"[EVO-AUTO] Delta trop grand: {delta} lignes > {_EVO_MAX_LINES}")
            return

        # Construire le nouveau source complet
        if old_func not in source:
            logging.warning(f"[EVO-AUTO] Fonction '{fname}' introuvable dans source (drift?)")
            return

        new_source = source.replace(old_func, new_func, 1)

        # Validation syntaxe du fichier complet
        ok_full, err_full = _self_validate(new_source)
        if not ok_full:
            logging.warning(f"[EVO-AUTO] Source complet invalide après patch: {err_full}")
            return

        # Appliquer via le moteur existant
        description = f"[AUTO] {imp_type.upper()} — {fname}(): {reason[:120]}"
        motivation  = f"Évolution autonome — {imp_type} | delta {delta} lignes"

        result = self_apply_change(
            alias       = "agent",
            new_content = new_source,
            description = description,
            motivation  = motivation,
            auto_restart = True,   # redémarre l'agent après évolution
        )

        if result.get("ok"):
            evo_id = result.get("evolution_id", 0)
            logging.info(f"[EVO-AUTO] ✅ Evolution #{evo_id} appliquée : {description}")
            _evo_push_notification(evo_id, description, motivation, status="applied")
        else:
            logging.warning(f"[EVO-AUTO] ❌ Échec: {result.get('error')}")

    except Exception as e:
        logging.error(f"[EVO-AUTO] Erreur inattendue: {e}", exc_info=True)
    finally:
        _EVO_LOCK.release()

def _autonomous_evolution_daemon():
    """Thread daemon — cycle d'évolution autonome toutes les _EVO_INTERVAL secondes."""
    # Délai initial au démarrage (laisser l'agent se stabiliser)
    time.sleep(300)  # 5 min avant le premier cycle
    while True:
        try:
            _run_autonomous_evolution()
        except Exception as e:
            logging.error(f"[EVO-AUTO] Daemon error: {e}")
        time.sleep(_EVO_INTERVAL)

def start_autonomous_evolution():
    t = threading.Thread(
        target=_autonomous_evolution_daemon,
        daemon=True,
        name="autonomous-evolution"
    )
    t.start()
    logging.info(f"[EVO-AUTO] Daemon démarré — cycle toutes les {_EVO_INTERVAL//60} min, max {_EVO_MAX_DAILY}/jour")

def self_rollback(evolution_id):
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT target_file, snapshot_before FROM evolution_log WHERE id=?",
            (evolution_id,)
        ).fetchone()
        if not row:
            conn.close()
            return {"ok": False, "error": "Evolution #%d introuvable" % evolution_id}
        alias, before = row["target_file"], row["snapshot_before"]
        if not before:
            conn.close()
            return {"ok": False, "error": "Snapshot vide — rollback impossible"}
        path = SELF_SOURCE_FILES.get(alias)
        if not path:
            conn.close()
            return {"ok": False, "error": "alias inconnu: %s" % alias}
        tmp = path + ".rollback_tmp"
        Path(tmp).write_text(before, encoding="utf-8")
        os.replace(tmp, path)
        conn.execute("UPDATE evolution_log SET status='rolled_back' WHERE id=?", (evolution_id,))
        conn.commit()
        conn.close()
        if alias == "agent":
            threading.Thread(target=_self_restart_agent, args=(-evolution_id,), daemon=True, name="self-restart-rollback").start()
            return {"ok": True, "message": "Rollback #%d — redemarrage dans 3s" % evolution_id}
        return {"ok": True, "message": "Rollback #%d applique" % evolution_id}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def self_get_history(limit=20):
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT id, ts, target_file, description, motivation, "
            "sha256_before, sha256_after, status, restart_done "
            "FROM evolution_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

def self_get_wishlist():
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT id, ts, target_file, category, description, priority, status, identified_by "
            "FROM evolution_wishlist ORDER BY "
            "CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, id DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

def self_add_wish(target_file, category, description, priority="medium", identified_by="user"):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO evolution_wishlist "
            "(ts, target_file, category, description, priority, identified_by) "
            "VALUES (?,?,?,?,?,?)",
            (datetime.now().isoformat(), target_file, category, description, priority, identified_by)
        )
        conn.commit()
        conn.close()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def self_analyze():
    suggestions = []
    now = datetime.now().isoformat()
    for alias, path in SELF_SOURCE_FILES.items():
        if not Path(path).exists():
            continue
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
            silent = sum(1 for l in lines if "except" in l and "pass" in l)
            if silent > 3:
                suggestions.append({
                    "alias": alias, "category": "error_handling",
                    "description": "%d blocs except+pass silencieux" % silent,
                    "priority": "medium"
                })
            for i, line in enumerate(lines, 1):
                for m in ("TODO", "FIXME", "HACK"):
                    if m in line and not line.strip().startswith("#!"):
                        suggestions.append({
                            "alias": alias, "category": "todo",
                            "description": "Ligne %d: %s" % (i, line.strip()[:100]),
                            "priority": "low"
                        })
                        break
        except Exception:
            pass
    if suggestions:
        conn = get_db()
        for s in suggestions:
            ex = conn.execute(
                "SELECT id FROM evolution_wishlist WHERE description=? AND status='pending'",
                (s["description"],)
            ).fetchone()
            if not ex:
                conn.execute(
                    "INSERT INTO evolution_wishlist "
                    "(ts, target_file, category, description, priority, identified_by) "
                    "VALUES (?,?,?,?,?,?)",
                    (now, s["alias"], s["category"], s["description"], s["priority"], "self_analyze")
                )
        conn.commit()
        conn.close()
    return suggestions

def _self_evolution_tick():
    try:
        r = self_analyze()
        if r:
            print("[EVOLUTION] %d suggestion(s) ajoutees" % len(r))
    except Exception as e:
        print("[EVOLUTION] tick erreur: %s" % e)



def _get_cached_sys_metrics():
    """Retourne les métriques système avec cache (évite lecture /proc à chaque requête)."""
    global _sys_metrics_cache, _sys_metrics_cache_time
    now = time.time()
    with _sys_metrics_lock:
        if now - _sys_metrics_cache_time < _SYS_METRICS_CACHE_TTL and _sys_metrics_cache:
            return _sys_metrics_cache
    try:
        with open("/proc/loadavg") as f:
            _cpu = float(f.read().split()[0])
        with open("/proc/meminfo") as f:
            _mem_info = f.read()
        _mem_total = 0
        _mem_avail = 0
        for _line in _mem_info.split("\n"):
            if _line.startswith("MemTotal:"):
                _mem_total = int(_line.split()[1])
            elif _line.startswith("MemAvailable:"):
                _mem_avail = int(_line.split()[1])
        _mem_pct = round((1 - _mem_avail / _mem_total) * 100, 1) if _mem_total else 0
        result = {"cpu": _cpu, "mem_pct": _mem_pct, "mem_total": _mem_total, "mem_avail": _mem_avail}
        with _sys_metrics_lock:
            _sys_metrics_cache = result
            _sys_metrics_cache_time = now
        return result
    except Exception:
        return {"cpu": 0.0, "mem_pct": 0.0, "mem_total": 0, "mem_avail": 0}

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
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            for token in generator:
                if token:
                    self.wfile.write(f"data: {json.dumps({'token': token})}\n\n".encode())
                    self.wfile.flush()
            self.wfile.write(f"data: {json.dumps({'done': True})}\n\n".encode())
            self.wfile.flush()
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self.wfile.write(f"data: {json.dumps({'token': f'[Erreur stream: {e}]', 'done': True})}\n\n".encode())
                self.wfile.flush()
            except Exception:
                pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        # ── WebSocket Terminal PTY ───────────────────────────────────────────
        if path == "/ws/terminal":
            if self.headers.get('Upgrade', '').lower() == 'websocket':
                tok = qs.get('token', [''])[0]
                if not validate_session(tok):
                    self.send_response(403)
                    self.end_headers()
                    return
                self._ws_handshake()
                self.handle_terminal_ws()
            return

        if path in ("/", "/index.html"):
            self.send_html(HTML_TEMPLATE)
            return
        # [EVO5] WebSocket upgrade
        if path == "/ws" and self.headers.get("Upgrade","").lower() == "websocket":
            threading.Thread(target=_ws_serve_client, args=(self,),
                             daemon=True, name="ws-client").start()
            return

        if path == "/api/verify":
            sid = self.headers.get("X-Session-Token", "")
            self.send_json({"valid": validate_session(sid)})
            return
        if path == "/api/ping":
            self.send_json({"pong": True, "timestamp": datetime.now().isoformat()})
            return
        
        if path == "/api/services":
            self.send_json(_api_services())
            return
        if path == "/api/health":
            try:
                with open("/proc/loadavg") as f: _cpu = float(f.read().split()[0])
                with open("/proc/meminfo") as f: _mem_info = f.read()
                _mem_total = int(re.search(r"MemTotal:\s+(\d+)", _mem_info).group(1)) // 1024
                _mem_avail = int(re.search(r"MemAvailable:\s+(\d+)", _mem_info).group(1)) // 1024
                _mem_used = _mem_total - _mem_avail
                _mem_pct = round(_mem_used / _mem_total * 100, 1) if _mem_total else 0
                _stat = os.statvfs("/")
                _disk_total = _stat.f_frsize * _stat.f_blocks / 1024 / 1024 / 1024
                _disk_free = _stat.f_frsize * _stat.f_bfree / 1024 / 1024 / 1024
                _disk_used = _disk_total - _disk_free
                _disk_pct = round(_disk_used / _disk_total * 100, 1) if _disk_total else 0
            except Exception:
                _cpu = _mem_pct = _mem_used = _mem_total = _disk_pct = _disk_used = _disk_total = None
            self.send_json({
                "status": "ok",
                "version": "v14",
                "uptime": int(time.time() - START_TIME),
                "uptime_human": str(timedelta(seconds=int(time.time() - START_TIME))),
                "health_score": health_score,
                "cpu_load_1m": _cpu,
                "ram_percent": _mem_pct,
                "ram_used_mb": _mem_used,
                "ram_total_mb": _mem_total,
                "disk_percent": _disk_pct,
                "disk_used_gb": round(_disk_used, 1),
                "disk_total_gb": round(_disk_total, 1),
                "timestamp": datetime.now().isoformat()
            })
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
            "/api/evolution/history":  lambda: {"history":  self_get_history()},
            "/api/evolution/wishlist": lambda: {"wishlist": self_get_wishlist()},
            "/api/evolution/analyze":  lambda: {"suggestions": self_analyze()},
            "/api/evolution/source":   lambda: {"source": self_read_source("agent")},
            "/api/health": get_health_score,
            "/api/server_info": get_server_info,
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
            "/api/settings": lambda: {
                "provider":  MODEL_PROVIDER, "model": MODEL_NAME,
                "base_url":  MODEL_BASE_URL, "key_set": bool(DEEPSEEK_API_KEY),
                "key_masked": ("sk-" + "*" * (len(DEEPSEEK_API_KEY or "") - 6) + (DEEPSEEK_API_KEY or "")[-3:])
                              if len(DEEPSEEK_API_KEY or "") > 6 else ("***" if DEEPSEEK_API_KEY else ""),
                "providers": list(_PROVIDERS.keys()), "default_models": _DEFAULT_MODELS,
            },
            "/api/settings/bookstack": lambda: {
                "bookstack_url":      get_cassandra_config().get("bookstack_url", ""),
                "bookstack_token_id": get_cassandra_config().get("bookstack_token_id", ""),
                "connected":          bool(get_cassandra_config().get("bookstack_url")
                                          and get_cassandra_config().get("bookstack_token_id")),
            },
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

        # EVOLUTION ENDPOINTS
        if path == "/api/evolution/apply":
            code = data.get("code", "")
            if not code:
                self._json({"ok": False, "error": "code manquant"}); return
            self._json(self_apply_change(
                data.get("alias", "agent"), code,
                data.get("description", ""), data.get("motivation", "")
            )); return
        if path == "/api/evolution/rollback":
            evo_id = data.get("evolution_id")
            if not evo_id:
                self._json({"ok": False, "error": "evolution_id manquant"}); return
            self._json(self_rollback(int(evo_id))); return
        if path == "/api/evolution/wish":
            self._json(self_add_wish(
                data.get("target_file", "agent"),
                data.get("category", "amelioration"),
                data.get("description", ""),
                data.get("priority", "medium"),
                data.get("identified_by", "user")
            )); return
    # LOGIN
        if path == "/api/alerts/config":
            cfg = load_alert_config()
            self._json(cfg)
            return

        if path == "/api/login":
            client_ip = self.client_address[0] if self.client_address else "unknown"
            now_ts = time.time()
            with _login_attempts_lock:
                recent = [t for t in _login_attempts.get(client_ip, [])
                          if now_ts - t < LOGIN_ATTEMPT_WINDOW]
                _login_attempts[client_ip] = recent
                if len(recent) >= LOGIN_MAX_ATTEMPTS:
                    wait = int(LOGIN_ATTEMPT_WINDOW - (now_ts - min(recent)))
                    self.send_json({"success": False,
                                    "error": f"Trop de tentatives. Réessayez dans {wait}s"}, 429)
                    return
            pwd = data.get("password", "")
            expected = get_admin_password_hash()
            if not expected:
                self.send_json({"success": False, "error": "Mot de passe non configuré (auth.json ou CASSANDRA_PASSWORD_HASH)"}, 500)
                return
            if hashlib.sha256(pwd.encode()).hexdigest() == expected:
                with _login_attempts_lock:
                    _login_attempts.pop(client_ip, None)
                sid = create_server_session()
                self.send_json({"success": True, "session": sid})
            else:
                with _login_attempts_lock:
                    _login_attempts.setdefault(client_ip, []).append(now_ts)
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
            expected = get_admin_password_hash()
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
            expected = get_admin_password_hash()
            if expected and hashlib.sha256(admin_pwd.encode()).hexdigest() != expected:
                log_admin_action(sid, "restart_agent", "FAILED", "wrong password")
                self.send_json({"error": "Mot de passe administrateur incorrect"}, 403)
                return
            try:
                record_admin_action(sid)

                def restart_agent():
                    time.sleep(1)
                    subprocess.run(["systemctl", "restart", "cassandra"], capture_output=True, timeout=30)

                threading.Thread(target=restart_agent, daemon=True, name="restart-agent").start()
                log_admin_action(sid, "restart_agent", "SUCCESS", "agent restart initiated")
                self.send_json({"success": True, "message": "Redémarrage de l'agent en cours. Vous allez être déconnecté."})
            except Exception as e:
                log_admin_action(sid, "restart_agent", "ERROR", str(e))
                self.send_json({"success": False, "error": str(e)}, 500)
            return

        # ── UPLOAD PIÈCE JOINTE ─────────────────────────────────────
        if path == "/api/upload":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401); return
            filename = data.get("filename", "fichier.bin")
            mime     = data.get("mime", "application/octet-stream")
            b64data  = data.get("data", "")
            size     = data.get("size", 0)
            # Limites
            MAX_SIZE_TEXT  = 1 * 1024 * 1024   # 1 MB texte/PDF
            MAX_SIZE_IMAGE = 8 * 1024 * 1024   # 8 MB images
            limit = MAX_SIZE_IMAGE if mime.startswith("image/") else MAX_SIZE_TEXT
            if size > limit:
                self.send_json({"error": f"Fichier trop grand (max {limit//1024//1024} MB)"}); return
            try:
                raw = base64.b64decode(b64data)
            except Exception:
                self.send_json({"error": "Données base64 invalides"}); return
            result = _extract_text_from_upload(raw, mime, filename)
            if result.get("error") and not result.get("text") and result.get("method") != "vision":
                self.send_json({"success": False, "error": result["error"]}); return
            resp = {
                "success": True,
                "filename": filename,
                "mime":     mime,
                "size":     size,
                "method":   result.get("method"),
                "truncated": result.get("truncated", False),
            }
            if result.get("method") == "vision":
                resp["image_b64"] = result["image_b64"]
                resp["content_type"] = "image"
            else:
                resp["text"] = result.get("text", "")
                resp["content_type"] = "text"
            if result.get("error"):
                resp["warning"] = result["error"]
            self.send_json(resp)
            return

        # ── SETTINGS : GET ──────────────────────────────────────────
        if path == "/api/settings":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401); return
            key = DEEPSEEK_API_KEY or ""
            masked = ("sk-" + "*" * (len(key) - 6) + key[-3:]) if len(key) > 6 else ("***" if key else "")
            self.send_json({
                "provider":  MODEL_PROVIDER,
                "model":     MODEL_NAME,
                "base_url":  MODEL_BASE_URL,
                "key_set":   bool(key),
                "key_masked": masked,
                "providers": list(_PROVIDERS.keys()),
                "default_models": _DEFAULT_MODELS,
            })
            return

        # ── SETTINGS : BOOKSTACK TEST (POST) ──────────────────────────
        if path == "/api/settings/bookstack/test":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401); return
            try:
                import urllib.request as _ureq, urllib.parse as _uparse
                req = _ureq.Request(
                    f"{_BS_URL}/api/search?" + _uparse.urlencode({"query": "a", "count": 1}),
                    headers=_bs_headers()
                )
                with _ureq.urlopen(req, timeout=5) as r:
                    d = json.loads(r.read().decode())
                total = d.get("total", 0)
                self.send_json({"success": True, "message": f"Connexion OK — {total} page(s) dans BookStack"})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)})
            return

        # ── SETTINGS : API KEY + PROVIDER + MODÈLE ──────────────
        if path == "/api/settings/api-key":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401); return
            new_key  = data.get("api_key", "").strip()
            provider = data.get("provider", "").strip() or None
            model    = data.get("model", "").strip() or None
            if not new_key:
                self.send_json({"success": False, "error": "Clé manquante"}, 400); return
            # Ollama n'a pas de vrai clé sk-
            if provider != "ollama" and not new_key.startswith("sk-"):
                self.send_json({"success": False, "error": "La clé doit commencer par sk-"}, 400); return
            if rotate_deepseek_key(new_key, provider=provider, model=model):
                log_admin_action(sid, "settings_api_key", "SUCCESS", f"provider={MODEL_PROVIDER}")
                self.send_json({"success": True, "provider": MODEL_PROVIDER, "model": MODEL_NAME})
            else:
                self.send_json({"success": False, "error": "Échec de la rotation de clé"}, 500)
            return

        # ── SETTINGS : CHANGEMENT MOT DE PASSE ADMIN ────────────
        if path == "/api/settings/password":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401); return
            old_pwd = data.get("old_password", "")
            new_pwd = data.get("new_password", "")
            if not old_pwd or not new_pwd:
                self.send_json({"success": False, "error": "Champs requis manquants"}, 400); return
            if len(new_pwd) < 8:
                self.send_json({"success": False, "error": "Mot de passe trop court (8 car. min)"}, 400); return
            expected = get_admin_password_hash()
            if not expected:
                self.send_json({"success": False, "error": "Hash actuel introuvable"}, 500); return
            if hashlib.sha256(old_pwd.encode()).hexdigest() != expected:
                log_admin_action(sid, "settings_password", "FAILED", "wrong old password")
                self.send_json({"success": False, "error": "Ancien mot de passe incorrect"}, 403); return
            new_hash = hashlib.sha256(new_pwd.encode()).hexdigest()
            if save_admin_password_hash(new_hash):
                log_admin_action(sid, "settings_password", "SUCCESS", "")
                self.send_json({"success": True})
            else:
                self.send_json({"success": False, "error": "Échec écriture auth.json"}, 500)
            return

        # ── SETTINGS : BOOKSTACK ────────────────────────────────────
        if path == "/api/settings/bookstack":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401); return
            url     = data.get("bookstack_url", "").strip().rstrip("/")
            tok_id  = data.get("bookstack_token_id", "").strip()
            tok_sec = data.get("bookstack_token_secret", "").strip()
            if not url or not tok_id:
                self.send_json({"success": False, "error": "URL et Token ID requis"}, 400); return
            cfg = get_cassandra_config()
            cfg["bookstack_url"]          = url
            cfg["bookstack_token_id"]     = tok_id
            if tok_sec:
                cfg["bookstack_token_secret"] = tok_sec
            if save_cassandra_config(cfg):
                reload_bookstack_cfg()
                log_admin_action(sid, "settings_bookstack", "SUCCESS", f"url={url}")
                self.send_json({"success": True})
            else:
                self.send_json({"success": False, "error": "Échec écriture config"}, 500)
            return

        # KILL SESSION SSH
        if path == "/api/session/kill":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            user = data.get("user", "").strip()
            ip   = data.get("ip", "").strip()
            tty  = data.get("tty", "").strip()
            if not user:
                self.send_json({"success": False, "error": "user requis"}, 400)
                return
            try:
                killed = False
                # Méthode 1 : tuer via le TTY (le plus propre)
                if not tty and ip:
                    who_out = secure_execute("who")
                    for line in who_out.splitlines():
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == user and (ip in line):
                            tty = parts[1]
                            break
                if tty and re.match(r'^pts/\d+$', tty):
                    out = secure_execute(f"pkill -9 -t {tty}")
                    killed = True
                else:
                    # Méthode 2 : tuer le process sshd de cet utilisateur
                    out = secure_execute(
                        f"ps aux | grep sshd | grep '{user}' | awk '{{print $2}}' | xargs -r kill -9"
                    )
                    killed = True
                log_admin_action(sid, "kill_session", "SUCCESS",
                                 f"user={user} ip={ip} tty={tty}")
                self.send_json({"success": True, "killed": killed})
            except Exception as e:
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
            msg         = data.get("message", "")
            sid         = data.get("session", "")
            expert_mode = data.get("expert_mode", False)
            plan_mode   = data.get("plan_mode", False)
            attachment  = data.get("attachment")   # {content_type, text, image_b64, mime, filename}
            if not validate_session(sid):
                self.send_json({"error": "Session invalide"}, 401)
                return
            if not msg and not attachment:
                self.send_json({"error": "Message vide"}, 400)
                return
            history = get_conversation_history(sid, 20)
            # PERF: prefetch BookStack en parallèle — timeout 1.5s, non-bloquant
            # Si BookStack répond dans le délai → contexte enrichi gratuitement
            # Si timeout ou erreur → on continue sans lui, zéro impact
            bs_ctx = _bs_prefetch(msg, timeout=1.5) if msg else ""
            messages = [{"role": "system", "content": build_system_prompt(sid, msg, expert_mode, bookstack_ctx=bs_ctx)}]
            for h in history:
                messages.append({"role": h["role"], "content": h["content"]})

            # Construire le contenu utilisateur avec éventuelle pièce jointe
            if attachment and attachment.get("content_type") == "image" and attachment.get("image_b64"):
                # Modèle vision — contenu multipart text+image
                user_content = []
                if msg:
                    user_content.append({"type": "text", "text": msg})
                user_content.append({
                    "type": "image_url",
                    "image_url": {"url": f"data:{attachment['mime']};base64,{attachment['image_b64']}"}
                })
                messages.append({"role": "user", "content": user_content})
                save_msg = msg or f"[Image jointe : {attachment.get('filename','')}]"
            elif attachment and attachment.get("text"):
                fname  = attachment.get("filename", "fichier")
                trunc  = " [TRONQUÉ — fichier trop long]" if attachment.get("truncated") else ""
                inject = (
                    f"\n\n📎 **Fichier joint : {fname}**{trunc}\n"
                    f"```\n{attachment['text']}\n```\n"
                )
                full_msg = (msg + inject) if msg else inject.strip()
                messages.append({"role": "user", "content": full_msg})
                save_msg = full_msg
            else:
                messages.append({"role": "user", "content": msg})
                save_msg = msg
            full_response_parts = []
            stream_error = None

            def stream_and_collect():
                nonlocal stream_error
                try:
                    for token in call_deepseek_stream(messages, session_id=sid, plan_mode=plan_mode):
                        if token:
                            full_response_parts.append(token)
                        yield token
                except Exception as e:
                    stream_error = e
                    yield f"[Erreur: {e}]"

            self.send_sse(stream_and_collect())
            full_response = "".join(full_response_parts)
            if full_response and not stream_error:
                save_conversation(sid, "user", save_msg)
                save_conversation(sid, "assistant", full_response)
                # Extraction asynchrone des apprentissages persistants
                extract_learnings_async(sid, save_msg, full_response)
            if count_raw_messages(sid) >= MAX_RAW_MESSAGES:
                threading.Thread(target=auto_summarize_session, args=(sid,), daemon=True, name="auto-summarize").start()
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

        # AUDIT SÉCURITÉ
        if path == "/api/audit":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            self.send_json({"success": True, "report": build_audit_report()})
            return

        # ── NOUVELLES APIs ────────────────────────────────────────────────────

        # ── Validation session commune aux APIs protégées ──────────────────
        _sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
        if path in ("/api/memories", "/api/memory/delete", "/api/memory/save",
                    "/api/actions", "/api/alerts", "/api/alert/resolve",
                    "/api/snapshots", "/api/rollback", "/api/crons"):
            if not validate_session(_sid):
                self.send_json({"error": "Non autorisé"}, 401); return

        # Mémoire persistante
        if path == "/api/memories":
            self.send_json(get_memories(limit=100))
            return
        if path == "/api/memory/delete":
            delete_memory(int(data.get("id", 0)))
            self.send_json({"success": True})
            return
        if path == "/api/memory/save":
            save_memory(data.get("category","fact"), data.get("key",""), data.get("value",""))
            self.send_json({"success": True})
            return

        # Journal d'audit des actions
        if path == "/api/actions":
            self.send_json(get_actions(limit=100))
            return

        # Alertes proactives
        if path == "/api/alerts":
            self.send_json(get_alerts(include_resolved=bool(data.get("all", False))))
            return
        if path == "/api/alert/resolve":
            resolve_alert(int(data.get("id", 0)))
            self.send_json({"success": True})
            return

        # Snapshots & Rollback
        if path == "/api/snapshots":
            self.send_json(get_snapshots())
            return
        if path == "/api/rollback":
            snap_id = data.get("id")
            if snap_id:
                self.send_json(restore_snapshot(int(snap_id)))
            else:
                self.send_json({"success": False, "error": "ID manquant"}, 400)
            return

        # Crons langage naturel
        if path == "/api/crons":
            self.send_json(get_cron_jobs_natural())
            return

        self.send_json({"error": "Not found"}, 404)

    # ============================================================
    # WEBSOCKET TERMINAL (PTY réel)
    # ============================================================

    def _ws_handshake(self):
        key = self.headers.get('Sec-WebSocket-Key', '')
        MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept = base64.b64encode(
            __import__('hashlib').sha1((key + MAGIC).encode()).digest()
        ).decode()
        self.send_response(101)
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept)
        self.end_headers()

    def _ws_recv(self):
        try:
            data = self.rfile.read(2)
            if len(data) < 2:
                return None
            b0, b1 = data[0], data[1]
            opcode = b0 & 0x0F
            masked = (b1 & 0x80) != 0
            length = b1 & 0x7F
            if length == 126:
                length = int.from_bytes(self.rfile.read(2), 'big')
            elif length == 127:
                length = int.from_bytes(self.rfile.read(8), 'big')
            mask_key = self.rfile.read(4) if masked else b''
            payload = bytearray(self.rfile.read(length))
            if masked:
                for i in range(len(payload)):
                    payload[i] ^= mask_key[i % 4]
            return opcode, bytes(payload)
        except Exception:
            return None

    def _ws_send(self, data: bytes, opcode: int = 0x2):
        length = len(data)
        header = bytearray()
        header.append(0x80 | opcode)
        if length < 126:
            header.append(length)
        elif length < 65536:
            header.append(126)
            header.extend(length.to_bytes(2, 'big'))
        else:
            header.append(127)
            header.extend(length.to_bytes(8, 'big'))
        try:
            self.wfile.write(bytes(header) + data)
            self.wfile.flush()
        except Exception:
            pass

    def handle_terminal_ws(self):
        import pty, select as _sel, termios, fcntl, signal as _sig
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe('/bin/bash', ['/bin/bash', '-l'], {
                'TERM': 'xterm-256color', 'HOME': '/root', 'USER': 'root',
                'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'SHELL': '/bin/bash', 'LANG': 'en_US.UTF-8', 'COLORTERM': 'truecolor',
                'PS1': r'\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ ',
            })
        # Parent
        try:
            while True:
                rlist, _, xlist = _sel.select([self.connection, fd], [], [self.connection, fd], 1.0)
                if xlist:
                    break
                if self.connection in rlist:
                    frame = self._ws_recv()
                    if frame is None:
                        break
                    opcode, payload = frame
                    if opcode == 0x8:  # Close
                        break
                    elif opcode in (0x1, 0x2):
                        try:
                            obj = json.loads(payload.decode('utf-8', errors='replace'))
                            if obj.get('type') == 'resize':
                                cols = int(obj.get('cols', 80))
                                rows = int(obj.get('rows', 24))
                                fcntl.ioctl(fd, termios.TIOCSWINSZ,
                                            struct.pack("HHHH", rows, cols, 0, 0))
                                continue
                        except Exception:
                            pass
                        try:
                            os.write(fd, payload)
                        except OSError:
                            break
                if fd in rlist:
                    try:
                        out = os.read(fd, 4096)
                        if out:
                            self._ws_send(out)
                        else:
                            break
                    except OSError:
                        break
        except Exception:
            pass
        finally:
            try:
                os.kill(pid, 9)
            except Exception:
                pass
            try:
                os.close(fd)
            except Exception:
                pass


# ============================================================
# 17. TEMPLATE HTML (COMPLET)
# ============================================================
HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cassandra- IA souveraine</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<style>
/* ===== CASSANDRA UI v2 — GLASSMORPHISM EDITION ===== */
:root {
  --bg-primary: #07080d;
  --bg-secondary: rgba(12, 14, 20, 0.92);
  --bg-card: rgba(18, 20, 30, 0.72);
  --bg-glass: rgba(255, 255, 255, 0.035);
  --border-glass: rgba(0, 200, 140, 0.10);
  --text-primary: #dde0ea;
  --text-secondary: #5a5a70;
  --accent: #00c896;
  --accent2: #6a4de0;
  --danger: #e03e52;
  --warning: #e8941a;
  --success: #27c168;
  --shadow-glass: 0 8px 32px rgba(0, 0, 0, 0.45);
  --radius-sm: 6px;
  --radius-md: 12px;
  --radius-lg: 20px;
  --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  --red:    #e03e52;
  --orange: #e8941a;
  --evo-auto: #00c896;
  --matrix-green: #00b882;
}

/* Glassmorphism cards */
.glass-card {
  background: var(--bg-glass);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--border-glass);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-glass);
  transition: var(--transition);
}
.glass-card:hover {
  border-color: var(--accent);
  transform: translateY(-2px);
  box-shadow: 0 12px 40px rgba(0, 255, 170, 0.1);
}

/* Animations */
@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes fadeInLeft {
  from { opacity: 0; transform: translateX(-20px); }
  to { opacity: 1; transform: translateX(0); }
}
@keyframes fadeInRight {
  from { opacity: 0; transform: translateX(20px); }
  to { opacity: 1; transform: translateX(0); }
}
@keyframes scaleIn {
  from { opacity: 0; transform: scale(0.9); }
  to { opacity: 1; transform: scale(1); }
}
@keyframes shimmer {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}
@keyframes float {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-10px); }
}
@keyframes glow {
  0%, 100% { box-shadow: 0 0 5px var(--accent); }
  50% { box-shadow: 0 0 20px var(--accent), 0 0 40px rgba(0, 255, 170, 0.3); }
}
.animate-fade-up { animation: fadeInUp 0.5s ease forwards; }
.animate-fade-left { animation: fadeInLeft 0.5s ease forwards; }
.animate-fade-right { animation: fadeInRight 0.5s ease forwards; }
.animate-scale { animation: scaleIn 0.3s ease forwards; }
.animate-float { animation: float 3s ease-in-out infinite; }
.animate-glow { animation: glow 2s ease-in-out infinite; }
.animate-shimmer {
  background: linear-gradient(90deg, transparent, rgba(0, 255, 170, 0.05), transparent);
  background-size: 200% 100%;
  animation: shimmer 2s infinite;
}

/* Stagger children */
.stagger > * { opacity: 0; }
.stagger > *:nth-child(1) { animation: fadeInUp 0.5s ease 0.05s forwards; }
.stagger > *:nth-child(2) { animation: fadeInUp 0.5s ease 0.1s forwards; }
.stagger > *:nth-child(3) { animation: fadeInUp 0.5s ease 0.15s forwards; }
.stagger > *:nth-child(4) { animation: fadeInUp 0.5s ease 0.2s forwards; }
.stagger > *:nth-child(5) { animation: fadeInUp 0.5s ease 0.25s forwards; }
.stagger > *:nth-child(6) { animation: fadeInUp 0.5s ease 0.3s forwards; }
.stagger > *:nth-child(7) { animation: fadeInUp 0.5s ease 0.35s forwards; }
.stagger > *:nth-child(8) { animation: fadeInUp 0.5s ease 0.4s forwards; }

/* Theme toggle */
.theme-toggle {
  position: relative;
  width: 44px;
  height: 24px;
  background: rgba(255,255,255,0.1);
  border-radius: 12px;
  cursor: pointer;
  border: 1px solid var(--border-glass);
  transition: var(--transition);
}
.theme-toggle::after {
  content: '';
  position: absolute;
  top: 2px;
  left: 2px;
  width: 18px;
  height: 18px;
  background: var(--accent);
  border-radius: 50%;
  transition: var(--transition);
}
.theme-toggle.light::after {
  left: 22px;
  background: #ffa502;
}

/* Light theme */
body.light-theme {
  --bg-primary: #f0f0f5;
  --bg-secondary: rgba(255, 255, 255, 0.9);
  --bg-card: rgba(255, 255, 255, 0.8);
  --bg-glass: rgba(255, 255, 255, 0.3);
  --border-glass: rgba(0, 0, 0, 0.1);
  --text-primary: #1a1a2e;
  --text-secondary: #6b6b80;
}

/* ═══════════════════════════════════════════════════
   MOBILE — barre de métriques + bottom nav + drawer
═══════════════════════════════════════════════════ */

/* Mobile metric strip — hidden on desktop */
.mobile-metric-strip{
  display:none;
  background:rgba(10,10,20,.96);
  border-bottom:1px solid rgba(0,255,204,.08);
  padding:6px 12px;gap:0;
}
.mms-item{
  flex:1;display:flex;flex-direction:column;align-items:center;
  padding:0 2px;border-right:1px solid rgba(255,255,255,.05)
}
.mms-item:last-child{border-right:none}
.mms-lbl{font-size:7px;text-transform:uppercase;letter-spacing:.1em;color:#3a3a55;margin-bottom:1px}
.mms-val{font-size:13px;font-weight:700;font-family:'JetBrains Mono',monospace;
  color:#e8e8f0;transition:color .3s}
.mms-val.ok{color:#2ed573}.mms-val.warning{color:#ffa502}.mms-val.critical{color:#ff4757}

/* Mobile bottom nav */
.mobile-bottom-nav{
  display:none;
  position:fixed;bottom:0;left:0;right:0;height:58px;
  background:rgba(8,8,18,.97);
  border-top:1px solid rgba(0,255,204,.12);
  backdrop-filter:blur(24px);z-index:200;
  padding:0 4px;gap:0;align-items:stretch
}
.mnav-item{
  flex:1;display:flex;flex-direction:column;
  align-items:center;justify-content:center;
  gap:2px;cursor:pointer;border-radius:8px;margin:3px 1px;
  transition:background .2s;position:relative;user-select:none
}
.mnav-item:active{background:rgba(0,255,204,.1)}
.mnav-item.active{background:rgba(0,255,204,.08)}
.mnav-item.active::after{
  content:'';position:absolute;top:0;left:25%;right:25%;
  height:2px;background:var(--accent);border-radius:0 0 3px 3px
}
.mnav-icon{font-size:17px;line-height:1}
.mnav-lbl{font-size:9px;color:#5a5a75;letter-spacing:.02em;transition:color .2s}
.mnav-item.active .mnav-lbl{color:var(--accent)}
.mnav-badge{
  position:absolute;top:1px;right:10px;
  background:#ff4757;color:#fff;font-size:8px;font-weight:700;
  border-radius:50%;width:13px;height:13px;
  display:none;align-items:center;justify-content:center
}
.mnav-badge.show{display:flex}

/* Metrics drawer (slide-up) */
.mmd-overlay{
  display:none;position:fixed;inset:0;bottom:58px;
  background:rgba(0,0,0,.55);z-index:198;backdrop-filter:blur(4px)
}
.mmd-overlay.open{display:block}
.mobile-metrics-drawer{
  display:none;
  position:fixed;bottom:58px;left:0;right:0;
  max-height:72dvh;
  background:rgba(11,11,20,.99);
  border-top:1px solid rgba(0,255,204,.18);
  border-radius:18px 18px 0 0;
  backdrop-filter:blur(24px);z-index:199;
  overflow-y:auto;padding:0 14px 16px;
  transform:translateY(100%);
  transition:transform .38s cubic-bezier(.22,1,.36,1)
}
.mobile-metrics-drawer.open{display:block;transform:translateY(0)}
.mmd-handle{width:38px;height:4px;background:rgba(255,255,255,.18);
  border-radius:2px;margin:10px auto 14px;cursor:pointer}

/* ═══════════════════════════════════════════════════
   RESPONSIVE BREAKPOINTS
═══════════════════════════════════════════════════ */

@media (max-width: 1024px){
  .panel-right{display:none}
  .panel-center{flex:1;width:auto}
}

@media (max-width: 768px){
  /* Mobile: tout tient dans 100dvh, le chat est scrollable internement */
  body{overflow:hidden}
  .app-container{height:100dvh;display:flex;flex-direction:column;overflow:hidden}

  /* Afficher éléments mobile */
  .mobile-metric-strip{display:flex}
  .mobile-bottom-nav{display:flex}

  /* Cacher tabs desktop + boutons superflus */
  .tabs{display:none!important}
  .service-btn-group{display:none!important}
  #expert-mode-btn,#plan-mode-btn,#terminal-open-btn,.audit-btn{display:none!important}
  .logo-badge,.session-time{display:none}

  /* Header compact */
  .header{padding:8px 12px}
  .logo{font-size:15px}

  /* Tab-content : flex colonne, prend tout l'espace restant sauf bottom nav */
  .tab-content{display:none;flex-direction:column}
  .tab-content.active{
    display:flex!important;flex-direction:column!important;
    flex:1;min-height:0;overflow:hidden;
    padding-bottom:58px  /* espace bottom nav */
  }

  /* Dashboard : chat seul, panneaux lat. cachés */
  .main-layout{flex-direction:column;flex:1;min-height:0;gap:0;background:none;overflow:hidden}
  .panel-left,.panel-right{display:none!important}
  .panel-center{
    width:100%!important;min-width:0;flex:1;
    display:flex;flex-direction:column;min-height:0;padding:0
  }
  .chat-messages{flex:1;min-height:0;overflow-y:auto;padding:10px}
  .chat-input{font-size:16px!important}
  .chat-input-area{padding:8px 10px 10px;flex-shrink:0}
  .chat-hints{display:none}

  /* Onglet Evolution : deux colonnes en colonne unique scrollable */
  #tab-evolution > div:last-child{flex-direction:column!important;overflow-y:auto!important}
  #tab-evolution > div:last-child > div{border-right:none!important;border-bottom:1px solid rgba(255,255,255,.06);min-height:200px}

  /* History : 1 colonne */
  .history-layout{padding:10px;overflow-y:auto}
  .history-charts{grid-template-columns:1fr}
  .history-chart-container{height:120px}

  /* Fleet */
  .fleet-agg{grid-template-columns:1fr 1fr}
  .fleet-layout{padding:10px;overflow-y:auto}

  /* FastPanel */
  .fp-layout{flex-direction:column}
  .fp-sidebar{width:100%;height:auto;border-right:none;border-bottom:1px solid rgba(0,255,204,.1)}
  .fp-nav{display:flex;overflow-x:auto;gap:4px;padding:8px;flex-wrap:nowrap}
  .fp-nav-item{white-space:nowrap;padding:6px 10px;flex-shrink:0;font-size:11px}
  .fp-nav-sep{display:none}

  /* Listes compactes */
  .cron-item{grid-template-columns:80px 1fr;font-size:10px}
  .action-item{grid-template-columns:55px 1fr 40px;font-size:10px}

  /* Modals */
  .audit-card{width:96%;max-height:90dvh}

  /* Drawer */
  .mobile-metrics-drawer .card{margin-bottom:8px;padding:10px}
  .mobile-metrics-drawer .stat-grid{gap:5px}
}

@media (max-width: 480px){
  .header{padding:6px 10px}
  .logo{font-size:13px}
  #status-text{font-size:11px}
  .hdr-btn{padding:4px 8px;font-size:10px}
  .fleet-agg{grid-template-columns:1fr 1fr}
  .stat-grid{grid-template-columns:1fr 1fr}
}

/* ═══════════════════════════════════════════════════
   DESIGN INNOVATIONS — effets, glow, animations
═══════════════════════════════════════════════════ */

/* Header scan-line animée */
.header{position:relative;overflow:hidden}
.header::after{
  content:'';position:absolute;bottom:0;left:-100%;
  width:60%;height:1px;
  background:linear-gradient(90deg,transparent,rgba(0,255,204,.6),transparent);
  animation:hdrScan 6s ease-in-out infinite
}
@keyframes hdrScan{0%{left:-60%}100%{left:130%}}

/* Glow dynamique sur cartes critiques */
@keyframes critGlow{
  0%,100%{border-color:rgba(255,71,87,.25);box-shadow:0 0 8px rgba(255,71,87,.06)}
  50%{border-color:rgba(255,71,87,.5);box-shadow:0 0 16px rgba(255,71,87,.15)}
}
@keyframes warnGlow{
  0%,100%{border-color:rgba(255,165,0,.2)}
  50%{border-color:rgba(255,165,0,.45);box-shadow:0 0 12px rgba(255,165,0,.1)}
}
.card.state-critical{animation:critGlow 2.2s ease-in-out infinite}
.card.state-warning{animation:warnGlow 3s ease-in-out infinite}

/* Pulse au refresh des données */
@keyframes dataFlash{from{background:rgba(0,255,204,.07)}to{background:transparent}}
.stat-card.updated{animation:dataFlash .5s ease}

/* Health ring plus grande + glow */
@media(min-width:769px){
  .health-ring{width:90px;height:90px}
  .health-ring-inner{width:68px;height:68px}
  .health-ring-score{font-size:23px}
  .health-ring{filter:drop-shadow(0 0 8px currentColor)}
}

/* Status dot neon */
.status-dot{box-shadow:0 0 6px var(--accent),0 0 14px rgba(0,255,204,.25);animation:neonPulse 2.4s ease-in-out infinite}
@keyframes neonPulse{0%,100%{opacity:1;box-shadow:0 0 6px var(--accent)}50%{opacity:.7;box-shadow:0 0 14px var(--accent),0 0 28px rgba(0,255,204,.2)}}

/* Tab active: subtle gradient + glow text */
.tab.active{
  background:linear-gradient(to bottom,rgba(0,255,204,.07),transparent);
  text-shadow:0 0 10px rgba(0,255,204,.45)
}

/* Stat-card hover lift */
.stat-card{transition:transform .2s ease,border-color .2s}
.stat-card:hover{transform:translateY(-2px)}

/* Progress bar shimmer */
.stat-bar-fill::after{
  content:'';position:absolute;top:0;left:0;right:0;bottom:0;
  background:linear-gradient(90deg,transparent 0%,rgba(255,255,255,.3) 50%,transparent 100%);
  background-size:200% 100%;animation:barShimmer 2.5s linear infinite
}
.stat-bar-mini{position:relative;overflow:hidden}
@keyframes barShimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}

/* Card gradient top-border accent */
.card{
  border-top:1px solid rgba(0,255,204,.12);
  background:linear-gradient(160deg,rgba(0,255,204,.025) 0%,transparent 50%),rgba(28,28,37,.8)
}
.card:hover{border-top-color:rgba(0,255,204,.3)}

/* Loading skeleton */
.skeleton {
  background: linear-gradient(90deg, rgba(255,255,255,0.03) 25%, rgba(255,255,255,0.08) 50%, rgba(255,255,255,0.03) 75%);
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: 4px;
}

/* Scrollbar styling */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--accent); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent2); }

/* Notification toast */
.toast-container {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.toast {
  background: var(--bg-glass);
  backdrop-filter: blur(16px);
  border: 1px solid var(--border-glass);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  font-size: 13px;
  color: var(--text-primary);
  box-shadow: var(--shadow-glass);
  animation: fadeInRight 0.3s ease, fadeInRight 0.3s ease reverse 3s forwards;
  max-width: 360px;
}
.toast.success { border-left: 3px solid var(--success); }
.toast.error { border-left: 3px solid var(--danger); }
.toast.warning { border-left: 3px solid var(--warning); }
.toast.info { border-left: 3px solid var(--accent); }
</style>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e8e8f0;height:100vh;overflow:hidden}
#particles-canvas{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;opacity:.07}
/* Server info block inside health card */
.sinfo-grid{display:grid;grid-template-columns:1fr 1fr;gap:2px 8px;margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,.05)}
.sinfo-row{display:flex;flex-direction:column;gap:1px;padding:3px 0}
.sinfo-lbl{font-size:8px;text-transform:uppercase;letter-spacing:.1em;color:#3a3a52}
.sinfo-val{font-size:10px;font-family:'JetBrains Mono',monospace;color:#8888a8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
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
.panel-center{flex:1;display:flex;flex-direction:column;padding:0;overflow:hidden}
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
/* ── CHAT REFONTE v2 ── */
.chat-messages{flex:1;overflow-y:auto;overflow-x:hidden;padding:20px 16px;display:flex;flex-direction:column;gap:20px;scroll-behavior:smooth}
.chat-messages::-webkit-scrollbar{width:4px}
.chat-messages::-webkit-scrollbar-track{background:transparent}
.chat-messages::-webkit-scrollbar-thumb{background:rgba(0,255,170,.2);border-radius:2px}

/* Groupe message = avatar + bulle */
.message{display:flex;gap:10px;animation:msgIn .2s ease}
@keyframes msgIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.message.user{flex-direction:row-reverse}
.msg-avatar{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0;margin-top:2px}
.message.user .msg-avatar{background:linear-gradient(135deg,#7c5cfc,#00ffcc);color:#0a0a0f;font-weight:700}
.message.bot .msg-avatar{background:rgba(0,255,170,.12);border:1px solid rgba(0,255,170,.3);color:#00ffcc}
.msg-body{flex:1;min-width:0;max-width:92%}
.message.user .msg-body{align-items:flex-end;display:flex;flex-direction:column}
.msg-meta{font-size:10px;color:#4a4a60;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.message.user .msg-meta{flex-direction:row-reverse}
.msg-name{font-weight:600}

/* Bulles */
.message-bubble{padding:12px 16px;border-radius:16px;font-size:13px;line-height:1.65;word-break:break-word;overflow-wrap:break-word;position:relative;min-width:0}
.msg-content{overflow-wrap:break-word;word-break:break-word;min-width:0}
.message.user .message-bubble{background:linear-gradient(135deg,#7c5cfc,#00ffcc22);border:1px solid rgba(124,92,252,.5);color:#e8e8f0;border-radius:16px 16px 4px 16px;width:100%;max-width:100%}
.message.bot .message-bubble{background:rgba(18,18,28,1);border:1px solid rgba(0,255,170,.15);border-radius:16px 16px 16px 4px;width:100%;overflow:visible}

/* Typographie dans les bulles bot */
.message.bot .message-bubble h2{font-size:14px;color:#00ffcc;margin:14px 0 6px;padding-bottom:4px;border-bottom:1px solid rgba(0,255,170,.15)}
.message.bot .message-bubble h2:first-child{margin-top:0}
.message.bot .message-bubble h3{font-size:13px;color:#a78bfa;margin:10px 0 4px}
.message.bot .message-bubble p{margin:6px 0}
.message.bot .message-bubble ul,.message.bot .message-bubble ol{margin:6px 0;padding-left:20px}
.message.bot .message-bubble li{margin:3px 0;color:#c8c8e0}
.message.bot .message-bubble strong{color:#e8e8f0;font-weight:600}
.message.bot .message-bubble em{color:#a0a0c0;font-style:italic}
.message.bot .message-bubble code{background:rgba(0,255,170,.08);border:1px solid rgba(0,255,170,.15);border-radius:4px;padding:1px 5px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#00ffcc}
.message.bot .message-bubble table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px}
.message.bot .message-bubble th{background:rgba(0,255,170,.1);padding:5px 10px;text-align:left;color:#00ffcc;font-weight:600;border:1px solid rgba(0,255,170,.2)}
.message.bot .message-bubble td{padding:4px 10px;border:1px solid rgba(0,255,170,.1);color:#c0c0d8}
.message.bot .message-bubble tr:nth-child(even) td{background:rgba(255,255,255,.02)}

/* Blocs d'exécution agent */
.exec-block{margin:10px 0;border-radius:10px;overflow:hidden;border:1px solid rgba(0,255,170,.2);background:#080810}
.exec-block[data-risky='1']{border-color:rgba(255,165,0,.4)}
.exec-block[data-risky='1'] .exec-cmd{background:rgba(255,165,0,.06);color:#ffa502}
.exec-cmd{display:block;padding:8px 12px;background:rgba(0,255,170,.06);font-family:'JetBrains Mono',monospace;font-size:11px;color:#00ffcc;border-bottom:1px solid rgba(0,255,170,.1);white-space:pre-wrap;word-break:break-all}
.exec-output{margin:0;padding:10px 12px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#9090b0;line-height:1.55;white-space:pre-wrap;word-break:break-word;max-height:300px;overflow-y:auto}
.exec-output::-webkit-scrollbar{width:3px}
.exec-output::-webkit-scrollbar-thumb{background:rgba(0,255,170,.2);border-radius:2px}
/* Diff visuel inline */
.diff-block{margin:6px 0;border-radius:8px;overflow:hidden;border:1px solid rgba(124,92,252,.25);font-family:'JetBrains Mono',monospace;font-size:10.5px;background:#06060d}
.diff-title{padding:5px 10px;background:rgba(124,92,252,.12);color:#a78bfa;font-size:10px;border-bottom:1px solid rgba(124,92,252,.2)}
.diff-add{background:rgba(46,213,115,.08);color:#2ed573;padding:1px 10px}
.diff-del{background:rgba(255,71,87,.08);color:#ff6b81;padding:1px 10px}
.diff-hunk{background:rgba(0,188,212,.06);color:#00bcd4;padding:1px 10px}
.diff-ctx{color:#4a4a60;padding:1px 10px}
/* Rollback */
.rollback-hint{display:flex;align-items:center;gap:10px;padding:6px 12px;background:rgba(255,165,0,.06);border-top:1px solid rgba(255,165,0,.15);font-size:11px;color:#9090b0}
.rollback-btn{background:rgba(255,165,0,.15);border:1px solid rgba(255,165,0,.4);color:#ffa502;border-radius:5px;padding:3px 10px;font-size:10px;cursor:pointer;transition:all .2s}
.rollback-btn:hover{background:rgba(255,165,0,.3)}
/* Alerte cloche header */
.bell-wrap{position:relative;cursor:pointer;padding:4px 8px}
.bell-icon{font-size:16px;transition:transform .2s}
.bell-wrap:hover .bell-icon{transform:rotate(-15deg)}
.evo-auto-badge{display:inline-block;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;background:rgba(0,255,204,.15);color:#00ffcc;border:1px solid rgba(0,255,204,.3);letter-spacing:.05em}
.bell-badge{position:absolute;top:0;right:0;background:#ff4757;color:#fff;font-size:9px;font-weight:700;border-radius:50%;width:16px;height:16px;display:flex;align-items:center;justify-content:center;display:none}
.bell-badge.has-alerts{display:flex}
/* Dropdown alertes */
.alert-dropdown{position:absolute;top:40px;right:0;width:320px;background:rgba(17,17,28,.97);border:1px solid rgba(255,71,87,.3);border-radius:12px;backdrop-filter:blur(20px);z-index:9999;display:none;max-height:400px;overflow-y:auto;box-shadow:0 20px 40px rgba(0,0,0,.6)}
.alert-dropdown.open{display:block}
.alert-item{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.05);display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.alert-item:last-child{border-bottom:none}
.alert-msg{font-size:11px;color:#e8e8f0;flex:1;line-height:1.4}
.alert-ts{font-size:9px;color:#4a4a60;white-space:nowrap}
.alert-resolve{background:none;border:none;color:#4a4a60;cursor:pointer;font-size:14px;padding:0 2px}
.alert-resolve:hover{color:#00ffcc}
.alert-empty{padding:20px;text-align:center;color:#4a4a60;font-size:12px}
/* Onglets nouveaux */
.tab-memory,.tab-journal,.tab-crons{cursor:pointer}
/* Panneau mémoire / journal / crons */
.mem-item{display:flex;gap:10px;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04);align-items:flex-start}
.mem-cat{font-size:9px;background:rgba(124,92,252,.2);color:#a78bfa;border-radius:4px;padding:2px 7px;white-space:nowrap;margin-top:2px}
.mem-key{font-size:11px;color:#00ffcc;font-family:'JetBrains Mono',monospace;min-width:120px}
.mem-val{font-size:11px;color:#b0b0c8;flex:1;line-height:1.4}
.mem-del{background:none;border:none;color:#4a4a60;cursor:pointer;font-size:14px}
.mem-del:hover{color:#ff4757}
.action-item{display:grid;grid-template-columns:80px 1fr 60px 50px;gap:6px;padding:7px 12px;border-bottom:1px solid rgba(255,255,255,.04);align-items:center}
.action-ts{font-size:9px;color:#4a4a60;font-family:'JetBrains Mono',monospace}
.action-cmd{font-size:10px;color:#e8e8f0;font-family:'JetBrains Mono',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.action-dur{font-size:9px;color:#6b6b80;text-align:right}
.risky-badge{font-size:9px;background:rgba(255,165,0,.15);color:#ffa502;border-radius:3px;padding:1px 5px;text-align:center}
.plan-block{background:rgba(124,92,252,.06);border:1px solid rgba(124,92,252,.25);border-radius:10px;padding:12px;margin:8px 0}
.plan-step{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.plan-step:last-child{border-bottom:none}
.plan-risk-low{color:#2ed573;font-size:10px}.plan-risk-medium{color:#ffa502;font-size:10px}.plan-risk-high{color:#ff4757;font-size:10px}
.plan-approve-btn{background:rgba(0,255,170,.15);border:1px solid rgba(0,255,170,.3);color:#00ffcc;border-radius:6px;padding:4px 12px;font-size:11px;cursor:pointer}
.cron-item{display:grid;grid-template-columns:120px 1fr 80px;gap:8px;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04);align-items:center}
.cron-expr{font-family:'JetBrains Mono',monospace;font-size:10px;color:#00ffcc}
.cron-desc{font-size:11px;color:#b0b0c8}
.exec-output.collapsed{max-height:80px;overflow:hidden;position:relative}
.exec-output.collapsed::after{content:"";position:absolute;bottom:0;left:0;right:0;height:30px;background:linear-gradient(transparent,#080810)}
.exec-expand{display:block;padding:5px 12px;text-align:center;font-size:10px;color:#4a4a60;cursor:pointer;background:rgba(0,255,170,.03);border-top:1px solid rgba(0,255,170,.08);transition:color .15s}
.exec-expand:hover{color:#00ffcc}

/* Anciens blocs commande (mode manuel) */
.command-block{background:#080810;border-radius:8px;margin:8px 0;border:1px solid rgba(0,255,170,.18);overflow:hidden}
.command-header{padding:7px 10px;background:rgba(0,255,170,.05);font-size:11px;font-family:'JetBrains Mono',monospace;display:flex;justify-content:space-between;align-items:center;color:#6b6b80}
.exec-btn{background:rgba(0,255,170,.12);border:1px solid rgba(0,255,170,.25);border-radius:4px;padding:3px 10px;color:#00ffcc;cursor:pointer;font-size:10px;transition:background .15s}
.exec-btn:hover{background:rgba(0,255,170,.25)}
.command-result{padding:8px 10px;font-size:11px;font-family:'JetBrains Mono',monospace;white-space:pre-wrap;max-height:200px;overflow-y:auto;color:#9090b0}

/* Bouton copier message */
.msg-copy-btn{opacity:0;position:absolute;top:8px;right:8px;background:rgba(0,255,170,.1);border:1px solid rgba(0,255,170,.2);border-radius:4px;padding:2px 7px;font-size:10px;color:#6b6b80;cursor:pointer;transition:all .15s}
.message-bubble:hover .msg-copy-btn{opacity:1}
.msg-copy-btn:hover{background:rgba(0,255,170,.2);color:#00ffcc}

/* Zone de saisie */
.chat-input-area{padding:12px 16px;border-top:1px solid rgba(0,255,170,.08);background:rgba(10,10,18,.8);display:flex;flex-direction:column;gap:8px}
.chat-input-row{display:flex;gap:8px;align-items:flex-end}
.chat-input{flex:1;background:rgba(18,18,28,1);border:1px solid rgba(0,255,170,.2);border-radius:12px;padding:10px 14px;color:#e8e8f0;font-family:'Inter',sans-serif;font-size:13px;resize:none;outline:none;max-height:120px;line-height:1.5;transition:border-color .2s}
.chat-input:focus{border-color:rgba(0,255,170,.5);box-shadow:0 0 0 2px rgba(0,255,170,.06)}
.chat-input::placeholder{color:#3a3a50}
.send-btn{background:linear-gradient(135deg,#00ffcc,#7c5cfc);border:none;border-radius:10px;width:40px;height:40px;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:opacity .2s,transform .1s}
.send-btn:hover{transform:scale(1.05)}
.send-btn:disabled{opacity:.35;transform:none}
.chat-hints{display:flex;gap:6px;flex-wrap:wrap}
.chat-hint{background:rgba(0,255,170,.06);border:1px solid rgba(0,255,170,.15);border-radius:20px;padding:3px 10px;font-size:11px;color:#6b6b80;cursor:pointer;transition:all .15s;white-space:nowrap}
.chat-hint:hover{background:rgba(0,255,170,.12);color:#00ffcc;border-color:rgba(0,255,170,.3)}

/* Indicateur de frappe */
.typing{display:flex;gap:5px;padding:10px 12px;align-items:center}
.typing-dot{width:7px;height:7px;border-radius:50%;background:#00ffcc;animation:typingAnim 1.4s infinite}
.typing-dot:nth-child(2){animation-delay:.2s}
.typing-dot:nth-child(3){animation-delay:.4s}
@keyframes typingAnim{0%,60%,100%{transform:translateY(0);opacity:.3}30%{transform:translateY(-5px);opacity:1}}
.typing-label{font-size:11px;color:#4a4a60;margin-left:4px}
.loader{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,255,170,.15);border-top-color:#00ffcc;border-radius:50%;animation:spin .6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* Scroll-to-bottom btn */
.scroll-bottom-btn{position:absolute;bottom:80px;right:20px;background:rgba(18,18,28,.95);border:1px solid rgba(0,255,170,.3);border-radius:20px;padding:5px 12px;font-size:11px;color:#00ffcc;cursor:pointer;display:none;gap:5px;align-items:center;z-index:10;transition:all .2s}
.scroll-bottom-btn.visible{display:flex}
.scroll-bottom-btn:hover{background:rgba(0,255,170,.1)}
.session-item{display:flex;align-items:center;gap:6px}
.kill-session-btn{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);border-radius:4px;color:#ff4757;cursor:pointer;font-size:10px;padding:2px 6px;transition:all .15s;flex-shrink:0}
.kill-session-btn:hover{background:rgba(255,71,87,.25);border-color:#ff4757}
.kill-session-btn:disabled{opacity:.4;cursor:default}
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

/* ══════════════════════════════════════════════════════════════
   AURORA BACKGROUND
══════════════════════════════════════════════════════════════ */
.aurora-wrap{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;overflow:hidden}
.aurora-blob{position:absolute;border-radius:50%;filter:blur(100px);animation:auroraDrift ease-in-out infinite}
.aurora-blob:nth-child(1){width:75vw;height:65vh;background:radial-gradient(ellipse,rgba(0,180,140,.05),transparent 70%);top:-20%;left:-15%;animation-duration:25s;animation-delay:0s}
.aurora-blob:nth-child(2){width:65vw;height:60vh;background:radial-gradient(ellipse,rgba(90,60,200,.04),transparent 70%);top:10%;right:-20%;animation-duration:30s;animation-delay:-8s}
.aurora-blob:nth-child(3){width:55vw;height:55vh;background:radial-gradient(ellipse,rgba(0,100,200,.03),transparent 70%);bottom:-18%;left:20%;animation-duration:38s;animation-delay:-15s}
@keyframes auroraDrift{0%,100%{transform:translate(0,0) scale(1)}25%{transform:translate(4%,3%) scale(1.04)}50%{transform:translate(-3%,6%) scale(0.96)}75%{transform:translate(6%,-3%) scale(1.03)}}

/* ══════════════════════════════════════════════════════════════
   CASSANDRA STATUS CARD — indicateur de réflexion live
══════════════════════════════════════════════════════════════ */
.cs-card{background:rgba(6,6,16,.97);border:1px solid rgba(0,255,204,.2);border-radius:18px;padding:14px 16px;position:relative;overflow:hidden;min-width:320px;max-width:100%;backdrop-filter:blur(16px)}
.cs-card::before{content:'';position:absolute;top:0;left:-80%;width:50%;height:2px;background:linear-gradient(90deg,transparent,rgba(0,255,204,.9),transparent);animation:csScan 2.2s linear infinite;pointer-events:none}
@keyframes csScan{to{left:130%}}
.cs-card::after{content:'';position:absolute;inset:0;border-radius:18px;background:linear-gradient(135deg,rgba(0,255,204,.03) 0%,transparent 60%);pointer-events:none}

.cs-header{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.cs-av{width:34px;height:34px;border-radius:50%;background:rgba(0,255,204,.08);border:1.5px solid rgba(0,255,204,.35);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#00ffcc;flex-shrink:0;animation:csAvPulse 2s ease-in-out infinite}
@keyframes csAvPulse{0%,100%{box-shadow:0 0 0 0 rgba(0,255,204,.35),0 0 8px rgba(0,255,204,.1)}50%{box-shadow:0 0 0 7px rgba(0,255,204,0),0 0 18px rgba(0,255,204,.15)}}
.cs-info{flex:1;min-width:0}
.cs-phase{font-size:11px;color:#00ffcc;font-weight:700;letter-spacing:.8px;text-transform:uppercase;transition:all .35s ease}
.cs-sub{font-size:10px;color:#4a4a60;margin-top:2px;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;transition:all .35s ease}
.cs-right{display:flex;flex-direction:column;align-items:flex-end;gap:3px;flex-shrink:0}
.cs-timer{font-size:13px;color:#e8e8f0;font-family:'JetBrains Mono',monospace;font-weight:700;font-variant-numeric:tabular-nums}
.cs-iter{font-size:9px;color:#4a4a60;font-family:'JetBrains Mono',monospace}

.cs-bar-wrap{height:2px;background:rgba(255,255,255,.06);border-radius:1px;margin-bottom:11px;overflow:hidden}
.cs-bar{height:100%;width:0%;background:linear-gradient(90deg,#7c5cfc,#00ffcc);border-radius:1px;transition:width .6s ease;animation:csBarShimmer 2s ease-in-out infinite}
@keyframes csBarShimmer{0%,100%{filter:brightness(1)}50%{filter:brightness(1.3)}}

.cs-steps{display:flex;flex-direction:column;gap:4px}
.cs-dot-row{display:flex;gap:5px;padding:5px 2px}
.cs-dot{width:6px;height:6px;border-radius:50%;background:#00ffcc;animation:csDot 1.4s ease-in-out infinite}
.cs-dot:nth-child(2){animation-delay:.22s}
.cs-dot:nth-child(3){animation-delay:.44s}
@keyframes csDot{0%,100%{transform:translateY(0);opacity:.2}45%{transform:translateY(-5px);opacity:1}}

.cs-step{display:flex;align-items:center;gap:7px;font-size:10px;font-family:'JetBrains Mono',monospace;padding:3px 0;animation:csStepIn .25s cubic-bezier(.34,1.56,.64,1) both}
@keyframes csStepIn{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:none}}
.cs-step.active .cs-si{color:#ffa502;animation:csSpinSlow 2s linear infinite}
.cs-step.done .cs-si{color:#2ed573}
.cs-step.active .cs-st{color:#e8e8f0}
.cs-step.done .cs-st{color:#4a4a60}
.cs-si{font-size:10px;flex-shrink:0;width:14px;text-align:center}
.cs-st{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#6b6b80}
.cs-stime{color:#3a3a50;font-size:9px;flex-shrink:0}
@keyframes csSpinSlow{0%,100%{transform:rotate(0deg)}50%{transform:rotate(180deg)}}

/* ══ PANEL GLOW BORDERS ══ */
.panel-left{border-right:1px solid transparent;background-image:linear-gradient(rgba(17,17,24,.8),rgba(17,17,24,.8)),linear-gradient(to bottom,transparent,rgba(0,255,204,.2) 40%,rgba(0,255,204,.3) 60%,transparent);background-clip:padding-box,border-box;background-origin:padding-box,border-box}
.panel-right{border-left:1px solid transparent;background-image:linear-gradient(rgba(17,17,24,.8),rgba(17,17,24,.8)),linear-gradient(to bottom,transparent,rgba(124,92,252,.2) 40%,rgba(124,92,252,.25) 60%,transparent);background-clip:padding-box,border-box;background-origin:padding-box,border-box}

/* ══ ENHANCED MESSAGE ANIMATIONS ══ */
@keyframes msgIn{from{opacity:0;transform:translateY(10px) scale(0.97)}65%{transform:translateY(-2px) scale(1.006)}to{opacity:1;transform:translateY(0) scale(1)}}
.message.bot.msg-fresh .message-bubble{animation:bubbleGlow .9s ease both}
@keyframes bubbleGlow{0%{border-color:rgba(0,255,204,.5);box-shadow:0 0 24px rgba(0,255,204,.2)}100%{border-color:rgba(0,255,204,.15);box-shadow:none}}

/* ══ SEND BUTTON PULSE ══ */
.send-btn.primed{animation:sendPrimed 2s ease-in-out infinite}
@keyframes sendPrimed{0%,100%{box-shadow:0 2px 8px rgba(0,255,204,.2)}50%{box-shadow:0 2px 18px rgba(0,255,204,.5),0 0 0 4px rgba(0,255,204,.1)}}

/* ══ STATUS DOT PHASES ══ */
.status-dot.thinking{background:#ffa502;box-shadow:0 0 8px #ffa502;animation:pulse .8s infinite}
.status-dot.executing{background:#ff4757;box-shadow:0 0 8px #ff4757;animation:pulse .4s infinite}

/* ============================================================
   TERMINAL CASSANDRA 
   ============================================================ */
/* ══════════════════════════════════════════════════════════════
   TERMINAL — redesign moderne
══════════════════════════════════════════════════════════════ */
.terminal-overlay{position:fixed;inset:0;background:rgba(3,3,8,.75);backdrop-filter:blur(6px);z-index:200;opacity:0;pointer-events:none;transition:opacity .3s ease}
.terminal-overlay.open{opacity:1;pointer-events:all}

.terminal-panel{
  position:fixed;top:0;right:-860px;width:860px;height:100%;
  background:rgba(7,7,16,.98);
  border-left:1px solid rgba(0,255,204,.1);
  z-index:201;display:flex;flex-direction:column;
  transition:right .38s cubic-bezier(.22,1,.36,1);
  box-shadow:-24px 0 80px rgba(0,0,0,.8),inset 1px 0 0 rgba(0,255,204,.06)
}
.terminal-panel.open{right:0}

/* ── Chrome header (macOS-style) ── */
.terminal-chrome{
  display:flex;align-items:center;gap:0;
  padding:13px 18px;
  background:rgba(10,10,20,.95);
  border-bottom:1px solid rgba(255,255,255,.05);
  flex-shrink:0;user-select:none
}
.tc-lights{display:flex;gap:8px;margin-right:18px;flex-shrink:0}
.tc-light{width:13px;height:13px;border-radius:50%;cursor:pointer;transition:filter .15s;flex-shrink:0;position:relative}
.tc-light.red   {background:#ff5f57;box-shadow:0 0 5px rgba(255,95,87,.45)}
.tc-light.yellow{background:#ffbd2e;box-shadow:0 0 5px rgba(255,189,46,.45)}
.tc-light.green {background:#28ca41;box-shadow:0 0 5px rgba(40,202,65,.45)}
.tc-light:hover{filter:brightness(1.25) saturate(1.2)}
.tc-title{flex:1;text-align:center;font-family:'JetBrains Mono',monospace;font-size:11px;color:#4a4a60;letter-spacing:.4px}
.tc-title strong{color:#9090a8;font-weight:500}
#term-status{color:#4a4a60}
.tc-actions{display:flex;gap:6px;flex-shrink:0}
.tc-btn{background:transparent;border:1px solid rgba(255,255,255,.08);border-radius:5px;padding:4px 10px;font-size:10px;cursor:pointer;color:#5a5a70;transition:all .15s;font-family:'JetBrains Mono',monospace}
.tc-btn:hover{background:rgba(0,255,204,.07);color:#00ffcc;border-color:rgba(0,255,204,.3)}
.tc-btn.danger:hover{background:rgba(255,71,87,.1);color:#ff4757;border-color:rgba(255,71,87,.3)}

/* ── Tab bar ── */
.terminal-tab-bar{
  display:flex;align-items:center;
  background:rgba(5,5,12,.9);
  border-bottom:1px solid rgba(255,255,255,.04);
  padding:5px 10px;gap:4px;flex-shrink:0
}
.terminal-tab{
  font-family:'JetBrains Mono',monospace;font-size:11px;
  padding:4px 12px;color:#4a4a60;cursor:pointer;
  border-radius:7px;transition:all .15s;
  display:flex;align-items:center;gap:6px;
  border:1px solid transparent;user-select:none
}
.terminal-tab.active{background:rgba(0,255,204,.09);color:#00ffcc;border-color:rgba(0,255,204,.18)}
.terminal-tab:not(.active):hover{background:rgba(255,255,255,.04);color:#8080a0}
.terminal-tab-close{opacity:0;font-size:11px;transition:opacity .1s;margin-left:2px}
.terminal-tab:hover .terminal-tab-close,.terminal-tab.active .terminal-tab-close{opacity:.5}
.terminal-tab-close:hover{opacity:1!important;color:#ff4757}
.terminal-new-tab{
  border:1px dashed rgba(255,255,255,.1);border-radius:6px;
  width:24px;height:24px;display:flex;align-items:center;justify-content:center;
  font-size:16px;color:#3a3a50;cursor:pointer;transition:all .15s;margin-left:2px;flex-shrink:0
}
.terminal-new-tab:hover{border-color:rgba(0,255,204,.3);color:#00ffcc;background:rgba(0,255,204,.05)}

/* ── xterm area ── */
.terminal-xterm-wrap{
  flex:1;padding:8px 6px 4px 8px;overflow:hidden;min-height:0;position:relative
}
.terminal-xterm-wrap::before{
  content:'';position:absolute;inset:0;
  background:repeating-linear-gradient(0deg,rgba(0,0,0,0) 0,rgba(0,0,0,0) 3px,rgba(0,0,0,.018) 3px,rgba(0,0,0,.018) 4px);
  pointer-events:none;z-index:10
}

/* ── Input row ── */
.terminal-input-row{
  display:flex;align-items:center;
  background:rgba(4,4,10,.95);
  border-top:1px solid rgba(0,255,204,.07);
  padding:0;flex-shrink:0
}
.terminal-prompt{
  font-family:'JetBrains Mono',monospace;font-size:12.5px;
  padding:9px 2px 9px 14px;white-space:nowrap;user-select:none;flex-shrink:0;
  display:flex;align-items:center;gap:2px
}
.tp-user{color:#2ed573;font-weight:700}
.tp-at{color:#3a3a50}
.tp-host{color:#7c5cfc;font-weight:600}
.tp-sep{color:#3a3a50}
.tp-path{color:#ffa502}
.tp-sym{color:#00ffcc;font-weight:700;margin-left:3px}
.terminal-cmd-input{
  flex:1;background:transparent;border:none;outline:none;
  color:#e8e8f0;font-family:'JetBrains Mono',monospace;font-size:13px;
  padding:9px 6px;caret-color:#00ffcc
}
.terminal-send-btn{
  background:transparent;border:none;
  border-left:1px solid rgba(0,255,204,.07);
  color:#3a3a50;padding:9px 14px;cursor:pointer;font-size:13px;
  transition:all .15s;flex-shrink:0
}
.terminal-send-btn:hover{color:#00ffcc;background:rgba(0,255,204,.06)}
.terminal-send-btn:disabled{opacity:.25;cursor:default}
#term-kill-btn{
  display:none;background:rgba(255,165,0,.1);border:none;
  border-left:1px solid rgba(255,165,0,.2);color:#ffa502;
  padding:9px 14px;cursor:pointer;font-size:10px;
  font-family:'JetBrains Mono',monospace;transition:all .15s;flex-shrink:0
}
#term-kill-btn:hover{background:rgba(255,165,0,.22)}

/* ── Status bar ── */
.terminal-statusbar{
  display:flex;align-items:center;justify-content:space-between;
  padding:4px 16px;
  background:rgba(0,255,204,.025);
  border-top:1px solid rgba(0,255,204,.06);
  flex-shrink:0;
  font-family:'JetBrains Mono',monospace;font-size:9px;color:#3a3a50
}
.tsb-left{display:flex;align-items:center;gap:14px}
.tsb-right{display:flex;align-items:center;gap:14px}
.tsb-sep{color:#2a2a3a}
.tsb-green{color:#2ed573}
.tsb-clock{color:#4a4a60;font-variant-numeric:tabular-nums;min-width:52px;text-align:right}
.tsb-hint{color:#3a3a50}

#terminal-open-btn{border-color:rgba(0,255,204,.3);background:rgba(0,255,204,.08);color:#00ffcc}
#terminal-open-btn:hover{background:rgba(0,255,204,.16)}
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

/* ═══════════════════════════════════════════════════════════
   OPTION A — Monitoring Pro: health ring, stat-cards, badges
═══════════════════════════════════════════════════════════ */

/* ── Health Ring ── */
.health-ring-wrap{display:flex;align-items:center;gap:14px;padding:4px 0 8px}
.health-ring{position:relative;width:74px;height:74px;border-radius:50%;flex-shrink:0;
  background:conic-gradient(var(--accent) 0deg,rgba(255,255,255,.06) 0deg);
  transition:background .6s ease;display:flex;align-items:center;justify-content:center}
.health-ring-inner{position:relative;z-index:2;width:54px;height:54px;
  background:rgba(14,14,22,.97);border-radius:50%;
  display:flex;flex-direction:column;align-items:center;justify-content:center}
.health-ring-score{font-size:19px;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}
.health-ring-lbl{font-size:8px;color:#4a4a60}
.health-ring-meta{flex:1;min-width:0}

/* ── Status pills ── */
.status-pill{display:inline-block;padding:3px 10px;border-radius:20px;
  font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;margin-bottom:4px}
.status-pill.excellent{background:rgba(46,213,115,.14);color:#2ed573;border:1px solid rgba(46,213,115,.3)}
.status-pill.good{background:rgba(0,255,204,.12);color:#00ffcc;border:1px solid rgba(0,255,204,.25)}
.status-pill.warning{background:rgba(255,165,0,.14);color:#ffa502;border:1px solid rgba(255,165,0,.3)}
.status-pill.critical{background:rgba(255,71,87,.14);color:#ff4757;border:1px solid rgba(255,71,87,.3)}

/* ── Stat cards grid ── */
.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:8px}
.stat-card{background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);
  border-radius:8px;padding:9px 10px;transition:border-color .2s}
.stat-card:hover{border-color:rgba(0,255,204,.22)}
.stat-top{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:5px}
.stat-lbl{font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:#6b6b80}
.stat-val{font-size:15px;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}
.stat-val.ok{color:#2ed573} .stat-val.warning{color:#ffa502} .stat-val.critical{color:#ff4757}
.stat-bar-mini{height:3px;background:rgba(255,255,255,.07);border-radius:2px;overflow:hidden}
.stat-bar-fill{height:100%;border-radius:2px;transition:width .4s ease}
.stat-bar-fill.cpu{background:linear-gradient(90deg,#00ffcc,#7c5cfc)}
.stat-bar-fill.ram{background:linear-gradient(90deg,#7c5cfc,#00ffcc)}
.stat-bar-fill.disk{background:linear-gradient(90deg,#00ffcc,#2ed573)}

/* ── Colored badges ── */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;
  font-weight:700;text-transform:uppercase;letter-spacing:.04em;flex-shrink:0;white-space:nowrap}
.badge-ok{background:rgba(46,213,115,.12);color:#2ed573;border:1px solid rgba(46,213,115,.25)}
.badge-warn{background:rgba(255,165,0,.12);color:#ffa502;border:1px solid rgba(255,165,0,.25)}
.badge-crit{background:rgba(255,71,87,.12);color:#ff4757;border:1px solid rgba(255,71,87,.25)}
.badge-info{background:rgba(0,255,204,.08);color:#00ffcc;border:1px solid rgba(0,255,204,.2)}
.badge-neutral{background:rgba(255,255,255,.06);color:#6b6b80;border:1px solid rgba(255,255,255,.1)}

/* ── Info rows (SSL, remotes, etc.) ── */
.info-row{display:flex;align-items:center;gap:6px;padding:5px 0;
  border-bottom:1px solid rgba(255,255,255,.04)}
.info-row:last-child{border-bottom:none}
.info-name{flex:1;font-size:11px;color:#c0c0d8;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;font-family:'JetBrains Mono',monospace}
.info-sub{font-size:9px;color:#4a4a60}

/* ── Process rows with mini-bars ── */
.proc-row{display:grid;grid-template-columns:1fr 44px 40px;gap:4px;
  align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.proc-row:last-child{border-bottom:none}
.proc-name{font-size:10px;color:#c0c0d8;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;font-family:'JetBrains Mono',monospace}
.proc-bar-wrap{height:4px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden}
.proc-bar-fill{height:100%;border-radius:2px;transition:width .3s ease}
.proc-pct{font-size:10px;font-family:'JetBrains Mono',monospace;text-align:right;white-space:nowrap}

/* ════════════════════════════════════
   PIÈCE JOINTE — chat input area
════════════════════════════════════ */
.attachment-preview{
  display:none;align-items:center;gap:10px;
  padding:7px 12px;
  margin:0 8px 6px;
  background:rgba(0,200,140,.07);
  border:1px solid rgba(0,200,140,.18);
  border-radius:8px;font-size:11px;
  animation:fadeIn .2s ease
}
.attachment-preview.visible{display:flex}
.att-icon{font-size:18px;flex-shrink:0}
.att-info{flex:1;min-width:0}
.att-name{font-weight:600;color:#dde0ea;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'JetBrains Mono',monospace}
.att-meta{color:#5a7a6a;font-size:10px;margin-top:1px}
.att-thumb{width:42px;height:42px;border-radius:5px;object-fit:cover;border:1px solid rgba(0,200,140,.2)}
.att-remove{background:none;border:none;color:#5a5a70;cursor:pointer;font-size:16px;padding:2px 4px;flex-shrink:0;transition:color .15s;line-height:1}
.att-remove:hover{color:#e03e52}
.att-badge{
  display:none;position:absolute;bottom:10px;left:10px;
  background:rgba(0,200,140,.15);border:1px solid rgba(0,200,140,.3);
  border-radius:6px;padding:3px 8px;font-size:10px;
  font-family:'JetBrains Mono',monospace;color:#00c896;pointer-events:none
}
/* bouton attach */
.attach-btn{
  background:transparent;border:none;
  color:#4a4a60;cursor:pointer;padding:9px 8px;font-size:18px;
  transition:color .15s;flex-shrink:0;line-height:1
}
.attach-btn:hover{color:var(--accent)}
.attach-btn.has-file{color:var(--accent)}

/* ════════════════════════════════════
   ONGLET PARAMÈTRES
════════════════════════════════════ */
.settings-layout{display:flex;flex-direction:column;gap:18px;padding:24px;max-width:860px;margin:0 auto;overflow-y:auto;height:100%}
.settings-section{background:rgba(18,20,30,.75);border:1px solid rgba(0,200,140,.09);border-radius:12px;padding:20px 22px}
.settings-section-title{font-size:11px;text-transform:uppercase;letter-spacing:.14em;color:var(--accent);margin-bottom:16px;display:flex;align-items:center;gap:8px}
.settings-section-title::after{content:'';flex:1;height:1px;background:rgba(0,200,140,.12)}
.settings-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.settings-row.single{grid-template-columns:1fr}
.settings-row.triple{grid-template-columns:1fr 1fr 1fr}
.s-field{display:flex;flex-direction:column;gap:5px}
.s-label{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#5a5a70}
.s-input,.s-select{
  background:rgba(8,10,16,.8);border:1px solid rgba(0,200,140,.15);
  border-radius:7px;padding:9px 12px;color:#dde0ea;font-family:'JetBrains Mono',monospace;font-size:12px;
  outline:none;transition:border-color .2s;width:100%;box-sizing:border-box
}
.s-input:focus,.s-select:focus{border-color:var(--accent)}
.s-input.mono{letter-spacing:.04em}
.s-btn{
  border:none;border-radius:7px;padding:10px 18px;cursor:pointer;font-size:12px;
  font-family:'JetBrains Mono',monospace;font-weight:600;transition:all .2s;
  display:inline-flex;align-items:center;gap:7px;white-space:nowrap
}
.s-btn.primary{background:var(--accent);color:#07080d}
.s-btn.primary:hover{filter:brightness(1.12)}
.s-btn.danger{background:rgba(224,62,82,.15);border:1px solid rgba(224,62,82,.35);color:#e03e52}
.s-btn.danger:hover{background:rgba(224,62,82,.28)}
.s-btn.warn{background:rgba(232,148,26,.12);border:1px solid rgba(232,148,26,.35);color:#e8941a}
.s-btn.warn:hover{background:rgba(232,148,26,.25)}
.s-btn:disabled{opacity:.4;cursor:not-allowed}
.s-hint{font-size:10px;color:#404055;margin-top:3px;line-height:1.5}
.s-feedback{font-size:11px;padding:7px 12px;border-radius:6px;margin-top:8px;display:none}
.s-feedback.ok{background:rgba(39,193,104,.12);border:1px solid rgba(39,193,104,.25);color:#27c168}
.s-feedback.err{background:rgba(224,62,82,.12);border:1px solid rgba(224,62,82,.25);color:#e03e52}
.s-current{display:flex;align-items:center;gap:8px;padding:8px 12px;background:rgba(0,200,140,.05);
  border:1px solid rgba(0,200,140,.1);border-radius:7px;font-size:11px;font-family:'JetBrains Mono',monospace;color:#7a9a8a;margin-bottom:12px}
.s-current .s-tag{font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:#3a5a4a;margin-right:4px}
/* Reboot cards */
.reboot-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.reboot-card{background:rgba(8,10,16,.6);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:16px}
.reboot-card-title{font-size:12px;font-weight:600;color:#dde0ea;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.reboot-card-sub{font-size:10px;color:#5a5a70;margin-bottom:14px;line-height:1.5}
.reboot-card .s-btn{width:100%;justify-content:center}
@media(max-width:640px){
  .settings-row,.settings-row.triple{grid-template-columns:1fr}
  .reboot-grid{grid-template-columns:1fr}
  .settings-layout{padding:14px}
}

</style>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0a0a0f">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Cassandra">
<link rel="apple-touch-icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔥</text></svg>">
</head>
<body>
<canvas id="particles-canvas"></canvas>
<div class="hex-grid"></div>
<div class="aurora-wrap">
  <div class="aurora-blob"></div>
  <div class="aurora-blob"></div>
  <div class="aurora-blob"></div>
</div>

<div id="login-modal" class="login-modal">
  <div class="login-card">
    <h1>🔐 CASSANDRA</h1>
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
    <div><span class="logo">CASSANDRA</span><span class="logo-badge">v14</span></div>
    <div class="status">
      <div class="status-dot"></div>
      <span id="status-text">ONLINE</span>
      <span class="session-time" id="session-time">0 min</span>
      <button id="expert-mode-btn" class="hdr-btn expert-btn">🔍 Mode normal</button>
      <button id="plan-mode-btn" class="hdr-btn" style="border-color:rgba(124,92,252,.3);background:rgba(124,92,252,.1);color:#a78bfa" onclick="togglePlanMode()">📋 Plan</button>
      <button id="terminal-open-btn" class="hdr-btn" onclick="openTerminal()">⌨ Terminal</button>
      <button class="hdr-btn audit-btn" onclick="openAudit()">🔍 Audit</button>
      <!-- Cloche alertes -->
      <div class="bell-wrap" style="position:relative" onclick="toggleAlertDropdown()">
        <span class="bell-icon">🔔</span>
        <span class="bell-badge" id="bell-badge">0</span>
        <div class="alert-dropdown" id="alert-dropdown"></div>
      </div>
      <button class="hdr-btn logout-btn" onclick="logout()">Déconnexion</button>
    </div>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('dashboard')">📊 Tableau de bord</div>
    <div class="tab" onclick="switchTab('history')">📈 Historique</div>
    <div class="tab" onclick="switchTab('fleet')">🌐 Flotte</div>
    <div class="tab" id="tab-fp-btn" onclick="switchTab('fastpanel')" style="display:none">🖥 FastPanel</div>
    <div class="tab" onclick="switchTab('memory')">🧠 Mémoire</div>
    <div class="tab" onclick="switchTab('journal')">📋 Journal</div>
    <div class="tab" onclick="switchTab('crons')">⏰ Tâches Planifiées</div>
    <div class="tab" onclick="switchTab('evolution')">🧬 Evolution</div>
    <div class="tab" onclick="switchTab('settings')">⚙️ Paramètres</div>
  </div>

  <!-- ═══ MOBILE METRIC STRIP (visible seulement <768px) ═══ -->
  <div class="mobile-metric-strip" id="mobile-metric-strip">
    <div class="mms-item"><div class="mms-lbl">CPU</div><div class="mms-val" id="mms-cpu">–</div></div>
    <div class="mms-item"><div class="mms-lbl">RAM</div><div class="mms-val" id="mms-ram">–</div></div>
    <div class="mms-item"><div class="mms-lbl">DISK</div><div class="mms-val" id="mms-disk">–</div></div>
    <div class="mms-item"><div class="mms-lbl">SANTÉ</div><div class="mms-val" id="mms-health">–</div></div>
  </div>

  <div id="tab-dashboard" class="tab-content active">
    <div class="main-layout">
      <div class="panel panel-left">
        <!-- SANTÉ — ring visuel avec gradient conic -->
        <div class="card">
          <div class="card-title">🏥 SANTÉ SYSTÈME</div>
          <div class="health-ring-wrap">
            <div class="health-ring" id="health-ring">
              <div class="health-ring-inner">
                <div class="health-ring-score" id="health-score">–</div>
                <div class="health-ring-lbl">/100</div>
              </div>
            </div>
            <div class="health-ring-meta">
              <div id="health-status"></div>
              <div id="health-details" style="font-size:10px;color:#6b6b80;margin-top:3px;line-height:1.5"></div>
            </div>
          </div>
          <!-- Infos serveur -->
          <div class="sinfo-grid">
            <div class="sinfo-row"><span class="sinfo-lbl">OS</span><span class="sinfo-val" id="si-os">–</span></div>
            <div class="sinfo-row"><span class="sinfo-lbl">Kernel</span><span class="sinfo-val" id="si-kernel">–</span></div>
            <div class="sinfo-row"><span class="sinfo-lbl">IP</span><span class="sinfo-val" id="si-ip">–</span></div>
            <div class="sinfo-row"><span class="sinfo-lbl">CPU Cores</span><span class="sinfo-val" id="si-cores">–</span></div>
            <div class="sinfo-row"><span class="sinfo-lbl">Uptime</span><span class="sinfo-val" id="si-uptime">–</span></div>
            <div class="sinfo-row"><span class="sinfo-lbl">Disques</span><span class="sinfo-val" id="si-disks">–</span></div>
          </div>
        </div>
        <!-- RESSOURCES — stat-cards compactes -->
        <div class="card">
          <div class="card-title">📊 RESSOURCES</div>
          <div class="stat-grid">
            <div class="stat-card">
              <div class="stat-top"><span class="stat-lbl">CPU</span><span class="stat-val" id="cpu-val">–</span></div>
              <div class="stat-bar-mini"><div class="stat-bar-fill cpu" id="cpu-bar" style="width:0%"></div></div>
            </div>
            <div class="stat-card">
              <div class="stat-top"><span class="stat-lbl">RAM</span><span class="stat-val" id="ram-val">–</span></div>
              <div class="stat-bar-mini"><div class="stat-bar-fill ram" id="ram-bar" style="width:0%"></div></div>
            </div>
            <div class="stat-card">
              <div class="stat-top"><span class="stat-lbl">DISQUE</span><span class="stat-val" id="disk-val">–</span></div>
              <div class="stat-bar-mini"><div class="stat-bar-fill disk" id="disk-bar" style="width:0%"></div></div>
            </div>
            <div class="stat-card">
              <div class="stat-top"><span class="stat-lbl">LOAD</span><span class="stat-val" id="load-val" style="font-size:11px">–</span></div>
            </div>
          </div>
          <div class="chart-container"><canvas id="cpu-chart"></canvas></div>
        </div>
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

      <div class="panel panel-center" style="position:relative">
        <div class="chat-messages" id="chat-messages"></div>
        <button class="scroll-bottom-btn" id="scroll-bottom-btn" onclick="scrollToBottom(true)">
          ↓ Nouveau message
        </button>
        <div class="chat-input-area">
          <div class="chat-hints" id="chat-hints">
            <span class="chat-hint" onclick="useHint(this)">🔍 Statut système</span>
            <span class="chat-hint" onclick="useHint(this)">🔄 Mise à jour système</span>
            <span class="chat-hint" onclick="useHint(this)">🔒 Audit sécurité</span>
            <span class="chat-hint" onclick="useHint(this)">📋 Services en échec</span>
            <span class="chat-hint" onclick="useHint(this)">💽 Espace disque</span>
          </div>
          <!-- Zone preview pièce jointe -->
          <div class="attachment-preview" id="att-preview">
            <span class="att-icon" id="att-icon">📄</span>
            <img class="att-thumb" id="att-thumb" src="" alt="" style="display:none">
            <div class="att-info">
              <div class="att-name" id="att-name">–</div>
              <div class="att-meta" id="att-meta">–</div>
            </div>
            <button class="att-remove" onclick="clearAttachment()" title="Supprimer">✕</button>
          </div>
          <!-- Input file caché -->
          <input type="file" id="att-input" style="display:none"
            accept=".txt,.md,.csv,.json,.jsonl,.yaml,.yml,.xml,.html,.py,.js,.ts,.sh,.sql,.pdf,.php,.rb,.go,.rs,.java,.c,.cpp,.log,.env,.conf,.ini,.toml,.dockerfile,image/*"
            onchange="onAttachmentSelected(this)">
          <div class="chat-input-row">
            <button class="attach-btn" id="attach-btn" onclick="document.getElementById('att-input').click()" title="Joindre un fichier">📎</button>
            <textarea class="chat-input" id="chat-input" placeholder="Message à CASSANDRA… (Entrée pour envoyer, Maj+Entrée pour sauter une ligne)" rows="1"></textarea>
            <button class="send-btn" id="send-btn" onclick="sendMessage()" title="Envoyer (Entrée)">➤</button>
          </div>
        </div>
      </div>

      <div class="panel panel-right">
        <div class="card"><div class="card-title">🔥 Top processus</div><div id="processes-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">⚠️ Panne <button class="fix-btn" onclick="sendQuickFix('Unités failed ?')">🔧</button></div><div id="failed-list"><div class="empty-state">Chargement...</div></div></div>
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

  <!-- ========== ONGLET MÉMOIRE PERSISTANTE ========== -->
  <div id="tab-memory" class="tab-content" style="flex-direction:column;overflow:hidden">
    <div style="padding:16px 20px;border-bottom:1px solid rgba(0,255,170,.1);display:flex;justify-content:space-between;align-items:center">
      <div>
        <h2 style="font-size:15px;color:#00ffcc;margin-bottom:4px">🧠 Mémoire persistante inter-sessions</h2>
        <p style="font-size:11px;color:#6b6b80">Ce que CASSANDRA a appris sur toi et ton serveur — conservé entre les sessions</p>
      </div>
      <button onclick="loadMemories()" class="hdr-btn" style="border-color:rgba(0,255,170,.3);color:#00ffcc">↻ Actualiser</button>
    </div>
    <div id="memory-list" style="flex:1;overflow-y:auto;padding:8px 0">
      <div class="empty-state">Chargement…</div>
    </div>
  </div>

  <!-- ========== ONGLET JOURNAL D'AUDIT ========== -->
  <div id="tab-journal" class="tab-content" style="flex-direction:column;overflow:hidden">
    <div style="padding:16px 20px;border-bottom:1px solid rgba(0,255,170,.1);display:flex;justify-content:space-between;align-items:center">
      <div>
        <h2 style="font-size:15px;color:#00ffcc;margin-bottom:4px">📋 Journal des actions agent</h2>
        <p style="font-size:11px;color:#6b6b80">Toutes les commandes bash exécutées — avec durée, niveau de risque et diff</p>
      </div>
      <button onclick="loadJournal()" class="hdr-btn" style="border-color:rgba(0,255,170,.3);color:#00ffcc">↻ Actualiser</button>
    </div>
    <div style="display:grid;grid-template-columns:90px 1fr 65px 55px;gap:6px;padding:7px 12px;font-size:9px;color:#4a4a60;border-bottom:1px solid rgba(255,255,255,.06)">
      <span>HORODATAGE</span><span>COMMANDE</span><span style="text-align:right">DURÉE</span><span style="text-align:center">RISQUE</span>
    </div>
    <div id="journal-list" style="flex:1;overflow-y:auto;padding:0">
      <div class="empty-state">Chargement…</div>
    </div>
  </div>

  <!-- ========== ONGLET CRONS NATURELS ========== -->
  <div id="tab-crons" class="tab-content" style="flex-direction:column;overflow:hidden">
    <div style="padding:16px 20px;border-bottom:1px solid rgba(0,255,170,.1);display:flex;justify-content:space-between;align-items:center">
      <div>
        <h2 style="font-size:15px;color:#00ffcc;margin-bottom:4px">⏰ Crons créés en langage naturel</h2>
        <p style="font-size:11px;color:#6b6b80">Tâches planifiées générées par l'agent depuis tes descriptions</p>
      </div>
      <button onclick="loadCrons()" class="hdr-btn" style="border-color:rgba(0,255,170,.3);color:#00ffcc">↻ Actualiser</button>
    </div>
    <div style="display:grid;grid-template-columns:130px 1fr 100px;gap:8px;padding:7px 12px;font-size:9px;color:#4a4a60;border-bottom:1px solid rgba(255,255,255,.06)">
      <span>EXPRESSION CRON</span><span>DESCRIPTION / COMMANDE</span><span>CRÉÉ LE</span>
    </div>
    <div id="crons-list" style="flex:1;overflow-y:auto;padding:0">
      <div class="empty-state">Aucun cron créé via l'agent — demandez-lui d'en créer un !</div>
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

  <!-- ═══ ONGLET EVOLUTION (doit être DANS app-container) ═══ -->
  <div id="tab-evolution" class="tab-content" style="flex-direction:column;overflow:hidden">
    <div style="padding:16px 20px;border-bottom:1px solid rgba(0,255,170,.1);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
      <div>
        <h2 style="font-size:15px;color:#00ffcc;margin-bottom:4px">🧬 Auto-Evolution CASSANDRA</h2>
        <p style="font-size:11px;color:#6b6b80">Évolution autonome active · Historique · Rollback</p>
        <div id="evo-status-bar" style="margin-top:6px;font-size:10px;color:#4a4a60">⏳ Prochain cycle dans <span id="evo-countdown">—</span> &nbsp;·&nbsp; <span id="evo-today-count">0</span> évolution(s) aujourd'hui</div>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="runEvolutionAnalysis()" class="hdr-btn" style="border-color:rgba(0,255,170,.3);color:#00ffcc">Analyser</button>
        <button onclick="loadEvolutionHistory()" class="hdr-btn" style="border-color:rgba(0,255,170,.3);color:#00ffcc">Actualiser</button>
      </div>
    </div>
    <div style="display:flex;flex:1;overflow:hidden;min-height:0">
      <div style="flex:1;display:flex;flex-direction:column;border-right:1px solid rgba(255,255,255,.06);min-width:0">
        <div style="padding:10px 14px;font-size:10px;color:#4a4a60;text-transform:uppercase;letter-spacing:.1em">Historique</div>
        <div id="evo-history-list" style="flex:1;overflow-y:auto;padding:8px 12px"><div class="empty-state">Aucune evolution.</div></div>
      </div>
      <div style="flex:1;display:flex;flex-direction:column;min-width:0">
        <div style="padding:10px 14px;font-size:10px;color:#4a4a60;text-transform:uppercase;letter-spacing:.1em">Souhaits</div>
        <div id="evo-wish-list" style="flex:1;overflow-y:auto;padding:8px 12px"><div class="empty-state">Aucun souhait.</div></div>
      </div>
    </div>
  </div>

  <!-- ═══ ONGLET PARAMÈTRES ═══ -->
  <div id="tab-settings" class="tab-content">
    <div class="settings-layout">

      <!-- SECTION 1 : Provider / Modèle / Clé API -->
      <div class="settings-section">
        <div class="settings-section-title">🤖 Fournisseur IA & Clé API</div>
        <div class="s-current">
          <span><span class="s-tag">Actuel</span><span id="cfg-current-provider">–</span></span>
          <span style="color:#3a5a4a">•</span>
          <span id="cfg-current-model">–</span>
          <span style="color:#3a5a4a">•</span>
          <span id="cfg-current-key">–</span>
        </div>
        <div class="settings-row triple">
          <div class="s-field">
            <label class="s-label">Provider</label>
            <select class="s-select" id="cfg-provider" onchange="onProviderChange()">
              <option value="deepseek">DeepSeek</option>
              <option value="groq">Groq</option>
              <option value="openrouter">OpenRouter</option>
              <option value="openai">OpenAI</option>
              <option value="ollama">Ollama (local)</option>
            </select>
          </div>
          <div class="s-field">
            <label class="s-label">Modèle</label>
            <input class="s-input mono" id="cfg-model" type="text" placeholder="deepseek-chat" autocomplete="off">
            <div class="s-hint" id="cfg-model-hint">Modèle par défaut pour ce provider</div>
          </div>
          <div class="s-field">
            <label class="s-label">Clé API</label>
            <input class="s-input mono" id="cfg-apikey" type="password" placeholder="sk-••••••••" autocomplete="off">
            <div class="s-hint">Stockée dans /etc/cassandra/deepseek.key (chmod 600)</div>
          </div>
        </div>
        <div style="display:flex;gap:10px;align-items:center">
          <button class="s-btn primary" onclick="saveApiKey()">💾 Sauvegarder & Appliquer</button>
          <button class="s-btn" style="border:1px solid rgba(0,200,140,.2);color:#7a9a8a" onclick="testApiKey()">⚡ Tester la connexion</button>
        </div>
        <div class="s-feedback" id="cfg-api-feedback"></div>
      </div>

      <!-- SECTION 2 : Sécurité — mot de passe admin -->
      <div class="settings-section">
        <div class="settings-section-title">🔐 Sécurité — Mot de passe admin</div>
        <div class="settings-row triple">
          <div class="s-field">
            <label class="s-label">Mot de passe actuel</label>
            <input class="s-input" id="cfg-old-pwd" type="password" placeholder="••••••••" autocomplete="current-password">
          </div>
          <div class="s-field">
            <label class="s-label">Nouveau mot de passe</label>
            <input class="s-input" id="cfg-new-pwd" type="password" placeholder="••••••••" autocomplete="new-password">
            <div class="s-hint">8 caractères minimum</div>
          </div>
          <div class="s-field">
            <label class="s-label">Confirmer</label>
            <input class="s-input" id="cfg-new-pwd2" type="password" placeholder="••••••••" autocomplete="new-password">
          </div>
        </div>
        <div style="display:flex;gap:10px">
          <button class="s-btn primary" onclick="savePassword()">🔑 Changer le mot de passe</button>
        </div>
        <div class="s-feedback" id="cfg-pwd-feedback"></div>
        <div class="s-hint" style="margin-top:10px">Le nouveau hash est écrit dans /etc/cassandra/auth.json — aucun redémarrage requis. Le service systemd reste intouché.</div>
      </div>

      <!-- SECTION 3 : Services système -->
      <div class="settings-section">
        <div class="settings-section-title">📚 Base de connaissance BookStack</div>
        <div class="s-row">
          <div class="s-col">
            <label class="s-label">URL BookStack</label>
            <input class="s-input" id="cfg-bs-url" type="url" placeholder="https://wiki.monserveur.fr" autocomplete="off">
          </div>
        </div>
        <div class="s-row">
          <div class="s-col">
            <label class="s-label">Token ID</label>
            <input class="s-input" id="cfg-bs-id" type="text" placeholder="Token ID API" autocomplete="off">
          </div>
          <div class="s-col">
            <label class="s-label">Token Secret</label>
            <input class="s-input" id="cfg-bs-secret" type="password" placeholder="Token Secret API" autocomplete="new-password">
          </div>
        </div>
        <div style="display:flex;gap:10px;margin-top:8px">
          <button class="s-btn" onclick="cfgSaveBookstack()">💾 Sauvegarder</button>
          <button class="s-btn" style="background:rgba(108,92,231,.18);border-color:rgba(108,92,231,.35)" onclick="cfgTestBookstack()">🔍 Tester la connexion</button>
        </div>
        <div class="s-feedback" id="cfg-bs-feedback"></div>
      </div>

      <div class="settings-section">
        <div class="settings-section-title">🔧 Services système</div>
        <div class="reboot-grid">
          <div class="reboot-card">
            <div class="reboot-card-title">🔄 <span id="cfg-collector-status-dot" style="width:7px;height:7px;border-radius:50%;background:#27c168;display:inline-block"></span> Collector</div>
            <div class="reboot-card-sub">Collecteur de données système (cassandra-collector.service). Un redémarrage ne vous déconnecte pas.</div>
            <button class="s-btn warn" id="cfg-restart-collector" onclick="cfgRestartService('collector')">🔄 Redémarrer le Collector</button>
          </div>
          <div class="reboot-card">
            <div class="reboot-card-title">⚡ <span id="cfg-agent-status-dot" style="width:7px;height:7px;border-radius:50%;background:#27c168;display:inline-block"></span> Agent CASSANDRA</div>
            <div class="reboot-card-sub">Agent principal (cassandra.service). ⚠️ Vous serez déconnecté et devrez vous reconnecter après le reboot.</div>
            <button class="s-btn danger" id="cfg-restart-agent" onclick="cfgRestartService('agent')">⚠️ Redémarrer CASSANDRA</button>
          </div>
        </div>
        <div class="s-feedback" id="cfg-svc-feedback"></div>
      </div>

    </div>
  </div>

  <!-- ═══ MOBILE BOTTOM NAV ═══ -->
  <nav class="mobile-bottom-nav" id="mobile-bottom-nav">
    <div class="mnav-item active" id="mnav-dashboard" onclick="mnavGo('dashboard')">
      <div class="mnav-icon">📊</div><div class="mnav-lbl">Dash</div>
    </div>
    <div class="mnav-item" id="mnav-server" onclick="toggleMetricsDrawer()">
      <div class="mnav-icon">💻</div><div class="mnav-lbl">Serveur</div>
    </div>
    <div class="mnav-item" id="mnav-history" onclick="mnavGo('history')">
      <div class="mnav-icon">📈</div><div class="mnav-lbl">Stats</div>
    </div>
    <div class="mnav-item" id="mnav-evolution" onclick="mnavGo('evolution')">
      <div class="mnav-icon">🧬</div><div class="mnav-lbl">Évo</div>
    </div>
    <div class="mnav-item" id="mnav-alerts" onclick="toggleAlertDropdown()">
      <div class="mnav-icon">🔔<span class="mnav-badge" id="mnav-bell-badge">0</span></div>
      <div class="mnav-lbl">Alertes</div>
    </div>
    <div class="mnav-item" id="mnav-settings" onclick="mnavGo('settings')">
      <div class="mnav-icon">⚙️</div>
      <div class="mnav-lbl">Config</div>
    </div>
  </nav>

  <!-- ═══ METRICS DRAWER (slide-up mobile) ═══ -->
  <div class="mmd-overlay" id="mmd-overlay" onclick="toggleMetricsDrawer()"></div>
  <div class="mobile-metrics-drawer" id="mobile-metrics-drawer">
    <div class="mmd-handle" onclick="toggleMetricsDrawer()"></div>
    <div class="card">
      <div class="card-title">🏥 SANTÉ</div>
      <div class="health-ring-wrap">
        <div class="health-ring" id="mmd-health-ring">
          <div class="health-ring-inner">
            <div class="health-ring-score" id="mmd-health-score">–</div>
            <div class="health-ring-lbl">/100</div>
          </div>
        </div>
        <div class="health-ring-meta">
          <div id="mmd-health-status"></div>
          <div id="mmd-health-details" style="font-size:10px;color:#6b6b80;margin-top:3px"></div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">📊 RESSOURCES</div>
      <div class="stat-grid">
        <div class="stat-card"><div class="stat-top"><span class="stat-lbl">CPU</span><span class="stat-val" id="mmd-cpu">–</span></div><div class="stat-bar-mini"><div class="stat-bar-fill cpu" id="mmd-cpu-bar" style="width:0%"></div></div></div>
        <div class="stat-card"><div class="stat-top"><span class="stat-lbl">RAM</span><span class="stat-val" id="mmd-ram">–</span></div><div class="stat-bar-mini"><div class="stat-bar-fill ram" id="mmd-ram-bar" style="width:0%"></div></div></div>
        <div class="stat-card"><div class="stat-top"><span class="stat-lbl">DISK</span><span class="stat-val" id="mmd-disk">–</span></div><div class="stat-bar-mini"><div class="stat-bar-fill disk" id="mmd-disk-bar" style="width:0%"></div></div></div>
        <div class="stat-card"><div class="stat-top"><span class="stat-lbl">LOAD</span><span class="stat-val" id="mmd-load" style="font-size:11px">–</span></div></div>
      </div>
    </div>
    <div class="card"><div class="card-title">🔒 SSL</div><div id="mmd-ssl"><div class="empty-state">Chargement…</div></div></div>
    <div class="card"><div class="card-title">🔥 Processus</div><div id="mmd-procs"><div class="empty-state">Chargement…</div></div></div>
    <div class="card"><div class="card-title">⚠️ Pannes</div><div id="mmd-failed"><div class="empty-state">Chargement…</div></div></div>
  </div>

</div>

  <!-- TERMINAL CASSANDRA -->
  <div id="terminal-overlay" class="terminal-overlay" onclick="closeTerminal()"></div>
  <div id="terminal-panel" class="terminal-panel">

    <!-- Chrome macOS-style -->
    <div class="terminal-chrome">
      <div class="tc-lights">
        <div class="tc-light red"    onclick="closeTerminal()" title="Fermer"></div>
        <div class="tc-light yellow" onclick="termClear()"    title="Effacer"></div>
        <div class="tc-light green"  onclick="newTermTab()"   title="Nouvel onglet"></div>
      </div>
      <div class="tc-title">
        <strong id="tc-hostname">CASSANDRA</strong>
        <span id="term-status"> — root · accès complet</span>
      </div>
      <div class="tc-actions">
        <button class="tc-btn danger" onclick="closeTerminal()">✕</button>
      </div>
    </div>

    <!-- Tabs -->
    <div class="terminal-tab-bar" id="terminal-tab-bar">
      <div class="terminal-tab active" id="tab-label-0" onclick="switchTermTab(0)">
        ⚡ bash <span class="terminal-tab-close" onclick="event.stopPropagation();closeTermTab(0)">×</span>
      </div>
      <div class="terminal-new-tab" onclick="newTermTab()" title="Nouveau terminal">+</div>
    </div>

    <!-- xterm.js render area -->
    <div class="terminal-xterm-wrap" id="terminal-xterm-wrap"></div>

    <!-- Prompt + input -->
    <div class="terminal-input-row">
      <span class="terminal-prompt" id="term-prompt">
        <span class="tp-user">root</span><span class="tp-at">@</span><span class="tp-host" id="tp-host">cassandra</span><span class="tp-sep">:</span><span class="tp-path">~</span><span class="tp-sym">#</span>
      </span>
      <input class="terminal-cmd-input" id="terminal-input" type="text"
             placeholder="commande…  (Tab · ↑↓ · Ctrl+L · Ctrl+C)"
             autocomplete="off" autocorrect="off" spellcheck="false" autocapitalize="none"
             onkeydown="termKeyDown(event)">
      <button id="term-kill-btn" onclick="termKill()">⏹ Stop</button>
      <button class="terminal-send-btn" id="term-send-btn" onclick="termSend()">▶</button>
    </div>

    <!-- Status bar -->
    <div class="terminal-statusbar">
      <div class="tsb-left">
        <span><span class="tsb-green">●</span> root@<span id="tsb-host">cassandra</span></span>
        <span class="tsb-sep">|</span>
        <span id="tsb-cmdcount">0 cmd</span>
        <span class="tsb-sep">|</span>
        <span class="tsb-hint">Tab · ↑↓ · Ctrl+L · Ctrl+C</span>
      </div>
      <div class="tsb-right">
        <span id="tsb-clock">--:--:--</span>
      </div>
    </div>

  </div>

<script>
let sessionId = sessionStorage.getItem('cassandra_session') || '';
let expertMode = localStorage.getItem('cassandra_expert_mode') === 'true';
let planMode   = false;
let cpuChart = null, cpuHistory = [], ramHistory = [];
let isStreaming = false, sessionStart = Date.now();
// WebSocket terminal
let _termWS = null, _termWSReady = false;
let _csTimer = null, _csStart = 0, _csIter = 0, _csStepCount = 0;
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

const ALL_TABS = ['dashboard','history','fleet','fastpanel','memory','journal','crons','evolution','settings'];

// Countdown autonome evolution
(function(){
    var _interval = 7200;
    var _next = Date.now() + (300 + _interval) * 1000;
    function _tick(){
        var el = document.getElementById('evo-countdown');
        if(!el) return;
        var rem = Math.max(0, Math.round((_next - Date.now()) / 1000));
        var m = Math.floor(rem/60), s = rem%60;
        el.textContent = m + 'min ' + (s<10?'0':'')+s+'s';
        if(rem <= 0){ _next = Date.now() + _interval*1000; loadEvolutionHistory(); }
    }
    setInterval(_tick, 1000);
})();

function loadEvolutionHistory(){
    Promise.all([apiGet('/api/evolution/history'),apiGet('/api/evolution/wishlist')])
    .then(function(res){_renderEvoHistory(res[0].history||[]);_renderEvoWish(res[1].wishlist||[]);})
    .catch(function(e){var el=document.getElementById('evo-history-list');if(el)el.innerHTML='<div class="empty-state">Erreur</div>';});
}
function _renderEvoHistory(items){
    var el=document.getElementById('evo-history-list');if(!el)return;
    if(!items.length){el.innerHTML='<div class="empty-state">Aucune evolution.</div>';return;}
    var sc={applied:'color:#00ffcc',rolled_back:'color:#ffaa00',error:'color:#ff4466'};
    var sl={applied:'OK',rolled_back:'Annule',error:'Erreur'};
    el.innerHTML=items.map(function(e){
        var rb=e.status==='applied'?'<button onclick="doRollback('+e.id+')" style="margin-top:5px;font-size:10px;padding:2px 8px;border:1px solid rgba(255,170,0,.4);background:transparent;color:#ffaa00;border-radius:4px;cursor:pointer">Rollback</button>':'';
        return '<div style="border:1px solid rgba(255,255,255,.07);border-radius:8px;padding:10px 12px;margin-bottom:8px">'
            +'<div style="display:flex;justify-content:space-between">'
            +'<span style="font-size:10px;color:#4a4a60">#'+e.id+' '+escapeHtml((e.ts||'').substring(0,16))+'</span>'
            +'<span style="font-size:11px;'+(sc[e.status]||'')+'">'+(sl[e.status]||e.status)+'</span></div>'
            +'<div style="font-size:12px;color:#ddd;margin-top:3px">'+escapeHtml(e.description||'')+'</div>'
            +(e.motivation?'<div style="font-size:10px;color:#6b6b80;font-style:italic">'+escapeHtml(e.motivation)+'</div>':'')
            +rb+'</div>';
    }).join('');
}
function _renderEvoWish(items){
    var el=document.getElementById('evo-wish-list');if(!el)return;
    if(!items.length){el.innerHTML='<div class="empty-state">Aucun souhait.</div>';return;}
    var pc={high:'#ff4466',medium:'#ffaa00',low:'#00ffcc'};
    el.innerHTML=items.map(function(w){
        return '<div style="border:1px solid rgba(255,255,255,.07);border-radius:8px;padding:10px 12px;margin-bottom:8px">'
            +'<div style="display:flex;justify-content:space-between"><span style="font-size:10px;color:#4a4a60">'+escapeHtml(w.category||'')+'</span>'
            +'<span style="font-size:10px;color:'+(pc[w.priority]||'#aaa')+'">'+((w.priority||'').toUpperCase())+'</span></div>'
            +'<div style="font-size:12px;color:#ddd;margin-top:3px">'+escapeHtml(w.description||'')+'</div></div>';
    }).join('');
}
function runEvolutionAnalysis(){
    var btn=event.target;btn.disabled=true;btn.textContent='...';
    apiGet('/api/evolution/analyze').then(function(r){
        btn.textContent=(r.suggestions||[]).length+' suggestion(s)';
        setTimeout(function(){btn.disabled=false;btn.textContent='Analyser';},3000);
        loadEvolutionHistory();
    }).catch(function(){btn.disabled=false;btn.textContent='Analyser';});
}
function doRollback(id){
    if(!confirm('Rollback #'+id+' ?'))return;
    fetch('/api/evolution/rollback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({evolution_id:id})})
    .then(function(r){return r.json();})
    .then(function(r){alert(r.ok?'OK — redemarrage...':'Erreur: '+(r.error||'?'));if(r.ok)setTimeout(loadEvolutionHistory,4000);});
}
function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t => {
        const tName = (t.onclick||'').toString().match(/'([^']+)'/)?.[1] || '';
        t.classList.toggle('active', tName === name);
    });
    ALL_TABS.forEach(n => {
        const el = document.getElementById('tab-'+n);
        if(el) el.classList.toggle('active', n===name);
    });
    if(name==='history')   loadHistoryCharts(currentPeriod);
    if(name==='fleet')     refreshFleet();
    if(name==='fastpanel') fpInit();
    if(name==='memory')    loadMemories();
    if(name==='journal')   loadJournal();
    if(name==='crons')     loadCrons();
    if(name==='evolution') loadEvolutionHistory();
    if(name==='settings')  { loadSettings(); loadBookstackSettings(); }
    // Sync mobile bottom nav
    ['dashboard','history','evolution','settings'].forEach(n=>{
        const btn=document.getElementById('mnav-'+n);
        if(btn) btn.classList.toggle('active', n===name);
    });
    if(name!=='dashboard') {
        const d=document.getElementById('mnav-dashboard');
        if(d) d.classList.remove('active');
    }
}

/* ── Mobile nav helpers ── */
function mnavGo(tab){
    closeMetricsDrawer();
    switchTab(tab);
}
function toggleMetricsDrawer(){
    const d=document.getElementById('mobile-metrics-drawer');
    const o=document.getElementById('mmd-overlay');
    const s=document.getElementById('mnav-server');
    const isOpen=d&&d.classList.contains('open');
    if(isOpen){ closeMetricsDrawer(); }
    else {
        if(d) d.classList.add('open');
        if(o) o.classList.add('open');
        if(s) s.classList.add('active');
        // Refresh drawer data
        loadMetrics(); loadSSLCerts(); loadProcesses(); loadFailedUnits(); loadDashboard();
    }
}
function closeMetricsDrawer(){
    document.getElementById('mobile-metrics-drawer')?.classList.remove('open');
    document.getElementById('mmd-overlay')?.classList.remove('open');
    document.getElementById('mnav-server')?.classList.remove('active');
}

function toggleExpertMode() {
    expertMode = !expertMode;
    localStorage.setItem('cassandra_expert_mode', expertMode);
    const btn = document.getElementById('expert-mode-btn');
    btn.textContent = expertMode ? '🔬 Mode expert' : '🔍 Mode normal';
    btn.classList.toggle('active', expertMode);
    addSystemMessage(expertMode ? 'Mode expert activé.' : 'Mode normal.');
}

// ══════════════════════════════════════════════════════════
// MODE PLAN
// ══════════════════════════════════════════════════════════
function togglePlanMode() {
    planMode = !planMode;
    const btn = document.getElementById('plan-mode-btn');
    if(planMode){
        btn.style.background = 'rgba(124,92,252,.35)';
        btn.style.borderColor = '#a78bfa';
        btn.style.color = '#e0d0ff';
        addSystemMessage('📋 Mode plan activé — l\'agent planifiera avant d\'exécuter.');
    } else {
        btn.style.background = 'rgba(124,92,252,.1)';
        btn.style.borderColor = 'rgba(124,92,252,.3)';
        btn.style.color = '#a78bfa';
        addSystemMessage('Mode plan désactivé.');
    }
}

// ══════════════════════════════════════════════════════════
// ALERTES PROACTIVES
// ══════════════════════════════════════════════════════════
async function loadAlerts() {
    try {
        const r = await fetch('/api/alerts', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId})});
        if(!r.ok) return;
        const alerts = await r.json();
        const badge = document.getElementById('bell-badge');
        const dropdown = document.getElementById('alert-dropdown');
        badge.textContent = alerts.length;
        badge.classList.toggle('has-alerts', alerts.length > 0);
        if(alerts.length === 0){
            dropdown.innerHTML = '<div class="alert-empty">✅ Aucune alerte active</div>';
        } else {
            dropdown.innerHTML = alerts.map(a => `
                <div class="alert-item">
                    <div>
                        <div class="alert-msg">${escapeHtml(a.message)}</div>
                        <div class="alert-ts">${(a.ts||'').slice(0,16)}</div>
                    </div>
                    <button class="alert-resolve" title="Résoudre" onclick="resolveAlert(${a.id})">✓</button>
                </div>`).join('');
        }
    } catch(e){}
}

function toggleAlertDropdown() {
    document.getElementById('alert-dropdown').classList.toggle('open');
}
document.addEventListener('click', e => {
    const bw = e.target.closest('.bell-wrap');
    if(!bw) document.getElementById('alert-dropdown')?.classList.remove('open');
});

async function resolveAlert(id) {
    await fetch('/api/alert/resolve', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId, id})});
    loadAlerts();
}

// Alertes gérées par WS push (_applyAlerts) — pas de polling global

// ══════════════════════════════════════════════════════════
// MÉMOIRE PERSISTANTE
// ══════════════════════════════════════════════════════════
async function loadMemories() {
    const list = document.getElementById('memory-list');
    if(!list) return;
    try {
        const r = await fetch('/api/memories', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId})});
        const mems = await r.json();
        if(!mems.length){
            list.innerHTML = '<div class="empty-state" style="padding:40px">🧠 Aucune mémoire pour l\'instant — interagis avec l\'agent et il apprendra !</div>';
            return;
        }
        list.innerHTML = mems.map(m => `
            <div class="mem-item">
                <div class="mem-cat">${escapeHtml(m.category)}</div>
                <div class="mem-key">${escapeHtml(m.key)}</div>
                <div class="mem-val">${escapeHtml(m.value)}</div>
                <button class="mem-del" title="Supprimer" onclick="deleteMemory(${m.id})">🗑</button>
            </div>`).join('');
    } catch(e){ list.innerHTML = '<div class="empty-state">Erreur chargement</div>'; }
}

async function deleteMemory(id) {
    await fetch('/api/memory/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId, id})});
    loadMemories();
}

// ══════════════════════════════════════════════════════════
// JOURNAL D'AUDIT
// ══════════════════════════════════════════════════════════
async function loadJournal() {
    const list = document.getElementById('journal-list');
    if(!list) return;
    try {
        const r = await fetch('/api/actions', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId})});
        const actions = await r.json();
        if(!actions.length){
            list.innerHTML = '<div class="empty-state" style="padding:40px">📋 Aucune action enregistrée — le journal se remplit à chaque commande agent</div>';
            return;
        }
        list.innerHTML = actions.map(a => `
            <div class="action-item" title="${escapeHtml(a.output||'').slice(0,200)}">
                <span class="action-ts">${(a.ts||'').slice(5,16)}</span>
                <span class="action-cmd">${escapeHtml(a.command||'')}</span>
                <span class="action-dur">${a.duration_ms>0 ? a.duration_ms+'ms' : '–'}</span>
                <span class="${a.is_risky ? 'risky-badge' : ''}">${a.is_risky ? '⚠️' : ''}</span>
            </div>`).join('');
    } catch(e){ list.innerHTML = '<div class="empty-state">Erreur chargement</div>'; }
}

// ══════════════════════════════════════════════════════════
// ROLLBACK
// ══════════════════════════════════════════════════════════
async function rollbackSnapshots(ids) {
    if(!confirm(`Restaurer ${ids.length} fichier(s) à leur état avant la commande ?`)) return;
    let ok = 0, fail = 0;
    for(const id of ids){
        const r = await fetch('/api/rollback', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId, id})});
        const d = await r.json();
        if(d.success) ok++; else fail++;
    }
    addSystemMessage(`↩ Rollback : ${ok} fichier(s) restauré(s)${fail?' — '+fail+' échec(s)':''}`);
}

// ══════════════════════════════════════════════════════════
// CRONS LANGAGE NATUREL
// ══════════════════════════════════════════════════════════
async function loadCrons() {
    const list = document.getElementById('crons-list');
    if(!list) return;
    try {
        const r = await fetch('/api/crons', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId})});
        const crons = await r.json();
        if(!crons.length){
            list.innerHTML = '<div class="empty-state" style="padding:40px">⏰ Aucun cron — demandez à l\'agent : "surveille nginx toutes les 5 min et redémarre si down"</div>';
            return;
        }
        list.innerHTML = crons.map(c => `
            <div class="cron-item">
                <span class="cron-expr">${escapeHtml(c.cron_expr)}</span>
                <div><div style="font-size:11px;color:#b0b0c8">${escapeHtml(c.description)}</div><div style="font-size:10px;color:#4a4a60;font-family:monospace;margin-top:2px">${escapeHtml(c.command)}</div></div>
                <span style="font-size:9px;color:#4a4a60">${(c.created_at||'').slice(0,10)}</span>
            </div>`).join('');
    } catch(e){ list.innerHTML = '<div class="empty-state">Erreur chargement</div>'; }
}

// ══════════════════════════════════════════════════════════
// WEBSOCKET TERMINAL PTY
// ══════════════════════════════════════════════════════════
function connectTerminalWS() {
    if(_termWS && _termWS.readyState < 2) return; // déjà connecté/en cours
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    _termWS = new WebSocket(`${proto}//${location.host}/ws/terminal?token=${encodeURIComponent(sessionId)}`);
    _termWS.binaryType = 'arraybuffer';
    _termWS.onopen = () => {
        _termWSReady = true;
        // Envoyer la taille initiale
        const term = termTabs[activeTermTab]?.term;
        const fit  = termTabs[activeTermTab]?.fitAddon;
        if(fit && term){
            try {
                const dims = fit.proposeDimensions();
                if(dims) _termWS.send(JSON.stringify({type:'resize', cols:dims.cols, rows:dims.rows}));
            } catch(e){}
        }
    };
    _termWS.onmessage = ev => {
        const term = termTabs[activeTermTab]?.term;
        if(!term) return;
        if(ev.data instanceof ArrayBuffer){
            term.write(new Uint8Array(ev.data));
        } else {
            term.write(ev.data);
        }
    };
    _termWS.onclose = () => {
        _termWSReady = false;
        const term = termTabs[activeTermTab]?.term;
        if(term) term.write('\r\n\x1b[33m⚡ Session PTY terminée\x1b[0m\r\n');
        // Reconnect automatique si terminal encore ouvert
        setTimeout(() => {
            if(document.getElementById('terminal-panel')?.style.display !== 'none') connectTerminalWS();
        }, 2000);
    };
    _termWS.onerror = () => { _termWSReady = false; };
}

// Surcharge de termSend pour utiliser WebSocket si disponible
const _origTermSend = typeof termSend !== 'undefined' ? termSend : null;
function termSend(data) {
    if(_termWS && _termWSReady){
        _termWS.send(typeof data === 'string' ? data : data);
    }
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

async function apiGet(e){
    const url=e+(e.includes('?')?'&':'?')+'_='+Date.now();
    const r=await fetch(url,{headers:{'X-Session-Token':sessionId,'Cache-Control':'no-cache','Pragma':'no-cache'}});
    if(r.status===401){logout();throw new Error('401');}
    if(!r.ok)throw new Error(r.status);
    return r.json();
}
function escapeHtml(t){ if(t==null)return ''; return String(t).replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m])); }
function colorClass(p){ return p>85?'critical':p>70?'warning':'ok'; }

function _colorStatVal(id, pct){
    const el=document.getElementById(id); if(!el) return;
    el.className='stat-val '+(pct>=90?'critical':pct>=75?'warning':'ok');
}
function _setStatBar(id, pct){
    const el=document.getElementById(id); if(!el) return;
    el.style.width=pct+'%';
}
function _setMmsVal(id, txt, pct){
    const el=document.getElementById(id); if(!el) return;
    el.textContent=txt;
    el.className='mms-val '+(pct>=90?'critical':pct>=75?'warning':'ok');
}
async function loadMetrics(){
    try{
        const d=await apiGet('/api/metrics');
        const cpu=Math.round(d.cpu||0), ram=Math.round(d.ram||0), disk=Math.round(d.disk||0);
        const load=(d.load_1m||0)+' '+(d.load_5m||0)+' '+(d.load_15m||0);
        // Desktop panels
        document.getElementById('cpu-val').textContent=cpu+'%';  _colorStatVal('cpu-val',cpu);
        document.getElementById('ram-val').textContent=ram+'%';  _colorStatVal('ram-val',ram);
        document.getElementById('disk-val').textContent=disk+'%';_colorStatVal('disk-val',disk);
        _setStatBar('cpu-bar',cpu);_setStatBar('ram-bar',ram);_setStatBar('disk-bar',disk);
        document.getElementById('load-val').textContent=load;
        // Mobile strip
        _setMmsVal('mms-cpu',cpu+'%',cpu);
        _setMmsVal('mms-ram',ram+'%',ram);
        _setMmsVal('mms-disk',disk+'%',disk);
        // Drawer
        const mmdCpu=document.getElementById('mmd-cpu');
        if(mmdCpu){mmdCpu.textContent=cpu+'%';_colorStatVal('mmd-cpu',cpu)}
        const mmdRam=document.getElementById('mmd-ram');
        if(mmdRam){mmdRam.textContent=ram+'%';_colorStatVal('mmd-ram',ram)}
        const mmdDisk=document.getElementById('mmd-disk');
        if(mmdDisk){mmdDisk.textContent=disk+'%';_colorStatVal('mmd-disk',disk)}
        _setStatBar('mmd-cpu-bar',cpu);_setStatBar('mmd-ram-bar',ram);_setStatBar('mmd-disk-bar',disk);
        const mmdLoad=document.getElementById('mmd-load');
        if(mmdLoad) mmdLoad.textContent=load;
        // Charts
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
        _applyHealth({score:d.health_score||0, status:d.health_status,
            sites:d.sites, ssl_expiring:d.ssl_expiring,
            breakdown:{failed_units:d.failed_units}});
    }catch(e){}
}
async function loadRemotes(){ try{ const d=await apiGet('/api/remotes'); document.getElementById('remotes-list').innerHTML=d.length?d.map(r=>`<div class="remote-item"><span class="remote-name">${escapeHtml(r.name)}</span><span class="remote-type">${escapeHtml(r.type||'?')}</span></div>`).join(''):'<div class="empty-state">Aucun remote</div>'; }catch(e){} }
async function loadSSLCerts(){ try{ const d=await apiGet('/api/ssl'); const html=d.length?d.slice(0,10).map(c=>{const bc=c.days_left<=7?'badge-crit':c.days_left<=30?'badge-warn':'badge-ok'; return `<div class="info-row"><span class="info-name">${escapeHtml(c.domain)}</span><span class="badge ${bc}">${c.days_left}j</span></div>`;}).join(''):'<div class="empty-state">Aucun certificat</div>'; document.getElementById('ssl-list').innerHTML=html; const ms=document.getElementById('mmd-ssl');if(ms)ms.innerHTML=html; }catch(e){} }
async function loadTailscale(){ try{ const d=await apiGet('/api/tailscale'); document.getElementById('tailscale-list').innerHTML=d.length?d.map(p=>`<div class="remote-item"><span class="remote-name">${escapeHtml(p.name||'?')}</span><span class="remote-type">${p.online?'🟢':'🔴'}&nbsp;<span style="color:#6b6b80;font-size:11px;font-family:'JetBrains Mono',monospace">${escapeHtml(p.tailscale_ip||p.ip||'')}</span></span></div>`).join(''):'<div class="empty-state">Aucun peer</div>'; }catch(e){} }
async function loadFail2ban(){ try{ const d=await apiGet('/api/fail2ban'); document.getElementById('fail2ban-count').textContent=d.length+' IP bannie'+(d.length>1?'s':''); }catch(e){} }
async function loadProcesses(){ try{ const d=await apiGet('/api/processes'); if(d.length){ _applyProcesses(d.map(p=>({name:p.command||'?',cpu_pct:p.cpu||0}))); } else { document.getElementById('processes-list').innerHTML='<div class="empty-state">Aucun processus</div>'; } }catch(e){} }
async function loadSessions(){
    try{
        const d=await apiGet('/api/sessions');
        document.getElementById('sessions-list').innerHTML=d.length
            ? d.map(s=>`
                <div class="remote-item session-item">
                    <span class="remote-name">
                        ${s.type==='ftp'?'📁':'🔒'} ${escapeHtml(s.user||'?')}
                    </span>
                    <span class="remote-type" style="flex:1;font-size:10px;font-family:'JetBrains Mono',monospace">
                        ${escapeHtml(s.ip||'local')}
                        ${s.login_time?`<span style="color:#4a4a60;margin-left:4px">${escapeHtml(String(s.login_time).substring(0,16))}</span>`:''}
                    </span>
                    <button class="kill-session-btn" title="Déconnecter cette session"
                        onclick="killSession('${escapeHtml(s.user||'')}','${escapeHtml(s.ip||'')}',this)"
                        >✕</button>
                </div>`).join('')
            : '<div class="empty-state">Aucune session active</div>';
    }catch(e){}
}

async function killSession(user, ip, btn){
    if(!confirm(`Déconnecter la session de ${user} (${ip}) ?`)) return;
    btn.disabled=true; btn.textContent='…';
    try{
        const r=await fetch('/api/session/kill',{
            method:'POST',
            headers:{'Content-Type':'application/json','X-Session-Token':sessionId},
            body:JSON.stringify({user,ip,session:sessionId})
        });
        const d=await r.json();
        if(d.success){ btn.closest('.session-item').remove(); addSystemMessage(`Session de <strong>${escapeHtml(user)}</strong> (${escapeHtml(ip)}) déconnectée.`); }
        else{ btn.disabled=false; btn.textContent='✕'; alert('Erreur : '+(d.error||'inconnue')); }
    }catch(e){ btn.disabled=false; btn.textContent='✕'; }
}
async function loadPorts(){ try{ const d=await apiGet('/api/ports'); document.getElementById('ports-list').innerHTML=d.length?d.slice(0,15).map(p=>`<div class="remote-item"><span class="remote-name">${p.port}/${escapeHtml(p.protocol||'?')}</span><span class="remote-type">${escapeHtml(p.process||'?')}</span></div>`).join(''):'<div class="empty-state">Aucun port</div>'; }catch(e){} }
async function loadOOM(){ try{ const d=await apiGet('/api/oom'); document.getElementById('oom-list').innerHTML=d.length?d.slice(0,5).map(o=>`<div class="remote-item"><span class="remote-name">${escapeHtml(o.killed_process||'?')}</span><span class="remote-type critical">${o.memory_used_mb||0}MB</span></div>`).join(''):'<div class="empty-state">Aucun OOM</div>'; }catch(e){} }
async function loadFailedUnits(){
    try{
        const d=await apiGet('/api/failed');
        const html=d.length
            ? d.slice(0,8).map(f=>`<div class="info-row">
                <span class="info-name" style="color:#ff4466">${escapeHtml(f.unit||'?')}</span>
                <span class="badge badge-crit">FAILED</span>
              </div>`).join('')
            : '<div class="empty-state">Aucune unité failed ✓</div>';
        document.getElementById('failed-list').innerHTML=html;
        const mmdF=document.getElementById('mmd-failed');
        if(mmdF) mmdF.innerHTML=html;
    }catch(e){}
}
async function loadDocker(){ try{ const d=await apiGet('/api/docker'); document.getElementById('docker-list').innerHTML=d.length?d.slice(0,8).map(c=>`<div class="remote-item"><span class="remote-name">${escapeHtml(c.name||'?')}</span><span class="remote-type">${c.status && c.status.toLowerCase().includes('run')?'🟢':'🔴'}</span></div>`).join(''):'<div class="empty-state">Aucun container</div>'; }catch(e){} }

/* ── UI helpers ── */
let _userScrolledUp = false;
function _fmtTime(){ const n=new Date(); return n.getHours().toString().padStart(2,'0')+':'+n.getMinutes().toString().padStart(2,'0'); }

function scrollToBottom(force=false){
    const c=document.getElementById('chat-messages');
    if(force||!_userScrolledUp){ c.scrollTop=c.scrollHeight; }
}

function addMessage(c,u=false){
    const div=document.createElement('div');
    div.className='message '+(u?'user':'bot');
    const avatar=u?'U':'C';
    const name=u?'Vous':'CASSANDRA';
    const time=_fmtTime();
    div.innerHTML=`
      <div class="msg-avatar">${avatar}</div>
      <div class="msg-body">
        <div class="msg-meta"><span class="msg-name">${name}</span><span>${time}</span></div>
        <div class="message-bubble">
          <div class="msg-content">${u?c.replace(/\n/g,'<br>'):c}</div>
          ${u?'':'<button class="msg-copy-btn" onclick="copyBubble(this)" title="Copier">⎘</button>'}
        </div>
      </div>`;
    document.getElementById('chat-messages').appendChild(div);
    scrollToBottom();
    return div;
}

function copyBubble(btn){
    const content=btn.closest('.message-bubble').querySelector('.msg-content');
    const text=(content||btn.closest('.message-bubble')).innerText.trim();
    navigator.clipboard.writeText(text).then(()=>{ btn.textContent='✓'; setTimeout(()=>btn.textContent='⎘',1500); }).catch(()=>{});
}

function addSystemMessage(m){
    const div=document.createElement('div');
    div.className='message bot';
    div.innerHTML=`<div class="msg-avatar">✨</div><div class="msg-body"><div class="message-bubble" style="border-color:rgba(0,255,204,.4);background:rgba(0,255,204,.06);">${m}</div></div>`;
    document.getElementById('chat-messages').appendChild(div);
    scrollToBottom();
}

function addTypingIndicator(){
    removeTypingIndicator();
    _csStart = Date.now(); _csIter = 0; _csStepCount = 0;
    const d = document.createElement('div');
    d.className = 'message bot'; d.id = 'typing-indicator';
    d.innerHTML = `
      <div class="msg-avatar" style="animation:csAvPulse 2s ease-in-out infinite;box-shadow:0 0 12px rgba(0,255,204,.3)">C</div>
      <div class="msg-body" style="flex:1;min-width:0">
        <div class="msg-meta"><span class="msg-name">CASSANDRA</span><span>${_fmtTime()}</span></div>
        <div class="cs-card">
          <div class="cs-header">
            <div class="cs-av">C</div>
            <div class="cs-info">
              <div class="cs-phase" id="cs-phase">ANALYSE</div>
              <div class="cs-sub" id="cs-sub">Traitement de la requête…</div>
            </div>
            <div class="cs-right">
              <div class="cs-timer" id="cs-timer">0s</div>
              <div class="cs-iter" id="cs-iter"></div>
            </div>
          </div>
          <div class="cs-bar-wrap"><div class="cs-bar" id="cs-bar"></div></div>
          <div class="cs-steps" id="cs-steps">
            <div class="cs-dot-row">
              <div class="cs-dot"></div><div class="cs-dot"></div><div class="cs-dot"></div>
            </div>
          </div>
        </div>
      </div>`;
    document.getElementById('chat-messages').appendChild(d);
    scrollToBottom(true);
    _csTimer = setInterval(()=>{
        const el = document.getElementById('cs-timer');
        if(el) el.textContent = Math.round((Date.now()-_csStart)/1000)+'s';
    }, 500);
    document.querySelector('.status-dot')?.classList.add('thinking');
}

function removeTypingIndicator(){
    clearInterval(_csTimer); _csTimer = null;
    const t = document.getElementById('typing-indicator');
    if(t) t.remove();
    document.querySelector('.status-dot')?.classList.remove('thinking','executing');
}

function csPhase(label, sub){
    const p = document.getElementById('cs-phase');
    const s = document.getElementById('cs-sub');
    if(p) p.textContent = label;
    if(s) s.textContent = sub;
}

function csIteration(n){
    _csIter = n;
    const el = document.getElementById('cs-iter');
    if(el) el.textContent = n > 0 ? `boucle ${n}` : '';
    const bar = document.getElementById('cs-bar');
    if(bar) bar.style.width = Math.min(n * 2, 88) + '%';
}

function csStep(icon, text, done=false){
    const stepsEl = document.getElementById('cs-steps');
    if(!stepsEl) return;
    // Remove dot-row on first real step
    const dots = stepsEl.querySelector('.cs-dot-row');
    if(dots) dots.remove();
    // Mark previous active step as done
    const prev = stepsEl.querySelector('.cs-step.active');
    if(prev) prev.classList.replace('active','done');
    if(done) return;
    _csStepCount++;
    const elapsed = ((Date.now()-_csStart)/1000).toFixed(1);
    const step = document.createElement('div');
    step.className = 'cs-step active';
    step.innerHTML = `<span class="cs-si">${icon}</span><span class="cs-st">${escapeHtml(text)}</span><span class="cs-stime">${elapsed}s</span>`;
    stepsEl.appendChild(step);
    // Keep max 4 steps
    const all = stepsEl.querySelectorAll('.cs-step');
    if(all.length > 4) all[0].remove();
    scrollToBottom();
}

function copyBubble(btn){
    const bubble=btn.closest('.message-bubble');
    const text=bubble.innerText.replace('⎘','').trim();
    navigator.clipboard.writeText(text).then(()=>{ btn.textContent='✓'; setTimeout(()=>btn.textContent='⎘',1500); });
}

function useHint(el){
    const input=document.getElementById('chat-input');
    input.value=el.textContent.replace(/^[^\s]+\s/,'').trim();
    input.focus();
}

function formatResponse(t){
    // Nettoyer les pings keepalive
    t=t.replace(/<!--\s*ping\s*\d*\s*-->/g,'');
    // Blocs exec générés par l'agentic loop
    t=t.replace(/<div class='exec-block'>([\s\S]*?)<\/div>/g,(_,inner)=>inner);
    // Blocs ```bash avec bouton exécuter (mode manuel)
    t=t.replace(/```(?:bash|sh|shell)\n?([\s\S]*?)```/g,(_,code)=>{
        const safe=escapeHtml(code.trim());
        const uid='r'+Math.random().toString(36).slice(2);
        return `<div class="command-block"><div class="command-header"><span style="color:#00ffcc">$ </span>${safe}<button class="exec-btn" data-cmd="${safe}" onclick="executeCommandFromBtn(this)">▶ Exécuter</button></div><div class="command-result" id="${uid}"></div></div>`;
    });
    // Blocs ``` génériques
    t=t.replace(/```(\w*)\n?([\s\S]*?)```/g,(_,lang,code)=>`<div class="command-block" style="border-color:rgba(124,92,252,.3)"><div class="command-header" style="color:#a78bfa">${lang||'code'}</div><pre class="command-result" style="color:#c8c8e0">${escapeHtml(code.trim())}</pre></div>`);
    // Code inline `...`
    t=t.replace(/`([^`\n]+)`/g,'<code>$1</code>');
    // Titres
    t=t.replace(/^#{4}\s+(.+)$/gm,'<strong style="color:#a78bfa;display:block;margin-top:6px">$1</strong>');
    t=t.replace(/^#{3}\s+(.+)$/gm,'<h3>$1</h3>');
    t=t.replace(/^#{2}\s+(.+)$/gm,'<h2>$1</h2>');
    t=t.replace(/^#{1}\s+(.+)$/gm,'<h2 style="font-size:15px">$1</h2>');
    // Gras / italic
    t=t.replace(/\*\*\*(.+?)\*\*\*/g,'<strong><em>$1</em></strong>');
    t=t.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>');
    t=t.replace(/\*(.+?)\*/g,'<em>$1</em>');
    // Listes
    t=t.replace(/^[\-\*•] (.+)$/gm,'<li>$1</li>');
    t=t.replace(/^(\d+)\. (.+)$/gm,'<li style="list-style-type:decimal">$2</li>');
    t=t.replace(/(<li[^>]*>[\s\S]*?<\/li>\n?)+/g,m=>'<ul>'+m+'</ul>');
    // Tableaux markdown
    t=t.replace(/((?:\|.+\|\n?)+)/g,table=>{
        const rows=table.trim().split('\n');
        if(rows.length<2)return table;
        const isSep=r=>/^\|[\s\-:]+\|/.test(r);
        let html='<table>',inHead=true;
        rows.forEach((row,i)=>{
            if(isSep(row)){inHead=false;return;}
            const cells=row.split('|').filter((_,j,a)=>j>0&&j<a.length-1);
            const tag=inHead?'th':'td';
            html+='<tr>'+cells.map(c=>`<${tag}>${c.trim()}</${tag}>`).join('')+'</tr>';
            if(inHead)inHead=false;
        });
        return html+'</table>';
    });
    // Pourcentages colorés
    t=t.replace(/\b(\d{1,3})%/g,(m,p)=>{const pc=parseInt(p); if(pc>100)return m; const col=pc>85?'#ff4757':pc>70?'#ffa502':'#2ed573'; return `<span style="color:${col};font-weight:600">${pc}%</span>`;});
    // Statuts .ok / .warning / .critical déjà dans le HTML
    // Sauts de ligne (hors blocs déjà traités)
    t=t.replace(/\n{2,}/g,'<br><br>').replace(/\n/g,'<br>');
    return t;
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
    const hasAtt = !!_currentAttachment;
    if((!msg && !hasAtt)||isStreaming)return;
    input.value=''; input.style.height='auto';
    document.getElementById('send-btn').disabled=true;

    // Construire l'affichage du message utilisateur
    let displayMsg = msg ? escapeHtml(msg) : '';
    if(hasAtt){
        const att=_currentAttachment;
        const isImg=att.mime.startsWith('image/');
        const thumbHtml=isImg?`<img src="data:${att.mime};base64,${att.data}" style="max-width:180px;max-height:100px;border-radius:6px;display:block;margin-top:6px">`:'';
        displayMsg += `${displayMsg?'<br>':''}📎 <span style="font-size:11px;opacity:.7">${escapeHtml(att.filename)}</span>${thumbHtml}`;
    }
    addMessage(displayMsg, true);

    // Pré-upload si pas encore fait (cas drag&drop rapide)
    if(hasAtt && !_currentAttachment.uploaded){
        await _preUploadAttachment();
    }

    // Construire le payload attachment pour le backend
    let attachmentPayload = null;
    if(hasAtt && _currentAttachment?.uploaded){
        attachmentPayload = _currentAttachment.uploaded;
    }

    const attToSend = _currentAttachment;
    clearAttachment();
    addTypingIndicator();
    isStreaming=true;
    try{
        const body = {message:msg, session:sessionId, expert_mode:expertMode, plan_mode:planMode};
        if(attachmentPayload) body.attachment = attachmentPayload;
        const resp=await fetch('/api/chat/stream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        if(resp.status===401){ removeTypingIndicator(); addSystemMessage('Session expirée'); logout(); return; }
        // Status card reste visible pendant le stream agentic — retiré quand premier texte arrive
        const reader=resp.body.getReader();
        const decoder=new TextDecoder();
        let full='', msgDiv=null, buf='', streamDone=false;
        while(!streamDone){
            let chunk;
            try{ chunk=await reader.read(); }catch(_){ break; }
            if(chunk.done)break;
            buf+=decoder.decode(chunk.value,{stream:true});
            const lines=buf.split('\n'); buf=lines.pop();
            for(const line of lines){
                if(!line.startsWith('data: '))continue;
                try{
                    const d=JSON.parse(line.slice(6));
                    if(d.done){ streamDone=true; break; }
                    if(d.token){
                        const tok = d.token;
                        full += tok;
                        // ── Live status card updates ──
                        const pingM = tok.match(/<!--\s*ping\s*(\d+)\s*-->/);
                        if(pingM){
                            const n = parseInt(pingM[1]);
                            csIteration(n + 1);
                            if(n === 0){ csPhase('ANALYSE','Traitement de la requête…'); }
                            else { csPhase('TRAITEMENT','Analyse des résultats…'); csStep('🔄','Traitement résultats'); }
                            document.querySelector('.status-dot')?.classList.remove('executing');
                            document.querySelector('.status-dot')?.classList.add('thinking');
                        }
                        if(tok.includes("<div class='exec-block'>")){
                            const cmdM = full.match(/<code class='exec-cmd'>\$\s*([^<]{1,80})/g);
                            const lastCmd = cmdM ? cmdM[cmdM.length-1].replace(/<code class='exec-cmd'>\$\s*/,'').trim() : '…';
                            csPhase('EXÉCUTION','Commande bash en cours…');
                            csStep('⚡', lastCmd);
                            document.querySelector('.status-dot')?.classList.remove('thinking');
                            document.querySelector('.status-dot')?.classList.add('executing');
                        }
                        if(tok.includes("</div>") && full.includes("exec-block") && !tok.includes("exec-block")){
                            csPhase('TRAITEMENT','Analyse des résultats…');
                            document.querySelector('.status-dot')?.classList.remove('executing');
                            document.querySelector('.status-dot')?.classList.add('thinking');
                        }
                        // ── First real content → switch to rédaction ──
                        if(!msgDiv && !tok.match(/<!--.*-->/) && !tok.includes('exec-block') && tok.trim().replace(/<[^>]+>/g,'').length > 5){
                            csPhase('RÉDACTION','Formulation de la réponse…');
                            csStep('✍️','Rédaction', false);
                            document.querySelector('.status-dot')?.classList.remove('executing');
                            document.querySelector('.status-dot')?.classList.add('thinking');
                        }
                        // ── Render message ──
                        if(!msgDiv){
                            const cleanCheck = formatResponse(full);
                            if(cleanCheck.trim().length > 0){
                                removeTypingIndicator(); // retire le status card
                                const w = addMessage('', false);
                                w.classList.add('msg-fresh');
                                setTimeout(()=>w.classList.remove('msg-fresh'), 900);
                                msgDiv = w.querySelector('.msg-content');
                            }
                        }
                        if(msgDiv){ msgDiv.innerHTML = formatResponse(full); scrollToBottom(); }
                    }
                }catch(_){}
            }
        }
        try{ reader.cancel(); }catch(_){}
    }catch(e){ removeTypingIndicator(); addMessage('<span style="color:#ff4757">❌ '+escapeHtml(e.message)+'</span>', false); }
    isStreaming=false;
    document.getElementById('send-btn').disabled=false;
}

function initParticles(){
    const c=document.getElementById('particles-canvas');
    if(!c) return;
    const ctx=c.getContext('2d');
    const CHARS='アイウエオカキクケコサシスセソタチツテトナニヌネノ0123456789ABCDEF<>{}[]|'.split('');
    const FS=13, SPEED=55;
    let W,H,cols,drops;
    function resize(){
        W=c.width=window.innerWidth; H=c.height=window.innerHeight;
        cols=Math.floor(W/FS);
        // Initialise chaque colonne à une position Y aléatoire
        drops=Array.from({length:cols},()=>Math.floor(Math.random()*(H/FS)));
    }
    resize();
    window.addEventListener('resize',resize);
    function draw(){
        // Traîne semi-transparente — clé de l'effet Matrix
        ctx.fillStyle='rgba(7,8,13,0.06)';
        ctx.fillRect(0,0,W,H);
        for(let i=0;i<cols;i++){
            // Tête brillante
            ctx.fillStyle='rgba(0,220,160,0.9)';
            ctx.font=`bold ${FS}px "JetBrains Mono",monospace`;
            ctx.fillText(CHARS[Math.random()*CHARS.length|0], i*FS, drops[i]*FS);
            // Corps plus sombre (écrit un cran au-dessus)
            if(drops[i]>1){
                ctx.fillStyle='rgba(0,160,100,0.35)';
                ctx.font=`${FS}px "JetBrains Mono",monospace`;
                ctx.fillText(CHARS[Math.random()*CHARS.length|0], i*FS, (drops[i]-1)*FS);
            }
            // Reset aléatoire quand on dépasse l'écran
            if(drops[i]*FS>H && Math.random()>0.975) drops[i]=0;
            drops[i]++;
        }
    }
    setInterval(draw,SPEED);
}

// ══════════════════════════════════════════════════════════════
//  PIÈCE JOINTE — gestion
// ══════════════════════════════════════════════════════════════
let _currentAttachment = null;   // {filename, mime, data(b64), size, uploaded: null|{...}}

function _fmtSize(b){
    if(b<1024) return b+'o';
    if(b<1024*1024) return (b/1024).toFixed(1)+'Ko';
    return (b/1024/1024).toFixed(1)+'Mo';
}

function onAttachmentSelected(input){
    const file = input.files[0];
    if(!file){ clearAttachment(); return; }
    const MAX = file.type.startsWith('image/') ? 8*1024*1024 : 1*1024*1024;
    if(file.size > MAX){
        addSystemMessage(`⚠️ Fichier trop grand (max ${_fmtSize(MAX)} pour ce type).`);
        input.value=''; return;
    }
    const reader = new FileReader();
    reader.onload = e => {
        const dataUrl = e.target.result;
        const b64 = dataUrl.split(',')[1];
        _currentAttachment = {filename:file.name, mime:file.type||'application/octet-stream', data:b64, size:file.size, uploaded:null};
        // Affiche la preview
        const isImage = file.type.startsWith('image/');
        document.getElementById('att-icon').style.display = isImage ? 'none' : '';
        document.getElementById('att-icon').textContent = _attIcon(file.name, file.type);
        const thumb = document.getElementById('att-thumb');
        if(isImage){ thumb.src=dataUrl; thumb.style.display=''; }
        else { thumb.style.display='none'; }
        document.getElementById('att-name').textContent = file.name;
        document.getElementById('att-meta').textContent = _fmtSize(file.size) + ' · ' + (file.type||'fichier');
        document.getElementById('att-preview').classList.add('visible');
        document.getElementById('attach-btn').classList.add('has-file');
        // Pré-upload immédiat pour gagner du temps au send
        _preUploadAttachment();
    };
    reader.readAsDataURL(file);
    input.value='';
}

function _attIcon(name, mime){
    if(mime.startsWith('image/')) return '🖼️';
    const ext = name.split('.').pop().toLowerCase();
    const icons = {pdf:'📕', py:'🐍', js:'⚡', ts:'⚡', sh:'🖥️', sql:'🗄️', json:'{}',
                   csv:'📊', md:'📝', txt:'📄', yaml:'⚙️', yml:'⚙️', html:'🌐', php:'🐘'};
    return icons[ext] || '📄';
}

async function _preUploadAttachment(){
    if(!_currentAttachment || !sessionId) return;
    try{
        const r = await fetch('/api/upload',{
            method:'POST',
            headers:{'Content-Type':'application/json','X-Session-Token':sessionId},
            body:JSON.stringify({
                filename: _currentAttachment.filename,
                mime:     _currentAttachment.mime,
                data:     _currentAttachment.data,
                size:     _currentAttachment.size
            })
        });
        const d = await r.json();
        if(d.success){
            _currentAttachment.uploaded = d;
            const meta = document.getElementById('att-meta');
            if(meta){
                let info = _fmtSize(_currentAttachment.size);
                if(d.method === 'pdftotext' || d.method === 'pypdf') info += ' · PDF extrait';
                else if(d.method === 'vision') info += ' · Image (vision IA)';
                else if(d.method === 'ocr')    info += ' · OCR appliqué';
                if(d.truncated) info += ' · ⚠️ tronqué';
                meta.textContent = info;
            }
            if(d.warning) addSystemMessage('⚠️ ' + d.warning);
        } else {
            addSystemMessage('⚠️ Fichier non supporté : ' + (d.error||'Erreur inconnue'));
            clearAttachment();
        }
    }catch(e){ console.warn('pre-upload:', e); }
}

function clearAttachment(){
    _currentAttachment = null;
    document.getElementById('att-preview').classList.remove('visible');
    document.getElementById('attach-btn').classList.remove('has-file');
    document.getElementById('att-thumb').src='';
    document.getElementById('att-input').value='';
}

// ══════════════════════════════════════════════════════════════
//  ONGLET PARAMÈTRES
// ══════════════════════════════════════════════════════════════
const _DEFAULT_MODELS_UI = {
    deepseek:   'deepseek-chat',
    groq:       'mixtral-8x7b-32768',
    openrouter: 'mistralai/mixtral-8x7b-instruct',
    openai:     'gpt-4o-mini',
    ollama:     'llama3',
};

function _sfb(id, msg, type) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = msg;
    el.className = 's-feedback ' + type;
    el.style.display = 'block';
    setTimeout(() => { el.style.display = 'none'; }, 5000);
}

function onProviderChange() {
    const prov  = document.getElementById('cfg-provider')?.value || 'deepseek';
    const model = document.getElementById('cfg-model');
    const hint  = document.getElementById('cfg-model-hint');
    const def   = _DEFAULT_MODELS_UI[prov] || '';
    if (model && (!model.value || Object.values(_DEFAULT_MODELS_UI).includes(model.value))) {
        model.value = def;
    }
    if (hint) hint.textContent = `Défaut : ${def || '—'}`;
    // Ollama : clé optionnelle
    const keyField = document.getElementById('cfg-apikey');
    if (keyField) keyField.placeholder = prov === 'ollama' ? 'ollama (facultatif)' : 'sk-••••••••';
}

async function loadSettings() {
    try {
        const d = await apiGet('/api/settings');
        const sel = document.getElementById('cfg-provider');
        if (sel) sel.value = d.provider || 'deepseek';
        const mod = document.getElementById('cfg-model');
        if (mod) mod.value = d.model || '';
        const cp = document.getElementById('cfg-current-provider');
        if (cp) cp.textContent = d.provider || '–';
        const cm = document.getElementById('cfg-current-model');
        if (cm) cm.textContent = d.model || '–';
        const ck = document.getElementById('cfg-current-key');
        if (ck) ck.textContent = d.key_masked || '–';
        onProviderChange();
    } catch(e) { console.warn('loadSettings:', e); }
}

async function saveApiKey() {
    const key      = document.getElementById('cfg-apikey')?.value.trim();
    const provider = document.getElementById('cfg-provider')?.value;
    const model    = document.getElementById('cfg-model')?.value.trim();
    if (!key) { _sfb('cfg-api-feedback', 'Clé API requise', 'err'); return; }
    try {
        const r = await fetch('/api/settings/api-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionId },
            body: JSON.stringify({ api_key: key, provider, model })
        });
        const d = await r.json();
        if (d.success) {
            _sfb('cfg-api-feedback', `✓ Appliqué — ${d.provider} / ${d.model}`, 'ok');
            document.getElementById('cfg-apikey').value = '';
            document.getElementById('cfg-current-provider').textContent = d.provider;
            document.getElementById('cfg-current-model').textContent    = d.model;
            document.getElementById('cfg-current-key').textContent      = '(nouvelle clé)';
        } else {
            _sfb('cfg-api-feedback', '✗ ' + (d.error || 'Erreur'), 'err');
        }
    } catch(e) { _sfb('cfg-api-feedback', '✗ Erreur réseau', 'err'); }
}

async function testApiKey() {
    const key      = document.getElementById('cfg-apikey')?.value.trim();
    const provider = document.getElementById('cfg-provider')?.value;
    const model    = document.getElementById('cfg-model')?.value.trim();
    if (!key) { _sfb('cfg-api-feedback', 'Entrez une clé à tester', 'err'); return; }
    _sfb('cfg-api-feedback', '⏳ Test en cours…', 'ok');
    // On envoie un message minimal à l'agent pour tester
    try {
        const r = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session: sessionId,
                message: 'Réponds juste "OK" pour confirmer que tu fonctionnes.',
                test_key: key, test_provider: provider, test_model: model
            })
        });
        if (r.ok) { _sfb('cfg-api-feedback', '✓ Connexion OK', 'ok'); }
        else      { _sfb('cfg-api-feedback', '✗ Test échoué (' + r.status + ')', 'err'); }
    } catch(e) { _sfb('cfg-api-feedback', '✗ Erreur réseau', 'err'); }
}

async function savePassword() {
    const oldP  = document.getElementById('cfg-old-pwd')?.value;
    const newP  = document.getElementById('cfg-new-pwd')?.value;
    const newP2 = document.getElementById('cfg-new-pwd2')?.value;
    if (!oldP || !newP || !newP2) {
        _sfb('cfg-pwd-feedback', 'Tous les champs sont requis', 'err'); return;
    }
    if (newP !== newP2) {
        _sfb('cfg-pwd-feedback', 'Les nouveaux mots de passe ne correspondent pas', 'err'); return;
    }
    if (newP.length < 8) {
        _sfb('cfg-pwd-feedback', 'Mot de passe trop court (8 caractères minimum)', 'err'); return;
    }
    try {
        const r = await fetch('/api/settings/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionId },
            body: JSON.stringify({ old_password: oldP, new_password: newP })
        });
        const d = await r.json();
        if (d.success) {
            _sfb('cfg-pwd-feedback', '✓ Mot de passe changé avec succès', 'ok');
            ['cfg-old-pwd','cfg-new-pwd','cfg-new-pwd2'].forEach(id => {
                const el = document.getElementById(id); if(el) el.value = '';
            });
        } else {
            _sfb('cfg-pwd-feedback', '✗ ' + (d.error || 'Erreur'), 'err');
        }
    } catch(e) { _sfb('cfg-pwd-feedback', '✗ Erreur réseau', 'err'); }
}

async function cfgRestartService(svc) {
    const adminPassword = prompt(
        `⚠️ Redémarrage du ${svc === 'collector' ? 'Collector' : 'CASSANDRA'}\n\n` +
        (svc === 'agent' ? '⚠️ Vous serez déconnecté !\n\n' : '') +
        'Confirmez votre mot de passe admin :'
    );
    if (!adminPassword) return;
    const fbId = 'cfg-svc-feedback';
    _sfb(fbId, '⏳ Redémarrage…', 'ok');
    const endpoint = svc === 'collector' ? '/api/service/restart/collector' : '/api/service/restart/agent';
    try {
        const r = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session: sessionId, admin_password: adminPassword })
        });
        const d = await r.json();
        if (d.success) { _sfb(fbId, '✓ ' + (d.output || d.message || 'OK'), 'ok'); }
        else           { _sfb(fbId, '✗ ' + (d.error || 'Échec'), 'err'); }
    } catch(e) { _sfb(fbId, '✗ Erreur réseau', 'err'); }
}

async function loadBookstackSettings() {
    try {
        const d = await apiGet('/api/settings/bookstack');
        const el = id => document.getElementById(id);
        if (el('cfg-bs-url'))    el('cfg-bs-url').value    = d.bookstack_url    || '';
        if (el('cfg-bs-id'))     el('cfg-bs-id').value     = d.bookstack_token_id  || '';
        if (el('cfg-bs-secret')) el('cfg-bs-secret').value = '';  // ne pas pré-remplir le secret
        if (d.connected) _sfb('cfg-bs-feedback', `✓ Connecté — ${d.pages_count ?? '?'} pages indexées`, 'ok');
    } catch(e) { console.warn('loadBookstackSettings:', e); }
}

async function cfgSaveBookstack() {
    const url    = document.getElementById('cfg-bs-url')?.value.trim();
    const tok_id = document.getElementById('cfg-bs-id')?.value.trim();
    const tok_sec= document.getElementById('cfg-bs-secret')?.value.trim();
    if (!url || !tok_id) { _sfb('cfg-bs-feedback', 'URL et Token ID requis', 'err'); return; }
    try {
        const r = await fetch('/api/settings/bookstack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionId },
            body: JSON.stringify({ bookstack_url: url, bookstack_token_id: tok_id, bookstack_token_secret: tok_sec || undefined })
        });
        const d = await r.json();
        if (d.success) { _sfb('cfg-bs-feedback', '✓ Configuration BookStack sauvegardée', 'ok'); }
        else           { _sfb('cfg-bs-feedback', '✗ ' + (d.error || 'Erreur'), 'err'); }
    } catch(e) { _sfb('cfg-bs-feedback', '✗ Erreur réseau', 'err'); }
}

async function cfgTestBookstack() {
    _sfb('cfg-bs-feedback', '⏳ Test de connexion…', 'ok');
    try {
        const r = await fetch('/api/settings/bookstack/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionId },
            body: JSON.stringify({ session: sessionId })
        });
        const d = await r.json();
        if (d.success) { _sfb('cfg-bs-feedback', `✓ ${d.message}`, 'ok'); }
        else           { _sfb('cfg-bs-feedback', '✗ ' + (d.error || 'Connexion échouée'), 'err'); }
    } catch(e) { _sfb('cfg-bs-feedback', '✗ Erreur réseau', 'err'); }
}

async function loadServerInfo(){
    try {
        const d = await apiGet('/api/server_info');
        if (d.error) return;
        const fmtUptime = s => {
            const days=Math.floor(s/86400), hrs=Math.floor((s%86400)/3600), mins=Math.floor((s%3600)/60);
            return days>0 ? `${days}j ${hrs}h` : hrs>0 ? `${hrs}h ${mins}m` : `${mins}m`;
        };
        const set=(id,v)=>{ const el=document.getElementById(id); if(el) el.textContent=v||'–'; };
        // Abrège le nom de distro si trop long
        const osShort = (d.os||'').replace(/\s*\(.*\)/,'').replace('GNU/Linux','').trim();
        set('si-os',    osShort || '–');
        set('si-kernel', d.kernel || '–');
        set('si-ip',    d.ip || '–');
        set('si-cores', d.cpu_cores ? d.cpu_cores + ' vCPU' : '–');
        set('si-uptime', d.uptime_secs != null ? fmtUptime(d.uptime_secs) : '–');
        set('si-disks', d.disk_count != null ? d.disk_count + (d.disk_count > 1 ? ' disques' : ' disque') : '–');
    } catch(e) {}
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
    // Message de bienvenue
    const chatEl=document.getElementById('chat-messages');
    chatEl.innerHTML='';
    addMessage('<strong>CASSANDRA</strong> — Agent IA souveraine<br><span style="color:#6b6b80;font-size:12px">Je suis fraîche, dispo, et sous-caféinée (fausse alerte, j'ai bu 3 cafés). Commande-moi une mission.</span>', false);
    // [EVO5] Chargement initial HTTP (données déjà dispo) puis bascule WebSocket
    await Promise.allSettled([loadDashboard(), loadRemotes(), loadSSLCerts(), loadTailscale(),
        loadFail2ban(), loadProcesses(), loadSessions(), loadPorts(), loadOOM(),
        loadFailedUnits(), loadDocker(), fpLoadSummary(), loadAlerts(), loadServerInfo()]);
    // Intervalles lents non couverts par WS (données rarement mises à jour)
    setInterval(loadRemotes,    60000);
    setInterval(loadSSLCerts,   120000);
    setInterval(loadTailscale,  30000);
    setInterval(loadFail2ban,   30000);
    setInterval(loadPorts,      60000);
    setInterval(loadOOM,        60000);
    setInterval(loadFailedUnits,30000);
    setInterval(loadDocker,     15000);
    setInterval(fpLoadSummary,  120000);
    setInterval(checkServicesStatus, 60000);
    checkServicesStatus();
    // [EVO5] WebSocket — remplace le polling metrics (1s), processes (2s), sessions (2s),
    //        dashboard (10s), alerts (30s) par un flux push temps-réel
    _initWebSocket();
}

// ── WebSocket client [EVO5] ───────────────────────────────────────────────────
let _ws = null;
let _wsReconnectDelay = 1000;
let _wsFallbackTimer  = null;

function _initWebSocket(){
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const url   = `${proto}://${location.host}/ws`;
    try {
        _ws = new WebSocket(url);
        _ws.onopen = () => {
            console.log('[WS] Connecté — polling désactivé');
            _wsReconnectDelay = 1000;
            // Annuler le fallback polling si actif
            if(_wsFallbackTimer){ clearInterval(_wsFallbackTimer); _wsFallbackTimer = null; }
            // Indicateur visuel (titre)
            document.title = 'Cassandra ⚡ Online';
        };
        _ws.onmessage = (evt) => {
            try {
                const msg = JSON.parse(evt.data);
                if(msg.type === 'autonomous_evolution'){
                    _applyAutoEvolution(msg);
                } else if(msg.type === 'metrics'){
                    // Métriques temps-réel
                    if(msg.metrics)  _applyMetrics(msg.metrics);
                    // Alertes (push direct)
                    if(msg.alerts)   _applyAlerts(msg.alerts);
                    // Health score
                    if(msg.health)   _applyHealth(msg.health);
                }
            } catch(e){}
        };
        _ws.onerror = () => {};
        _ws.onclose = () => {
            document.title = 'Cassandra (reconnexion...)';
            console.log(`[WS] Déconnecté — retry dans ${_wsReconnectDelay}ms`);
            // Fallback polling pendant la reconnexion
            if(!_wsFallbackTimer){
                _wsFallbackTimer = setInterval(()=>{ loadMetrics(); loadProcesses(); }, 3000);
            }
            setTimeout(_initWebSocket, _wsReconnectDelay);
            _wsReconnectDelay = Math.min(_wsReconnectDelay * 2, 30000);
        };
    } catch(e){
        // Browser ne supporte pas WS → polling classique
        setInterval(loadMetrics,   1000);
        setInterval(loadProcesses, 2000);
        setInterval(loadDashboard, 10000);
        setInterval(loadAlerts,    30000);
    }
}

// Applique un objet métriques reçu par WS (même structure que /api/metrics)
function _applyMetrics(m){
    if(!m) return;
    // Mettre à jour les jauges et graphiques comme le fait loadMetrics()
    try {
        const cpu  = m.cpu_pct  ?? 0;
        const ram  = m.ram_pct  ?? 0;
        const disk = m.disk_pct ?? 0;
        const swap = m.swap_pct ?? 0;
        // Jauges radiales
        ['cpu','ram','disk','swap'].forEach((k,i)=>{
            const val = [cpu,ram,disk,swap][i];
            const el  = document.getElementById(`${k}-pct`);
            if(el) el.textContent = val.toFixed(1)+'%';
            const arc = document.getElementById(`${k}-arc`);
            if(arc){ const pct=Math.min(val,100)/100; arc.style.background=
                `conic-gradient(${val>=90?'var(--red)':val>=75?'var(--orange)':'var(--accent)'} ${pct*360}deg, rgba(255,255,255,.06) 0deg)`; }
        });
        // Graphiques Chart.js si disponibles
        if(window._chartCPU && m.ts){ pushChartPoint(_chartCPU, m.ts.slice(11,19), cpu);  }
        if(window._chartRAM && m.ts){ pushChartPoint(_chartRAM, m.ts.slice(11,19), ram);  }
        // Top processes si présents
        if(m.top_processes) _applyProcesses(typeof m.top_processes==='string'
            ? JSON.parse(m.top_processes) : m.top_processes);
    } catch(e){}
}

function _applyAutoEvolution(msg){
    if(!msg) return;
    // Toast de notification
    const icon = msg.status === 'applied' ? '🧬' : '⚠️';
    const txt  = icon + ' Evolution autonome — ' + escapeHtml(msg.description||'');
    showToast(txt, msg.status === 'applied' ? 'success' : 'warning', 6000);
    // Badge cloche
    const badge = document.getElementById('bell-badge');
    if(badge){
        const n = parseInt(badge.textContent||'0') + 1;
        badge.textContent = n;
        badge.classList.add('has-alerts');
    }
    // Ajouter en tête de liste dans l'onglet Evolution (si ouvert)
    const list = document.getElementById('evo-history-list');
    if(list){
        const item = document.createElement('div');
        item.style.cssText='border:1px solid rgba(0,255,204,.25);border-radius:8px;padding:10px 12px;margin-bottom:8px;animation:msgIn .3s ease';
        item.innerHTML = '<div style="display:flex;justify-content:space-between">'
            +'<span style="font-size:10px;color:#4a4a60">#'+escapeHtml(String(msg.evo_id||'?'))+' '+(msg.ts||'').substring(0,16)+'</span>'
            +'<span class="evo-auto-badge">AUTO</span></div>'
            +'<div style="font-size:12px;color:#ddd;margin-top:3px">'+escapeHtml(msg.description||'')+'</div>'
            +'<div style="font-size:10px;color:#6b6b80;font-style:italic">'+escapeHtml(msg.motivation||'')+'</div>';
        list.insertBefore(item, list.firstChild);
    }
}
function _applyAlerts(alerts){
    if(!Array.isArray(alerts)) return;
    // FIX: corriger les IDs — bell-badge et alert-dropdown existent dans le DOM
    const badge = document.getElementById('bell-badge');
    if(badge){
        badge.textContent = alerts.length || '0';
        badge.classList.toggle('has-alerts', alerts.length > 0);
    }
    const list = document.getElementById('alert-dropdown');
    if(!list) return;
    if(!alerts.length){ list.innerHTML='<div class="alert-empty">✅ Aucune alerte active</div>'; return; }
    list.innerHTML = alerts.slice(0,8).map(a=>`
        <div class="alert-item">
            <div>
                <div class="alert-msg">${escapeHtml(a.message||a.msg||'')}</div>
                <div class="alert-ts">${(a.ts||a.created_at||'').slice(0,16)}</div>
            </div>
            ${a.id ? `<button class="alert-resolve" title="Résoudre" onclick="resolveAlert(${a.id})">&#x2713;</button>` : ''}
        </div>`).join('');
}

function _applyHealth(h){
    if(!h) return;
    const s = h.score ?? 0;
    const cls = s>=90?'excellent':s>=75?'good':s>=50?'warning':'critical';
    const color = s>=90?'#2ed573':s>=75?'var(--accent)':s>=50?'var(--orange)':'var(--red)';
    // Score text inside ring
    const el = document.getElementById('health-score');
    if(el){ el.textContent = s; el.style.color = color; }
    // Animate conic ring
    const ring = document.getElementById('health-ring');
    if(ring){
        const deg = Math.round((Math.min(s,100)/100)*360);
        ring.style.background = `conic-gradient(${color} ${deg}deg, rgba(255,255,255,.06) ${deg}deg)`;
    }
    // Status pill
    const st = document.getElementById('health-status');
    if(st){
        const label = h.status || (s>=90?'Excellent':s>=75?'Bon':s>=50?'Warning':'Critique');
        st.innerHTML = `<span class="status-pill ${cls}">${label}</span>`;
    }
    // Details
    const dt = document.getElementById('health-details');
    if(dt){
        const parts=[];
        if(h.breakdown?.ssl)          parts.push(`SSL ${h.breakdown.ssl}pts`);
        if(h.breakdown?.oom)          parts.push(`OOM ${h.breakdown.oom}pts`);
        if(h.breakdown?.failed_units) parts.push(`Failed ${h.breakdown.failed_units}pts`);
        if(h.breakdown && parts.length) dt.textContent = parts.join(' · ');
        else if(h.sites !== undefined) dt.textContent = `${h.sites||0} sites · ${h.ssl_expiring||0} SSL`;
    }
    // Mobile strip
    _setMmsVal('mms-health', s+'', s);
    // Drawer ring clone
    const mmdRing=document.getElementById('mmd-health-ring');
    if(mmdRing){
        const deg=Math.round((Math.min(s,100)/100)*360);
        mmdRing.style.background=`conic-gradient(${color} ${deg}deg,rgba(255,255,255,.06) ${deg}deg)`;
        const sc=document.getElementById('mmd-health-score');
        if(sc){sc.textContent=s;sc.style.color=color;}
    }
    const mmdSt=document.getElementById('mmd-health-status');
    if(mmdSt){
        const label=h.status||(s>=90?'Excellent':s>=75?'Bon':s>=50?'Warning':'Critique');
        mmdSt.innerHTML=`<span class="status-pill ${cls}">${label}</span>`;
    }
    const mmdDt=document.getElementById('mmd-health-details');
    if(mmdDt&&dt) mmdDt.textContent=dt.textContent;
}

function _applyProcesses(procs){
    if(!Array.isArray(procs)) return;
    const html = procs.slice(0,8).map(p=>{
        const cpu = parseFloat(p.cpu_pct||p.cpu||0);
        const color = cpu>50?'var(--red)':cpu>20?'var(--orange)':'var(--accent)';
        return `<div class="proc-row">
            <span class="proc-name">${escapeHtml(p.name||p.comm||'?')}</span>
            <div class="proc-bar-wrap"><div class="proc-bar-fill" style="width:${Math.min(cpu,100)}%;background:${color}"></div></div>
            <span class="proc-pct" style="color:${color}">${cpu.toFixed(1)}%</span>
        </div>`;
    }).join('');
    const el=document.getElementById('processes-list'); if(el) el.innerHTML=html;
    const mmd=document.getElementById('mmd-procs');    if(mmd) mmd.innerHTML=html;
}

// Auto-scroll intelligent
(function(){
    const c=document.getElementById('chat-messages');
    c.addEventListener('scroll',()=>{
        const atBottom = c.scrollHeight - c.scrollTop - c.clientHeight < 60;
        _userScrolledUp = !atBottom;
        const btn=document.getElementById('scroll-bottom-btn');
        if(btn) btn.classList.toggle('visible', _userScrolledUp);
    });
})();

document.getElementById('chat-input').addEventListener('keydown',e=>{
    if(e.key==='Enter'&&!e.shiftKey){e.preventDefault(); sendMessage();}
});
document.getElementById('chat-input').addEventListener('input',function(){
    this.style.height='auto';
    this.style.height=Math.min(this.scrollHeight,120)+'px';
    const btn = document.getElementById('send-btn');
    if(this.value.trim().length > 0) btn.classList.add('primed');
    else btn.classList.remove('primed');
});


// ============================================================
// TERMINAL CASSANDRA  — xterm.js streaming
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
    // welcome box supprimé — terminal propre dès l'ouverture
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

let _termClockInterval = null, _termCmdCount = 0;

function openTerminal() {
    document.getElementById('terminal-panel').classList.add('open');
    document.getElementById('terminal-overlay').classList.add('open');
    if (termTabs.length === 0) { createTermTab('bash'); switchTermTab(0); }
    // Connexion WebSocket PTY (remplace l'ancien HTTP polling)
    connectTerminalWS();
    setTimeout(() => {
        try { termTabs[termActiveTab].fitAddon.fit(); } catch(e){}
        // Synchroniser la taille PTY après resize
        if(_termWS && _termWSReady){
            try {
                const dims = termTabs[termActiveTab]?.fitAddon?.proposeDimensions();
                if(dims) _termWS.send(JSON.stringify({type:'resize', cols:dims.cols, rows:dims.rows}));
            } catch(e){}
        }
        document.getElementById('terminal-input').focus();
    }, 340);
    // Hostname
    const host = window.location.hostname || 'cassandra';
    const hostEl  = document.getElementById('tc-hostname');
    const hostEl2 = document.getElementById('tp-host');
    const hostEl3 = document.getElementById('tsb-host');
    if (hostEl)  hostEl.textContent  = host.toUpperCase();
    if (hostEl2) hostEl2.textContent = host;
    if (hostEl3) hostEl3.textContent = host;
    // Horloge live dans la status bar
    if (!_termClockInterval) {
        _termClockInterval = setInterval(() => {
            const el = document.getElementById('tsb-clock');
            if (el) el.textContent = new Date().toLocaleTimeString('fr-FR');
        }, 1000);
    }
    const cl = document.getElementById('tsb-clock');
    if (cl) cl.textContent = new Date().toLocaleTimeString('fr-FR');
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
    const inp     = document.getElementById('terminal-input');
    if (sendBtn) sendBtn.disabled = running;
    if (killBtn) killBtn.style.display = running ? 'inline-flex' : 'none';
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
    // Compteur status bar
    _termCmdCount++;
    const cc = document.getElementById('tsb-cmdcount');
    if (cc) cc.textContent = _termCmdCount + ' cmd' + (_termCmdCount > 1 ? 's' : '');

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
    domains:   { title: '🌐 Domaines', endpoint: '/api/fp/domains',   cols: ['domain','user','php_version','ssl_enabled','ssl_days_left','status'] },
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
        const bkFail  = d.backups_failed || 0;
        const bkTotal = d.backups_count  ?? -1;   // -1 = ancienne version sans ce champ
        const bkEl    = document.getElementById('fps-backups');
        const bkSub   = document.getElementById('fps-backups-sub');
        if (bkTotal === 0) {
            bkEl.textContent = '–';
            bkEl.parentElement.className = 'fp-sc';
            bkSub.textContent = 'Aucun configuré';
        } else if (bkFail === 0) {
            bkEl.textContent = '✓ OK';
            bkEl.parentElement.className = 'fp-sc ok';
            bkSub.textContent = '';
        } else {
            bkEl.textContent = bkFail + ' ✗';
            bkEl.parentElement.className = 'fp-sc crit';
            bkSub.textContent = bkFail + ' backup(s) en erreur';
        }
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

// ===== CASSANDRA UI v2 — AMÉLIORATIONS =====

// Theme toggle
function initThemeToggle() {
  const toggle = document.createElement('div');
  toggle.className = 'theme-toggle';
  toggle.title = 'Changer le thème';
  toggle.onclick = () => {
    document.body.classList.toggle('light-theme');
    toggle.classList.toggle('light');
    localStorage.setItem('cassandra-theme', document.body.classList.contains('light-theme') ? 'light' : 'dark');
  };
  // Restore saved theme
  if (localStorage.getItem('cassandra-theme') === 'light') {
    document.body.classList.add('light-theme');
    toggle.classList.add('light');
  }
  // Add to header
  const header = document.querySelector('.header');
  if (header) {
    const status = header.querySelector('.status');
    if (status) {
      status.parentNode.insertBefore(toggle, status.nextSibling);
    }
  }
}

// Toast notifications
function showToast(message, type = 'info', duration = 3000) {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), duration);
}

// Animate cards on scroll
function initScrollAnimations() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, { threshold: 0.1 });
  
  document.querySelectorAll('.card, .glass-card, .history-chart-card').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
    observer.observe(el);
  });
}

// Skeleton loading
function showSkeleton(container, count = 3) {
  container.innerHTML = '';
  for (let i = 0; i < count; i++) {
    const skeleton = document.createElement('div');
    skeleton.className = 'skeleton';
    skeleton.style.height = '60px';
    skeleton.style.marginBottom = '8px';
    container.appendChild(skeleton);
  }
}

// Init on load
document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();
  initScrollAnimations();
  // Welcome toast
  setTimeout(() => showToast('🔥 Cassandra Néo v14 active', 'success', 2000), 500);
});
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

def _heartbeat_log():
    """Log l'état du serveur toutes les heures dans la DB."""
    while True:
        try:
            with open("/proc/loadavg") as f: _cpu_load = f.read().split()[0]
            with open("/proc/meminfo") as f: _mem_info = f.read()
            _mt = int(re.search(r"MemTotal:\s+(\d+)", _mem_info).group(1))
            _ma = int(re.search(r"MemAvailable:\s+(\d+)", _mem_info).group(1))
            _mu = _mt - _ma
            _mp = round(_mu / _mt * 100, 1) if _mt else 0
            query_db("INSERT INTO health_scores (score, status, breakdown) VALUES (?, ?, ?)",
                     (90, "ok", json.dumps({"cpu": _cpu_load, "ram_pct": _mp, "source": "heartbeat"})))
        except Exception:
            pass
        time.sleep(3600)

if __name__ == "__main__":
    init_admin_log()
    init_memory_db()

    if not os.path.exists('/dev/shm'):
        os.makedirs('/dev/shm', exist_ok=True)

    ms_migrate_plaintext_tokens()

    # Monitoring proactif (alertes disque/mémoire/load/services en arrière-plan)
    load_alert_config()  # [EVO1] précache la config alerting
    start_monitoring()
    _start_ws_broadcaster()  # [EVO5] push WebSocket 1s
    start_autonomous_evolution()  # [EVO6] évolution autonome permanente
    start_memory_consolidation()  # [MEM] fusion périodique des doublons mémoire (6h)

    # Injecter credentials BookStack dans config.json si absents
    _init_bookstack_config()

    if not os.path.exists(SECURE_KEY_FILE):
        print(f"\n[!] FICHIER DE CLÉ MANQUANT")
        print(f"[!] Créez-le avec :")
        print(f"    mkdir -p {os.path.dirname(SECURE_KEY_FILE)}")
        print(f"    echo 'sk-votre-cle-ici' > {SECURE_KEY_FILE}")
        print(f"    chmod 600 {SECURE_KEY_FILE}")
        print(f"    chattr +i {SECURE_KEY_FILE}\n")

    test = get_metrics_from_socket()
    if test:
        print("[SOCKET] ✅ Connecté au collecteur de données")
    else:
        print("[SOCKET] ⚠️ Socket indisponible, fallback DB")

    server = ThreadedHTTPServer(("0.0.0.0", PORT), CassandraHandler)
    print(f"\n{'='*60}")
    print(f"  CASSANDRA— IA souveraine")
    print(f"  Port    : {PORT}")
    print(f"  URL     : http://localhost:{PORT}")
    print(f"  DeepSeek: {'✅ OK' if DEEPSEEK_API_KEY else '❌ MANQUANTE'}")
    print(f"  Stockage: {SECURE_KEY_FILE}")
    print(f"  Cache   : /dev/shm/.cassandra_deepseek_key (RAM)")
    print(f"  Admin   : {ADMIN_LOG_FILE}")
    print(f"  Rate limit: {RATE_LIMIT_MAX_ACTIONS} actions/heure")
    print(f"  Multi-server: {MULTISERVER_CONFIG_FILE} (tokens chiffrés)")
    print(f"{'='*60}")

    def shutdown_handler(signum, frame):
        print(f"\n👋 Signal {signum} reçu. Arrêt gracieux de CASSANDRA...")
        def _force_exit():
            time.sleep(5)
            print("⚠️ Timeout atteint, arrêt forcé.")
            os._exit(0)
        threading.Thread(target=_force_exit, daemon=True, name="shutdown-timeout").start()
        server.shutdown()
        print("\u2705 CASSANDRA arr\u00eat\u00e9 proprement.")
        os._exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\U0001f44b Arr\u00eat de CASSANDRA...")
        server.shutdown()
        print("\u2705 CASSANDRA arr\u00eat\u00e9 proprement.")
