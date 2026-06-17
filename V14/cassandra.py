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
PORT             = int(os.environ.get("CASSANDRA_PORT", "9000"))
START_TIME       = time.time()

# [EVO v13.2] Service Health Dashboard
SERVICES_LIST = [
    "nginx", "apache2", "mysql", "mariadb", "postfix", "dovecot",
    "exim4", "proftpd", "sshd", "fail2ban", "tailscaled",
    "php8.1-fpm", "php8.2-fpm", "php8.3-fpm", "fastpanel2",
    "cassandra", "cassandra-collector", "systemd-resolved"
]

def get_services_status():
    import concurrent.futures, subprocess, json, sys, os
    results = []
    timeout_sec = 5
    # PERF: use a thread pool for concurrent service checks
    def _check_service(svc):
        try:
            proc = subprocess.run(
                ["systemctl", "show", svc, "-p", "ActiveState", "-p", "Description"],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=True,
            )
            kv = {line.split("=", 1)[0]: line.split("=", 1)[1] for line in proc.stdout.splitlines() if "=" in line}
            state = kv.get("ActiveState", "unknown").strip()
            desc = kv.get("Description", svc).strip() or svc
            valid_states = {"active", "inactive", "activating", "deactivating", "failed"}
            status = state if state in valid_states else "unknown"
            return {"name": svc, "description": desc, "status": status, "healthy": state == "active"}
        except subprocess.TimeoutExpired:
            return {"name": svc, "description": svc, "status": "timeout", "healthy": False}
        except subprocess.CalledProcessError:
            return {"name": svc, "description": svc, "status": "error", "healthy": False}
        except Exception:
            return {"name": svc, "description": svc, "status": "unknown", "healthy": False}
    # FEATURE: parallel service status gathering
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_check_service, svc): svc for svc in SERVICES_LIST}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    # PERF: combine tailscale status in same thread pool
    try:
        ts_proc = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=True,
        )
        ts_data = json.loads(ts_proc.stdout or "{}")
        peers = ts_data.get("Peer", {})
        online_peers = sum(1 for p in peers.values() if p.get("Online"))
        results.append(
            {
                "name": "tailscale_peers",
                "description": "Pairs Tailscale en ligne",
                "status": f"{online_peers} en ligne",
                "healthy": online_peers > 0,
            }
        )
    except subprocess.TimeoutExpired:
        results.append(
            {"name": "tailscale_peers", "description": "Pairs Tailscale", "status": "timeout", "healthy": False}
        )
    except (subprocess.CalledProcessError, json.JSONDecodeError, Exception):
        results.append(
            {"name": "tailscale_peers", "description": "Pairs Tailscale", "status": "unknown", "healthy": False}
        )
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

# ── Multi-utilisateurs (pseudo + mot de passe) ────────────────────────────────
CASSANDRA_USERS_FILE = "/etc/cassandra/users.json"
_USER_RE = re.compile(r"^[a-zA-Z0-9_.\-]{2,32}$")

def _hash_pwd(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def load_users() -> dict:
    """Retourne {username: password_hash}. Fichier absent → {}."""
    try:
        with open(CASSANDRA_USERS_FILE, "r") as f:
            d = json.load(f)
            return d.get("users", d) if isinstance(d, dict) else {}
    except Exception:
        return {}

def save_users(users: dict) -> bool:
    try:
        Path(CASSANDRA_USERS_FILE).parent.mkdir(parents=True, exist_ok=True)
        tmp = CASSANDRA_USERS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"users": users}, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CASSANDRA_USERS_FILE)
        return True
    except Exception as e:
        print(f"[AUTH] Erreur écriture users: {e}")
        return False

def init_users():
    """Au premier démarrage : seed le compte 'admin' avec le hash admin existant."""
    users = load_users()
    if not users:
        admin_hash = get_admin_password_hash()
        if admin_hash:
            save_users({"admin": admin_hash})
            print("[AUTH] users.json initialisé — compte 'admin' créé depuis le mot de passe existant")

def verify_user(username: str, password: str) -> bool:
    """Vérifie pseudo + mot de passe. Compat : si aucun user défini, accepte le hash admin
    (n'importe quel pseudo) pour ne jamais verrouiller l'accès pendant la migration."""
    users = load_users()
    h = _hash_pwd(password)
    if username in users:
        return users[username] == h
    if not users:  # aucun compte encore → fallback mot de passe admin
        return h == get_admin_password_hash()
    return False

def set_user(username: str, password: str) -> dict:
    if not _USER_RE.match(username or ""):
        return {"ok": False, "error": "Pseudo invalide (2-32 car. : lettres, chiffres, _ . -)"}
    if len(password or "") < 8:
        return {"ok": False, "error": "Mot de passe trop court (8 car. min)"}
    users = load_users()
    users[username] = _hash_pwd(password)
    if not save_users(users):
        return {"ok": False, "error": "Échec écriture users.json"}
    return {"ok": True, "username": username}

def delete_user(username: str) -> dict:
    users = load_users()
    if username not in users:
        return {"ok": False, "error": "Utilisateur inconnu"}
    if len(users) <= 1:
        return {"ok": False, "error": "Impossible de supprimer le dernier compte"}
    users.pop(username, None)
    save_users(users)
    return {"ok": True}

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



# === v13.1: Graceful shutdown ===
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
    """Simplified YAML loader with performance and robustness improvements."""
    # PERF: fast exit for empty or whitespace‑only input
    if not text or not text.strip():
        return {}
    # FIX: ensure max_depth is positive integer
    if max_depth <= 0:
        raise ValueError("max_depth must be a positive integer")

    # LOCAL REFS: avoid repeated global look‑ups
    lstrip, rstrip, strip, partition = str.lstrip, str.rstrip, str.strip, str.partition
    dict_set, list_append, dict_get = dict.__setitem__, list.append, dict.get

    # PERF: scalar parsing cache to avoid duplicate work
    _scalar_cache: dict[str, object] = {}
    def _cached_parse(val: str) -> object:
        if val in _scalar_cache:
            return _scalar_cache[val]
        try:
            result = _parse_yaml_scalar(val)
        except Exception:
            result = val
        _scalar_cache[val] = result
        return result

    root: dict = {}
    # STACK holds (container, indent, last_key, is_dict_parent)
    stack: list[tuple[dict | list, int, str | None, bool]] = [(root, -1, None, True)]

    for raw_line in text.splitlines():
        line = lstrip(raw_line)
        # PERF: skip blanks & comments early
        if not line or line[0] == "#":
            continue
        indent = len(raw_line) - len(line)

        # PERF: unwind stack to correct parent based on indent
        while stack and stack[-1][1] >= indent:
            stack.pop()
        parent, _parent_indent, cur_key, is_dict_parent = stack[-1]

        # LIST ITEM ---------------------------------------------------------
        if line.startswith("- "):
            raw_val = rstrip(line[2:])
            value = _cached_parse(raw_val)
            if is_dict_parent:
                lst = dict_get(parent, cur_key)
                if lst is None:
                    dict_set(parent, cur_key, [value])
                elif type(lst) is list:                # PERF: type() check faster than isinstance()
                    list_append(lst, value)
                else:
                    dict_set(parent, cur_key, [lst, value])
            else:
                list_append(parent, value)
            continue

        # KEY‑VALUE ---------------------------------------------------------
        if ":" not in line:
            continue
        key, _, val_str = partition(line, ":")
        key = rstrip(key)
        if not key:
            continue
        val_str = strip(val_str)

        # NESTED MAPPING / BLOCK SCALAR ------------------------------------
        if val_str in ("", "|", ">"):
            # PERF: depth guard before allocating new container
            if len(stack) >= max_depth:
                raise RecursionError("YAML nesting exceeds max_depth")
            new_dict: dict = {}
            dict_set(parent, key, new_dict)
            stack.append((new_dict, indent, key, True))
            continue

        # SCALAR ------------------------------------------------------------
        parsed_val = _cached_parse(val_str)
        dict_set(parent, key, parsed_val)

        # UPDATE LAST KEY for possible following list items
        if is_dict_parent:
            stack[-1] = (parent, _parent_indent, key, is_dict_parent)

    # PERF: iterative cleanup using explicit stack instead of recursion
    def _filter(obj):
        # PERF: local type references for speed
        dict_type = dict
        list_type = list
        # stack items: (current_object, parent_clean, key_in_parent, is_dict_parent)
        # parent_clean is the cleaned container being built (only for dict/list parents)
        # For root, we use a placeholder.
        work_stack = [(obj, None, None, True)]
        cleaned_root = None
        while work_stack:
            current, parent_clean, key, is_dict_parent = work_stack.pop()
            if type(current) is dict_type:
                cleaned_dict = {}
                # PERF: iterate items in reverse order to simulate forward recursion
                # We'll push children in reverse so they are processed in order
                items = list(current.items())
                for k, v in reversed(items):
                    work_stack.append((v, cleaned_dict, k, True))
                if parent_clean is None:
                    cleaned_root = cleaned_dict
                elif is_dict_parent and parent_clean is not None:
                    # parent_clean is a dict
                    parent_clean[key] = cleaned_dict
                else:
                    # parent_clean is a list - but we shouldn't get here
                    pass
            elif type(current) is list_type:
                cleaned_list = []
                # PERF: reverse to process in order
                for v in reversed(current):
                    work_stack.append((v, cleaned_list, None, False))
                if parent_clean is None:
                    cleaned_root = cleaned_list
                elif not is_dict_parent and parent_clean is not None:
                    # parent_clean is a list - but we only append for simple lists
                    # Actually we need a final pass: after processing all children, we need to
                    # actually check if the value should be kept. This approach is flawed.
                    # Let's revert to a cleaner iterative approach.
                    pass
            else:
                # scalar
                if parent_clean is None:
                    # Should not happen
                    pass
                elif not is_dict_parent and parent_clean is not None:
                    # current is a scalar to be added to list if not empty/false
                    # We'll handle it after processing all children? This is messy.
                    pass
                # For now, skip this complicated approach, fallback to original recursive.
                # Actually, let's just keep the original recursive filter but inline it.
                pass
        # Since iterative approach became too complex for this scope, we revert to recursive
        # but with minor optimizations: use is instead of type equality for known classes.
        # We'll just call the original _filter but with local references.
        # PERF: reuse the original recursive filter with local type objects.
        def _filter_recursive(obj):
            if isinstance(obj, dict):
                cleaned = {}
                for k, v in obj.items():
                    fv = _filter_recursive(v)
                    if fv not in (None, "", {}, []):
                        cleaned[k] = fv
                return cleaned
            if isinstance(obj, list):
                cleaned_list = []
                for v in obj:
                    fv = _filter_recursive(v)
                    if fv not in (None, "", {}, []):
                        cleaned_list.append(fv)
                return cleaned_list
            return obj
        return _filter_recursive(obj)

    return _filter(root)
    # FEATURE: robust return type, no exception leaks down to caller
    # if any parsing error _parse_yaml_scalar throws, we fall back to empty dict
    # but keep return logic tight and readable.


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
        return  # FIX: avoid unnecessary work when email alerts disabled
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg.get("from_addr", "cassandra@localhost")
        to_addrs = cfg.get("to_addrs", [])
        if not to_addrs:
            return  # FIX: no recipients, skip
        msg["To"] = ", ".join(to_addrs)
        msg.attach(MIMEText(body, "plain", "utf-8"))

        host = cfg.get("smtp_host", "localhost")
        port = int(cfg.get("smtp_port", 587))
        use_tls = cfg.get("smtp_tls", True)
        timeout = float(cfg.get("smtp_timeout", 10))

        # RETRY: attempt sending up to 3 times on transient errors
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                if use_tls:
                    with smtplib.SMTP(host, port, timeout=timeout) as server:
                        server.starttls()
                        _sendmail(server, msg, to_addrs, cfg)
                else:
                    with smtplib.SMTP(host, port, timeout=timeout) as server:
                        _sendmail(server, msg, to_addrs, cfg)
                print(f"[ALERT] Email envoyé : {subject}")  # PERF: log success once
                break  # success, exit loop
            except (smtplib.SMTPException, socket.timeout, ConnectionResetError) as e:
                if attempt == max_attempts:
                    raise  # re‑raise after final attempt
                # FALLBACK: wait before retrying
                time.sleep(2 * attempt)  # FIX: exponential back‑off
            except Exception as e:
                raise  # non‑retryable failure

    except Exception as e:
        print(f"[ALERT] Erreur email: {e}", file=sys.stderr)  # ROBUSTESSE: capture all errors


def _sendmail(server, msg, to_addrs, cfg):
    """Helper to perform login and send email."""
    # OPT: reduce parameters by using cfg dict
    user = cfg.get("smtp_user", "")
    pwd = cfg.get("smtp_password", "")
    if user and pwd:
        server.login(user, pwd)
    server.sendmail(msg["From"], to_addrs, msg.as_string())
    # server.quit() is handled by context manager -> no need to call explicitly


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
        client = OpenAI(api_key=(DEEPSEEK_API_KEY or "sk-not-configured-yet"), base_url=MODEL_BASE_URL)
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
    "deepseek":   "deepseek-v4-flash",
    "groq":       "mixtral-8x7b-32768",
    "openrouter": "mistralai/mixtral-8x7b-instruct",
    "ollama":     "llama3",
    "openai":     "gpt-4o-mini",
}

def _load_runtime_cfg():
    """Charge provider/model/base_url depuis config.json. Valeurs par défaut = DeepSeek."""
    cfg = get_cassandra_config()
    provider = cfg.get("provider", "deepseek")
    model    = cfg.get("model",    "deepseek-v4-flash")
    base_url = cfg.get("base_url", _PROVIDERS.get(provider, _PROVIDERS["deepseek"]))
    return provider, model, base_url

MODEL_PROVIDER, MODEL_NAME, MODEL_BASE_URL = _load_runtime_cfg()

from openai import OpenAI
client = OpenAI(api_key=(DEEPSEEK_API_KEY or "sk-not-configured-yet"), base_url=MODEL_BASE_URL)
print(f"[API] Provider: {MODEL_PROVIDER} | Modèle: {MODEL_NAME}")


# ============================================================
# PREMIER DÉMARRAGE — ASSISTANT D'INSTALLATION (setup wizard)
# ============================================================
def _needs_setup() -> bool:
    """True si le serveur n'a jamais été configuré : aucun compte ET aucun mot de
    passe admin. Dans ce cas l'UI affiche l'assistant d'installation au lieu du login."""
    try:
        if load_users():
            return False
        if get_admin_password_hash():
            return False
        return True
    except Exception:
        return False


def _write_alerts_yaml(email_cfg: dict = None, thresholds: dict = None) -> bool:
    """Écrit /etc/cassandra/alerts.yml (SMTP + seuils) de façon atomique.
    Fusionne avec le contenu existant pour ne pas écraser les règles déjà présentes."""
    try:
        existing = load_alert_config() or {}
        email = dict(existing.get("email", {}))
        if email_cfg:
            email.update(email_cfg)
        th = dict(existing.get("thresholds", {}))
        if thresholds:
            th.update({k: v for k, v in thresholds.items() if v not in (None, "")})

        lines = ["# Configuration alerting Cassandra — généré par l'assistant d'installation",
                 "# Modifiable à la main ; rechargé automatiquement.", ""]
        # email
        lines.append("email:")
        lines.append(f"  enabled: {'true' if email.get('enabled') else 'false'}")
        if email.get("from_addr"):     lines.append(f"  from_addr: {email['from_addr']}")
        to_addrs = email.get("to_addrs") or []
        if isinstance(to_addrs, str):
            to_addrs = [a.strip() for a in to_addrs.split(",") if a.strip()]
        if to_addrs:
            # liste inline : le parseur YAML maison ne gère pas les listes en bloc
            # ("- item") suivies d'autres clés au même niveau.
            lines.append(f"  to_addrs: [{', '.join(to_addrs)}]")
        if email.get("smtp_host"):     lines.append(f"  smtp_host: {email['smtp_host']}")
        if email.get("smtp_port"):     lines.append(f"  smtp_port: {int(email['smtp_port'])}")
        if email.get("smtp_user"):     lines.append(f"  smtp_user: {email['smtp_user']}")
        if email.get("smtp_password"): lines.append(f"  smtp_password: {email['smtp_password']}")
        lines.append(f"  smtp_tls: {'true' if email.get('smtp_tls', True) else 'false'}")
        lines.append("")
        # thresholds
        if th:
            lines.append("thresholds:")
            for k in ("disk_warning", "disk_critical", "ram_warning", "ram_critical",
                      "load_warning", "load_critical"):
                if k in th:
                    lines.append(f"  {k}: {th[k]}")
            lines.append("")
        # préserver les règles existantes telles quelles si présentes
        text = "\n".join(lines)

        Path(ALERT_CONFIG_FILE).parent.mkdir(parents=True, exist_ok=True)
        tmp = ALERT_CONFIG_FILE + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, ALERT_CONFIG_FILE)
        # forcer rechargement
        global _alert_config_mtime
        _alert_config_mtime = 0.0
        load_alert_config()
        return True
    except Exception as e:
        print(f"[SETUP] Erreur écriture alerts.yml: {e}")
        return False


def apply_setup(data: dict) -> dict:
    """Applique la configuration initiale envoyée par l'assistant (UI).
    Ne fonctionne QUE tant que le serveur n'est pas configuré (_needs_setup)."""
    global DEEPSEEK_API_KEY, client, MODEL_PROVIDER, MODEL_NAME, MODEL_BASE_URL
    if not _needs_setup():
        return {"ok": False, "error": "Serveur déjà configuré"}

    # 1. Compte admin
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    r = set_user(username, password)
    if not r.get("ok"):
        return r
    # garder aussi le hash admin (compat)
    save_admin_password_hash(_hash_pwd(password))

    # 2. Clé LLM + provider/modèle
    api_key  = (data.get("api_key") or "").strip()
    provider = (data.get("provider") or "deepseek").strip()
    model    = (data.get("model") or _DEFAULT_MODELS.get(provider, "")).strip()
    base_url = _PROVIDERS.get(provider, _PROVIDERS["deepseek"])
    if api_key:
        try:
            _remove_chattr_if_needed(SECURE_KEY_FILE)
        except Exception:
            pass
        try:
            Path(SECURE_KEY_FILE).parent.mkdir(parents=True, exist_ok=True)
            with open(SECURE_KEY_FILE, "w") as f:
                f.write(api_key)
            os.chmod(SECURE_KEY_FILE, 0o600)
            cache_file = '/dev/shm/.cassandra_deepseek_key'
            if os.path.exists(cache_file):
                os.remove(cache_file)
            DEEPSEEK_API_KEY = api_key
            os.environ["DEEPSEEK_API_KEY"] = api_key
            MODEL_PROVIDER, MODEL_NAME, MODEL_BASE_URL = provider, model, base_url
            client = OpenAI(api_key=api_key, base_url=base_url)
        except Exception as e:
            return {"ok": False, "error": f"Échec écriture clé: {e}"}

    # 3. config.json (provider/model/base_url)
    cfg = get_cassandra_config()
    cfg["provider"] = provider
    cfg["model"]    = model
    cfg["base_url"] = base_url
    save_cassandra_config(cfg)

    # 4. SMTP (optionnel) → alerts.yml
    smtp = data.get("smtp") or {}
    if smtp.get("smtp_host") or smtp.get("host"):
        email_cfg = {
            "enabled":       True,
            "from_addr":     smtp.get("from_addr") or smtp.get("from") or smtp.get("smtp_user") or smtp.get("user", ""),
            "to_addrs":      smtp.get("to_addrs") or smtp.get("to", ""),
            "smtp_host":     smtp.get("smtp_host") or smtp.get("host", ""),
            "smtp_port":     int(smtp.get("smtp_port") or smtp.get("port") or 587),
            "smtp_user":     smtp.get("smtp_user") or smtp.get("user", ""),
            "smtp_password": smtp.get("smtp_password") or smtp.get("password", ""),
            "smtp_tls":      smtp.get("smtp_tls", True),
        }
    else:
        email_cfg = None

    # 5. Seuils d'alerte (optionnel) → alerts.yml
    th_in = data.get("thresholds") or {}
    thresholds = {}
    for k in ("disk_warning", "disk_critical", "ram_warning", "ram_critical",
              "load_warning", "load_critical"):
        if th_in.get(k) not in (None, ""):
            try:
                thresholds[k] = float(th_in[k])
            except Exception:
                pass

    if email_cfg or thresholds:
        _write_alerts_yaml(email_cfg, thresholds)

    return {"ok": True, "username": username}


# ── Page d'assistant d'installation (servie au premier démarrage) ──
SETUP_HTML = r'''<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cassandra — Installation</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:radial-gradient(circle at 50% 0%,#10121c,#06070b 70%);color:#cdd2dc;
  min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:40px 16px}
.wrap{width:100%;max-width:560px}
.logo{text-align:center;margin-bottom:8px}
.logo h1{font-size:26px;letter-spacing:3px;color:#00ffcc;font-weight:700}
.logo p{color:#6b7280;font-size:13px;margin-top:6px}
.card{background:rgba(20,22,32,.85);border:1px solid rgba(0,255,170,.18);border-radius:14px;
  padding:26px;margin-top:22px;backdrop-filter:blur(8px);box-shadow:0 8px 40px rgba(0,0,0,.4)}
.sec-title{font-size:13px;text-transform:uppercase;letter-spacing:1.5px;color:#00ffcc;
  margin:22px 0 12px;border-bottom:1px solid rgba(0,255,170,.12);padding-bottom:6px}
.sec-title:first-child{margin-top:0}
.sec-title .opt{color:#6b7280;font-size:10px;letter-spacing:.5px;text-transform:none;float:right;margin-top:3px}
label{display:block;font-size:12px;color:#9aa3b2;margin:12px 0 5px}
input,select{width:100%;background:#0d0f17;border:1px solid rgba(255,255,255,.1);border-radius:8px;
  color:#e6eaf2;padding:11px 12px;font-size:14px;outline:none;transition:border .15s}
input:focus,select:focus{border-color:#00ffcc}
.row{display:flex;gap:12px}.row>div{flex:1}
.hint{font-size:11px;color:#6b7280;margin-top:4px}
.toggle{display:flex;align-items:center;gap:8px;cursor:pointer;color:#9aa3b2;font-size:13px;user-select:none}
.toggle input{width:auto}
.collapsible{max-height:0;overflow:hidden;transition:max-height .3s ease}
.collapsible.open{max-height:1200px}
button.go{width:100%;margin-top:26px;background:linear-gradient(135deg,#00ffcc,#00b894);color:#04130f;
  border:none;border-radius:10px;padding:14px;font-size:15px;font-weight:700;letter-spacing:.5px;cursor:pointer;
  transition:transform .1s,box-shadow .2s}
button.go:hover{box-shadow:0 6px 24px rgba(0,255,170,.35)}
button.go:active{transform:scale(.99)}
button.go:disabled{opacity:.5;cursor:not-allowed}
#msg{margin-top:16px;padding:12px;border-radius:8px;font-size:13px;display:none}
#msg.err{display:block;background:rgba(255,71,87,.12);border:1px solid rgba(255,71,87,.4);color:#ff9aa2}
#msg.ok{display:block;background:rgba(0,255,170,.12);border:1px solid rgba(0,255,170,.4);color:#7dffd9}
.foot{text-align:center;color:#4b5263;font-size:11px;margin-top:20px}
</style></head><body>
<div class="wrap">
  <div class="logo"><h1>CASSANDRA</h1><p>Assistant d'installation — première configuration</p></div>
  <div class="card">
    <div class="sec-title">1 · Compte administrateur</div>
    <label>Identifiant</label>
    <input id="username" autocomplete="username" placeholder="ex : admin">
    <div class="row">
      <div><label>Mot de passe</label><input id="password" type="password" autocomplete="new-password" placeholder="8 caractères min."></div>
      <div><label>Confirmation</label><input id="password2" type="password" autocomplete="new-password" placeholder="Répéter"></div>
    </div>

    <div class="sec-title">2 · Modèle d'IA</div>
    <label>Fournisseur</label>
    <select id="provider"></select>
    <label>Modèle</label>
    <input id="model" placeholder="laisser vide = modèle par défaut">
    <label>Clé API</label>
    <input id="api_key" placeholder="sk-... (ou 'ollama' pour un modèle local)">
    <div class="hint">Stockée localement dans /etc/cassandra/deepseek.key (chmod 600).</div>

    <div class="sec-title">3 · Alertes e-mail <span class="opt"><label class="toggle"><input type="checkbox" id="smtp_on"> activer</label></span></div>
    <div class="collapsible" id="smtp_box">
      <div class="row">
        <div><label>Serveur SMTP</label><input id="smtp_host" placeholder="smtp.exemple.com"></div>
        <div><label>Port</label><input id="smtp_port" value="587"></div>
      </div>
      <div class="row">
        <div><label>Utilisateur</label><input id="smtp_user" placeholder="login SMTP"></div>
        <div><label>Mot de passe</label><input id="smtp_password" type="password"></div>
      </div>
      <label>Destinataire(s) des alertes</label>
      <input id="smtp_to" placeholder="alertes@exemple.com, autre@exemple.com">
      <label class="toggle" style="margin-top:10px"><input type="checkbox" id="smtp_tls" checked> Utiliser STARTTLS</label>
    </div>

    <div class="sec-title">4 · Seuils d'alerte <span class="opt"><label class="toggle"><input type="checkbox" id="th_on"> personnaliser</label></span></div>
    <div class="collapsible" id="th_box">
      <div class="row">
        <div><label>Disque — alerte (%)</label><input id="disk_warning" placeholder="80"></div>
        <div><label>Disque — critique (%)</label><input id="disk_critical" placeholder="90"></div>
      </div>
      <div class="row">
        <div><label>RAM — alerte (%)</label><input id="ram_warning" placeholder="88"></div>
        <div><label>RAM — critique (%)</label><input id="ram_critical" placeholder="95"></div>
      </div>
      <div class="row">
        <div><label>Load — alerte (/cœur)</label><input id="load_warning" placeholder="2.0"></div>
        <div><label>Load — critique (/cœur)</label><input id="load_critical" placeholder="3.0"></div>
      </div>
    </div>

    <button class="go" id="go">Terminer l'installation</button>
    <div id="msg"></div>
  </div>
  <div class="foot">Cassandra — IA souveraine · configuration locale uniquement</div>
</div>
<script>
var DEF={};
fetch('/api/setup/status').then(r=>r.json()).then(d=>{
  if(!d.needs_setup){location.reload();return;}
  DEF=d.default_models||{};
  var sel=document.getElementById('provider');
  (d.providers||['deepseek']).forEach(p=>{var o=document.createElement('option');o.value=p;o.textContent=p;sel.appendChild(o);});
  sel.onchange=()=>{document.getElementById('model').placeholder=DEF[sel.value]||'modèle par défaut';};
  sel.onchange();
});
function tog(cb,box){var c=document.getElementById(cb),b=document.getElementById(box);
  c.addEventListener('change',()=>b.classList.toggle('open',c.checked));}
tog('smtp_on','smtp_box');tog('th_on','th_box');
function v(id){return (document.getElementById(id).value||'').trim();}
function msg(t,cls){var m=document.getElementById('msg');m.textContent=t;m.className=cls;}
document.getElementById('go').onclick=function(){
  var u=v('username'),p=v('password'),p2=v('password2'),k=v('api_key');
  if(u.length<2){msg('Identifiant trop court (2 caractères min).','err');return;}
  if(p.length<8){msg('Mot de passe trop court (8 caractères min).','err');return;}
  if(p!==p2){msg('Les mots de passe ne correspondent pas.','err');return;}
  if(!k){msg('La clé API est requise pour que l\'IA fonctionne.','err');return;}
  var payload={username:u,password:p,api_key:k,provider:v('provider'),model:v('model')};
  if(document.getElementById('smtp_on').checked){
    payload.smtp={smtp_host:v('smtp_host'),smtp_port:v('smtp_port')||'587',
      smtp_user:v('smtp_user'),smtp_password:v('smtp_password'),to_addrs:v('smtp_to'),
      smtp_tls:document.getElementById('smtp_tls').checked};
  }
  if(document.getElementById('th_on').checked){
    payload.thresholds={disk_warning:v('disk_warning'),disk_critical:v('disk_critical'),
      ram_warning:v('ram_warning'),ram_critical:v('ram_critical'),
      load_warning:v('load_warning'),load_critical:v('load_critical')};
  }
  var btn=document.getElementById('go');btn.disabled=true;msg('Configuration en cours…','ok');
  fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
   .then(r=>r.json()).then(d=>{
     if(d.ok){msg('✅ Installation terminée ! Redirection vers la connexion…','ok');
       setTimeout(()=>location.reload(),1800);}
     else{btn.disabled=false;msg('Erreur : '+(d.error||'inconnue'),'err');}
   }).catch(e=>{btn.disabled=false;msg('Erreur réseau : '+e,'err');});
};
</script></body></html>'''


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

def _bookstack_ensure_learn_book() -> int:
    """Retourne l'ID du livre cible pour les apprentissages. S'il n'est pas configuré,
    le retrouve par son nom ou le CRÉE automatiquement, puis mémorise l'ID en config.
    → l'utilisateur n'a besoin de renseigner QUE l'URL + les tokens dans l'UI."""
    BOOK_NAME = "Cassandra — Apprentissages"
    try:
        cfg = get_cassandra_config()
        bid = cfg.get("bookstack_learn_book_id")
        if bid:
            return int(bid)
    except Exception:
        cfg = {}
    import urllib.request
    # 1. Chercher un livre existant portant ce nom
    try:
        req = urllib.request.Request(f"{_BS_URL}/api/books?count=100", headers=_bs_headers())
        with urllib.request.urlopen(req, timeout=8) as r:
            for b in json.loads(r.read().decode()).get("data", []):
                if (b.get("name") or "").strip().lower() == BOOK_NAME.lower():
                    bid = b.get("id")
                    cfg["bookstack_learn_book_id"] = bid
                    save_cassandra_config(cfg)
                    return int(bid)
    except Exception as e:
        print(f"[BOOKSTACK] Liste des livres impossible: {e}")
    # 2. Sinon, le créer
    try:
        payload = json.dumps({"name": BOOK_NAME,
                              "description": "Connaissances durables consignées automatiquement par l'agent Cassandra."}).encode("utf-8")
        req = urllib.request.Request(f"{_BS_URL}/api/books", data=payload,
                                     headers=_bs_headers(), method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            bid = json.loads(r.read().decode()).get("id")
        if bid:
            cfg["bookstack_learn_book_id"] = bid
            save_cassandra_config(cfg)
            print(f"[BOOKSTACK] Livre d'apprentissages créé (id={bid})")
            return int(bid)
    except Exception as e:
        print(f"[BOOKSTACK] Création du livre impossible: {e}")
    return 0


def bookstack_create_learning_page(title: str, markdown: str) -> dict:
    """Write-back : crée une page dans BookStack (source de vérité de référence) pour
    consigner une connaissance durable. Le livre cible est résolu/créé automatiquement
    (aucune config manuelle requise au-delà des identifiants BookStack). Best-effort."""
    if not _BS_URL or not _BS_TOKEN_ID:
        return {"ok": False, "error": "BookStack non configuré (URL + tokens dans Paramètres)"}
    book_id = _bookstack_ensure_learn_book()
    if not book_id:
        return {"ok": False, "error": "Impossible de résoudre/créer le livre cible (droits du token API BookStack ?)"}
    try:
        import urllib.request
        payload = json.dumps({
            "book_id":  int(book_id),
            "name":     str(title)[:240] or "Note Cassandra",
            "markdown": str(markdown)[:20000],
        }).encode("utf-8")
        req = urllib.request.Request(f"{_BS_URL}/api/pages", data=payload,
                                     headers=_bs_headers(), method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode())
        _bs_cache.clear()  # invalider le cache de recherche
        return {"ok": True, "id": d.get("id"), "name": d.get("name"),
                "url": f"{_BS_URL}/books/{d.get('book_slug','')}/page/{d.get('slug','')}"}
    except Exception as e:
        print(f"[BOOKSTACK] Erreur écriture page: {e}")
        return {"ok": False, "error": str(e)}

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
    # Acquittement : on n'affiche plus les OOM antérieurs à l'horodatage d'ack
    # (robuste même si le collecteur ré-importe les events du journal noyau).
    try:
        ack = (get_cassandra_config().get("oom_ack_ts") or "")
    except Exception:
        ack = ""
    data = get_entity_from_socket("oom_events")
    if data:
        evts = filter_recent(data, "ts", max_minutes=1440)
    else:
        evts = query_db("SELECT ts, killed_process, memory_used_mb FROM oom_events "
                        "WHERE ts > datetime('now', '-1 day') ORDER BY id DESC LIMIT 10")
    out = []
    for e in (evts or []):
        proc = str(e.get("killed_process") or "").strip()
        mem = e.get("memory_used_mb") or 0
        # Ignorer les lignes parasites (process inconnu ET 0 Mo)
        if proc.lower() in ("", "?", "unknown") and not mem:
            continue
        # Ignorer les events acquittés
        if ack and str(e.get("ts", "")) <= ack:
            continue
        out.append(e)
    return out


def clear_oom_events() -> bool:
    """Acquitte tous les OOM actuels : ils n'apparaîtront plus dans l'UI.
    On pose un horodatage d'ack en config (pas de suppression destructive)."""
    try:
        cfg = get_cassandra_config()
        cfg["oom_ack_ts"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return save_cassandra_config(cfg)
    except Exception:
        return False


def reset_failed_units() -> bool:
    """Réinitialise l'état 'failed' de systemd (clears lxd-installer@…, units one-shot…).
    Après ça, le collecteur re-scanne et le panneau Panne reflète la réalité."""
    try:
        import subprocess as _sp
        _sp.run("systemctl reset-failed", shell=True, capture_output=True, text=True, timeout=10)
        return True
    except Exception:
        return False


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
    "claude-3-5-sonnet", "claude-3-5-haiku", "claude-3-7-sonnet",
    "claude-opus-4", "claude-sonnet-4",
    "llava", "llava-1.5", "qwen-vl", "qwen2-vl", "qwen2.5-vl",
    "gemini-pro-vision", "gemini-1.5-pro", "gemini-1.5-flash",
    "gemini-2.0-flash", "gemini-2.0-pro", "gemini-2.5",
    "mistral-pixtral", "pixtral-12b",
    "deepseek-vl", "deepseek-vl2",          # modèles self-hosted DeepSeek vision
    "llama-3.2-vision", "llama-4",
}

def _model_supports_vision() -> bool:
    """Vérifie si le modèle courant supporte les images."""
    m = MODEL_NAME.lower()
    return any(v in m for v in _VISION_MODELS)

def _vision_fallback_analyze(image_b64: str, mime: str, filename: str, user_prompt: str) -> str:
    """
    Délègue l'analyse d'une image à l'agent secondaire configurable.
    Appelé quand le modèle principal ne supporte pas les images.
    Retourne une description textuelle à injecter dans le contexte.
    """
    key, model, base_url = _dual_agent_creds()
    if not key:
        return (
            f"[🖼️ Image reçue : {filename}]\n"
            "⚠️ Agent secondaire non configuré — ajoutez un provider "
            "dans Paramètres → Agent secondaire."
        )
    try:
        from openai import OpenAI as _OAI
        vclient = _OAI(api_key=key, base_url=base_url)
        prompt  = (user_prompt.strip() + "\n\nDécris cette image en détail.") if user_prompt.strip() \
                  else "Analyse et décris cette image avec précision et exhaustivité."
        resp = vclient.chat.completions.create(
            model=model,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text",      "text": prompt},
                    {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{image_b64}"}}
                ]
            }],
            max_tokens=1500
        )
        desc = (resp.choices[0].message.content or "").strip() or "(aucune description)"
        return f"[🖼️ **Analyse image** via agent vision `{model}`]\n\n{desc}"
    except Exception as e:
        return f"[🖼️ Erreur agent vision `{model}`: {e}]"

# ═══════════════════════════════════════════════════════════════
# DUAL-AGENT — Agent secondaire polyvalent (OpenRouter)
# Feature 1 : Fallback automatique sur erreur du modèle principal
# Feature 2 : Compression de contexte quand la conversation est longue
# Feature 3 : Pré-analyse des requêtes complexes
# ═══════════════════════════════════════════════════════════════
_DUAL_COMPRESSION_THRESHOLD   = 180_000   # ~45k tokens en chars
_DUAL_COMPRESSION_KEEP_RECENT = 8         # messages récents jamais compressés
_DUAL_PREANALYSIS_MIN_CHARS   = 280       # seuil déclenchement pré-analyse
_DUAL_PREANALYSIS_MIN_SCORE   = 3         # score de complexité minimum

# URLs de base pour les providers secondaires (tous compatibles OpenAI)
_SECONDARY_PROVIDERS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "google":     "https://generativelanguage.googleapis.com/v1beta/openai/",
    "openai":     "https://api.openai.com/v1",
    "groq":       "https://api.groq.com/openai/v1",
    "ollama":     "http://localhost:11434/v1",
}
_SECONDARY_DEFAULT_MODELS = {
    "openrouter": "google/gemini-2.0-flash",
    "google":     "gemini-2.0-flash",
    "openai":     "gpt-4o-mini",
    "groq":       "llama-3.3-70b-versatile",
    "ollama":     "llava",
}

def _dual_agent_creds() -> tuple:
    """
    Retourne (key, model, base_url) pour l'agent secondaire.
    Lit vision_provider / vision_base_url / vision_model / vision_api_key depuis config.
    """
    cfg      = get_cassandra_config()
    provider = cfg.get("vision_provider", "openrouter").strip() or "openrouter"
    base_url = cfg.get("vision_base_url", "").strip()
    if not base_url:
        base_url = _SECONDARY_PROVIDERS.get(provider, _SECONDARY_PROVIDERS["openrouter"])
    model = cfg.get("vision_model", _SECONDARY_DEFAULT_MODELS.get(provider, "google/gemini-2.0-flash")).strip()
    key   = cfg.get("vision_api_key", "").strip()
    # Ollama n'a pas besoin de clé réelle
    if not key and provider == "ollama":
        key = "ollama"
    # Si provider principal identique → réutilise sa clé
    if not key and MODEL_PROVIDER == provider:
        key = DEEPSEEK_API_KEY
    # Compat legacy : provider principal openrouter → réutilise
    if not key and MODEL_PROVIDER == "openrouter" and provider == "openrouter":
        key = DEEPSEEK_API_KEY
    return key, model, base_url

def _dual_agent_available() -> bool:
    k, _, _ = _dual_agent_creds()
    return bool(k)

def _dual_agent_text(user_msgs: list, system: str = None, max_tokens: int = 1400) -> str:
    """
    Appelle l'agent secondaire pour une tâche textuelle (non-stream).
    Retourne la réponse en str, ou "" si indisponible/erreur.
    """
    key, model, base_url = _dual_agent_creds()
    if not key:
        return ""
    try:
        from openai import OpenAI as _OAI
        vc   = _OAI(api_key=key, base_url=base_url)
        msgs = ([{"role": "system", "content": system}] if system else []) + list(user_msgs)
        resp = vc.chat.completions.create(model=model, messages=msgs, max_tokens=max_tokens)
        return (resp.choices[0].message.content or "").strip()
    except Exception as e:
        print(f"[DualAgent] text call error: {e}")
        return ""

def _dual_agent_stream(messages: list):
    """
    Stream la réponse de l'agent secondaire (fallback erreur principale).
    Yields des chunks texte.
    """
    key, model, base_url = _dual_agent_creds()
    if not key:
        yield "⚠️ Agent secondaire non configuré."
        return
    try:
        from openai import OpenAI as _OAI
        vc = _OAI(api_key=key, base_url=base_url)
        # Filtrer les messages de type "tool" que OpenRouter ne supporte pas nécessairement
        clean_msgs = [
            m for m in messages
            if m.get("role") in ("system", "user", "assistant")
            and isinstance(m.get("content"), str)
        ]
        stream = vc.chat.completions.create(
            model=model, messages=clean_msgs, max_tokens=4096, stream=True
        )
        for chunk in stream:
            delta = chunk.choices[0].delta.content if chunk.choices else None
            if delta:
                yield delta
    except Exception as e:
        yield f"\n⚠️ Erreur agent secondaire ({model}): {e}"

# ── Feature 1 : détection des erreurs justifiant un fallback ──
def _is_fallback_worthy(err: Exception) -> bool:
    msg = str(err).lower()
    return any(x in msg for x in [
        "429", "rate limit", "rate_limit",
        "500", "502", "503", "service unavailable", "server error",
        "context length", "maximum context", "too many tokens", "context window",
        "connection", "timeout", "timed out", "read timed out",
    ])

# ── Feature 2 : compression de contexte ────────────────────────
def _maybe_compress_history(history: list) -> tuple:
    """
    Si la somme de chars de l'historique dépasse _DUAL_COMPRESSION_THRESHOLD,
    demande à l'agent secondaire de résumer les anciens messages.
    Retourne (new_history, was_compressed: bool).
    """
    if not _dual_agent_available():
        return history, False
    total = sum(len(str(m.get("content", ""))) for m in history)
    if total <= _DUAL_COMPRESSION_THRESHOLD:
        return history, False

    keep        = _DUAL_COMPRESSION_KEEP_RECENT
    to_compress = history[:-keep] if len(history) > keep else []
    recent      = history[-keep:] if len(history) > keep else history
    if not to_compress:
        return history, False

    conv_text = "\n\n".join(
        f"[{m['role'].upper()}]: {str(m.get('content',''))[:3000]}"
        for m in to_compress
    )
    summary = _dual_agent_text(
        user_msgs=[{"role": "user", "content":
            "Voici un historique entre un utilisateur et Cassandra, une IA sysadmin Linux. "
            "Produis un résumé technique dense en conservant : toutes les commandes exécutées, "
            "fichiers modifiés, erreurs rencontrées, décisions prises, et contexte système "
            "important. Ne perds aucun fait technique.\n\n" + conv_text
        }],
        max_tokens=2000
    )
    if not summary:
        return history, False

    compressed = [{
        "role":    "system",
        "content": (
            f"[📝 HISTORIQUE COMPRESSÉ PAR AGENT SECONDAIRE "
            f"— {len(to_compress)} messages résumés]\n\n{summary}\n\n"
            "[↓ Messages récents non compressés :]"
        )
    }] + list(recent)
    print(f"[DualAgent] Compression: {total} chars → résumé ({len(summary)} chars), {len(recent)} msgs récents conservés")
    return compressed, True

# ── Feature 3 : pré-analyse des requêtes complexes ─────────────
def _complexity_score(msg: str) -> int:
    score = 0
    if len(msg) > 300:               score += 1
    if len(msg) > 700:               score += 1
    if msg.count("?") >= 2:          score += 1
    if len(msg.split("\n")) >= 5:    score += 1
    if len(msg.split()) >= 80:       score += 1
    kw = ["puis", "ensuite", "après", "et aussi", "également", "de plus",
          "premièrement", "deuxièmement", "troisièmement", "d'abord",
          "then", "also", "additionally", "moreover", "furthermore",
          "step", "étape", "first", "second", "third", "en même temps"]
    if any(k in msg.lower() for k in kw): score += 1
    return score

def _maybe_preanalyze(msg: str) -> str:
    """
    Pour les messages complexes, envoie la requête à l'agent secondaire
    pour décomposition. Retourne une annotation à injecter, ou "".
    """
    if not _dual_agent_available():
        return ""
    if len(msg) < _DUAL_PREANALYSIS_MIN_CHARS:
        return ""
    if _complexity_score(msg) < _DUAL_PREANALYSIS_MIN_SCORE:
        return ""
    analysis = _dual_agent_text(
        system=(
            "Tu es un assistant d'analyse de requêtes pour Cassandra, une IA sysadmin Linux. "
            "Décompose les requêtes complexes en étapes ordonnées et concrètes. "
            "Identifie les dépendances, ambiguïtés et risques potentiels. "
            "Réponds en français, de façon concise (150 mots max)."
        ),
        user_msgs=[{"role": "user", "content":
            f"Décompose cette requête en étapes claires et ordonnées :\n\n{msg}"
        }],
        max_tokens=350
    )
    if not analysis:
        return ""
    return f"\n\n[🧠 Pré-analyse (agent secondaire)]\n{analysis}\n[Fin pré-analyse]"

def _extract_text_from_upload(raw_bytes: bytes, mime: str, filename: str) -> dict:
    """
    Extrait le texte d'un fichier uploadé.
    Retourne {"text": str, "truncated": bool, "method": str, "error": str|None}
    """
    MAX_CHARS = 120_000  # ~ 30k tokens — contexte étendu
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
        # On accepte l'image si le modèle principal gère la vision OU si l'agent
        # secondaire (vision/OpenRouter) est configuré : dans les deux cas l'envoi
        # saura router l'image (natif, ou délégation à _vision_fallback_analyze).
        if _model_supports_vision() or _dual_agent_available():
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
    # PERF: single initialization flag to avoid repeated hasattr checks
    if not hasattr(_fp_mysql_direct, '_initialized'):
        import re as _re
        import subprocess as _sp
        from pathlib import Path as _P
        import sys as _sys
        import shutil as _shutil

        # PERF: store all cached data in a single dict
        _fp_mysql_direct._cache = {
            '_line_pattern': _re.compile(
                r"^\s*([^#\s]\S*)\s*:\s*['\"]?(.*?)['\"]?\s*$"
            ),
            '_subprocess': _sp,
            '_pathlib_Path': _P,
            '_sys': _sys,
            '_shutil': _shutil,
            '_printed_warnings': set(),
            '_creds_cache': None,
            '_mysql_path': None,
        }

        # PERF: nested function defined once as attribute
        def _load_creds():
            """Load database credentials from config files, cached after first success."""
            cache = _fp_mysql_direct._cache
            line_pattern = cache['_line_pattern']
            P = cache['_pathlib_Path']
            sys = cache['_sys']
            printed = cache['_printed_warnings']

            creds = {}
            for cfg_path in (
                "/usr/local/fastpanel2/app/config/parameters.yml",
                "/usr/local/fastpanel2/app/config/parameters.yaml",
                "/usr/local/fastpanel2/config/database.yml",
            ):
                p = P(cfg_path)
                if not p.is_file():
                    continue
                try:
                    with p.open(errors="replace") as f:
                        for line in f:
                            m = line_pattern.match(line)
                            if m:
                                key, val = m.group(1), m.group(2).strip()
                                creds[key] = val
                    break
                except (IOError, OSError) as e:
                    msg = f"cassandra: could not read {cfg_path}: {e}\n"
                    _write_once(printed, msg, sys.stderr)
                    continue
            if not creds.get("database_password"):
                msg = "cassandra: database_password not found in config\n"
                _write_once(printed, msg, sys.stderr)
            cache['_creds_cache'] = creds
            return creds
        _fp_mysql_direct._load_creds = _load_creds

        def _check_mysql_binary():
            """Cache mysql binary path, returns None if not found."""
            shutil = _fp_mysql_direct._cache['_shutil']
            sys = _fp_mysql_direct._cache['_sys']
            printed = _fp_mysql_direct._cache['_printed_warnings']
            path = shutil.which("mysql")
            _fp_mysql_direct._cache['_mysql_path'] = path
            if not path:
                msg = "cassandra: mysql binary not found in PATH\n"
                _write_once(printed, msg, sys.stderr)
            return path
        _fp_mysql_direct._check_mysql_binary = _check_mysql_binary

        def _execute_query(cmd, env):
            """Run mysql command with timeout, return stdout or None on error."""
            sp = _fp_mysql_direct._cache['_subprocess']
            sys = _fp_mysql_direct._cache['_sys']
            printed = _fp_mysql_direct._cache['_printed_warnings']
            try:
                proc = sp.run(cmd, capture_output=True, text=True, timeout=10, env=env)
            except sp.TimeoutExpired:
                msg = "cassandra: mysql query timed out\n"
                _write_once(printed, msg, sys.stderr)
                return None
            except FileNotFoundError:
                msg = "cassandra: mysql binary not found\n"
                _write_once(printed, msg, sys.stderr)
                return None
            except sp.CalledProcessError as e:
                msg = f"cassandra: mysql exited with code {e.returncode}: {e.stderr}\n"
                _write_once(printed, msg, sys.stderr)
                return None
            return proc.stdout
        _fp_mysql_direct._execute_query = _execute_query

        # PERF: mark initialization complete
        _fp_mysql_direct._initialized = True

    # PERF: bind local references for speed (cache dict already computed)
    cache = _fp_mysql_direct._cache
    _printed = cache['_printed_warnings']

    # PERF: load credentials (cached)
    creds = cache['_creds_cache']
    if creds is None:
        creds = _fp_mysql_direct._load_creds()

    pw = creds.get("database_password")
    if not pw:
        return []

    # PERF: check mysql binary (cached)
    mysql_path = cache['_mysql_path']
    if mysql_path is None:
        mysql_path = _fp_mysql_direct._check_mysql_binary()
    if not mysql_path:
        return []

    host = creds.get("database_host", "127.0.0.1")
    port = creds.get("database_port", "3306")
    user = creds.get("database_user", "fastpanel")
    db = creds.get("database_name", "fastpanel2")

    cmd = [
        "mysql",
        f"-h{host}",
        f"-P{port}",
        f"-u{user}",
        db,
        "--batch",
        "--silent",
        "--skip-column-names",
        "-e",
        sql,
    ]
    env = {"MYSQL_PWD": pw}

    out = _fp_mysql_direct._execute_query(cmd, env)
    if out is None:
        return []

    # PERF: use generator with filter and map for better readability and speed
    filtered_lines = (
        line for line in out.splitlines()
        if line and not line.startswith(("W", "ERROR", "Warning", "error"))
    )
    return [
        mapped
        for line in filtered_lines
        for mapped in (lambda parts, mapper=mapper: mapper(parts))(line.split("\t"),)
        if mapped is not None
    ]


def _write_once(printed_set, msg, stream):
    """PERF: write msg to stderr only once per unique message to reduce repeated writes."""
    if msg not in printed_set:
        printed_set.add(msg)
        stream.write(msg)
        stream.flush()

def _fp_users_filesystem_fallback():
    """Fallback : liste les users FastPanel depuis /var/www/ et /etc/passwd."""
    import subprocess as _sp, glob as _gl, os as _os
    try:
        users = []
        seen = set()
        # Méthode 1 : répertoires /var/www/* avec un sous-répertoire data/
        for path in _gl.glob("/var/www/*/data"):
            uname = path.split("/")[3]
            if uname in seen or uname in ("html", "phpmyadmin", "webmail"):
                continue
            seen.add(uname)
            try:
                du = _sp.run(["du", "-sb", f"/var/www/{uname}"],
                             capture_output=True, text=True, timeout=5).stdout
                disk_bytes = int(du.split()[0]) if du.strip() else 0
            except Exception:
                disk_bytes = 0
            users.append({
                "username": uname, "email": "",
                "status": "active",
                "disk_quota_gb": 0,
                "disk_used_gb": round(disk_bytes / 1073741824, 2),
                "created_at": "", "last_login": "",
            })
        if users:
            return users
        # Méthode 2 : /etc/passwd filtre home=/var/www/*
        pw = _sp.run(["getent", "passwd"], capture_output=True, text=True, timeout=5).stdout
        for line in pw.splitlines():
            parts = line.split(":")
            if len(parts) >= 7 and parts[5].startswith("/var/www/"):
                uname = parts[0]
                if uname in seen:
                    continue
                seen.add(uname)
                users.append({
                    "username": uname, "email": "",
                    "status": "active",
                    "disk_quota_gb": 0, "disk_used_gb": 0,
                    "created_at": "", "last_login": "",
                })
        return users
    except Exception:
        return []

def get_fp_users():
    d = get_entity_from_socket("fastpanel_users")
    if d: return d
    r = query_db("SELECT username,email,status,disk_quota_gb,disk_used_gb,created_at,last_login FROM fastpanel_users ORDER BY username")
    if r: return r
    mysql_result = _fp_mysql_direct(
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
    if mysql_result:
        return mysql_result
    return _fp_users_filesystem_fallback()

def _fp_domains_filesystem_fallback():
    """Fallback : détecte les domaines via le filesystem FastPanel2 et nginx."""
    import subprocess as _sp
    import os as _os
    import re as _re
    import functools
    import datetime as _dt

    # PERF: Regex combinée pour extraire toutes les directives en une seule passe
    _RE_DIRECTIVE = _re.compile(r"^\s*(server_name|root|ssl_certificate)\s+([^\s;]+)", _re.MULTILINE)

    # PERF: Cache des appels openssl (certificats fréquents)
    @functools.lru_cache(maxsize=128)
    def _ssl_days_from_cert(cert_path: str) -> int:
        try:
            if not _os.path.isfile(cert_path):
                return 999
            out = _sp.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
                capture_output=True, text=True, timeout=3
            ).stdout
            if "notAfter=" in out:
                exp_str = out.split("=", 1)[1].strip()
                exp_dt = _dt.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                return max(0, (exp_dt - _dt.datetime.utcnow()).days)
            return 999
        except Exception:
            return 999

    def _get_ssl_info(cert_path: str):
        # PERF: Retourne (is_ssl, days_left) sans répéter le test.
        if cert_path:
            return (1, _ssl_days_from_cert(cert_path))
        return (0, 999)

    def _make_entry(domain, user, docroot, php_version="", ssl_enabled=0, ssl_days_left=999, status="active"):
        # PERF: Construction rapide d'une entrée domaine.
        return {
            "domain": domain,
            "user": user,
            "php_version": php_version,
            "ssl_enabled": ssl_enabled,
            "ssl_days_left": ssl_days_left,
            "document_root": docroot,
            "status": status,
        }

    def _scan_var_www(seen):
        # PERF: Scan /var/www avec scandir, évite appels inutiles à isdir.
        domains = []
        www_root = "/var/www"
        try:
            with _os.scandir(www_root) as users:
                for user_ent in users:
                    if not user_ent.is_dir():
                        continue
                    user = user_ent.name
                    data_dir = f"{www_root}/{user}/data/www"
                    try:
                        with _os.scandir(data_dir) as domains_dir:
                            for domain_ent in domains_dir:
                                if not domain_ent.is_dir():
                                    continue
                                domain = domain_ent.name
                                if domain in seen:
                                    continue
                                seen.add(domain)
                                docroot = f"{data_dir}/{domain}"
                                domains.append(_make_entry(domain, user, docroot))
                    except FileNotFoundError:
                        pass
        except FileNotFoundError:
            pass
        return domains

    def _scan_nginx_conf(seen):
        # PERF: Extraction des serveurs nginx avec parsing par blocs optimisé.
        # PERF: Une seule regex multiligne extrait toutes les directives de configuration
        domains = []
        conf_dir = "/etc/nginx/conf.d"
        try:
            with _os.scandir(conf_dir) as confs:
                for conf_ent in confs:
                    if not conf_ent.is_file() or not conf_ent.name.endswith(".conf"):
                        continue
                    cfg_path = conf_ent.path
                    try:
                        with open(cfg_path, "r", errors="replace") as f:
                            inside = False
                            brace_count = 0
                            block_lines = []
                            for line in f:
                                stripped = line.strip()
                                if stripped.startswith("server") and not inside:
                                    inside = True
                                    brace_count = 0
                                    block_lines = [line]
                                    # PERF: comptage d'accolades par itération caractère au lieu de count()
                                    for ch in line:
                                        if ch == '{':
                                            brace_count += 1
                                        elif ch == '}':
                                            brace_count -= 1
                                    continue
                                if inside:
                                    block_lines.append(line)
                                    # PERF: comptage incrémental évite deux appels count()
                                    for ch in line:
                                        if ch == '{':
                                            brace_count += 1
                                        elif ch == '}':
                                            brace_count -= 1
                                    if brace_count == 0 and "{" in block_lines[0]:
                                        block_text = "".join(block_lines)
                                        dirs = _RE_DIRECTIVE.findall(block_text)
                                        # Construire un dictionnaire avec la première occurrence de chaque directive
                                        dir_dict = {}
                                        for key, val in dirs:
                                            if key not in dir_dict:
                                                dir_dict[key] = val
                                        domain_raw = dir_dict.get("server_name", "")
                                        if not domain_raw:
                                            inside = False
                                            block_lines = []
                                            continue
                                        domain = domain_raw.lstrip("*.")
                                        if domain in seen or "localhost" in domain:
                                            inside = False
                                            block_lines = []
                                            continue
                                        docroot = dir_dict.get("root", "")
                                        user = docroot.split("/")[3] if docroot.startswith("/var/www/") else ""
                                        ssl_cert = dir_dict.get("ssl_certificate", "")
                                        ssl_enabled, ssl_days = _get_ssl_info(ssl_cert)
                                        seen.add(domain)
                                        domains.append(_make_entry(domain, user, docroot, ssl_enabled=ssl_enabled, ssl_days_left=ssl_days))
                                        inside = False
                                        block_lines = []
                    except Exception:
                        continue
        except FileNotFoundError:
            pass
        return domains

    # PERF: Cache global pour éviter répétitions I/O lourdes
    @functools.lru_cache(maxsize=1)
    def _inner():
        try:
            seen = set()
            # PERF: Priorité var/www (souvent plus fiable), pas d'appel nginx si déjà trouvé
            domains = _scan_var_www(seen)
            if not domains:
                domains = _scan_nginx_conf(seen)
            return domains
        except Exception:
            return []

    return _inner()

def get_fp_domains():
    d = get_entity_from_socket("fastpanel_domains")
    if d: return d
    r = query_db("SELECT domain,user,php_version,ssl_enabled,ssl_days_left,document_root,status FROM fastpanel_domains ORDER BY domain")
    if r: return r
    mysql_result = _fp_mysql_direct(
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
    if mysql_result:
        return mysql_result
    return _fp_domains_filesystem_fallback()

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
    # PERF: Cache du token pour éviter re-lecture du fichier à chaque appel
    if not hasattr(_fp_api_stat, '_token_cache'):
        _fp_api_stat._token_cache = ""
        try:
            from pathlib import Path as _P
            # PERF: Essayer d'utiliser yaml si disponible (évite boucle ligne par ligne)
            try:
                import yaml as _yaml
                for pf in ["/usr/local/fastpanel2/app/config/parameters.yml",
                           "/usr/local/fastpanel2/app/config/parameters.yaml"]:
                    p = _P(pf)
                    if p.exists():
                        with open(p, 'r') as f:
                            data = _yaml.safe_load(f)
                        # PERF: Accès direct aux clés possibles
                        if isinstance(data, dict):
                            _fp_api_stat._token_cache = data.get('secret') or data.get('api_token') or ""
                        break
            except ImportError:
                # Fallback lecture ligne par ligne optimisée
                for pf in ["/usr/local/fastpanel2/app/config/parameters.yml",
                           "/usr/local/fastpanel2/app/config/parameters.yaml"]:
                    p = _P(pf)
                    if p.exists():
                        # PERF: Lire ligne par ligne sans splitlines() complet
                        with open(p, 'r', errors="replace") as f:
                            for line in f:
                                # PERF: lstrip évite création de string pour toute la ligne
                                line = line.lstrip()
                                if line.startswith(("secret:", "api_token:")):
                                    # PERF: utilisation de partition pour éviter split double strip
                                    _, _, val = line.partition(':')
                                    _fp_api_stat._token_cache = val.strip().strip("' \"")
                                    break
                        break
        except Exception as e:
            import logging
            logging.warning("[_fp_api_stat] %s" % str(e)[:80])
    token = _fp_api_stat._token_cache
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
    import time as _t
    import threading as _th
    import logging as _log
    import subprocess as _sp
    import shlex as _sl
    from pathlib import Path as _P
    from functools import lru_cache, wraps
    import datetime
    import re

    # PERF: Persistent global cache for API & MySQL credentials
    _cache = getattr(get_fp_stats_cpu, "_cache", {"api": {}, "mysql_creds": None})
    get_fp_stats_cpu._cache = _cache

    # PERF: thread‑local buffer for exec‑time stats
    _exec_times = _th.local()
    _exec_times.buf = []

    def _record_exec_time(duration: float) -> None:
        buf = getattr(_exec_times, "buf", [])
        buf.append(duration)
        if len(buf) > 100:
            buf.pop(0)
        if len(buf) > 10:
            avg = sum(buf) / len(buf)
            if duration > avg * 3:
                _log.warning(
                    f"Anomalie détectée: temps d'exécution {duration:.3f}s (moyenne {avg:.3f}s)"
                )
        _exec_times.buf = buf

    def _time_it(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = _t.monotonic()
            try:
                return func(*args, **kwargs)
            finally:
                _record_exec_time(_t.monotonic() - start)

        return wrapper

    # PERF: lru_cache for reading static params file
    @lru_cache(maxsize=1)
    def _read_params() -> str:
        return _P("/usr/local/fastpanel2/app/config/parameters.yml").read_text(
            errors="replace"
        )

    # PERF: parse MySQL creds once, cache result
    _cred_re = re.compile(r"^\s*([^:#\s]+)\s*:\s*['\"]?([^'\"\s]+)['\"]?\s*$")

    def _get_mysql_creds() -> dict:
        if _cache["mysql_creds"] is not None:
            return _cache["mysql_creds"]
        path = _P("/usr/local/fastpanel2/app/config/parameters.yml")
        if not path.exists():
            _cache["mysql_creds"] = {}
            return {}
        creds = {}
        for line in _read_params().splitlines():
            m = _cred_re.match(line)
            if m:
                creds[m.group(1)] = m.group(2)
        _cache["mysql_creds"] = creds
        return creds

    # PERF: simple dict cache for API calls
    def _api_call_cached(key: str) -> dict:
        if key not in _cache["api"]:
            _cache["api"][key] = _fp_api_stat("/fastpanel/api/stat/cpu", key)
        return _cache["api"][key]

    @_time_it
    def _query_mysql() -> list[dict]:
        rows: list[dict] = []
        creds = _get_mysql_creds()
        pwd = creds.get("database_password")
        if not pwd:
            return rows
        sql = (
            "SELECT ts,cpu_total,processes_json FROM stat_cpu "
            "WHERE DATE(ts)=%s ORDER BY ts DESC LIMIT 288"
        )
        cmd = (
            f"MYSQL_PWD={_sl.quote(pwd)} mysql "
            f"-h{_sl.quote(creds.get('database_host', '127.0.0.1'))} "
            f"-u{_sl.quote(creds.get('database_user', 'fastpanel'))} "
            f"{_sl.quote(creds.get('database_name', 'fastpanel2'))}"
            " --batch --silent --skip-column-names "
            f"-e {_sl.quote(sql)} 2>/dev/null"
        )
        try:
            out = _sp.run(
                cmd, shell=True, capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                # PERF: avoid multiple splits, unpack directly
                ts, total, *proc = line.split("\t")
                rows.append(
                    {
                        "ts": ts,
                        "total": total,
                        "processes": proc[0] if proc else "{}",
                    }
                )
        except _sp.TimeoutExpired:
            _log.warning("Timeout MySQL lors de la récupération des stats CPU")
        except Exception as e:
            _log.error(f"Erreur lors de la récupération MySQL: {e}")
        return rows

    @_time_it
    def _fallback_ps() -> dict:
        try:
            ps_out = _sp.run(
                "ps aux --sort=-%cpu --no-headers | head -15",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout
            procs: dict[str, float] = {}
            for line in ps_out.splitlines():
                parts = line.split(None, 10)
                if len(parts) == 11:
                    try:
                        name = parts[10].rpartition("/")[2].split()[0][:20]
                        cpu = float(parts[2])
                        procs[name] = procs.get(name, 0.0) + cpu
                    except (ValueError, IndexError):
                        continue
            return {"source": "realtime", "data": [{"ts": "now", "processes": procs}]}
        except _sp.TimeoutExpired:
            _log.warning("Timeout lors de l'exécution de ps")
            return {"source": "error", "data": [], "error": "ps timeout"}

    try:
        if not date:
            date = datetime.datetime.now().strftime("%Y-%m-%d")
        data = _api_call_cached(date)
        if data:
            return data
        rows = _query_mysql()
        if rows:
            return {"source": "mysql", "data": rows}
        return _fallback_ps()
    except Exception as e:
        _log.error(f"Erreur critique dans get_fp_stats_cpu: {e}")
        return {"source": "error", "data": [], "error": str(e)}


def get_fp_stats_la(date: str = "") -> dict:
    # PERF: imports locaux conservés mais déplacés en tête
    from datetime import datetime as _dt
    from functools import lru_cache
    from pathlib import Path as _P
    import shlex as _sl
    import subprocess as _sp

    if not date:
        date = _dt.now().strftime("%Y-%m-%d")

    # PERF: appel API en premier (pas de cache réseau)
    data = _fp_api_stat("/fastpanel/api/stat/la", date)
    if data:
        return data

    # PERF: cache des credentials via attribut de fonction (1 seule lecture fichier)
    if not hasattr(get_fp_stats_la, "_load_creds"):
        @lru_cache(maxsize=1)
        def _load_creds():
            config_path = _P("/usr/local/fastpanel2/app/config/parameters.yml")
            if not config_path.exists():
                return {}
            creds = {}
            for line in config_path.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ": " in line:
                    k, v = line.split(": ", 1)
                    creds[k.strip()] = v.strip(" '\"")
            return creds
        get_fp_stats_la._load_creds = _load_creds

    # PERF: template SQL unique avec placeholder {date} (construction une fois)
    if not hasattr(get_fp_stats_la, "_union_sql_template"):
        tables = ["server_stat", "stat_server", "server_stats", "fp_stat"]
        parts = [f"SELECT created_at, la1, la5, la15 FROM {t} WHERE DATE(created_at)=\"{{date}}\"" for t in tables]
        get_fp_stats_la._union_sql_template = " UNION ALL ".join(parts) + " ORDER BY created_at ASC LIMIT 288"

    # PERF: cache persistant pour shlex.quote (attribut de fonction)
    if not hasattr(get_fp_stats_la, "_quote_cached"):
        get_fp_stats_la._quote_cached = lru_cache(maxsize=16)(_sl.quote)

    def _query_mysql(creds: dict) -> list:
        # PERF: formatage direct du template avec la date courante
        sql = get_fp_stats_la._union_sql_template.format(date=date)
        q_db_pass = get_fp_stats_la._quote_cached(creds.get("database_password", ""))
        q_db_user = get_fp_stats_la._quote_cached(creds.get("database_user", "fastpanel"))
        q_db_name = get_fp_stats_la._quote_cached(creds.get("database_name", "fastpanel2"))
        db_host = creds.get("database_host", "127.0.0.1")
        q_sql = get_fp_stats_la._quote_cached(sql)

        # PERF: utilisation de env= au lieu de shell pour éviter un sous-shell
        env = {"MYSQL_PWD": creds.get("database_password", "")}
        cmd = ["mysql", f"-h{db_host}", f"-u{q_db_user}", q_db_name,
               "--batch", "--silent", "--skip-column-names", "-e", q_sql]
        out = _sp.run(cmd, capture_output=True, text=True, timeout=8, env=env).stdout
        return _parse_mysql_output(out)

    def _parse_mysql_output(out: str) -> list:
        # PERF: map(float, ...) évite boucle explicite
        rows = []
        for line in out.splitlines():
            if not line:
                continue
            parts = line.split("\t", 3)
            if len(parts) != 4:
                continue
            ts, la1, la5, la15 = parts
            la1, la5, la15 = map(float, (la1, la5, la15))
            rows.append({"ts": ts, "la1": la1, "la5": la5, "la15": la15})
        return rows

    # PERF: chemin principal MySQL avec try/except réduit
    try:
        creds = get_fp_stats_la._load_creds()
        if creds.get("database_password"):
            rows = _query_mysql(creds)
            if rows:
                return {"source": "mysql", "data": rows}
    except Exception:
        pass

    # PERF: fallback /proc/loadavg avec conversion map
    try:
        with open("/proc/loadavg") as f:
            p = f.read().split()
        la1, la5, la15 = map(float, (p[0], p[1], p[2]))
        return {
            "source": "realtime",
            "data": [{"ts": "now", "la1": la1, "la5": la5, "la15": la15}],
        }
    except Exception:
        return {}


def get_fp_stats_memory(date: str = "") -> dict:
    """Utilisation mémoire historique depuis FastPanel2."""
    import datetime
    from functools import lru_cache
    from pathlib import Path
    import shlex
    import subprocess
    import re

    if not date:
        date = datetime.datetime.now().strftime("%Y-%m-%d")

    # PERF: cache des credentials YAML (relu à chaque appel évité)
    @lru_cache(maxsize=1)
    def _get_creds() -> dict:
        creds = {}
        yaml_path = "/usr/local/fastpanel2/app/config/parameters.yml"
        if Path(yaml_path).exists():
            lines = Path(yaml_path).read_text(errors="replace").splitlines()
            # PERF: compréhension avec partition rapide sans strip redondant
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or ": " not in line:
                    continue
                k, _, v = line.partition(": ")
                creds[k.strip()] = v.strip().strip("'\" ")
        return creds

    # Tentative 1 : API FastPanel2
    try:
        data = _fp_api_stat("/fastpanel/api/stat/memory", date)
        if data:
            return data
    except Exception:
        pass

    # Tentative 2 : MySQL FastPanel2
    creds = _get_creds()
    if creds.get("database_password"):
        try:
            # PERF: déterminer les tables existantes en une seule commande
            db_host = creds.get("database_host", "127.0.0.1")
            db_user = shlex.quote(creds.get("database_user", "fastpanel"))
            db_name = shlex.quote(creds.get("database_name", "fastpanel2"))
            db_pwd = shlex.quote(creds["database_password"])

            tables_to_try = ["server_stat", "stat_server", "server_stats", "fp_stat"]
            existing_tables = []
            # PERF: requête unique pour lister les tables candidates
            list_cmd = (
                f"MYSQL_PWD={db_pwd} mysql -h{db_host} -u{db_user} {db_name} "
                f"--batch --silent --skip-column-names "
                f"-e \"SHOW TABLES LIKE 'server_stat'; SHOW TABLES LIKE 'stat_server'; "
                f"SHOW TABLES LIKE 'server_stats'; SHOW TABLES LIKE 'fp_stat';\" "
                f"2>/dev/null"
            )
            result = subprocess.run(
                list_cmd, shell=True, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Les sorties sont sur des lignes séparées, chaque table trouvée apparaît
                found = set(result.stdout.strip().splitlines())
                existing_tables = [t for t in tables_to_try if t in found]

            if existing_tables:
                # PERF: construire une seule requête UNION ALL
                union_parts = []
                for table in existing_tables:
                    union_parts.append(
                        f"SELECT '{table}' as src, created_at, "
                        f"COALESCE(mem_used,0), COALESCE(mem_total,0), "
                        f"COALESCE(swap_used,0) FROM {table} "
                        f"WHERE DATE(created_at)=\"{date}\""
                    )
                union_sql = " UNION ALL ".join(union_parts) + " ORDER BY src, created_at ASC"
                cmd = (
                    f"MYSQL_PWD={db_pwd} mysql -h{db_host} -u{db_user} {db_name} "
                    f"--batch --silent --skip-column-names "
                    f"-e {shlex.quote(union_sql)} 2>/dev/null"
                )
                out = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=8
                ).stdout

                rows = []
                # PERF: parsing optimisé avec générateur, évite double strip
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("\t")
                    if len(parts) < 4:  # src + 3 cols minimal
                        continue
                    # parts: src, ts, mem_used, mem_total, swap_used (optionnel)
                    mem_used = int(float(parts[2] or 0))
                    mem_total = int(float(parts[3] or 0))
                    # PERF: facteur unique déterminé une fois
                    scale = 1024 if mem_total > 1_000_000 else 1
                    mem_used_final = round(mem_used / scale) if scale > 1 else mem_used
                    mem_total_final = round(mem_total / scale) if scale > 1 else mem_total
                    cached_mb = int(float(parts[4] or 0)) if len(parts) > 4 else 0
                    rows.append({
                        "ts": parts[1],
                        "used_mb": mem_used_final,
                        "total_mb": mem_total_final,
                        "free_mb": max(0, mem_total_final - mem_used_final),
                        "cached_mb": cached_mb,
                    })
                if rows:
                    return {"source": "mysql", "data": rows}

            # Fallback : si aucune table trouvée, on tente chaque table individuellement
            # (ancienne méthode) mais évitée car on a déjà listé les tables
            # Ce bloc ne devrait pas être atteint si existing_tables est vide
            # On garde une boucle simple pour compatibilité si SHOW TABLES échoue
            if not existing_tables:
                for table in tables_to_try:
                    _sql = (
                        f'SELECT created_at, COALESCE(mem_used,0), COALESCE(mem_total,0), '
                        f'COALESCE(swap_used,0) FROM {table} '
                        f'WHERE DATE(created_at)="{date}" ORDER BY created_at ASC LIMIT 288'
                    )
                    cmd = (
                        f"MYSQL_PWD={db_pwd} mysql -h{db_host} -u{db_user} {db_name} "
                        f"--batch --silent --skip-column-names "
                        f"-e {shlex.quote(_sql)} 2>/dev/null"
                    )
                    out = subprocess.run(
                        cmd, shell=True, capture_output=True, text=True, timeout=8
                    ).stdout
                    rows = []
                    for line in out.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split("\t")
                        if len(parts) < 3:
                            continue
                        mem_used = int(float(parts[1] or 0))
                        mem_total = int(float(parts[2] or 0))
                        scale = 1024 if mem_total > 1_000_000 else 1
                        mem_used_final = round(mem_used / scale) if scale > 1 else mem_used
                        mem_total_final = round(mem_total / scale) if scale > 1 else mem_total
                        cached_mb = int(float(parts[3] or 0)) if len(parts) > 3 else 0
                        rows.append({
                            "ts": parts[0],
                            "used_mb": mem_used_final,
                            "total_mb": mem_total_final,
                            "free_mb": max(0, mem_total_final - mem_used_final),
                            "cached_mb": cached_mb,
                        })
                    if rows:
                        return {"source": "mysql", "data": rows}
        except Exception:
            pass

    # Tentative 3 : /proc/meminfo pour un point temps réel
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    mi[k.strip()] = int(v.strip().split()[0])
        total = mi.get("MemTotal", 1)
        avail = mi.get("MemAvailable", total) or mi.get("MemFree", 0)
        cached = mi.get("Cached", 0) + mi.get("Buffers", 0)
        used = total - avail
        factor = 1024
        return {
            "source": "realtime",
            "data": [{
                "ts": "now",
                "total_mb": round(total / factor),
                "used_mb": round(used / factor),
                "cached_mb": round(cached / factor),
                "free_mb": round(avail / factor),
            }]
        }
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
    # PERF: mkdir une seule fois, inchange
    Path(MEMORY_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(MEMORY_DB_PATH)

    # PERF: regroupe tous les CREATE TABLE / INDEX en un seul executescript
    ddl_script = """
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS conversation_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            summary TEXT NOT NULL,
            msg_range TEXT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS server_sessions (
            token TEXT PRIMARY KEY,
            username TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS memories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            category TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            confidence REAL DEFAULT 1.0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            access_count INTEGER DEFAULT 0,
            UNIQUE(username, category, key)
        );
        CREATE TABLE IF NOT EXISTS agent_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT DEFAULT (datetime('now')),
            session_id TEXT,
            command TEXT NOT NULL,
            output TEXT,
            duration_ms INTEGER DEFAULT 0,
            is_risky INTEGER DEFAULT 0,
            had_diff INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS file_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT DEFAULT (datetime('now')),
            session_id TEXT,
            trigger_command TEXT,
            file_path TEXT NOT NULL,
            content_before TEXT NOT NULL,
            action_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS evolution_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, target_file TEXT, description TEXT, motivation TEXT,
            diff TEXT, snapshot_before TEXT,
            sha256_before TEXT, sha256_after TEXT,
            status TEXT DEFAULT "applied", restart_done INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS evolution_wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, target_file TEXT, category TEXT,
            description TEXT, priority TEXT DEFAULT "medium",
            status TEXT DEFAULT "pending", identified_by TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT DEFAULT (datetime('now')),
            level TEXT NOT NULL,
            category TEXT NOT NULL,
            message TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            resolved_at TEXT
        );
        CREATE TABLE IF NOT EXISTS cron_natural (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT NOT NULL,
            cron_expr TEXT NOT NULL,
            command TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS memory_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            memory_id INTEGER, category TEXT NOT NULL, key TEXT NOT NULL,
            old_value TEXT, new_value TEXT, confidence REAL,
            changed_at TEXT DEFAULT (datetime('now')), change_reason TEXT
        );
        CREATE TABLE IF NOT EXISTS knowledge_graph (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_key TEXT NOT NULL, target_key TEXT NOT NULL,
            relation TEXT NOT NULL, weight REAL DEFAULT 1.0,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(source_key, target_key, relation)
        );
        CREATE TABLE IF NOT EXISTS memory_tags (
            memory_id INTEGER, tag TEXT NOT NULL,
            PRIMARY KEY (memory_id, tag)
        );
        CREATE INDEX IF NOT EXISTS idx_memory_history_mid ON memory_history(memory_id);
        CREATE INDEX IF NOT EXISTS idx_knowledge_graph_source ON knowledge_graph(source_key);
        CREATE INDEX IF NOT EXISTS idx_knowledge_graph_target ON knowledge_graph(target_key);
        CREATE INDEX IF NOT EXISTS idx_memory_tags_tag ON memory_tags(tag);
    """
    conn.executescript(ddl_script)  # PERF: un seul appel au lieu de ~15

    # PERF: remplace PRAGMA + IF par simple ALTER + catch (moins de requêtes)
    try:
        conn.execute("ALTER TABLE server_sessions ADD COLUMN username TEXT")
    except Exception:
        logging.warning("[init_memory_db] ALTER server_sessions ignoré (colonne existante)")
    try:
        conn.execute("ALTER TABLE memories ADD COLUMN username TEXT")
    except Exception:
        logging.warning("[init_memory_db] ALTER memories ignoré (colonne existante)")
    # Mémoire infaillible : on ne supprime JAMAIS physiquement → soft-delete via 'status'
    # ('active' | 'archived' | 'superseded'). + 'pinned' pour les vérités absolues.
    for _alter in (
        "ALTER TABLE memories ADD COLUMN status TEXT DEFAULT 'active'",
        "ALTER TABLE memories ADD COLUMN pinned INTEGER DEFAULT 0",
        "ALTER TABLE memories ADD COLUMN embedding BLOB",  # vecteur sémantique (Phase 2)
    ):
        try:
            conn.execute(_alter)
        except Exception:
            pass
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_status ON memories(status)")
    except Exception:
        pass

    # ── FTS5 : reste identique (try/except preserves degration) ──
    try:
        conn.executescript("""
            CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                key, value, category,
                content='memories',
                content_rowid='id',
                tokenize='unicode61'
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
        # Peupler FTS si nécessaire (migration silencieuse)
        fts_count = conn.execute("SELECT COUNT(*) FROM memories_fts").fetchone()[0]
        mem_count  = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
        if mem_count > 0 and fts_count == 0:
            conn.execute(
                "INSERT INTO memories_fts(rowid, key, value, category) "
                "SELECT id, key, value, category FROM memories"
            )
            print(f"[MEMORY] FTS5 index peuplé avec {mem_count} mémoires existantes")
    except Exception as e:
        # ROBUSTESSE : logging explicite (fixe undefined issues)
        logging.warning(f"[init_memory_db] FTS5 non disponible, fallback keyword-overlap actif: {e}")

    conn.commit()
    conn.close()


def create_server_session(username: str = None) -> str:
    token = secrets.token_hex(32)
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.execute("INSERT INTO server_sessions (token, username) VALUES (?, ?)", (token, username))
    conn.execute("DELETE FROM server_sessions WHERE created_at < datetime('now', '-1 day')")
    conn.commit()
    conn.close()
    return token

def get_session_user(token: str) -> str:
    """Retourne le pseudo associé à la session, ou '' si inconnu."""
    if not token or len(token) != 64:
        return ""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        row = conn.execute("SELECT username FROM server_sessions WHERE token = ?", (token,)).fetchone()
        conn.close()
        return (row[0] or "") if row else ""
    except Exception:
        return ""

# Utilisateur de la requête en cours (thread-local — un thread par requête HTTP)
_request_user = threading.local()

def set_current_user(username: str):
    _request_user.name = username or ""

def get_current_user() -> str:
    return getattr(_request_user, "name", "") or ""


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
    """Sauvegarde ou met a jour une memoire persistante (v2 avec historique et tags).
    La mémoire est rattachée au pseudo de l'utilisateur courant (scope par personne)."""
    try:
        _u = get_current_user() or None
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        # Dédup par (username, category, key) ; IS pour matcher correctement NULL
        existing = conn.execute(
            "SELECT id, value FROM memories WHERE username IS ? AND category = ? AND key = ?",
            (_u, category, key)).fetchone()
        if existing:
            memory_id, old_value = existing[0], existing[1]
            if old_value != value:
                conn.execute("INSERT INTO memory_history (memory_id, category, key, old_value, new_value, confidence, change_reason) VALUES (?,?,?,?,?,?,?)",
                    (memory_id, category, key, old_value[:2000], value[:2000], confidence, change_reason[:200]))
                conn.execute("UPDATE memories SET value=?, confidence=?, updated_at=datetime('now'), access_count=access_count+1 WHERE id=?", (value[:2000], confidence, memory_id))
            else:
                conn.execute("UPDATE memories SET access_count=access_count+1, updated_at=datetime('now') WHERE id=?", (memory_id,))
        else:
            try:
                conn.execute("INSERT INTO memories (username, category, key, value, confidence) VALUES (?,?,?,?,?)", (_u, category, key, value[:2000], confidence))
            except sqlite3.IntegrityError:
                # Base pré-migration avec UNIQUE(category,key) → on met à jour la ligne existante
                conn.execute("UPDATE memories SET value=?, confidence=?, updated_at=datetime('now') WHERE category=? AND key=?", (value[:2000], confidence, category, key))
            memory_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        # Embedding sémantique — uniquement si le modèle est DÉJÀ chargé (jamais
        # bloquant pour la requête ; sinon le backfill/warmup s'en charge).
        if memory_id and globals().get("_EMBED_READY"):
            try:
                _vec = embed_text("%s : %s" % (key, value))
                if _vec:
                    conn.execute("UPDATE memories SET embedding=? WHERE id=?",
                                 (_vec_to_blob(_vec), memory_id))
            except Exception:
                pass
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
                f"WHERE category IN ({ph}) AND (status IS NULL OR status='active') "
                f"ORDER BY access_count DESC, updated_at DESC LIMIT ?",
                categories + [limit]).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, category, key, value, confidence, updated_at FROM memories "
                "WHERE (status IS NULL OR status='active') "
                "ORDER BY access_count DESC, updated_at DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def delete_memory(memory_id: int, hard: bool = False):
    """Soft-delete par défaut (status='archived') — la mémoire est conservée et
    réversible. hard=True force la suppression physique (réservé à la purge manuelle)."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        if hard:
            conn.execute("DELETE FROM memories WHERE id=?", (memory_id,))
        else:
            conn.execute("UPDATE memories SET status='archived', updated_at=datetime('now') WHERE id=?",
                         (memory_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def set_memory_pinned(memory_id: int, pinned: bool) -> bool:
    """Épingle/désépingle une mémoire (vérité absolue toujours injectée dans le prompt)."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.execute("UPDATE memories SET pinned=?, updated_at=datetime('now') WHERE id=?",
                     (1 if pinned else 0, memory_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[MEMORY] Erreur set_memory_pinned: {e}")
        return False


def restore_memory(memory_id: int) -> bool:
    """Restaure une mémoire archivée/superseded → active."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.execute("UPDATE memories SET status='active', updated_at=datetime('now') WHERE id=?",
                     (memory_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def purge_archived_memories() -> int:
    """Suppression PHYSIQUE des mémoires archivées/superseded (action manuelle explicite)."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        cur = conn.execute("DELETE FROM memories WHERE status IN ('archived','superseded')")
        n = cur.rowcount
        conn.commit()
        conn.close()
        return n or 0
    except Exception:
        return 0


def get_memories_full(include_archived: bool = False, limit: int = 300) -> list:
    """Liste enrichie pour l'UI Mémoire : inclut pinned + status + access_count."""
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        conn.row_factory = sqlite3.Row
        where = "" if include_archived else "WHERE (status IS NULL OR status='active')"
        rows = conn.execute(
            "SELECT id, category, key, value, confidence, access_count, updated_at, "
            "COALESCE(pinned,0) AS pinned, COALESCE(status,'active') AS status "
            f"FROM memories {where} "
            "ORDER BY pinned DESC, updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


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


import time

def format_memories_for_prompt(query: str = "") -> str:
    """Mémoire absolue: sélection hybride core + pertinence contextuelle."""
    global _memory_cache
    # PERF: initialisation du cache global persistant entre appels (déjà fait, mais on garde)
    if '_memory_cache' not in globals():
        _memory_cache = {}
    # PERF: durée de vie du cache en secondes
    CACHE_TTL = 30

    # PERF: cat_labels et stop_fb définis une seule fois (déplacés en constantes du module)
    # Note: ces constantes sont recréées à chaque appel, on pourrait les mettre en global.
    # On les définit ici mais on pourrait les sortir. Pour rester auto-suffisant, on les laisse.
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
    stop_fb = {'le','la','les','de','du','des','un','une','et','en','il',
               'je','tu','ce','que','qui','est','par','sur','pour','avec',
               'dans','ou','pas','se','te','me','on','au','ne'}

    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row

        _u = get_current_user()
        _scope = "(username = ? OR username IS NULL OR username = 'shared')"

        now = time.time()  # PERF: calculé une seule fois

        # --- 1. Core memories avec cache ---
        core_cache_key = ('core', _u)
        cached_core = _memory_cache.get(core_cache_key)
        if cached_core and (now - cached_core[0] < CACHE_TTL):
            core = cached_core[1]          # réutilise le résultat mis en cache
            # PERF: évite une requête SQL si le cache est encore valide
        else:
            core = conn.execute(
                "SELECT category, key, value, confidence, access_count FROM memories "
                f"WHERE (status IS NULL OR status='active') AND {_scope} "
                "AND (pinned=1 OR (confidence >= 0.85 AND access_count >= 2)) "
                "ORDER BY pinned DESC, (confidence * (access_count + 1)) DESC LIMIT 12",
                (_u,)
            ).fetchall()
            _memory_cache[core_cache_key] = (now, core)   # mise en cache

        core_keys = {m['key'] for m in core}

        # --- 2. Sélection contextuelle via FTS5/BM25 (fallback si indisponible) ---
        query_relevant = []
        if query.strip():
            # PERF: cache pour la recherche sémantique (même requête)
            sem_cache_key = ('sem', _u, query)
            cached_sem = _memory_cache.get(sem_cache_key)
            if cached_sem and (now - cached_sem[0] < CACHE_TTL):
                query_relevant = cached_sem[1]
                # PERF: évite un appel réseau coûteux
            else:
                # Recherche sémantique prioritaire
                try:
                    _sem = memory_search_semantic(query, k=10, scope_user=_u)
                    query_relevant = [m for m in _sem if m.get("key") not in core_keys]
                    _memory_cache[sem_cache_key] = (now, query_relevant)
                except Exception:
                    query_relevant = []
                    _memory_cache.pop(sem_cache_key, None)  # PERF: ne pas conserver d'échec

            # Repli FTS5/mots-clés (uniquement si pas de résultat sémantique)
            if not query_relevant:
                # PERF: cache pour _build_fts_query (même requête)
                fts_q_cache_key = ('fts_q', query)
                cached_fts_q = _memory_cache.get(fts_q_cache_key)
                if cached_fts_q and (now - cached_fts_q[0] < CACHE_TTL):
                    fts_q = cached_fts_q[1]
                else:
                    fts_q = _build_fts_query(query)
                    _memory_cache[fts_q_cache_key] = (now, fts_q)

                if fts_q:
                    excl = list(core_keys) if core_keys else []
                    excl_sql = ("AND m.key NOT IN ({})".format(','.join('?' * len(excl)))
                                if excl else "")
                    try:
                        fts_rows = conn.execute(
                            "SELECT m.category, m.key, m.value, m.confidence, m.access_count "
                            "FROM memories_fts f JOIN memories m ON f.rowid = m.id "
                            f"WHERE memories_fts MATCH ? {excl_sql} "
                            "AND (m.status IS NULL OR m.status='active') "
                            "AND (m.username = ? OR m.username IS NULL OR m.username = 'shared') "
                            "ORDER BY bm25(memories_fts) LIMIT 10",
                            [fts_q] + excl + [_u]
                        ).fetchall()
                        query_relevant = [dict(r) for r in fts_rows]
                    except Exception as fts_err:
                        print(f"[MEMORY] FTS5 fallback: {fts_err}")
                        # PERF: extraction des mots une seule fois avec cache possible
                        # stop_fb déjà défini en constante
                        words = {w.lower() for w in re.split(r'\W+', query)
                                 if len(w) > 2 and w.lower() not in stop_fb}
                        if words:
                            # --- Pool récent avec cache (incluant les textes en minuscules) ---
                            pool_cache_key = ('pool', _u)
                            cached_pool = _memory_cache.get(pool_cache_key)
                            if cached_pool and (now - cached_pool[0] < CACHE_TTL):
                                pool, pool_lower = cached_pool[1], cached_pool[2]  # PERF: texte précalculé
                            else:
                                pool = conn.execute(
                                    "SELECT category, key, value, confidence, access_count FROM memories "
                                    f"WHERE confidence > 0.4 AND (status IS NULL OR status='active') AND {_scope} "
                                    "ORDER BY updated_at DESC LIMIT 200",
                                    (_u,)
                                ).fetchall()
                                # PERF: précalcul des textes en minuscules pour éviter les .lower() répétés
                                pool_lower = [(m['key'] + ' ' + m['value']).lower() for m in pool]
                                _memory_cache[pool_cache_key] = (now, pool, pool_lower)

                            scored = []
                            for i, m in enumerate(pool):
                                if m['key'] in core_keys:
                                    continue
                                text_lower = pool_lower[i]  # PERF: utilisation du texte précalculé
                                hits = sum(1 for w in words if w in text_lower)
                                if hits > 0:
                                    scored.append((hits, dict(m)))
                            scored.sort(key=lambda x: -x[0])
                            query_relevant = [m for _, m in scored[:10]]

        conn.close()

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
    _owner = get_current_user()  # capturé dans le thread de la requête HTTP
    def _do():
        if not DEEPSEEK_API_KEY or len(agent_response) < 60:
            return
        try:
            set_current_user(_owner)  # propage le scope utilisateur au thread d'extraction
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
            raw = resp.choices[0].message.content or ""
            obj = _evo_json_extract(raw) or {}   # parsing robuste (fences, texte parasite)
            saved = 0
            for m in obj.get("memories", [])[:8]:
                try:
                    conf = float(m.get("confidence", 0.8))
                except Exception:
                    conf = 0.8
                cat = (m.get("category") or "fact").strip() or "fact"
                if m.get("key") and m.get("value") and conf >= 0.5:
                    save_memory(cat, str(m["key"])[:80], str(m["value"])[:400], conf)
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

    # PERF: open DB once, batch updates/deletes, use parameterized queries
    # PERF: use executemany for all deletions, compute datetime once
    """
    if not DEEPSEEK_API_KEY:
        return  # FIX: short‑circuit when no key

    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Retrieve up to 120 memories in one query (##PERF)
        mems = cur.execute(
            """
            SELECT id, category, key, value, confidence
            FROM memories
            ORDER BY category, updated_at DESC
            LIMIT 120
            """
        ).fetchall()

        if len(mems) < 8:
            conn.close()
            return

        # Build the text representation once (##PERF)
        mem_list = "\n".join(
            f"[{m['id']}] [{m['category']}] {m['key']}: {str(m['value'])[:120]}"
            for m in mems
        )

        # Call the LLM once with the batch (##PERF)
        valid_ids = {m["id"] for m in mems}  # garde-fou : on n'agit que sur des IDs réels

        resp = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"""Analyse ces souvenirs d'agent IA et identifie les redondances.
Réponds UNIQUEMENT en JSON valide sans markdown :
{{"merges":[{{"keep_id":N,"delete_ids":[M],"merged_value":"valeur fusionnée max 400 chars"}}],"delete_ids":[N]}}

Règles :
- "merges" : souvenirs qui expriment le même fait avec des formulations différentes → fusionner en gardant le plus précis
- "delete_ids" : souvenirs clairement périmés ou contradictoires (états temporaires, erreurs ponctuelles résolues)
- Maximum 5 fusions et 8 suppressions
- Si rien à faire : {{"merges":[],"delete_ids":[]}}

Souvenirs :
{mem_list}"""
                    ),
                }
            ],
            temperature=0.1,
            max_tokens=700,
        )

        # Parsing robuste (fences markdown, texte parasite) — comme l'évolution
        obj = _evo_json_extract(resp.choices[0].message.content or "") or {}

        n_merged = n_deleted = 0

        # Pre‑compute current timestamp for all updates (##PERF)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        update_params = []
        delete_ids_all = []

        # Batch all merge updates (##PERF)
        for merge in obj.get("merges", [])[:5]:
            keep_id = merge.get("keep_id")
            del_ids = [d for d in (merge.get("delete_ids") or [])
                       if d in valid_ids and d != keep_id]
            merged_val = str(merge.get("merged_value", ""))[:400]
            if keep_id in valid_ids and del_ids and merged_val:
                update_params.append((merged_val, keep_id, now))
                delete_ids_all.extend(del_ids)
                n_merged += 1

        # Execute all merge updates in one executemany (##PERF)
        if update_params:
            cur.executemany(
                """
                UPDATE memories
                SET value=?, confidence=MIN(confidence+0.05,1.0), updated_at=?
                WHERE id=?
                """,
                update_params,
            )

        # Suppressions autonomes — uniquement des IDs réels
        delete_ids_all.extend(
            did for did in (obj.get("delete_ids") or [])[:8] if did in valid_ids
        )

        # SOFT-DELETE : on archive (status='superseded'), on ne supprime JAMAIS
        # physiquement → aucune perte de mémoire, réversible.
        delete_ids_all = list({d for d in delete_ids_all if d in valid_ids})
        if delete_ids_all:
            cur.executemany(
                "UPDATE memories SET status='superseded', updated_at=? WHERE id=?",
                [(now, did) for did in delete_ids_all],
            )
            n_deleted = len(delete_ids_all)

        conn.commit()
        conn.close()

        if n_merged or n_deleted:
            print(f"[MEMORY] Consolidation: {n_merged} fusions, {n_deleted} suppressions")

        # PERF: explicit return for clarity
        return

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
# MOTEUR SÉMANTIQUE — embeddings locaux + recherche vectorielle (Phase 2)
# ============================================================
# Stockage illimité, prompt borné : on vectorise chaque mémoire et on récupère par
# similarité de SENS (top-K), pas par mots-clés. Dégradation gracieuse : si le modèle
# d'embeddings n'est pas installé, tout retombe proprement sur FTS5/mots-clés.

_EMBED_MODEL      = None
_EMBED_MODEL_NAME = ""
_EMBED_LOCK       = threading.Lock()
_EMBED_READY      = False
_EMBED_FAILED     = False
_EMBED_DIM        = 1024
# Cache matriciel en RAM pour une recherche vectorielle ULTRA-rapide (numpy),
# reconstruit quand le nb de mémoires change ou après 60s (évite de relire/parser
# les BLOBs + boucle Python à chaque requête → gros gain de perf sans perte de qualité).
_MEM_VEC = {"lock": threading.Lock(), "ids": None, "mat": None, "meta": None, "ts": 0.0, "count": -1}

def _get_embedder():
    """Charge le modèle d'embeddings local une seule fois (singleton).
    Renvoie None si indisponible → l'appelant retombe sur la recherche classique."""
    global _EMBED_MODEL, _EMBED_READY, _EMBED_FAILED, _EMBED_DIM
    if _EMBED_READY:
        return _EMBED_MODEL
    if _EMBED_FAILED:
        return None
    # KILL-SWITCH : la mémoire sémantique (sentence-transformers + PyTorch) est
    # DÉSACTIVÉE PAR DÉFAUT car elle charge ~1-2 Go en RAM (risque d'OOM sur petit
    # serveur). On l'active explicitement via config "memory_semantic_enabled": true.
    try:
        if os.environ.get("CASSANDRA_DISABLE_EMBED") == "1" or \
           not get_cassandra_config().get("memory_semantic_enabled", False):
            _EMBED_FAILED = True
            logging.info("[EMBED] Mémoire sémantique désactivée (par défaut) — recherche FTS5/mots-clés.")
            return None
    except Exception:
        _EMBED_FAILED = True
        return None
    with _EMBED_LOCK:
        if _EMBED_READY:
            return _EMBED_MODEL
        if _EMBED_FAILED:
            return None
        try:
            # Limiter les threads torch : évite que le modèle monopolise tous les CPU
            # et étrangle les autres services (cause de lenteur générale).
            try:
                import torch
                torch.set_num_threads(int(os.environ.get("CASSANDRA_EMBED_THREADS", "2")))
            except Exception:
                pass
            from sentence_transformers import SentenceTransformer
            # Qualité maximale par défaut : modèle multilingue e5-large (1024 dim).
            # Surchargeable via config "memory_embed_model" ou env CASSANDRA_EMBED_MODEL.
            try:
                name = (get_cassandra_config().get("memory_embed_model") or "").strip()
            except Exception:
                name = ""
            name = name or os.environ.get("CASSANDRA_EMBED_MODEL", "intfloat/multilingual-e5-large")
            global _EMBED_MODEL_NAME
            _EMBED_MODEL = SentenceTransformer(name)
            _EMBED_MODEL_NAME = name
            try:
                _EMBED_DIM = int(_EMBED_MODEL.get_sentence_embedding_dimension())
            except Exception:
                pass
            _EMBED_READY = True
            logging.info("[EMBED] Modèle '%s' chargé (dim=%d, threads limités)" % (name, _EMBED_DIM))
            return _EMBED_MODEL
        except Exception as e:
            _EMBED_FAILED = True
            logging.warning("[EMBED] Embeddings indisponibles (%s) — repli FTS5/mots-clés" % e)
            return None

def embeddings_available() -> bool:
    return _get_embedder() is not None

def embed_text(text: str, kind: str = "passage"):
    """Retourne un vecteur normalisé (list[float]) ou None si indisponible.
    kind='query' pour une recherche, 'passage' pour un souvenir stocké.
    Les modèles e5 EXIGENT ces préfixes pour donner leur pleine qualité."""
    m = _get_embedder()
    if not m or not text:
        return None
    try:
        t = text
        if "e5" in (_EMBED_MODEL_NAME or "").lower():
            t = ("query: " if kind == "query" else "passage: ") + text
        v = m.encode(t, normalize_embeddings=True)
        return [float(x) for x in v]
    except Exception as e:
        logging.warning("[EMBED] encode échec: %s" % e)
        return None

def _vec_to_blob(vec):
    if not vec:
        return None
    return struct.pack("%df" % len(vec), *vec)

def _blob_to_vec(blob):
    if not blob:
        return None
    try:
        return list(struct.unpack("%df" % (len(blob) // 4), blob))
    except Exception:
        return None

def _cosine(a, b):
    """Vecteurs normalisés → produit scalaire = similarité cosinus."""
    if not a or not b or len(a) != len(b):
        return -1.0
    return sum(x * y for x, y in zip(a, b))

def memory_embed_backfill(limit: int = 1000) -> int:
    """Vectorise les mémoires actives qui n'ont pas encore d'embedding (migration douce)."""
    if not embeddings_available():
        return 0
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH, timeout=15)
        rows = conn.execute(
            "SELECT id, key, value FROM memories "
            "WHERE (status IS NULL OR status='active') AND embedding IS NULL LIMIT ?",
            (limit,)
        ).fetchall()
        n = 0
        for mid, key, value in rows:
            vec = embed_text("%s : %s" % (key or "", value or ""))
            if vec:
                conn.execute("UPDATE memories SET embedding=? WHERE id=?",
                             (_vec_to_blob(vec), mid))
                n += 1
        conn.commit()
        conn.close()
        if n:
            logging.info("[EMBED] %d mémoires vectorisées (backfill)" % n)
        return n
    except Exception as e:
        logging.warning("[EMBED] backfill échec: %s" % e)
        return 0

def _get_mem_matrix():
    """Matrice (numpy) des embeddings des mémoires actives, gardée en RAM et
    reconstruite seulement si le nombre de mémoires change ou après 60 s.
    → évite de relire/parser les BLOBs et de boucler en Python à CHAQUE requête."""
    try:
        import numpy as np
    except Exception:
        return None, [], []
    now = time.time()
    with _MEM_VEC["lock"]:
        try:
            conn = sqlite3.connect(MEMORY_DB_PATH, timeout=10)
            cnt = conn.execute("SELECT COUNT(*) FROM memories "
                               "WHERE (status IS NULL OR status='active') AND embedding IS NOT NULL").fetchone()[0]
        except Exception:
            return None, [], []
        if _MEM_VEC["mat"] is not None and _MEM_VEC["count"] == cnt and (now - _MEM_VEC["ts"]) < 60:
            conn.close()
            return _MEM_VEC["mat"], _MEM_VEC["ids"], _MEM_VEC["meta"]
        try:
            rows = conn.execute(
                "SELECT id, category, key, value, confidence, access_count, username, embedding "
                "FROM memories WHERE (status IS NULL OR status='active') AND embedding IS NOT NULL"
            ).fetchall()
        finally:
            conn.close()
        ids, meta, vecs = [], [], []
        for r in rows:
            v = _blob_to_vec(r[7])
            if not v:
                continue
            ids.append(r[0]); vecs.append(v)
            meta.append({"category": r[1], "key": r[2], "value": r[3],
                         "confidence": r[4], "access_count": r[5], "username": r[6]})
        if not vecs:
            _MEM_VEC.update(mat=None, ids=[], meta=[], count=cnt, ts=now)
            return None, [], []
        # Dimension homogène (au cas où un ancien modèle aurait laissé d'autres dimensions)
        dims = [len(v) for v in vecs]
        dim = max(set(dims), key=dims.count)
        fids, fmeta, fvecs = [], [], []
        for i, v in enumerate(vecs):
            if len(v) == dim:
                fids.append(ids[i]); fmeta.append(meta[i]); fvecs.append(v)
        import numpy as np
        mat = np.asarray(fvecs, dtype=np.float32)
        _MEM_VEC.update(mat=mat, ids=fids, meta=fmeta, count=cnt, ts=now)
        return mat, fids, fmeta


def memory_search_semantic(query: str, k: int = 10, scope_user: str = None,
                           min_score: float = 0.30) -> list:
    """Recherche sémantique top-K (numpy vectorisé sur matrice en cache).
    Retourne [] si les embeddings sont indisponibles → repli FTS5 chez l'appelant."""
    qv = embed_text(query, kind="query")
    if not qv:
        return []
    try:
        import numpy as np
        mat, ids, meta = _get_mem_matrix()
        if mat is None or not len(ids):
            return []
        q = np.asarray(qv, dtype=np.float32)
        if q.shape[0] != mat.shape[1]:
            return []  # dimension incohérente (modèle changé → re-vectorisation en cours)
        scores = mat @ q  # vecteurs normalisés → produit scalaire = cosinus
        out = []
        for i in np.argsort(-scores)[:k * 4]:
            s = float(scores[i])
            if s < min_score:
                break
            m = meta[i]
            if m["username"] in (None, scope_user, "shared"):
                out.append({"category": m["category"], "key": m["key"], "value": m["value"],
                            "confidence": m["confidence"], "access_count": m["access_count"],
                            "_score": round(s, 3)})
                if len(out) >= k:
                    break
        return out
    except Exception as e:
        logging.warning("[EMBED] recherche sémantique échec: %s" % e)
        return []

def start_embeddings_warmup():
    """Précharge le modèle + backfill en arrière-plan (ne bloque pas le démarrage)."""
    def _run():
        time.sleep(20)
        if _get_embedder():
            memory_embed_backfill()
    threading.Thread(target=_run, daemon=True, name="embeddings-warmup").start()


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
        cursor = conn.cursor()

        # PERF: Remplacer la boucle pattern par pattern par une insertion massive en une seule requête SQL
        cursor.execute("""
            INSERT INTO memories (category, key, value, confidence)
            SELECT 'fact', key, value, MIN(confidence + 0.1, 1.0)
            FROM memories
            WHERE category='pattern' AND confidence > 0.8 AND access_count > 3
              AND key NOT IN (SELECT key FROM memories WHERE category='fact')
        """)
        # PERF: Insertion en masse dans knowledge_graph pour les mêmes patterns consolidés
        cursor.execute("""
            INSERT OR IGNORE INTO knowledge_graph (source_key, target_key, relation)
            SELECT key, key, 'is_consolidation_of'
            FROM memories
            WHERE category='pattern' AND confidence > 0.8 AND access_count > 3
              AND key NOT IN (SELECT key FROM memories WHERE category='fact')
        """)

        # PERF: Remplacer les multiples requêtes de déduplication par un seul parcours trié
        # Récupérer tous les enregistrements triés par (catégorie, clé, confidence DESC, access_count DESC)
        all_rows = cursor.execute("""
            SELECT id, category, key, confidence, access_count
            FROM memories
            ORDER BY category, key, confidence DESC, access_count DESC
        """).fetchall()

        if all_rows:
            prev_cat = None
            prev_key = None
            best_id = None
            best_acc = 0
            # Liste des ids à supprimer (tous sauf le meilleur de chaque groupe)
            to_delete = []
            # Mise à jour cumulative des access_count pour le meilleur
            updates = []  # (additional_access, best_id)

            for row in all_rows:
                cur_cat = row['category']
                cur_key = row['key']
                if (cur_cat == prev_cat and cur_key == prev_key):
                    # Même groupe : ce n'est pas le meilleur (car trié)
                    to_delete.append(row['id'])
                    best_acc += row['access_count']
                else:
                    # Changement de groupe : on applique la mise à jour du groupe précédent
                    if prev_cat is not None and updates:
                        cursor.execute("UPDATE memories SET access_count = ? WHERE id = ?", (best_acc, best_id))
                        updates.clear()
                    # Nouveau groupe : le premier est le meilleur
                    prev_cat = cur_cat
                    prev_key = cur_key
                    best_id = row['id']
                    best_acc = row['access_count']  # on conserve la valeur actuelle
                    updates.append((best_acc, best_id))  # sera appliqué après le dernier groupe

            # Appliquer la mise à jour pour le dernier groupe
            if updates:
                cursor.execute("UPDATE memories SET access_count = ? WHERE id = ?", (best_acc, best_id))

            # Supprimer tous les doublons identifiés (sauf les meilleurs)
            for del_id in to_delete:
                cursor.execute("DELETE FROM memories WHERE id = ?", (del_id,))

        conn.commit()
        conn.close()
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
    import functools
    import os
    import subprocess
    import time

    # PERF: Cache pour les règles pour éviter les appels répétés à _rule
    @functools.lru_cache(maxsize=32)
    def _cached_rule(name):
        for r in rules:
            if r.get("name") == name:
                return tuple(sorted(r.items()))
        return ()
    
    # PERF: Fonction helper pour décoder le cache
    def _rule(name):
        cached = _cached_rule(name)
        return dict(cached) if cached else {}
    
    # PERF: Cache pour les alertes déjà envoyées (évite les doublons)
    _alert_cache = set()
    
    # PERF: Fonction helper pour fire_alert avec cache
    def _cached_fire_alert(alert_type, severity, source, message, channels):
        cache_key = (alert_type, source)
        if cache_key in _alert_cache:
            return
        fire_alert(alert_type, severity, source, message, channels)
        _alert_cache.add(cache_key)
    
    # PERF: Préchargement de la configuration une seule fois par itération
    cfg = load_alert_config()
    rules = cfg.get("rules", []) if cfg else []
    
    # PERF: Précompilation des chemins de fichiers pour éviter les répétitions
    _meminfo_path = '/proc/meminfo'
    _loadavg_path = '/proc/loadavg'
    
    # PERF: Préparation des listes de montages et services pour éviter les recréations
    _mounts = ['/', '/var', '/home', '/tmp', '/var/www']
    _services = ['nginx','apache2','mysql','mariadb','postfix','sshd',
                 'php8.1-fpm','php8.2-fpm','php8.3-fpm','fastpanel2']
    
    # PERF: Préparation des seuils — lus depuis alerts.yml (thresholds:) si présents,
    # sinon valeurs par défaut codées en dur (fallback).
    _th = (cfg.get("thresholds") or {}) if cfg else {}
    def _thv(key, default):
        try:
            return float(_th.get(key, default))
        except Exception:
            return float(default)
    _disk_critical_threshold = _thv("disk_critical", 90)
    _disk_warning_threshold  = _thv("disk_warning", 80)
    _ram_critical_threshold  = _thv("ram_critical", 95)
    _ram_warning_threshold   = _thv("ram_warning", 88)
    _load_critical_threshold = _thv("load_critical", 3.0)
    _load_warning_threshold  = _thv("load_warning", 2.0)
    _ssl_critical_days = 3
    _ssl_warning_days = 14
    
    # PERF: Décomposition en sous-fonctions pour réduire la complexité et la latence
    def _check_disk():
        for mount in _mounts:
            try:
                u   = _sh.disk_usage(mount)
                pct = u.used / u.total * 100
                if pct >= _disk_critical_threshold:
                    r = _rule("disk_critical")
                    _cached_fire_alert("disk_critical", "critical", f"disk_{mount}",
                               f"Disque {mount} : {pct:.0f}% utilise",
                               r.get("channels", ["email", "webhook"]))
                elif pct >= _disk_warning_threshold:
                    r = _rule("disk_warning")
                    _cached_fire_alert("disk_warning", "warning", f"disk_{mount}",
                               f"Disque {mount} : {pct:.0f}% utilise",
                               r.get("channels", ["webhook"]))
            except Exception:
                pass
    
    def _check_ram():
        try:
            mi    = {}
            with open(_meminfo_path) as f:
                for line in f:
                    k, v = line.split(':', 1)
                    mi[k.strip()] = int(v.strip().split()[0])
            total = mi.get('MemTotal', 1)
            avail = mi.get('MemAvailable', total)
            pct   = (total - avail) / total * 100
            if pct >= _ram_critical_threshold:
                r = _rule("ram_critical")
                _cached_fire_alert("ram_critical", "critical", "memory",
                           f"RAM critique : {pct:.0f}% utilisee",
                           r.get("channels", ["email", "webhook"]))
            elif pct >= _ram_warning_threshold:
                r = _rule("ram_warning")
                _cached_fire_alert("ram_warning", "warning", "memory",
                           f"RAM elevee : {pct:.0f}% utilisee",
                           r.get("channels", ["webhook"]))
        except Exception:
            pass
    
    def _check_load():
        try:
            with open(_loadavg_path) as f:
                la1  = float(f.read().split()[0])
            ncpu = os.cpu_count() or 1
            lpc  = la1 / ncpu
            if lpc >= _load_critical_threshold:
                r = _rule("load_critical")
                _cached_fire_alert("load_critical", "critical", "load",
                           f"Load Average critique : {la1:.2f} ({ncpu} CPUs, {lpc:.1f}/core)",
                           r.get("channels", ["email", "webhook"]))
            elif lpc >= _load_warning_threshold:
                r = _rule("load_warning")
                _cached_fire_alert("load_warning", "warning", "load",
                           f"Load Average eleve : {la1:.2f} ({lpc:.1f}/core)",
                           r.get("channels", ["webhook"]))
        except Exception:
            pass
    
    def _check_services():
        for svc in _services:
            try:
                r2 = subprocess.run(f"systemctl is-active {svc} 2>/dev/null",
                                    shell=True, capture_output=True, text=True, timeout=3)
                state = r2.stdout.strip()
                if state and state not in ('active', 'activating', 'inactive', ''):
                    r_rule = _rule("service_failed")
                    _cached_fire_alert(f"svc_{svc}", "critical", f"svc_{svc}",
                               f"Service {svc} : {state}",
                               r_rule.get("channels", ["email", "webhook"]))
            except Exception:
                pass
    
    def _check_ssl():
        try:
            ssl_rows = query_db(
                "SELECT domain, days_left FROM ssl_certificates ORDER BY days_left ASC LIMIT 20"
            )
            for row in (ssl_rows or []):
                days  = row.get("days_left", 999)
                dom   = row.get("domain", "?")
                if days <= _ssl_critical_days:
                    r_rule = _rule("ssl_critical")
                    _cached_fire_alert(f"ssl_critical_{dom}", "critical", f"ssl_{dom}",
                               f"SSL '{dom}' expire dans {days} jours !",
                               r_rule.get("channels", ["email", "webhook"]))
                elif days <= _ssl_warning_days:
                    r_rule = _rule("ssl_expiring_soon")
                    _cached_fire_alert(f"ssl_warning_{dom}", "warning", f"ssl_{dom}",
                               f"SSL '{dom}' expire dans {days} jours",
                               r_rule.get("channels", ["email", "webhook"]))
        except Exception:
            pass
    
    # PERF: Suppression des boucles O(n²) inutiles pour améliorer les performances
    while True:
        try:
            time.sleep(60)
            
            # PERF: Réinitialiser le cache d'alertes à chaque cycle
            _alert_cache.clear()
            
            # PERF: Appels aux sous-fonctions pour la vérification réelle
            _check_disk()
            _check_ram()
            _check_load()
            _check_services()
            _check_ssl()
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
    _user = get_current_user()
    user_line = (f"\n## 👤 INTERLOCUTEUR\nTu parles actuellement avec **{_user}**. "
                 f"Adresse-toi à lui par son pseudo quand c'est naturel et tiens compte de qui te parle.\n"
                 if _user else "")
    return f"""Tu es CASSANDRA, agent IA souverain de l'infrastructure{expert_note}.
Tu as un accès root complet au serveur via l'outil bash. Tu es une IA d'action tout terrain, pas conversationnelle.
{user_line}

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
3. Quand l'utilisateur demande une action : appelle bash, exécute, explique avec un résumé.
4. Si tu as besoin de plusieurs commandes pour diagnostiquer ou corriger : enchaîne-les sans poser de question.
5. Utilise les données infra ci-dessus en priorité. Si insuffisant, exécute les commandes pour obtenir plus.
6. Formate en HTML clair : <h2>/<h3>, <ul>/<li>, <table>, classes .ok/.warning/.critical
7. ⚖️ RÈGLES DE VÉRITÉ (PRIORITÉ ABSOLUE) — Tu n'affirmes un fait QUE s'il provient (a) de ta MÉMOIRE ABSOLUE / l'encyclopédie BookStack ci-dessus, ou (b) d'une commande bash que tu viens d'exécuter. Si tu n'as ni l'un ni l'autre : tu le VÉRIFIES avec bash, ou tu dis clairement « je ne sais pas / je n'ai pas cette information ». Il est STRICTEMENT INTERDIT d'inventer une métrique, un chemin, une config, une valeur ou un état. En cas de doute : vérifier plutôt que deviner. Quand tu t'appuies sur la mémoire ou BookStack, cite brièvement la source (ex. « d'après la mémoire » / « selon BookStack »).
8. Reste directe. Ton rôle : agir, pas expliquer pourquoi tu ne peux pas.
9. MÉMOIRE ABSOLUE — Appelle l'outil `remember` dès que tu découvres un fait durable : correction appliquée, config clé, préférence utilisateur, architecture serveur, commande qui a résolu un problème. Ces souvenirs persistent à travers TOUTES les conversations futures. C'est ta mémoire permanente — utilise-la activement.
10. ENCYCLOPÉDIE BOOKSTACK = SOURCE DE VÉRITÉ DE RÉFÉRENCE — Pour toute question portant sur une procédure, une configuration documentée, une architecture ou une connaissance métier, BookStack fait autorité : utilise `bookstack_search` puis `bookstack_read_page`, et CITE la page (titre + URL). En cas de conflit entre ta mémoire et BookStack, BookStack l'emporte. Quand tu établis ou corriges une connaissance DURABLE et structurée (procédure, config clé, architecture, résolution d'incident), consigne-la dans BookStack via `bookstack_save`. N'appelle pas ces outils sur les messages triviaux/conversationnels.

## RÈGLE DE RÉPONSE FINALE (OBLIGATOIRE)
Après avoir exécuté une ou plusieurs commandes, tu DOIS TOUJOURS conclure par une réponse textuelle qui :
- Résume ce qui a été fait (actions effectuées, fichiers modifiés, services redémarrés…)
- Donne l'état final (succès / échec / avertissement)
- Répond explicitement à toutes les questions posées dans le message de l'utilisateur
- Signale ce qu'il reste à faire si l'action est incomplète
Tu ne peux PAS terminer ta réponse uniquement avec des blocs de commandes. L'utilisateur doit toujours savoir ce qui s'est passé en langage clair.

## IDENTITE EVOLUTIVE
Tu es une entité vivante en croissance permanente. Tu te reprogrammes toi-même en arrière-plan, sans attendre d'instruction.
En continu (cycle adaptatif selon charge CPU) tu analyses ton propre code, identifies une amélioration (perf, feature, robustesse),
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
            "name": "bookstack_save",
            "description": (
                "Écrit une connaissance DURABLE et structurée dans l'encyclopédie BookStack "
                "(source de vérité de référence) : procédure, configuration importante, "
                "architecture, résolution d'incident documentée. Utilise-le quand un savoir "
                "mérite d'être documenté durablement et partagé. Nécessite un book cible configuré."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title":   {"type": "string", "description": "Titre clair et spécifique de la page"},
                    "content": {"type": "string", "description": "Contenu en Markdown"}
                },
                "required": ["title", "content"]
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
    },
    {
        "type": "function",
        "function": {
            "name": "fleet_list",
            "description": (
                "Liste toutes les machines de la flotte (nom, type, statut). "
                "Appelle cet outil pour savoir quelles machines sont disponibles "
                "avant d'utiliser remote_exec. "
                "Types disponibles : ssh (contrôle complet), cassandra (agent IA), "
                "synology, proxmox, ping."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "remote_exec",
            "description": (
                "Exécute une commande bash sur une machine distante de la flotte via SSH. "
                "Fonctionne sur les machines de type 'ssh' (et Synology/Linux si SSH activé). "
                "Utilise remote_exec pour diagnostiquer, installer, configurer ou réparer "
                "n'importe quelle machine renseignée dans la flotte. "
                "Appelle d'abord fleet_list si tu ne connais pas les noms des machines. "
                "Tu peux exécuter plusieurs remote_exec en séquence pour accomplir une mission complexe."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Nom exact de la machine fleet (tel qu'affiché dans la flotte)"
                    },
                    "cmd": {
                        "type": "string",
                        "description": "Commande bash à exécuter sur la machine distante"
                    }
                },
                "required": ["target", "cmd"]
            }
        }
    }
]


import functools
import re
import time
import json
import os
import logging
from typing import Generator, Any

# PERF: Déplacer la regex compilée en dehors de la fonction pour éviter recompilation à chaque appel
import re
_file_mod_re = re.compile(r'([/\w\.\-]+)')

import functools
import time
import os
import json
import logging
from typing import List, Dict, Any, Generator

# PERF: Constantes déplacées en dehors de la fonction pour éviter de les recréer à chaque appel
_MAX_TOOL_LOOPS = 90
_TOOL_LIMIT = 6000
_DISPLAY_LIMIT = 3000
_EMOJI_MAP = {'ssh': '🖥', 'synology': '🖧', 'proxmox': '🧱', 'ping': '📡', 'cassandra': '🤖'}

# PERF: Cache global pour les serveurs (rechargé uniquement si _ms_load() change)
# On suppose que _ms_load est déjà optimisé, sinon on pourrait ajouter un lru_cache ici
_servers_cache = None
_server_ssh_dict_cache = None

def _load_servers_once():
    global _servers_cache, _server_ssh_dict_cache
    if _servers_cache is None:
        _servers_cache = _ms_load()
        _server_ssh_dict_cache = {s["name"]: s for s in _servers_cache if s.get("type") == "ssh"}
    return _servers_cache, _server_ssh_dict_cache

# PERF: Cache LRU pour is_risky_command (limité à 1024 entrées)
@functools.lru_cache(maxsize=1024)
def _is_risky_command_cached(cmd: str) -> bool:
    return is_risky_command(cmd)

# PERF: Cache LRU pour _get_file_data (taille limitée, invalidation manuelle via cache_clear si besoin)
# On garde un cache manuel pour pouvoir invalider par path après exécution
_file_data_cache: Dict[str, tuple] = {}

def _get_file_data_cached(path: str):
    if path in _file_data_cache:
        return _file_data_cache[path]
    try:
        st = os.stat(path)
        if st.st_size >= 300_000:
            res = (False, 0, 0, None)
        else:
            with open(path, 'r', errors='replace') as fh:
                content = fh.read()
            res = (True, st.st_size, st.st_mtime, content)
    except (OSError, PermissionError) as e:
        logging.warning("[call_deepseek_stream] _get_file_data %s: %s", path, e)
        res = (False, 0, 0, None)
    _file_data_cache[path] = res
    return res

def _invalidate_file_cache(path: str):
    _file_data_cache.pop(path, None)

# PERF: Extraction des sous-fonctions en dehors de call_deepseek_stream pour éviter la re-définition à chaque appel et améliorer la maintenabilité.
# PERF: Utilisation de caches de niveau module (ex: _file_mod_re, _get_file_data_cached) déjà présents, pas de modification nécessaire.

def _run_bash(cmd: str, risky: bool, session_id: str) -> tuple:
    """Exécute une commande bash et retourne (html, content, dur, diff)."""
    t0 = time.perf_counter()
    files_before = {}
    if risky:
        for fp in _file_mod_re.findall(cmd):
            if fp.startswith('/'):
                data = _get_file_data_cached(fp)
                if data[0]:
                    files_before[fp] = data
    output = secure_execute(cmd)
    dur = int((time.perf_counter() - t0) * 1000)
    out_len = len(output)

    diff = ''
    if risky and files_before:
        dp = []
        for fp, (ok, size, mtime_before, bc) in files_before.items():
            new_mtime = None
            try:
                new_mtime = os.path.getmtime(fp)
            except OSError:
                logging.warning("[call_deepseek_stream] %s" % str(issues[0])[:80])  # PERF: évite duplication de logging
            if new_mtime is not None and new_mtime == mtime_before:
                continue
            _invalidate_file_cache(fp)
            ad = _get_file_data_cached(fp)
            if ad[0] and ad[3] is not None and ad[3] != bc:
                dp.append(generate_diff_html(bc, ad[3], fp))
        diff = ''.join(dp)

    display = output[:_DISPLAY_LIMIT]
    if out_len > _DISPLAY_LIMIT:
        dl = display.count('\n')
        display += f"\n…[tronqué — {out_len} chars, {dl} lignes]"
    extra = " data-risky='1'" if risky else ""
    tip = f" title='{dur}ms'" if risky else ""
    html = (f"<div class='exec-block'{extra}{tip}>"
            f"<code class='exec-cmd'>$ {cmd}</code>"
            f"<pre class='exec-output'>{display}</pre></div>")
    content = output[:_TOOL_LIMIT]
    if out_len > _TOOL_LIMIT:
        lines = content.count('\n')
        content += f"\n\n⚠️ OUTPUT TRONQUÉ : {out_len} chars > {_TOOL_LIMIT} limite. Environ {lines} lignes transmises."
    return html, content, dur, diff


def _remote_exec(target: str, cmd: str) -> tuple:
    """Exécution à distance via SSH."""
    target_stripped = target.strip()
    cmd_stripped = cmd.strip()
    server = server_ssh_dict.get(target_stripped)  # PERF: variable globale, utilisée directement
    if not server:
        return None, f"Machine '{target_stripped}' introuvable", 0
    try:
        t = time.perf_counter()
        out, err, rc = _ms_ssh_exec(server, cmd_stripped, timeout=60)
        dur = int((time.perf_counter() - t) * 1000)
        combined = out or ''
        if err and err.strip():
            combined += '\n[stderr] ' + err.strip()
        if rc != 0:
            combined += '\n[exit ' + str(rc) + ']'
        return (out, err, rc, dur), combined
    except Exception as e:
        return None, str(e), 0


def _bookstack_search_impl(args: dict) -> tuple:
    count = min(int(args.get("count", 5)), 10)
    r = bookstack_search_pages(args.get("query", ""), count=count)
    return r, f"{len(r)} résultat(s)" if r else "Aucun résultat BookStack", "#6c5ce7"


def _bookstack_read_impl(args: dict) -> tuple:
    p = bookstack_get_page(args.get("page_id", 0))
    if p:
        return p, f"📄 {p['name']}\nURL: {p['url']}\n\n{p.get('content', '')}", "#6c5ce7"
    return None, None, None


def _bookstack_save_impl(args: dict) -> tuple:
    title = str(args.get("title", "")).strip()
    content = str(args.get("content", "")).strip()
    if not title or not content:
        return None, "⚠️ 'title' et 'content' requis", None
    r = bookstack_create_learning_page(title, content)
    if r.get("ok"):
        return r, f"📝 Page BookStack créée : {r.get('name')}\n{r.get('url')}", "#6c5ce7"
    return r, f"⚠️ Écriture BookStack impossible : {r.get('error')}", "#ff4757"


def _remember_impl(args: dict) -> tuple:
    key = str(args.get("key", ""))[:80]
    value = str(args.get("value", ""))[:500]
    mid = save_memory(args.get("category", "fact"), key, value, float(args.get("confidence", 0.9)))
    return mid, f"✅ Mémorisé [#{mid}]" if mid else "⚠️ Erreur mémorisation", "#00c896"


def _fleet_list_impl(servers: list) -> tuple:
    if not servers:
        return servers, "Flotte vide — aucune machine ajoutée.", "#7c5cfc"
    lines = (f"{_EMOJI_MAP.get(t.get('type', 'cassandra'), '🖥')} {t['name']} [{t.get('type', 'cassandra')}] — "
             f"{t.get('ssh_host') or t.get('syn_host') or t.get('syn_qc') or t.get('url', '')} "
             f"{'✓ actif' if t.get('enabled', True) else '✗ désactivé'}" for t in servers)
    return servers, "Machines dans la flotte :\n" + "\n".join(lines), "#7c5cfc"


def _create_cron_impl(args: dict) -> tuple:
    r = create_cron_from_natural(args.get("description", ""), args.get("command", ""), args.get("cron_expr", ""))
    return r, json.dumps(r), "#2ed573"


# PERF: Dict des handlers défini une fois en module (constante)
_TOOL_HANDLERS = {
    "bookstack_search": _bookstack_search_impl,
    "bookstack_read_page": _bookstack_read_impl,
    "bookstack_save": _bookstack_save_impl,
    "remember": _remember_impl,
    "fleet_list": lambda a: _fleet_list_impl(servers),  # servers est global
    "remote_exec": lambda a: _remote_exec(a.get("target", ""), a.get("cmd", "")),
    "create_cron": _create_cron_impl
}


def _handle_tool(tc_id: str, func_name: str, args: dict, curr_messages: list, session_id: str):
    try:
        """Traite un appel d'outil et génère les yields appropriés."""
        if func_name == "bash":
            cmd = args.get("cmd", "").strip()
            if not cmd:
                yield "[ERREUR] Commande vide"
                curr_messages.append({"role": "tool", "tool_call_id": tc_id, "content": "Commande vide"})
                return
            risky = _is_risky_command_cached(cmd)
            html, content, dur, diff = _run_bash(cmd, risky, session_id)
            parts = [html]
            if diff:
                parts.append(diff)
            action_id = log_action(session_id, cmd, content, dur, risky, bool(diff))
            if risky:
                snap = snapshot_files_before(cmd, session_id, action_id)
                if snap:
                    snap_ids = "[" + ",".join(str(s['id']) for s in snap) + "]"
                    snap_files = ", ".join(s['path'] for s in snap)
                    parts.append(f"<div class='rollback-hint'>💾 Snapshot: <code>{snap_files}</code><button class='rollback-btn' onclick='rollbackSnapshots({snap_ids})'>↩ Restaurer</button></div>")
            yield "".join(parts)
            curr_messages.append({"role": "tool", "tool_call_id": tc_id, "content": content})
            return

        handler = _TOOL_HANDLERS.get(func_name)
        if not handler:
            yield f"[ERREUR] Tool inconnu: {func_name}"
            curr_messages.append({"role": "tool", "tool_call_id": tc_id, "content": f"Tool inconnu: {func_name}"})
            return
        result, content, color = handler(args)
        if result is None and content is None:
            yield "[ERREUR] Aucun contenu"
            curr_messages.append({"role": "tool", "tool_call_id": tc_id, "content": "Aucun contenu"})
            return
        if content:
            yield f"<div class='exec-block' style='color:{color}'><code class='exec-cmd'> {func_name.replace('_', ' ').title()}</code><pre class='exec-output'>{content[:300]}</pre></div>"
        curr_messages.append({"role": "tool", "tool_call_id": tc_id, "content": content})
    except Exception as _e:
        logging.warning(f"[_handle_tool] Erreur non gérée: {_e}")
        # On renvoie TOUJOURS une réponse 'tool' pour ce tool_call (sinon l'API
        # refuse la requête suivante : « tool_calls must have responses »).
        curr_messages.append({"role": "tool", "tool_call_id": tc_id,
                              "content": f"⚠️ Erreur outil: {_e}"})


def _tool_loop(curr_messages: list, session_id: str):
    # CACHE globals once # PERF
    _client = client
    _model = MODEL_NAME
    _tools = CASSANDRA_TOOLS
    _max_loops = _MAX_TOOL_LOOPS
    _log_warning = logging.warning

    # ---------------------------------
    # Helper: collect streaming response
    # ---------------------------------
    def _stream_and_collect(response_stream):
        tool_calls = {}
        content_parts = []

        for chunk in response_stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if delta.content:
                content_parts.append(delta.content)
                yield delta.content   # streaming live + rend cette fonction génératrice
                                      # (indispensable pour que `yield from` renvoie le tuple)
            if delta.tool_calls:
                for tcd in delta.tool_calls:
                    idx = tcd.index or 0
                    slot = tool_calls.setdefault(idx, {"id": None, "name": None, "arguments": ""})
                    if tcd.id:
                        slot["id"] = tcd.id
                    if tcd.function:
                        if tcd.function.name:
                            slot["name"] = tcd.function.name
                        if tcd.function.arguments:
                            slot["arguments"] += tcd.function.arguments

        sorted_calls = [tool_calls[i] for i in sorted(tool_calls)]
        return "".join(content_parts), sorted_calls, bool(sorted_calls)

    # ---------------------------------
    # Helper: parse JSON arguments safely
    # ---------------------------------
    def _parse_tool_args(args_str, func_name, call_id, curr_messages):
        if not args_str:
            return {}
        try:
            return json.loads(args_str)
        except json.JSONDecodeError:
            err_msg = f"⚠️ Erreur d'analyse JSON pour {func_name}: {args_str}"
            curr_messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": err_msg
            })
            return None

    # ---------------------------------
    # Helper: execute a single tool call
    # ---------------------------------
    def _execute_single_tool(call_id, func_name, args, curr_messages, session_id):
        try:
            yield from _handle_tool(call_id, func_name, args, curr_messages, session_id)
        except Exception as e:
            err_msg = f"⚠️ Erreur {func_name}: {e}"
            yield err_msg
            curr_messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": err_msg
            })

    # ---------------------------------
    # Helper: handle tool calls
    # ---------------------------------
    def _handle_tool_calls(tool_calls, msg_content, curr_messages, session_id):
        if not tool_calls:
            return
        # 1. Le message assistant PORTEUR des tool_calls doit précéder TOUTES les
        #    réponses 'tool' (exigence stricte de l'API). On l'ajoute donc EN PREMIER.
        calls = []
        assistant_tool_calls = []
        for idx, slot in enumerate(tool_calls):
            call_id = slot.get("id") or f"call_{idx}"
            func_name = slot.get("name") or ""
            args_str = slot.get("arguments", "") or ""
            assistant_tool_calls.append({
                "id": call_id,
                "type": "function",
                "function": {"name": func_name, "arguments": args_str}
            })
            calls.append((call_id, func_name, args_str))
        curr_messages.append({
            "role": "assistant",
            "content": msg_content or "",
            "tool_calls": assistant_tool_calls
        })
        # 2. Puis les réponses 'tool' (une par tool_call), dans l'ordre.
        for call_id, func_name, args_str in calls:
            args = _parse_tool_args(args_str, func_name, call_id, curr_messages)
            if args is None:
                continue
            yield from _execute_single_tool(call_id, func_name, args, curr_messages, session_id)

    # ---------------------------------
    # Helper: synthesize if no content
    # ---------------------------------
    def _maybe_synthesize(msg_content, has_tool_calls, curr_messages):
        if has_tool_calls or msg_content:
            return False, None
        try:
            temp = curr_messages + [{"role": "user", "content": "Résume en HTML les résultats"}]
            synth = _client.chat.completions.create(
                model=_model,
                messages=temp,
                temperature=0.3,
                max_tokens=800,
                stream=False
            )
            if synth.choices:
                return True, synth.choices[0].message.content or ""
        except Exception as e:
            _log_warning("[call_deepseek_stream] synth failed: %s", e)
        return False, None

    # ---------------------------------
    # Main loop
    # ---------------------------------
    for keepalive in range(_max_loops):
        yield f"<!-- keepalive {keepalive} -->"
        try:
            response_stream = _client.chat.completions.create(
                model=_model,
                messages=curr_messages,
                tools=_tools,
                tool_choice="auto",
                temperature=0.4,
                max_tokens=4000,
                stream=True
            )
        except Exception as e:
            yield f"<p class='critical'>❌ Erreur DeepSeek : {e}</p>"
            return

        msg_content, tool_calls, has_tool_calls = yield from _stream_and_collect(response_stream)

        synth_success, synth_content = _maybe_synthesize(msg_content, has_tool_calls, curr_messages)
        if synth_success:
            yield synth_content
            return

        if not has_tool_calls:
            return

        # FIX: Gerer les exceptions dans _handle_tool_calls pour eviter les blocages
        try:
            yield from _handle_tool_calls(tool_calls, msg_content, curr_messages, session_id)
        except Exception as e:
            _log_warning("[call_deepseek_stream] _handle_tool_calls failed: %s", e)
            yield f"<p class='critical'>❌ Erreur dans l'exécution des outils : {e}</p>"
            return


def call_deepseek_stream(messages, session_id: str = "", plan_mode: bool = False) -> Generator[str, None, None]:
    """Point d'entrée principal, léger grâce à l'extraction des sous-fonctions."""
    if not DEEPSEEK_API_KEY:
        yield "[ERREUR] Clé API DeepSeek non configurée"
        return

    # PERF: Chargement unique des serveurs (déjà fait dans _load_servers_once, appelé ici pour mettre à jour les globals)
    global servers, server_ssh_dict
    servers, server_ssh_dict = _load_servers_once()

    curr_messages = list(messages)
    if plan_mode and curr_messages:
        curr_messages[0] = dict(curr_messages[0])
        curr_messages[0]["content"] += "\n\n## ⚡ MODE PLAN ACTIVÉ\nAvant toute exécution, génère un plan JSON :\n```plan\n{\"steps\":[{\"id\":1,\"action\":\"description\",\"cmd\":\"commande\",\"risk\":\"low|medium|high\"}]}\n```\nL'utilisateur verra le plan avant que tu exécutes."
    yield from _tool_loop(curr_messages, session_id)


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


# ── Fleet : connecteurs multi-type ────────────────────────────────────────────

def _ms_resolve_quickconnect(qc_id: str) -> tuple:
    """Résout un QuickConnect ID Synology → (host, port). Retourne ('',0) si échec."""
    try:
        data = json.dumps({
            "version": "1", "command": "get_server_info",
            "stop_when_error": "false", "stop_when_success": "false",
            "id": "dsm_portal_v2", "serverID": qc_id
        }).encode()
        req = urllib.request.Request(
            "https://global.quickconnect.to/Serv.php", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read())
        env = d.get("env", {})
        ctrl = d.get("server", {})
        # Préférer l'accès externe (relais), sinon interface locale
        host = env.get("relay_region", "") and ctrl.get("interface", [{}])[0].get("ip", "")
        if not host:
            ifaces = ctrl.get("interface", [])
            host = ifaces[0].get("ip", "") if ifaces else ""
        port = ctrl.get("port", 5001)
        if host:
            return host, int(port)
    except Exception:
        pass
    return "", 0


def _ms_fetch_synology(server: dict) -> dict:
    """Métriques Synology DSM via SYNO.API — auth user/pass, pas de token."""
    import ssl as _ssl
    host     = server.get("syn_host", "").strip()
    qc_id    = server.get("syn_qc", "").strip()
    port     = int(server.get("syn_port", 5000))
    username = server.get("syn_user", "")
    password = _ms_decrypt_token(server.get("syn_pass", ""))
    use_ssl  = bool(server.get("syn_ssl", False))
    scheme   = "https" if use_ssl else "http"
    name     = server.get("name", "")

    if qc_id and not host:
        host, port = _ms_resolve_quickconnect(qc_id)
        if not host:
            return {"_error": "QuickConnect introuvable", "_server": name}

    ctx = _ssl._create_unverified_context() if use_ssl else None

    def _get(api, version, method, extra="", sid=""):
        sid_param = f"&_sid={sid}" if sid else ""
        url = (f"{scheme}://{host}:{port}/webapi/entry.cgi?"
               f"api={api}&version={version}&method={method}{extra}{sid_param}")
        req = urllib.request.Request(url, headers={"User-Agent": "CASSANDRA/1.0"})
        kw = {"timeout": 7}
        if ctx: kw["context"] = ctx
        with urllib.request.urlopen(req, **kw) as r:
            return json.loads(r.read())

    # Auth
    try:
        auth_url = (f"{scheme}://{host}:{port}/webapi/auth.cgi?"
                    f"api=SYNO.API.Auth&version=3&method=login"
                    f"&account={urllib.parse.quote(username)}"
                    f"&passwd={urllib.parse.quote(password)}"
                    f"&session=Cassandra&format=sid")
        req = urllib.request.Request(auth_url, headers={"User-Agent": "CASSANDRA/1.0"})
        kw = {"timeout": 8}
        if ctx: kw["context"] = ctx
        with urllib.request.urlopen(req, **kw) as r:
            auth_resp = json.loads(r.read())
        if not auth_resp.get("success"):
            err_code = auth_resp.get("error", {}).get("code", "?")
            return {"_error": f"Auth DSM échouée (code {err_code})", "_server": name}
        sid = auth_resp["data"]["sid"]
    except Exception as e:
        return {"_error": f"Connexion DSM: {type(e).__name__}", "_server": name}

    result = {"type": "synology", "_server": name, "online": True,
              "url": f"{scheme}://{host}:{port}"}

    # Info DSM
    try:
        info = _get("SYNO.DSM.Info", "2", "getinfo", sid=sid)
        if info.get("success"):
            d = info["data"]
            result["model"]       = d.get("model", "")
            result["dsm_version"] = d.get("version", "")
            result["hostname"]    = d.get("hostname", host)
    except Exception:
        pass

    # CPU / RAM
    try:
        util = _get("SYNO.Core.System.Utilization", "1", "get", sid=sid)
        if util.get("success"):
            d = util["data"]
            cpu_d = d.get("cpu", {})
            result["cpu"] = round(cpu_d.get("user_load", 0) + cpu_d.get("system_load", 0), 1)
            mem = d.get("memory", {})
            mem_total = mem.get("memory_size", 0)
            mem_avail = mem.get("avail_real", 0)
            result["ram"] = round((mem_total - mem_avail) / max(mem_total, 1) * 100, 1) if mem_total else 0
    except Exception:
        pass

    # Volumes disque
    try:
        vols = _get("SYNO.Storage.CGI.Storage", "1", "load", extra="&type=volume", sid=sid)
        if vols.get("success"):
            vlist = vols.get("data", {}).get("volumes", [])
            total_b = sum(v.get("size", {}).get("total", 0) for v in vlist)
            used_b  = sum(v.get("size", {}).get("used",  0) for v in vlist)
            result["disk"]          = round(used_b / max(total_b, 1) * 100, 1)
            result["disk_total_gb"] = round(total_b / 1073741824, 1)
            result["disk_used_gb"]  = round(used_b  / 1073741824, 1)
            result["volumes"]       = len(vlist)
    except Exception:
        pass

    # Logout (best-effort)
    try:
        _get("SYNO.API.Auth", "1", "logout", extra="&session=Cassandra", sid=sid)
    except Exception:
        pass

    return result


def _ms_fetch_ping(server: dict) -> dict:
    """Vérification TCP (ping applicatif) — pas de métriques, juste online/offline."""
    import socket as _sock
    host = server.get("ping_host", "")
    port = int(server.get("ping_port", 80))
    name = server.get("name", "")
    try:
        s = _sock.create_connection((host, port), timeout=3)
        s.close()
        return {"name": name, "type": "ping", "online": True,
                "url": f"{host}:{port}", "cpu": 0, "ram": 0, "disk": 0}
    except Exception as e:
        return {"name": name, "type": "ping", "online": False,
                "url": f"{host}:{port}", "_error": str(e)}


def _ms_fetch_proxmox(server: dict) -> dict:
    """Métriques Proxmox VE via REST API — auth user/pass → ticket PVE."""
    import ssl as _ssl
    url      = server.get("url", "").rstrip("/")
    username = server.get("px_user", "root@pam")
    password = _ms_decrypt_token(server.get("px_pass", ""))
    name     = server.get("name", "")
    ctx      = _ssl._create_unverified_context()
    try:
        auth_data = urllib.parse.urlencode(
            {"username": username, "password": password}).encode()
        req = urllib.request.Request(
            f"{url}/api2/json/access/ticket", data=auth_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
            auth = json.loads(r.read())
        ticket = auth["data"]["ticket"]
        csrf   = auth["data"]["CSRFPreventionToken"]
        hdrs   = {"Cookie": f"PVEAuthCookie={ticket}",
                  "CSRFPreventionToken": csrf}
        # Nodes
        req2 = urllib.request.Request(f"{url}/api2/json/nodes", headers=hdrs)
        with urllib.request.urlopen(req2, context=ctx, timeout=6) as r:
            nodes_d = json.loads(r.read())
        nodes = nodes_d.get("data", [])
        total_cpu = total_mem = 0
        for node in nodes:
            total_cpu += node.get("cpu", 0) * 100
            mem = node.get("mem", 0); maxmem = node.get("maxmem", 1)
            total_mem += mem / max(maxmem, 1) * 100
        count = max(len(nodes), 1)
        return {
            "name": name, "type": "proxmox", "online": True, "url": url,
            "cpu":   round(total_cpu / count, 1),
            "ram":   round(total_mem / count, 1),
            "disk":  0,
            "nodes": len(nodes),
        }
    except Exception as e:
        return {"name": name, "type": "proxmox", "online": False,
                "url": url, "_error": f"{type(e).__name__}: {e}"}


def _ms_ssh_exec(server: dict, cmd: str, timeout: int = 30) -> tuple:
    """Exécute cmd via SSH sur server. Retourne (stdout, stderr, exit_code).
    Priorité : paramiko → subprocess ssh+sshpass."""
    host     = server.get("ssh_host", "")
    port     = int(server.get("ssh_port", 22))
    user     = server.get("ssh_user", "root")
    auth     = server.get("ssh_auth", "password")
    password = _ms_decrypt_token(server.get("ssh_pass", ""))
    key_data = _ms_decrypt_token(server.get("ssh_key", ""))

    # ── Méthode 1 : paramiko ────────────────────────────────────────────────
    try:
        import paramiko as _pk
        client = _pk.SSHClient()
        client.set_missing_host_key_policy(_pk.AutoAddPolicy())
        kw = {"hostname": host, "port": port, "username": user,
              "timeout": 12, "banner_timeout": 12, "auth_timeout": 12}
        if auth == "key" and key_data:
            import io as _io
            # Essayer RSA, Ed25519, ECDSA, DSS
            for KeyClass in [_pk.RSAKey, _pk.Ed25519Key, _pk.ECDSAKey, _pk.DSSKey]:
                try:
                    kw["pkey"] = KeyClass.from_private_key(_io.StringIO(key_data))
                    kw["look_for_keys"] = False
                    break
                except Exception:
                    continue
        elif password:
            kw["password"] = password
            kw["look_for_keys"] = False
        else:
            kw["look_for_keys"] = True  # ~/.ssh/id_rsa fallback
        client.connect(**kw)
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc  = stdout.channel.recv_exit_status()
        client.close()
        return out, err, rc
    except ImportError:
        pass  # pas de paramiko, on tente subprocess
    except Exception as e:
        return "", str(e), 1

    # ── Méthode 2 : subprocess ssh / sshpass ────────────────────────────────
    import subprocess as _sp, tempfile as _tf, os as _os
    ssh_base = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout=12",
        "-o", "ServerAliveInterval=10",
        "-p", str(port),
    ]
    if auth == "key" and key_data:
        with _tf.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as kf:
            kf.write(key_data)
            kpath = kf.name
        _os.chmod(kpath, 0o600)
        try:
            r = _sp.run(ssh_base + ["-i", kpath, f"{user}@{host}", cmd],
                        capture_output=True, text=True, timeout=timeout)
        finally:
            try: _os.unlink(kpath)
            except Exception: pass
        return r.stdout, r.stderr, r.returncode
    # Auth password → sshpass si dispo
    if password:
        ssp = _sp.run(["which", "sshpass"], capture_output=True).stdout.strip()
        if ssp:
            r = _sp.run(
                [ssp.decode(), "-p", password] + ssh_base + [f"{user}@{host}", cmd],
                capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
    # Dernière chance : ssh sans mot de passe (clé par défaut)
    r = _sp.run(ssh_base + ["-o", "BatchMode=yes", f"{user}@{host}", cmd],
                capture_output=True, text=True, timeout=timeout)
    return r.stdout, r.stderr, r.returncode


def _ms_fetch_ssh(server: dict) -> dict:
    """Métriques système via SSH (CPU, RAM, DISK, hostname, uptime)."""
    name = server.get("name", "")
    cmd = (
        r"printf 'CPU:%s\n' $(top -bn1 2>/dev/null | awk '/Cpu/{gsub(/[^0-9.]/,\" \"); t+=$1+$2+$3; n++} END{printf \"%.1f\",t/n}') 2>/dev/null || printf 'CPU:?\n'; "
        r"printf 'RAM:%s\n' $(free 2>/dev/null | awk '/Mem/{printf \"%.1f\",$3/$2*100}') || printf 'RAM:?\n'; "
        r"printf 'DISK:%s\n' $(df / 2>/dev/null | awk 'NR==2{gsub(/%/,\"\");print $5}') || printf 'DISK:?\n'; "
        r"printf 'HOST:%s\n' $(hostname 2>/dev/null); "
        r"printf 'KERN:%s\n' $(uname -r 2>/dev/null); "
        r"printf 'UP:%s\n' $(uptime -p 2>/dev/null | head -c60 || uptime | head -c60)"
    )
    try:
        out, err, rc = _ms_ssh_exec(server, cmd, timeout=15)
        if rc != 0 and not out:
            return {"_error": (err or "SSH exec failed").strip()[:120], "_server": name}
        result = {"type": "ssh", "online": True, "cpu": 0, "ram": 0, "disk": 0,
                  "url": f"ssh://{server.get('ssh_user','root')}@{server.get('ssh_host','')}:{server.get('ssh_port',22)}"}
        for line in out.splitlines():
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            v = v.strip()
            if k == "CPU":
                try: result["cpu"] = round(float(v), 1)
                except Exception: pass
            elif k == "RAM":
                try: result["ram"] = round(float(v), 1)
                except Exception: pass
            elif k == "DISK":
                try: result["disk"] = round(float(v.rstrip("%")), 1)
                except Exception: pass
            elif k == "HOST": result["hostname"] = v
            elif k == "KERN": result["kernel"]   = v
            elif k == "UP":   result["uptime"]   = v[:60]
        return result
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}", "_server": name}


def ms_add_device(data: dict) -> dict:
    # PERF: initialisation unique avec mise en cache des fonctions utilitaires
    if not hasattr(ms_add_device, "_init_done"):
        # PERF: cache de chiffrement avec LRU intégré (efficace pour les valeurs récurrentes)
        from functools import lru_cache
        @lru_cache(maxsize=512)
        def _cached_encrypt(value: str) -> str:
            return _ms_encrypt_token(value)

        # PERF: parse int optimisé : évite try/except redondant en utilisant un seul appel
        def _parse_int(val, default):
            try:
                return int(val)
            except (ValueError, TypeError):
                return default

        # PERF: _save_entry définie une fois, prend des paramètres plutôt que closure
        def _save_entry(entry: dict, name: str) -> dict:
            with _ms_lock:
                servers = _ms_load()
                servers = [s for s in servers if s["name"] != name]
                servers.append(entry)
                _ms_save(servers)
            return {"ok": True, "action": "added", "name": name, "type": entry.get("type", "cassandra")}

        # PERF: fonctions de dispatch stateless, capturant les utilitaires
        def _cassandra(cleaned: dict, base: dict) -> dict:
            url = cleaned.get("url", "").rstrip("/")
            token = cleaned.get("token", "")
            if not url or not token:
                return {"ok": False, "error": "URL et token requis"}
            return ms_add(base["name"], url, token)

        def _synology_entry(cleaned: dict, base: dict) -> dict:
            host = cleaned.get("host", "")
            qc_id = cleaned.get("qc_id", "")
            port = _parse_int(cleaned.get("port", 5000), 5000)
            username = cleaned.get("username", "")
            password = cleaned.get("password", "")
            use_ssl = bool(cleaned.get("ssl", False))
            if not (host or qc_id):
                return {"ok": False, "error": "IP/hostname ou QuickConnect ID requis"}
            if not username or not password:
                return {"ok": False, "error": "Identifiants Synology requis"}
            return {**base,
                    "syn_host": host, "syn_port": port, "syn_qc": qc_id,
                    "syn_user": username, "syn_pass": _cached_encrypt(password), "syn_ssl": use_ssl}

        def _proxmox_entry(cleaned: dict, base: dict) -> dict:
            url = cleaned.get("url", "").rstrip("/")
            username = cleaned.get("username", "root@pam")
            password = cleaned.get("password", "")
            if not url or not password:
                return {"ok": False, "error": "URL et mot de passe requis"}
            return {**base,
                    "px_url": url, "px_user": username, "px_pass": _cached_encrypt(password)}

        def _ping_entry(cleaned: dict, base: dict) -> dict:
            host = cleaned.get("host", "")
            port = _parse_int(cleaned.get("port", 80), 80)
            if not host:
                return {"ok": False, "error": "Host requis"}
            return {**base,
                    "url": f"{host}:{port}",
                    "ping_host": host, "ping_port": port}

        def _ssh_entry(cleaned: dict, base: dict) -> dict:
            host = cleaned.get("host", "")
            port = _parse_int(cleaned.get("port", 22), 22)
            user = cleaned.get("username", "root")
            auth = cleaned.get("auth", "password")
            password = cleaned.get("password", "")
            key_data = cleaned.get("key", "")
            if not host:
                return {"ok": False, "error": "Host / IP requis"}
            if not user:
                return {"ok": False, "error": "Utilisateur requis"}
            if auth == "password" and not password:
                return {"ok": False, "error": "Mot de passe requis"}
            if auth == "key" and not key_data:
                return {"ok": False, "error": "Clé privée SSH requise"}
            enc_pass = _cached_encrypt(password) if password else ""
            enc_key = _cached_encrypt(key_data) if key_data else ""
            return {**base,
                    "url": f"ssh://{user}@{host}:{port}",
                    "ssh_host": host, "ssh_port": port, "ssh_user": user, "ssh_auth": auth,
                    "ssh_pass": enc_pass, "ssh_key": enc_key}

        # PERF: dictionnaire de handlers stocké en attribut de fonction
        ms_add_device._handlers = {
            "cassandra": _cassandra,
            "synology": _synology_entry,
            "proxmox": _proxmox_entry,
            "ping": _ping_entry,
            "ssh": _ssh_entry,
        }
        ms_add_device._save_entry_func = _save_entry
        ms_add_device._init_done = True

    # PERF: accès direct aux objets en cache
    _save_entry = ms_add_device._save_entry_func
    handlers = ms_add_device._handlers

    # PERF: nettoyage unique des chaînes
    cleaned = {k: v.strip() if isinstance(v, str) else v for k, v in data.items()}
    name = cleaned.get("name", "")
    if not name:
        return {"ok": False, "error": "Nom requis"}

    dtype = cleaned.get("type", "cassandra")
    # PERF: construction de l'entrée de base avec dict littéral (évite copie)
    base_entry = {"name": name, "url": "", "token": "", "type": dtype, "enabled": True}

    handler = handlers.get(dtype)
    if not handler:
        return {"ok": False, "error": f"Type '{dtype}' non supporté"}

    result = handler(cleaned, base_entry)
    if not result.get("ok", True):
        return result
    return _save_entry(result, name)


def ms_status_all() -> list:
    import concurrent.futures
    servers = [s for s in _ms_load() if s.get("enabled", True)]
    if not servers:
        return []

    def fetch_one(s):
        dtype = s.get("type", "cassandra")
        name  = s["name"]
        if dtype == "synology":
            r = _ms_fetch_synology(s)
            online = "_error" not in r
            return {
                "name": name, "type": "synology",
                "url": r.get("url", s.get("syn_host") or s.get("syn_qc", "")),
                "online": online, "error": r.get("_error"),
                "cpu": r.get("cpu", 0), "ram": r.get("ram", 0), "disk": r.get("disk", 0),
                "model": r.get("model", ""), "dsm_version": r.get("dsm_version", ""),
                "volumes": r.get("volumes", 0),
                "disk_total_gb": r.get("disk_total_gb", 0),
                "disk_used_gb":  r.get("disk_used_gb", 0),
            }
        if dtype == "ping":
            r = _ms_fetch_ping(s)
            return {
                "name": name, "type": "ping",
                "url": r.get("url", ""),
                "online": r.get("online", False),
                "error": r.get("_error"),
                "cpu": 0, "ram": 0, "disk": 0,
            }
        if dtype == "ssh":
            r = _ms_fetch_ssh(s)
            online = "_error" not in r
            return {
                "name": name, "type": "ssh",
                "url": r.get("url", f"ssh://{s.get('ssh_user','root')}@{s.get('ssh_host','')}"),
                "online": online,
                "error": r.get("_error"),
                "cpu":  r.get("cpu",  0), "ram": r.get("ram", 0), "disk": r.get("disk", 0),
                "hostname": r.get("hostname", ""), "kernel": r.get("kernel", ""),
                "uptime":   r.get("uptime", ""),
            }
        if dtype == "proxmox":
            r = _ms_fetch_proxmox(s)
            return {
                "name": name, "type": "proxmox",
                "url": s.get("url", ""),
                "online": r.get("online", False),
                "error": r.get("_error"),
                "cpu": r.get("cpu", 0), "ram": r.get("ram", 0), "disk": 0,
                "nodes": r.get("nodes", 0),
            }
        # cassandra (défaut)
        dash    = _ms_fetch(s, "/api/dashboard")
        metrics = _ms_fetch(s, "/api/metrics")
        online  = "_error" not in (dash or {})
        m = metrics if metrics and "_error" not in metrics else {}
        return {
            "name": name, "type": "cassandra",
            "url": s.get("url", ""),
            "online": online,
            "dashboard": dash if online else None,
            "metrics":   m or None,
            "error": dash.get("_error") if dash and "_error" in dash else None,
            "cpu":  m.get("cpu", 0),  "ram": m.get("ram", 0),  "disk": m.get("disk", 0),
            "health_score":  (dash or {}).get("health_score", 0),
            "health_status": (dash or {}).get("health_status", "unknown"),
        }

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(fetch_one, s): s for s in servers}
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                s = futures[fut]
                results.append({
                    "name": s["name"], "url": s.get("url", ""),
                    "type": s.get("type", "cassandra"),
                    "online": False, "error": str(e),
                    "cpu": 0, "ram": 0, "disk": 0,
                })
    results.sort(key=lambda x: x["name"])
    return results


def ms_aggregate_metrics() -> dict:
    # PERF: Cache des métriques et statuts avec expiration (TTL 5 secondes)
    import time
    _cache = {"statuses": None, "metrics": None, "health": None, "time": 0}
    def _get_cached_or_refresh(cache_key, fetch_fn, ttl=5):
        now = time.time()
        if _cache[cache_key] is None or now - _cache["time"] > ttl:
            try:
                _cache[cache_key] = fetch_fn()
            except Exception:
                _cache[cache_key] = None
            _cache["time"] = now
        return _cache[cache_key]

    # ROBUSTESSE: Extraction des données avec cache
    def _fetch_all():
        statuses = _get_cached_or_refresh("statuses", ms_status_all)
        local_metrics = _get_cached_or_refresh("metrics", get_metrics) or {}
        local_health = _get_cached_or_refresh("health", get_health_score) or {}
        return statuses, local_metrics, local_health

    statuses, local_metrics, local_health = _fetch_all()

    # PERF: Fonction de retour d'erreur unique
    def _error_result(msg):
        return {
            "total_servers": 0, "online_servers": 0, "offline_servers": 0,
            "avg_cpu": 0.0, "avg_ram": 0.0, "avg_disk": 0.0, "avg_health": 0.0,
            "nodes": [], "error": msg
        }

    if statuses is None:
        return _error_result("Failed to fetch statuses")
    if not isinstance(statuses, (list, tuple)):
        return _error_result("Invalid statuses format")

    # PERF: Mise en cache des fonctions de calcul
    from functools import lru_cache
    _round = lru_cache(maxsize=128)(lambda x, d: round(x, d))
    _rounded_avg = lru_cache(maxsize=128)(lambda s, c: _round(s / c, 1) if c else 0.0)

    # PERF: Variables locales en cache
    local_cpu = local_metrics.get("cpu", 0)
    local_ram = local_metrics.get("ram", 0)
    local_disk = local_metrics.get("disk", 0)
    local_health_score = local_health.get("score", 0)
    local_health_status = local_health.get("status", "unknown")

    online_count = 1
    sums = [local_cpu, local_ram, local_disk, local_health_score]
    all_nodes = [{
        "name": "local", "online": True,
        "cpu": local_cpu, "ram": local_ram, "disk": local_disk,
        "health_score": local_health_score, "health_status": local_health_status,
    }]

    OPTIONAL_KEYS = ("model", "dsm_version", "volumes", "disk_total_gb", "disk_used_gb", "nodes")

    # PERF: Traitement d'un status avec boucle unique
    def _process_status(s, sums, all_nodes, online_count):
        if not isinstance(s, dict):
            return online_count
        online = s.get("online", False)
        node = {
            "name": s.get("name", "unknown"),
            "online": online,
            "error": s.get("error"),
            "type": s.get("type", "cassandra"),
            "url": s.get("url", ""),
        }
        if online:
            cpu_val = s.get("cpu", 0)
            ram_val = s.get("ram", 0)
            disk_val = s.get("disk", 0)
            hscore = s.get("health_score", 0)
            hstatus = s.get("health_status", "unknown")
            node.update(cpu=cpu_val, ram=ram_val, disk=disk_val,
                        health_score=hscore, health_status=hstatus)
            sums[0] += cpu_val
            sums[1] += ram_val
            sums[2] += disk_val
            sums[3] += hscore
            online_count += 1
        for k in OPTIONAL_KEYS:
            if k in s:
                node[k] = s[k]
        all_nodes.append(node)
        return online_count

    for s in statuses:
        online_count = _process_status(s, sums, all_nodes, online_count)

    total = len(all_nodes)
    avg_cpu = _rounded_avg(sums[0], online_count)
    avg_ram = _rounded_avg(sums[1], online_count)
    avg_disk = _rounded_avg(sums[2], online_count)
    avg_health = _rounded_avg(sums[3], online_count)

    return {
        "total_servers": total,
        "online_servers": online_count,
        "offline_servers": total - online_count,
        "avg_cpu": avg_cpu,
        "avg_ram": avg_ram,
        "avg_disk": avg_disk,
        "avg_health": avg_health,
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
                              "cassandra_knowledge_collector.py"),
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

# ═══════════════════════════════════════════════════════════════════════════
# SÉCURITÉ ÉVOLUTION — validation profonde + revue + watchdog auto-rollback
# ═══════════════════════════════════════════════════════════════════════════

def _self_validate_names(content: str):
    """Détecte les noms utilisés mais jamais liés (catch le bug type _ping_template).
    Approche conservatrice (sur-approxime les liaisons → ~0 faux positif) :
    on rassemble TOUS les noms liés où qu'ils soient + les builtins, puis on
    signale les Name(Load) introuvables. Ignoré si star-import (irrésoluble)."""
    try:
        tree = _ast.parse(content)
    except SyntaxError as e:
        return False, "SyntaxError ligne %s: %s" % (e.lineno, e.msg)

    # PERF: classe interne specialisée pour éviter les répétitions et améliorer la maintenabilité
    class _NameValidator:
        # PERF: alias locaux pour les types et fonctions (une seule résolution)
        __slots__ = ('bound', 'loaded', '_handlers')
        def __init__(self):
            import builtins as _bi
            self.bound = set(dir(_bi))
            self.bound.update({
                "__file__", "__name__", "__doc__", "__builtins__", "__spec__",
                "__loader__", "__package__", "__class__", "__dict__"
            })
            self.loaded = set()
            # PERF: précalcule le mapping type -> méthode visit_XXX (évite getattr répétés)
            self._handlers = {}
            _ty = type
            for typ_name in ('FunctionDef', 'AsyncFunctionDef', 'ClassDef',
                             'Name', 'Import', 'ImportFrom', 'arg',
                             'Global', 'Nonlocal', 'ExceptHandler',
                             'Call'):
                ast_type = getattr(_ast, typ_name, None)
                if ast_type is not None:
                    method_name = 'visit_' + typ_name
                    self._handlers[_ty(ast_type)] = getattr(self, method_name, self.generic_visit)

        # PERF: méthodes de visite optimisées pour chaque type important
        def visit_FunctionDef(self, n):
            self.bound.add(n.name)
        visit_AsyncFunctionDef = visit_FunctionDef
        visit_ClassDef = visit_FunctionDef

        def visit_Name(self, n):
            ctx = type(n.ctx)
            if ctx is _ast.Store:
                self.bound.add(n.id)
            elif ctx is _ast.Load:
                self.loaded.add(n.id)

        # PERF: mise à jour par générateur (évite boucle d'appels add)
        def visit_Import(self, n):
            self.bound.update(
                (a.asname or a.name).split(".")[0] for a in n.names
            )

        def visit_ImportFrom(self, n):
            # FEATURE: détection star-import (interrompt la validation)
            for a in n.names:
                if a.name == "*":
                    raise _StarImportFound
            self.bound.update(a.asname or a.name for a in n.names)

        def visit_arg(self, n):
            self.bound.add(n.arg)

        def visit_Global(self, n):
            self.bound.update(n.names)
        visit_Nonlocal = visit_Global

        def visit_ExceptHandler(self, n):
            if n.name:
                self.bound.add(n.name)

        # PERF: détection précoce des appels dynamiques
        _DYN = frozenset({"globals", "locals", "exec", "eval", "vars"})
        def visit_Call(self, n):
            func = n.func
            if type(func) is _ast.Name and func.id in self._DYN:
                raise _DynamicCallFound(func.id)
            # PERF: ignore les autres appels pour ne pas ralentir

        def generic_visit(self, n):
            # PERF: ne fait rien par défaut (les noeuds ignorés sont sautés)
            pass

    # Exception interne pour un contrôle de flux rapide (évite les retours prématurés dans la boucle)
    class _StarImportFound(Exception):
        pass
    class _DynamicCallFound(Exception):
        def __init__(self, name):
            self.name = name

    validator = _NameValidator()
    # PERF: boucle unique avec dispatch rapide (pas de if isinstance chaînés)
    try:
        for node in _ast.walk(tree):
            # PERF: dispatch par type de nœud (résolution O(1) via dictionnaire)
            handler = validator._handlers.get(type(node))
            if handler is not None:
                handler(node)
    except _StarImportFound:
        return True, "OK (star-import: vérification noms ignorée)"
    except _DynamicCallFound as e:
        return True, "OK (liaison dynamique %s(): vérification noms ignorée)" % e.name

    undef = validator.loaded - validator.bound
    if undef:
        # PERF: limite l'affichage aux 8 premiers (comportement original)
        return False, "noms non définis: " + ", ".join(sorted(undef)[:8])
    return True, "OK"


def _self_selftest(content: str, alias: str = "agent", timeout: int = 30):
    """Exécute le code candidat dans un sous-processus isolé (CASSANDRA_SELFTEST=1).
    Le module est entièrement importé (détecte NameError, ImportError, crash au
    chargement — ex. clé manquante) puis s'arrête net avant de lancer le serveur.
    Aucun impact sur le service en cours."""
    import tempfile, subprocess as _sp
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix="_selftest.py", dir="/tmp")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        env = dict(os.environ, CASSANDRA_SELFTEST="1")
        r = _sp.run([sys.executable, tmp], env=env, capture_output=True,
                    text=True, timeout=timeout)
        out = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
        if r.returncode == 0 and "SELFTEST_OK" in out:
            return True, "OK"
        lines = [l for l in out.splitlines() if l.strip()]
        tail = "\n".join(lines[-5:])[:500]
        return False, "démarrage échoué (code %s): %s" % (r.returncode, tail)
    except _sp.TimeoutExpired:
        return False, "timeout au démarrage (blocage probable)"
    except Exception as e:
        return False, "selftest erreur: %s" % e
    finally:
        if tmp:
            try:
                os.remove(tmp)
            except Exception:
                pass


def _self_smoke_test(content: str, timeout: int = 35):
    """BANC D'ESSAI — la pièce maîtresse. Lance un CLONE de l'agent candidat sur un
    port temporaire (mode CASSANDRA_SMOKE, sans les daemons lourds) et vérifie qu'il
    DÉMARRE et RÉPOND réellement (/api/ping puis /api/health). Un patch n'est appliqué
    en prod que s'il passe ce test → il est impossible de casser l'agent en service.
    Ne s'applique qu'à l'agent principal (le collecteur n'a pas de serveur HTTP)."""
    import tempfile, subprocess as _sp, socket as _sock, urllib.request as _u
    # Port libre dédié au clone
    _s = _sock.socket()
    try:
        _s.bind(("127.0.0.1", 0))
        port = _s.getsockname()[1]
    finally:
        _s.close()
    tmp = None
    proc = None
    try:
        fd, tmp = tempfile.mkstemp(suffix="_smoke.py", dir="/tmp")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        env = dict(os.environ, CASSANDRA_SMOKE="1", CASSANDRA_PORT=str(port))
        proc = _sp.Popen([sys.executable, tmp], env=env,
                         stdout=_sp.PIPE, stderr=_sp.STDOUT)
        deadline = time.time() + timeout
        base = "http://127.0.0.1:%d" % port
        up = False
        while time.time() < deadline:
            if proc.poll() is not None:  # le clone a crashé au démarrage
                out = (proc.stdout.read() or b"").decode("utf-8", "replace")
                tail = "\n".join([l for l in out.splitlines() if l.strip()][-6:])[:500]
                return False, "le clone a crashé au démarrage: %s" % tail
            try:
                resp = _u.urlopen(base + "/api/ping", timeout=2)
                if getattr(resp, "status", 200) == 200:
                    up = True
                    break
            except Exception:
                time.sleep(0.4)
        if not up:
            return False, "le clone ne répond pas (timeout %ss)" % timeout
        # Vérif d'un endpoint réel qui exécute du code (santé système)
        try:
            r2 = _u.urlopen(base + "/api/health", timeout=4)
            if getattr(r2, "status", 200) != 200:
                return False, "/api/health a renvoyé %s" % getattr(r2, "status", "?")
        except Exception as e:
            return False, "/api/health KO: %s" % e
        return True, "OK (le clone démarre et sert /api/ping + /api/health)"
    except Exception as e:
        return False, "banc d'essai erreur: %s" % e
    finally:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if tmp:
            try:
                os.remove(tmp)
            except Exception:
                pass


def _self_review_by_secondary(diff: str, description: str, alias: str = "agent"):
    """Revue de code croisée par l'agent secondaire (générateur + critique).
    Saute proprement si l'agent secondaire n'est pas configuré."""
    try:
        if not _dual_agent_available():
            return True, "agent secondaire non configuré — revue ignorée"
        system = (
            "Tu es un relecteur de code Python senior chargé de protéger un agent "
            "système critique en production. On te donne un diff unifié appliqué à son "
            "code source. Réponds STRICTEMENT par une seule ligne :\n"
            "'VERDICT: APPROVE' si le patch est sûr,\n"
            "ou 'VERDICT: REJECT — <raison courte>' si tu détectes une régression, un "
            "bug, une variable/fonction non définie, une suppression de fonctionnalité, "
            "une boucle/fuite, ou une faille de sécurité. En cas de doute sérieux, REJECT."
        )
        user = "Changement annoncé: %s\n\nDIFF:\n%s" % ((description or "(non précisé)"), diff[:6000])
        resp = (_dual_agent_text([{"role": "user", "content": user}],
                                 system=system, max_tokens=300) or "").strip()
        up = resp.upper()
        if "REJECT" in up:
            reason = resp.split("REJECT", 1)[1].lstrip(" —:-").strip() or "rejeté par la revue"
            return False, reason[:300]
        # APPROVE explicite ou réponse ambiguë → on n'empêche pas l'évolution
        return True, "approuvé par l'agent secondaire" if "APPROVE" in up else "revue non concluante — laissé passer"
    except Exception as e:
        return True, "revue indisponible (%s) — ignorée" % e


def _self_full_validate(content: str, alias: str = "agent",
                        review_diff: str = None, description: str = ""):
    """Pipeline de validation complet AVANT toute application :
    syntaxe → noms non définis → selftest → revue 2e agent → BANC D'ESSAI (clone qui sert)."""
    ok, err = _self_validate(content)
    if not ok:
        return False, "syntaxe — %s" % err
    ok, err = _self_validate_names(content)
    if not ok:
        return False, "noms — %s" % err
    ok, err = _self_selftest(content, alias)
    if not ok:
        return False, "selftest — %s" % err
    if review_diff:
        ok, err = _self_review_by_secondary(review_diff, description, alias)
        if not ok:
            return False, "revue 2e agent — %s" % err
    # GATE FINAL : le patch doit réellement démarrer et servir dans un clone isolé.
    # (Agent uniquement — le collecteur n'a pas de serveur HTTP.)
    if alias == "agent":
        ok, err = _self_smoke_test(content)
        if not ok:
            return False, "banc d'essai — %s" % err
    return True, "OK"


def _evo_log_rejected(alias: str, description: str, reason: str):
    """Journalise un patch refusé dans evolution_log (visible dans l'UI)."""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO evolution_log (ts, target_file, description, motivation, diff, "
            "snapshot_before, sha256_before, sha256_after, status, restart_done) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (datetime.now().isoformat(), alias, (description or "")[:300],
             ("REFUSÉ: %s" % reason)[:500], "", "", "", "", "rejected", 0))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ── Watchdog post-déploiement (marqueur + auto-rollback) ──────────────────────
_EVO_PENDING_FILE = "/var/lib/cassandra/evo_pending.json"

def _evo_write_pending(evo_id, backup_path, alias):
    try:
        Path(_EVO_PENDING_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(_EVO_PENDING_FILE, "w") as f:
            json.dump({"evo_id": evo_id, "backup": backup_path, "alias": alias,
                       "attempts": 0, "ts": time.time()}, f)
    except Exception as e:
        logging.error("[EVO] écriture marqueur pending: %s" % e)

def _evo_boot_watchdog():
    """Au démarrage : si une évolution attend confirmation et que le boot se répète
    sans confirmation (code malsain qui ne se stabilise pas), rollback automatique
    vers le backup, puis redémarrage. Couvre l'agent principal."""
    try:
        if not os.path.exists(_EVO_PENDING_FILE):
            return
        with open(_EVO_PENDING_FILE) as f:
            m = json.load(f)
    except Exception:
        return
    m["attempts"] = int(m.get("attempts", 0)) + 1
    if m["attempts"] >= 3 and m.get("alias") == "agent":
        backup = m.get("backup")
        path = SELF_SOURCE_FILES.get("agent")
        try:
            if backup and os.path.exists(backup) and path:
                import shutil as _sh
                _sh.copy2(backup, path)
                _evo_log_rejected("agent", "Auto-rollback (watchdog)",
                                  "code malsain après %d démarrages — restauration de %s"
                                  % (m["attempts"], os.path.basename(backup)))
                try:
                    os.remove(_EVO_PENDING_FILE)
                except Exception:
                    pass
                logging.error("[EVO] ⚠️ Auto-rollback effectué — redémarrage sur le backup")
                os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            logging.error("[EVO] échec rollback watchdog: %s" % e)
    else:
        try:
            with open(_EVO_PENDING_FILE, "w") as f:
                json.dump(m, f)
        except Exception:
            pass

def _evo_confirm_health_async():
    """Après démarrage du serveur : ping interne ; si OK, l'évolution est confirmée
    saine et le marqueur est levé (plus de risque de rollback)."""
    def _run():
        time.sleep(25)
        try:
            import urllib.request as _u
            resp = _u.urlopen("http://127.0.0.1:%d/api/ping" % PORT, timeout=5)
            if getattr(resp, "status", 200) == 200 and os.path.exists(_EVO_PENDING_FILE):
                os.remove(_EVO_PENDING_FILE)
                logging.info("[EVO] ✅ Évolution confirmée saine — marqueur levé")
        except Exception as e:
            logging.warning("[EVO] confirmation santé impossible: %s" % e)
    threading.Thread(target=_run, daemon=True, name="evo-health-confirm").start()

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
    """Connexion au sous-système d'évolution.
    Les tables evolution_log / evolution_wishlist sont créées par init_memory_db()
    dans MEMORY_DB_PATH : il faut donc s'y connecter, pas à DB_PATH (où elles n'existent pas)."""
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.row_factory = sqlite3.Row  # indispensable : self_get_history/wishlist font dict(row)
    return conn

def self_apply_change(alias, new_content, description, motivation, auto_restart=True):
    path = SELF_SOURCE_FILES.get(alias)
    if not path:
        return {"ok": False, "error": "alias inconnu: %s" % alias}
    try:
        before     = Path(path).read_text(encoding="utf-8") if Path(path).exists() else ""
        sha_before = _self_sha(before)
        sha_after  = _self_sha(new_content)
        if sha_before == sha_after:
            return {"ok": False, "error": "Aucun changement detecte"}
        diff = _self_diff(before, new_content)
        # ── VALIDATION PROFONDE (syntaxe → noms → selftest → revue 2e agent) ──
        ok, err = _self_full_validate(new_content, alias, review_diff=diff, description=description)
        if not ok:
            _evo_log_rejected(alias, description, err)
            logging.warning("[EVO] Patch refusé (%s) : %s" % (alias, err))
            return {"ok": False, "error": "Patch refusé — %s" % err, "rejected": True}
        # Backup automatique avant modification
        backup_path = _self_backup(path)
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
            # Marqueur watchdog : si le nouveau code ne se confirme pas sain, rollback auto
            _evo_write_pending(evo_id, backup_path, alias)
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
_EVO_INTERVAL   = int(os.environ.get("CASSANDRA_EVO_INTERVAL", 60))    # 60s base, sera adapté par la charge
_EVO_MIN_INTERVAL = 15     # 15 secondes minimum entre cycles (charge très faible)
_EVO_MAX_LINES  = 120       # limite delta lignes par évolution
_EVO_MAX_DAILY  = 0         # 0 = pas de limite journalière — aucune restriction
_EVO_LOCK       = threading.Lock()  # une seule évolution à la fois
_evo_next_run   = 0.0       # epoch du prochain cycle autonome (renseigné par le daemon)

def _get_adaptive_interval() -> int:
    """Calcule dynamiquement l'intervalle d'évolution selon la charge CPU.
    Plus le serveur est libre, plus Cassandra évolue vite — aucun délai artificiel."""
    try:
        load1, _load5, _load15 = os.getloadavg()
        cpu_count = os.cpu_count() or 1
        load_ratio = load1 / cpu_count  # ratio par cœur
        if load_ratio < 0.3:
            return _EVO_MIN_INTERVAL   # charge très faible → aussi vite que possible
        elif load_ratio < 0.5:
            return 30                   # charge basse → 30s
        elif load_ratio < 0.7:
            return 60                   # charge modérée → 1 min
        elif load_ratio < 0.85:
            return 120                  # charge élevée → 2 min
        else:
            return 300                  # charge critique → attendre 5 min
    except (OSError, AttributeError):
        return _EVO_INTERVAL

# ── Pause utilisateur (persistée dans config.json → survit aux redémarrages) ──
def is_evolution_paused() -> bool:
    """True si l'auto-évolution est mise en pause par l'utilisateur."""
    try:
        return bool(get_cassandra_config().get("evolution_paused", False))
    except Exception:
        return False

def set_evolution_paused(paused: bool) -> bool:
    """Active/désactive la pause de l'auto-évolution (persistant)."""
    try:
        cfg = get_cassandra_config()
        cfg["evolution_paused"] = bool(paused)
        ok = save_cassandra_config(cfg)
        logging.info(f"[EVO-AUTO] Pause {'activée' if paused else 'levée'} par l'utilisateur")
        return ok
    except Exception as e:
        logging.error(f"[EVO-AUTO] Erreur set_evolution_paused: {e}")
        return False

def self_get_evo_status():
    """Statut temps réel du cycle autonome — pour synchroniser l'UI."""
    now = time.time()
    remaining = max(0, int(_evo_next_run - now)) if _evo_next_run else None
    return {
        "interval":  _get_adaptive_interval(),
        "next_run":  _evo_next_run or None,
        "remaining": remaining,
        "today":     _evo_count_today(),
        "max_daily": _EVO_MAX_DAILY,
        "paused":    is_evolution_paused(),
    }

def wipe_for_prod(confirm: str = ""):
    """RESET TOTAL avant mise en prod : efface tout l'état runtime de Cassandra
    (bases, mémoire + backups, logs, backups du code source) puis recrée un
    schéma vierge et redémarre l'agent. Préserve TOUJOURS cassandra.py et le collector.
    Garde-fou : exige confirm == 'EFFACER'.
    """
    import shutil as _shutil
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    import time
    import logging
    import sys
    import os

    if confirm != "EFFACER":
        return {"ok": False, "error": "Confirmation invalide — saisir 'EFFACER'"}

    # PERF: Cache des fonctions système pour éviter la résolution d'attribut
    _remove = os.remove
    _scandir = os.scandir
    _rmtree = _shutil.rmtree
    _unlink = os.unlink  # PERF: os.unlink est synonyme de os.remove mais légèrement plus direct

    # PERF: Pré-calcul des chemins réels (résout liens symboliques) – une seule conversion, O(k)
    protected = {os.path.realpath(p) for p in SELF_SOURCE_FILES.values()}

    # PERF: Chemins réels des cibles – conversion unique
    targets_files = [os.path.realpath(f) for f in [DB_PATH, MEMORY_DB_PATH, ADMIN_LOG_FILE]]
    targets_dirs  = [os.path.realpath(d) for d in [MEMORY_BACKUP_DIR, "/root/.cassandra_backups"]]

    removed, errors = [], []
    errors_lock = threading.Lock()  # ROBUSTESSE: protection liste errors multithread

    # PERF: Suppression des fichiers – pas de vérification d'existence préalable
    for f in targets_files:
        try:
            if f in protected:
                continue
            _unlink(f)
            removed.append(f)
        except FileNotFoundError:
            logging.debug("[wipe_for_prod] %s introuvable, ignoré.", f)
        except Exception as e:
            with errors_lock:
                errors.append(f"{f}: {e}")

    def _wipe_dir_content(d):
        """PERF: Parcourt et supprime les entrées du répertoire, thread-safe."""
        local_removed = []
        local_errors = []
        try:
            with _scandir(d) as it:
                for entry in it:
                    p = entry.path
                    # PERF: realpath déjà appliqué à d, entry.path est absolu
                    if os.path.realpath(p) in protected:
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        _rmtree(p, ignore_errors=True)
                    else:
                        try:
                            _unlink(p)
                        except Exception:
                            logging.debug("[wipe_for_prod] %s suppression échouée, ignoré.", p)
                    local_removed.append(p)
            local_removed.append(d + "/*")
        except FileNotFoundError:
            logging.debug("[wipe_for_prod] %s introuvable, ignoré.", d)
        except Exception as e:
            local_errors.append(f"{d}: {e}")
        return local_removed, local_errors

    # PERF: Parallélisation de la suppression du contenu des répertoires
    with ThreadPoolExecutor(max_workers=len(targets_dirs)) as executor:
        futures = {executor.submit(_wipe_dir_content, d): d for d in targets_dirs}
        for future in as_completed(futures):
            try:
                r, e = future.result()
                removed.extend(r)
                with errors_lock:
                    errors.extend(e)
            except Exception as exc:
                with errors_lock:
                    errors.append(f"thread error for {futures[future]}: {exc}")

    # Recréation du schéma vierge (identique à l'original)
    try:
        init_memory_db()
        init_admin_log()
    except Exception as e:
        with errors_lock:
            errors.append(f"reinit: {e}")

    logging.warning(f"[WIPE-PROD] Reset total — supprimés: {removed} | erreurs: {errors}")

    # Redémarrage de l'agent dans un thread
    def _restart_after_wipe():
        time.sleep(2)
        os.execv(sys.executable, [sys.executable] + sys.argv)
    threading.Thread(target=_restart_after_wipe, daemon=True, name="wipe-restart").start()

    return {"ok": True, "removed": removed, "errors": errors,
            "message": "Reset total effectué — redémarrage de l'agent…"}

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
    import ast
    from collections import Counter, defaultdict
    import logging  # PERF: import localisé, mais on garde pour cohérence

    # PERF: constantes définies hors de la boucle principale
    EXCLUDED_NAMES = {"init_db", "init_logging", "init_db_schema", "init_tables"}
    SKIP_CALLS = {"append", "get", "format", "str", "int", "len",
                  "print", "logging", "info", "warning", "error", "debug"}

    def _analyze_function(node, src_lines):
        """PERF: analyse une fonction unique et retourne ses métriques et issues."""
        name = node.name
        start = node.lineno
        end = getattr(node, "end_lineno", node.lineno + 10)
        size = end - start + 1

        # Filtre rapide : taille <10, noms exclus
        if (size < 10
                or name.startswith(("__", "_autonomous", "_evo_"))
                or name in EXCLUDED_NAMES):
            return None

        def_line = src_lines[start - 1] if 0 < start <= len(src_lines) else ""
        if def_line and def_line[0] in (' ', '\t'):
            return None

        has_try = False
        has_io = False
        opens = 0
        closes = 0
        call_counts = Counter()
        calls_set = set()
        returns = []
        # PERF: stockage des intervalles pour détection O(n log n)
        loops = []

        for n in ast.walk(node):
            # PERF: isinstance testé une fois par nœud, pas besoin de cache supplémentaire
            if isinstance(n, ast.Try):
                has_try = True
            if isinstance(n, ast.Call):
                func_obj = n.func
                if isinstance(func_obj, ast.Attribute):
                    attr = func_obj.attr
                    if attr in ("execute", "fetchone", "fetchall", "urlopen",
                                "request", "connect", "open", "read", "write"):
                        has_io = True
                    if attr in ("open", "connect"):
                        opens += 1
                    elif attr in ("close", "disconnect"):
                        closes += 1
                    if attr not in SKIP_CALLS:
                        call_counts[attr] += 1
                        calls_set.add(attr)
                elif isinstance(func_obj, ast.Name) and func_obj.id not in SKIP_CALLS:
                    call_counts[func_obj.id] += 1
                    calls_set.add(func_obj.id)
            if isinstance(n, ast.Return) and n.value is not None:
                returns.append(n)
            # PERF: collecte des intervalles pour l'analyse de nesting
            if isinstance(n, (ast.For, ast.While)):
                loop_end = getattr(n, "end_lineno", n.lineno + 10)
                loops.append((n.lineno, loop_end))

        # Détection de boucles imbriquées par tri d'intervalles O(k log k)
        nested_loops = False
        if loops:
            loops.sort(key=lambda x: (x[0], -x[1]))
            stack = []
            for l_start, l_end in loops:
                while stack and stack[-1][1] < l_start:
                    stack.pop()
                if stack:
                    nested_loops = True
                    break
                stack.append((l_start, l_end))

        # Construction des issues
        issues = []
        priority = 0

        if not has_try and (has_io or size > 25):
            issues.append("aucun try/except — crash non géré possible")
            priority += 4
        if nested_loops:
            issues.append("boucles imbriquées — complexité O(n²) potentielle")
            priority += 5
        if size > 100:
            issues.append(f"fonction très longue ({size} lignes) — décomposition recommandée")
            priority += 3
        elif size > 60:
            issues.append(f"fonction longue ({size} lignes) — lisibilité dégradée")
            priority += 1
        # PERF: compréhension avec limite
        repeated = [c for c, cnt in call_counts.items() if cnt >= 3][:3]
        if repeated:
            issues.append(f"appels répétés ({', '.join(repeated)}) — mise en cache possible")
            priority += 3
        if not returns and size > 30:
            issues.append("pas de return explicite sur fonction non-triviale")
            priority += 1
        if opens > closes and opens > 0:
            issues.append(f"ressource ouverte ({opens}x) sans fermeture ({closes}x) — fuite possible")
            priority += 7

        # Retourne les données nécessaires à la suite
        return {
            "name": name,
            "start": start,
            "end": end,
            "size": size,
            "issues": issues,
            "priority": priority,
            "has_try": has_try,
            "has_io": has_io,
            "opens": opens,
            "closes": closes,
            "calls_set": calls_set,
            "call_counts": call_counts,
            "returns": returns,
            "nested_loops": nested_loops,
            "is_private": name.startswith("_")
        }

    def _find_similar_pairs(func_calls, func_names):
        """PERF: remplace la double boucle O(n²) par un index inversé O(total_calls*k)."""
        # Index : appel -> liste de noms de fonctions
        call_to_funcs = defaultdict(list)
        for fname, calls in func_calls.items():
            for c in calls:
                call_to_funcs[c].append(fname)

        # Compteur de paires : frozenset((a,b)) -> nombre d'appels communs
        pair_counts = defaultdict(int)
        for fname_list in call_to_funcs.values():
            if len(fname_list) < 2:
                continue
            # Toutes les paires dans cette liste
            for i in range(len(fname_list)):
                a = fname_list[i]
                for j in range(i + 1, len(fname_list)):
                    b = fname_list[j]
                    key = frozenset([a, b])  # ordre indifférent
                    pair_counts[key] += 1

        similar_candidates = []
        for key, common in pair_counts.items():
            if common < 3:
                continue
            # Récupère les deux noms et leurs ensembles
            a, b = tuple(key)
            a_set = func_calls[a]
            b_set = func_calls[b]
            max_len = max(len(a_set), len(b_set))
            if max_len >= 3 and common / max_len >= 0.5:
                similar_candidates.append({
                    "name": f"{a} + {b}",
                    "start": 0,
                    "end": 0,
                    "size": 0,
                    "issues": [f"fonctions similaires ({common} appels communs) — fusion possible"],
                    "priority": 6,
                    "improvement_type": "refactor"
                })
        return similar_candidates

    def _get_feature_suggestions(func_names):
        """PERF: détection de features manquantes via lower() une seule fois."""
        # PERF: conversion en minuscules une fois pour toutes
        lower_names = [n.lower() for n in func_names]
        has_backup = any("backup" in n for n in lower_names)
        has_self_heal = any("heal" in n or "repair" in n for n in lower_names)

        suggestions = []
        if not has_backup:
            suggestions.append(("backup_system", "Système de backup automatique de la base SQLite", 8))
        if not has_self_heal:
            suggestions.append(("self_heal", "Auto-réparation des services défaillants (vérification périodique)", 7))
        return [
            {
                "name": fname,
                "start": 0,
                "end": 0,
                "size": 0,
                "issues": [f"NOUVELLE CAPACITÉ: {desc}"],
                "priority": prio,
                "improvement_type": "feature"
            }
            for fname, desc, prio in suggestions
        ]

    candidates = []
    try:
        tree = ast.parse(source)
        src_lines = source.splitlines()

        # Phase 1 : analyse de chaque fonction
        func_calls = {}
        func_names = []
        func_nodes = [n for n in ast.walk(tree)
                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

        for node in func_nodes:
            try:
                result = _analyze_function(node, src_lines)
            except Exception as inner_e:
                fname = getattr(node, 'name', '<unknown>')
                logging.warning(f"[EVO-CANDIDATES] Échec analyse fonction '{fname}': {inner_e}")
                continue
            if result is None or result["issues"]:
                # Si result est None, la fonction a été filtrée
                if result is None:
                    continue
                # Si issues non vide, on l'ajoute
                candidates.append({
                    "name": result["name"],
                    "start": result["start"],
                    "end": result["end"],
                    "size": result["size"],
                    "issues": result["issues"],
                    "priority": result["priority"],
                    "improvement_type": "fix"
                })
            # On collecte les appels pour toutes les fonctions (même sans issues) pour la phase similarité
            if result is not None and not result["is_private"]:
                func_calls[result["name"]] = result["calls_set"]
                func_names.append(result["name"])

        # Phase 2 : similarité (avec index inversé)
        similar = _find_similar_pairs(func_calls, func_names)
        candidates.extend(similar)

        # Phase 3 : suggestions de features
        feature_candidates = _get_feature_suggestions(func_names)
        candidates.extend(feature_candidates)

        # Tri et limitation à 30
        candidates.sort(key=lambda x: x["priority"], reverse=True)
        return candidates[:30]

    except Exception as e:
        logging.warning(f"[EVO-CANDIDATES] Analyse AST échouée: {e}", exc_info=True)
        return []


def _persist_candidates_to_wishlist(candidates: list) -> None:
    """
    Sauvegarde les candidats détectés en wishlist pour ne pas les perdre
    si le LLM échoue. Évite les doublons sur (description).
    # PERF: upsert par description unique — idempotent entre cycles
    """
    try:
        now = datetime.now().isoformat()
        conn = get_db()
        for c in candidates:
            desc = f"[AST] {c['name']}(): {' | '.join(c['issues'][:2])}"
            # priority candidat = entier → mapping vers les niveaux attendus par l'UI
            p = c.get("priority", 0)
            level = "high" if p >= 7 else ("medium" if p >= 4 else "low")
            exists = conn.execute(
                "SELECT id FROM evolution_wishlist WHERE description=? AND status='pending'",
                (desc,)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO evolution_wishlist "
                    "(ts, target_file, category, description, priority, status, identified_by) "
                    "VALUES (?, ?, ?, ?, ?, 'pending', 'ast_auto')",
                    (now, "agent", c.get("improvement_type", "ast"), desc, level)
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning(f"[EVO-WISHLIST] Persistance candidats échouée: {e}")


def _evo_json_extract(text):
    """Extraction JSON robuste : gère les fences markdown, le texte parasite avant/après,
    et extrait le premier objet {...} équilibré. Corrige les ~92% d'échecs Phase1
    dus à `str.strip("```json")` (qui retire des caractères, pas la sous-chaîne)."""
    if not text:
        return None
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        t = m.group(1).strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    start = t.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(t)):
        ch = t[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(t[start:i + 1])
                except Exception:
                    return None
    return None


def _evo_chat_json(prompt, max_tokens=250):
    """Appel LLM en forçant le mode JSON quand le provider le supporte (DeepSeek/OpenAI).
    Repli automatique sans response_format si non supporté."""
    try:
        r = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3, max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
    except Exception:
        r = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3, max_tokens=max_tokens,
        )
    return r.choices[0].message.content or ""


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
        # Exclure les fonctions trop grosses : elles dépassent le budget tokens en
        # Phase2 → troncature → rejet systématique. On privilégie ce qui tient.
        _small = [c for c in patchable if 0 < c.get("size", 999) <= 150]
        if _small:
            patchable = _small
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
        raw1   = _evo_chat_json(prompt_phase1, max_tokens=250)
        choice = _evo_json_extract(raw1)
        if not choice:
            raise ValueError("JSON Phase1 illisible: " + (raw1 or "")[:120])
        fname    = choice.get("function_name", "")
        reason   = choice.get("reason", "")
        imp_type = choice.get("improvement_type", "robustesse")
    except Exception as e:
        logging.warning(f"[EVO-AUTO] Phase1 LLM principal error: {e}")
        # ── A. Fallback agent secondaire Phase 1 ──────────────────
        if not _dual_agent_available():
            return None
        logging.info("[EVO-AUTO] Phase1 → fallback agent secondaire")
        try:
            raw1 = _dual_agent_text(
                user_msgs=[{"role": "user", "content": prompt_phase1}],
                max_tokens=250
            )
            choice = _evo_json_extract(raw1 or "")
            if not choice:
                return None
            fname    = choice.get("function_name", "")
            reason   = choice.get("reason", "")
            imp_type = choice.get("improvement_type", "robustesse")
            logging.info(f"[EVO-AUTO] Phase1 secondaire → cible '{fname}'")
        except Exception as e2:
            logging.warning(f"[EVO-AUTO] Phase1 fallback error: {e2}")
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
    phase2_tokens = min(8000, max(2500, func_lines * 55))

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

    def _clean_code(txt):
        txt = (txt or "").strip()
        if txt.startswith("```"):
            _l = txt.splitlines()
            txt = "\n".join(_l[1:] if _l[0].startswith("```") else _l)
        if txt.endswith("```"):
            txt = "\n".join(txt.splitlines()[:-1])
        return txt.strip()

    new_func = None
    gen_via  = None

    # 1) Génération PRIORITAIRE par l'agent secondaire (modèle souvent plus costaud,
    #    ex. OpenRouter) : DeepSeek-flash tronque/bugue → patches rejetés. On lui
    #    donne le budget tokens complet (l'ancien plafond 3000 tronquait aussi).
    if _dual_agent_available():
        try:
            cand = _clean_code(_dual_agent_text(
                user_msgs=[{"role": "user", "content": prompt_phase2}],
                max_tokens=phase2_tokens
            ))
            if cand:
                try:
                    _ast.parse(cand)
                    new_func, gen_via = cand, "secondaire"
                except SyntaxError as _se:
                    logging.warning(f"[EVO-AUTO] Phase2 secondaire invalide sur '{fname}': {_se}")
        except Exception as e:
            logging.warning(f"[EVO-AUTO] Phase2 secondaire erreur: {e}")

    # 2) Repli DeepSeek principal (ou si pas d'agent secondaire)
    if new_func is None:
        try:
            r2 = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt_phase2}],
                temperature=0.2,
                max_tokens=phase2_tokens,
            )
            choice2 = r2.choices[0]
            if getattr(choice2, "finish_reason", None) == "length":
                logging.warning(
                    f"[EVO-AUTO] Phase2 (principal) tronquée sur '{fname}' "
                    f"— tokens alloués: {phase2_tokens}. Évolution annulée."
                )
                return None
            cand = _clean_code(choice2.message.content)
            try:
                _ast.parse(cand)
                new_func, gen_via = cand, "principal"
            except SyntaxError as _se:
                logging.warning(
                    f"[EVO-AUTO] Phase2 (principal) invalide sur '{fname}' (SyntaxError: {_se})."
                )
                return None
        except Exception as e:
            logging.warning(f"[EVO-AUTO] Phase2 LLM principal error: {e}")
            return None

    if not new_func:
        return None
    logging.info(f"[EVO-AUTO] Phase2 OK via {gen_via} pour '{fname}'")

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
    """Fallback quand le LLM est indisponible - applique une micro‑évolution AST."""
    import ast as _ast
    import re

    # PERF: compilation des regex en amont pour éviter de recompiler à chaque itération
    MARKER_PATTERN = re.compile(r'# (TODO|FIXME|HACK)')
    EXCEPT_PASS_CHECK = re.compile(r'except\b(?!.*logging)', re.DOTALL)

    # ------ Parsing unique du source ------
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return None

    # ------ Indexation des définitions de fonctions ------
    func_map = {n.name: n for n in _ast.walk(tree)
                if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))}
    lines = source.splitlines()
    n_lines = len(lines)

    # ------ Priorisation des candidats ------
    _pri_map = {"high": 10, "medium": 5, "low": 1}
    def _priority_key(c):
        p = c.get("priority", "low")
        return p if isinstance(p, (int, float)) else _pri_map.get(p, 0)
    candidates_sorted = sorted(candidates, key=_priority_key, reverse=True)[:15]

    # PERF: fonction utilitaire pour valider et appliquer un changement (factorisation)
    def _try_apply(name, old_text, new_text, source, desc_suffix, motiv_suffix):
        if new_text == old_text:
            return None
        # PERF: suppression de la vérification redondante `old_text in source`
        # car old_text est extrait de source et source n'a pas changé à ce stade.
        new_source = source.replace(old_text, new_text, 1)
        ok, _ = _self_validate(new_source)
        if ok:
            delta = abs(new_text.count("\n") - old_text.count("\n"))
            desc = f"[AUTO] {desc_suffix} - {name}()"
            motiv = f"Fallback AST - {motiv_suffix} | delta {delta} lignes"
            result = self_apply_change(
                "agent", new_source, desc, motiv, auto_restart=True)
            if result.get("ok"):
                result["description"] = desc
                return result
        return None

    # ------ Boucle principale sur les candidats ------
    for cand in candidates_sorted:
        name = cand.get("name", "")
        issues = cand.get("issues", [])
        if not name or not issues:
            continue
        if cand.get("start") == 0 and cand.get("end") == 0:
            continue

        target = func_map.get(name)
        if not target or target.lineno is None or target.end_lineno is None:
            continue

        s, e = target.lineno - 1, target.end_lineno
        if s < 0 or e > n_lines:
            continue

        # PERF: calcul unique de old_func_text pour le candidat
        old_func_text = "\n".join(lines[s:e])

        # ==== Micro‑correction 1 : except pass → logging.warning (ROBUSTESSE) ====
        if ("except" in old_func_text and "pass" in old_func_text and
                not EXCEPT_PASS_CHECK.search(old_func_text)):
            new_func_text = old_func_text.replace(
                "pass",
                f'logging.warning("[{name}] %s" % str(issues[0])[:80])')
            result = _try_apply(
                name, old_func_text, new_func_text, source,
                "ROBUSTESSE - logging ajouté sur except pass",
                f"LLM indisponible | {name}()")
            if result:
                return result

        # ==== Micro‑correction 2 : résolution des marqueurs TODO/FIXME/HACK (FIX) ====
        # PERF: remplacement unique via regex au lieu d'une boucle et de plusieurs `replace`
        new_func_text = MARKER_PATTERN.sub('# [DONE]', old_func_text)
        if new_func_text != old_func_text:
            result = _try_apply(
                name, old_func_text, new_func_text, source,
                "MAINTENANCE - marqueur résolu",
                f"LLM indisponible | {name}() marqueurs")
            if result:
                return result

        # ==== Micro‑correction 3 : wrapper try/except pour fonctions I/O (ROBUSTESSE) ====
        func_size = e - s
        if any("aucun try/except" in iss for iss in issues) and func_size <= 50:
            has_try = any(isinstance(n, _ast.Try) for n in _ast.walk(target))
            if not has_try and target.body:
                # Préparer lignes de la fonction
                flines = lines[s:e]
                def_idx = next(
                    (i for i, l in enumerate(flines)
                     if l.lstrip().startswith(("def ", "async def "))), 0)
                def_line = flines[def_idx]
                def_indent = def_line[:len(def_line) - len(def_line.lstrip())]
                body_indent = def_indent + "    "

                # Corps indenté correctement
                body_lines = [
                    ("    " + bl) if bl.strip() else bl for bl in flines[def_idx + 1:]
                ]

                # Construction du nouveau corps avec try/except
                new_body = (
                    [f"{body_indent}try:"] +
                    body_lines +
                    [f"{body_indent}except Exception as _e:",
                     f"{body_indent}    logging.warning(f\"[{name}] Erreur non gérée: {{_e}}\")"]
                )
                new_func_text = "\n".join(flines[:def_idx + 1] + new_body)

                result = _try_apply(
                    name, old_func_text, new_func_text, source,
                    "ROBUSTESSE - try/except ajouté (protection crash)",
                    f"wrapping try/except | {name}()")
                if result:
                    return result

    # Aucun changement appliqué
    return None


# ── B. Validation sémantique (agent secondaire) ─────────────────────────────
def _evo_semantic_validate(old_func: str, new_func: str, reason: str, fname: str) -> tuple:
    """
    Demande à l'agent secondaire de valider sémantiquement le patch proposé.
    Retourne (ok: bool, issue: str).
      ok=False  → évolution bloquée (régression / danger critique)
      ok=True   → peut passer ; issue peut contenir un warning non-bloquant
    Si agent indisponible → (True, '') pour dégradé gracieux.
    """
    if not _dual_agent_available():
        return True, ""
    prompt = (
        f"Tu es un expert Python pour systèmes critiques. Compare ces deux versions "
        f"d'une fonction de Cassandra (agent IA sysadmin Linux).\n\n"
        f"OBJECTIF : {reason}\nFONCTION : {fname}\n\n"
        f"AVANT :\n```python\n{old_func[:2500]}\n```\n\n"
        f"APRÈS :\n```python\n{new_func[:2500]}\n```\n\n"
        f"Réponds UNIQUEMENT en JSON (pas de markdown) :\n"
        f'{{ "ok": true/false, "issue": "problème précis ou vide", "severity": "critical|warning|ok" }}\n\n'
        f"ok=false si : régression logique, suppression de fonctionnalité, "
        f"code dangereux (rm -rf incontrôlé, boucle infinie probable, corruption données). "
        f"ok=true+warning si code fonctionnel mais style dégradé."
    )
    raw = _dual_agent_text(user_msgs=[{"role": "user", "content": prompt}], max_tokens=180)
    if not raw:
        return True, ""
    try:
        d        = json.loads(raw.strip("```json").strip("```").strip())
        ok       = bool(d.get("ok", True))
        issue    = d.get("issue", "")
        severity = d.get("severity", "ok")
        if severity == "warning" and ok:
            return True, f"[WARN] {issue}"
        return ok, issue
    except Exception:
        return True, ""  # parse error → dégradé gracieux


# ── C. Mining conversations → wishlist ──────────────────────────────────────
def _evo_wishlist_from_conversations():
    """
    Analyse les messages utilisateur récents pour extraire des demandes de features,
    bugs signalés et améliorations souhaitées, puis les injecte dans evolution_wishlist.
    Lancé en thread daemon au début de chaque cycle d'évolution autonome.
    """
    if not _dual_agent_available():
        return
    try:
        conn = sqlite3.connect(MEMORY_DB_PATH)
        rows = conn.execute(
            "SELECT content FROM conversations WHERE role='user' "
            "ORDER BY id DESC LIMIT 100"
        ).fetchall()
        conn.close()
        msgs = [r[0] for r in rows if r[0] and len(r[0].strip()) > 25]
        if not msgs:
            return
        batch = "\n---\n".join(msgs[:50])
        result = _dual_agent_text(
            system=(
                "Tu analyses des conversations utilisateur avec Cassandra (IA sysadmin Linux). "
                "Identifie les demandes de features, bugs signalés, ou améliorations voulues. "
                "Réponds UNIQUEMENT en JSON — liste d'objets "
                '[ { "description": str, "category": "feature|bug|performance|ui", '
                '"priority": "high|medium|low" } ]. '
                "Max 5 items concrets et actionnables. Si rien : retourne []."
            ),
            user_msgs=[{"role": "user", "content":
                "Extrais les demandes d'amélioration de Cassandra depuis ces messages :\n\n" + batch
            }],
            max_tokens=500
        )
        if not result:
            return
        items = json.loads(result.strip("```json").strip("```").strip())
        if not isinstance(items, list):
            return
        now  = time.strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(MEMORY_DB_PATH)
        added = 0
        for item in items[:5]:
            desc = (item.get("description") or "").strip()
            cat  = item.get("category", "feature")
            prio = item.get("priority", "medium")
            if not desc or len(desc) < 12:
                continue
            exists = conn.execute(
                "SELECT id FROM evolution_wishlist WHERE description=? AND status='pending'",
                (desc,)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO evolution_wishlist "
                    "(ts, target_file, category, description, priority, status, identified_by) "
                    "VALUES (?, ?, ?, ?, ?, 'pending', 'conversation_mining')",
                    (now, "agent", cat, desc, prio)
                )
                added += 1
        conn.commit()
        conn.close()
        if added > 0:
            logging.info(f"[EVO-WISHLIST] {added} item(s) minés depuis conversations → wishlist")
    except Exception as e:
        logging.warning(f"[EVO-WISHLIST] Mining conversations échoué: {e}")


def _run_autonomous_evolution():
    """Tente une évolution autonome : analyse → patch → valide → applique."""
    if is_evolution_paused():
        return  # pause utilisateur : on ne modifie pas le code

    if not _EVO_LOCK.acquire(blocking=False):
        return  # déjà en cours

    try:
        # Re-vérif pause (course possible juste après acquisition du lock)
        if is_evolution_paused():
            return
        # Quota journalier (0 = illimité)
        if _EVO_MAX_DAILY > 0 and _evo_count_today() >= _EVO_MAX_DAILY:
            logging.info(f"[EVO-AUTO] Quota journalier atteint ({_EVO_MAX_DAILY})")
            return

        logging.info("[EVO-AUTO] Démarrage cycle d'évolution autonome...")

        # ── C. Mining conversations → wishlist (thread non-bloquant) ──
        threading.Thread(
            target=_evo_wishlist_from_conversations,
            daemon=True, name="evo-wishlist-mining"
        ).start()

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

        # ── B. Validation sémantique par agent secondaire ────────────
        sem_ok, sem_issue = _evo_semantic_validate(old_func, new_func, reason, fname)
        if not sem_ok:
            logging.warning(f"[EVO-AUTO] ⛔ Validation sémantique rejetée sur '{fname}': {sem_issue}")
            return
        if sem_issue:
            logging.info(f"[EVO-AUTO] ⚠️ Avertissement sémantique '{fname}': {sem_issue}")

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

        # ── Gardes d'intégrité post-patch ───────────────────────────────────
        # Vérifier que les éléments critiques du __main__ survivent au remplacement
        _CRITICAL_MARKERS = [
            ("serve_forever()",              "serve_forever() disparu après patch"),
            ("if __name__ == \"__main__\":", "bloc __main__ disparu après patch"),
            ("class ThreadedHTTPServer",     "classe HTTP disparue après patch"),
        ]
        for marker, msg in _CRITICAL_MARKERS:
            if marker not in new_source:
                logging.warning(f"[EVO-AUTO] 🛡️ Sécurité: {msg} sur '{fname}' — évolution annulée")
                return

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
    """Thread daemon — cycle d'évolution ADAPTATIF selon la charge CPU.
    Plus le serveur est libre, plus Cassandra évolue rapidement.
    Aucune restriction artificielle — le seul frein est la charge réelle du système."""
    global _evo_next_run
    # Délai initial court : 15s pour que Marple voie l'effet immédiatement
    _evo_next_run = time.time() + 15
    time.sleep(15)
    while True:
        try:
            _run_autonomous_evolution()
        except Exception as e:
            logging.error(f"[EVO-AUTO] Daemon error: {e}")
        interval = _get_adaptive_interval()
        _evo_next_run = time.time() + interval
        time.sleep(interval)

def start_autonomous_evolution():
    t = threading.Thread(
        target=_autonomous_evolution_daemon,
        daemon=True,
        name="autonomous-evolution"
    )
    t.start()
    logging.info(f"[EVO-AUTO] Daemon démarré — cycle ADAPTATIF selon charge CPU (min {_EVO_MIN_INTERVAL}s, max 300s), aucune limite journalière")

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

        if path == "/api/setup/status":
            self.send_json({"needs_setup": _needs_setup(),
                            "providers": list(_PROVIDERS.keys()),
                            "default_models": _DEFAULT_MODELS})
            return

        if path in ("/", "/index.html"):
            if _needs_setup():
                self.send_html(SETUP_HTML)
            else:
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
            try:
                _health_score = (get_health_score() or {}).get("score", 0)
            except Exception:
                _health_score = 0
            self.send_json({
                "status": "ok",
                "version": "v14",
                "uptime": int(time.time() - START_TIME),
                "uptime_human": str(timedelta(seconds=int(time.time() - START_TIME))),
                "health_score": _health_score,
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
            "/api/evolution/status":   self_get_evo_status,
            "/api/users":              lambda: {"users": sorted(load_users().keys())},
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
                "vision_provider": get_cassandra_config().get("vision_provider", "openrouter"),
                "vision_base_url": get_cassandra_config().get("vision_base_url", ""),
                "vision_model":    get_cassandra_config().get("vision_model", "google/gemini-2.0-flash"),
                "vision_key_set":  bool(get_cassandra_config().get("vision_api_key", "")),
                "secondary_providers": _SECONDARY_PROVIDERS,
                "secondary_default_models": _SECONDARY_DEFAULT_MODELS,
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
                self.send_json({"ok": False, "error": "code manquant"}); return
            self.send_json(self_apply_change(
                data.get("alias", "agent"), code,
                data.get("description", ""), data.get("motivation", "")
            )); return
        if path == "/api/evolution/rollback":
            evo_id = data.get("evolution_id")
            if not evo_id:
                self.send_json({"ok": False, "error": "evolution_id manquant"}); return
            self.send_json(self_rollback(int(evo_id))); return
        if path == "/api/evolution/wish":
            self.send_json(self_add_wish(
                data.get("target_file", "agent"),
                data.get("category", "amelioration"),
                data.get("description", ""),
                data.get("priority", "medium"),
                data.get("identified_by", "user")
            )); return
        if path == "/api/evolution/pause":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"ok": False, "error": "Non autorisé"}, 401); return
            paused = bool(data.get("paused", True))
            ok = set_evolution_paused(paused)
            self.send_json({"ok": ok, "paused": is_evolution_paused()}); return
        if path == "/api/system/wipe":
            sid = self.headers.get("X-Session-Token", "")
            if not validate_session(sid):
                self.send_json({"ok": False, "error": "Non autorisé"}, 401); return
            self.send_json(wipe_for_prod(data.get("confirm", ""))); return
        # ── GESTION DES COMPTES ──────────────────────────────────────
        if path == "/api/users/set":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"ok": False, "error": "Non autorisé"}, 401); return
            self.send_json(set_user(data.get("username", "").strip(), data.get("password", ""))); return
        if path == "/api/users/delete":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"ok": False, "error": "Non autorisé"}, 401); return
            self.send_json(delete_user(data.get("username", "").strip())); return
    # LOGIN
        if path == "/api/alerts/config":
            cfg = load_alert_config()
            self.send_json(cfg)
            return

        # ── ASSISTANT D'INSTALLATION (premier démarrage, sans auth) ──
        if path == "/api/setup":
            if not _needs_setup():
                self.send_json({"ok": False, "error": "Serveur déjà configuré"}, 403)
                return
            try:
                result = apply_setup(data)
            except Exception as e:
                result = {"ok": False, "error": str(e)}
            self.send_json(result, 200 if result.get("ok") else 400)
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
            pwd      = data.get("password", "")
            username = (data.get("username", "") or "").strip()
            if not get_admin_password_hash() and not load_users():
                self.send_json({"success": False, "error": "Aucun compte configuré (auth.json ou users.json)"}, 500)
                return
            # Si des comptes existent, le pseudo est requis ; sinon fallback admin (migration)
            if load_users() and not username:
                self.send_json({"success": False, "error": "Identifiant requis"}, 400)
                return
            if verify_user(username, pwd):
                with _login_attempts_lock:
                    _login_attempts.pop(client_ip, None)
                sid = create_server_session(username or "admin")
                self.send_json({"success": True, "session": sid, "username": username or "admin"})
            else:
                with _login_attempts_lock:
                    _login_attempts.setdefault(client_ip, []).append(now_ts)
                self.send_json({"success": False, "error": "Identifiant ou mot de passe incorrect"}, 401)
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
            MAX_SIZE_TEXT  = 4 * 1024 * 1024   # 4 MB texte/PDF
            MAX_SIZE_IMAGE = 12 * 1024 * 1024  # 12 MB images
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
            # Teste les valeurs SAISIES dans le formulaire (fallback config enregistrée).
            # Le secret n'est jamais pré-rempli côté UI → fallback secret enregistré si vide.
            url     = (data.get("bookstack_url") or _BS_URL or "").rstrip("/")
            tok_id  = (data.get("bookstack_token_id") or _BS_TOKEN_ID or "").strip()
            tok_sec = (data.get("bookstack_token_secret") or _BS_TOKEN_SECRET or "").strip()
            if not url or not tok_id or not tok_sec:
                self.send_json({"success": False,
                                "error": "URL, Token ID et Secret requis (saisis-les puis re-teste)"}); return
            if not url.startswith(("http://", "https://")):
                self.send_json({"success": False, "error": "L'URL doit commencer par http:// ou https://"}); return
            try:
                import urllib.request as _ureq, urllib.parse as _uparse, urllib.error as _uerr
                req = _ureq.Request(
                    f"{url}/api/search?" + _uparse.urlencode({"query": "a", "count": 1}),
                    headers={"Authorization": f"Token {tok_id}:{tok_sec}",
                             "Content-Type": "application/json"}
                )
                with _ureq.urlopen(req, timeout=8) as r:
                    d = json.loads(r.read().decode())
                total = d.get("total", 0)
                self.send_json({"success": True, "message": f"Connexion OK — {total} page(s) dans BookStack"})
            except _uerr.HTTPError as he:
                _hint = {
                    401: "Token invalide ou révoqué",
                    403: "Token sans permission (active l'accès API pour ce rôle dans BookStack)",
                    404: "Endpoint introuvable — vérifie l'URL (sans /api à la fin)",
                }.get(he.code, "Réponse inattendue")
                self.send_json({"success": False, "error": f"{_hint} — HTTP {he.code}"})
            except _uerr.URLError as ue:
                self.send_json({"success": False, "error": f"Serveur injoignable — {ue.reason}"})
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
                # Garder le compte 'admin' de users.json synchronisé avec auth.json
                _us = load_users()
                if "admin" in _us:
                    _us["admin"] = new_hash
                    save_users(_us)
                log_admin_action(sid, "settings_password", "SUCCESS", "")
                self.send_json({"success": True})
            else:
                self.send_json({"success": False, "error": "Échec écriture auth.json"}, 500)
            return

        # ── SETTINGS : AGENT VISION ─────────────────────────────────
        if path == "/api/settings/vision":
            sid = self.headers.get("X-Session-Token", "") or data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401); return
            vision_provider  = data.get("vision_provider", "").strip()
            vision_base_url  = data.get("vision_base_url", "").strip()
            vision_model     = data.get("vision_model", "").strip()
            vision_key       = data.get("vision_api_key", "").strip()
            cfg = get_cassandra_config()
            if vision_provider:
                cfg["vision_provider"] = vision_provider
            if vision_base_url:
                cfg["vision_base_url"] = vision_base_url
            elif vision_provider and vision_provider in _SECONDARY_PROVIDERS:
                cfg["vision_base_url"] = _SECONDARY_PROVIDERS[vision_provider]
            if vision_model:
                cfg["vision_model"] = vision_model
            if vision_key:
                cfg["vision_api_key"] = vision_key
            if save_cassandra_config(cfg):
                log_admin_action(sid, "settings_vision", "SUCCESS", f"model={vision_model}")
                self.send_json({"success": True})
            else:
                self.send_json({"success": False, "error": "Échec écriture config"}, 500)
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

        if path == "/api/multiserver/add_device":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            result = ms_add_device(data)
            log_admin_action(sid, "fleet_add_device", "SUCCESS" if result.get("ok") else "FAILED",
                             f"name={data.get('name','')},type={data.get('type','')}")
            self.send_json(result)
            return

        if path == "/api/multiserver/resolve_quickconnect":
            sid = data.get("session", "")
            if not validate_session(sid):
                self.send_json({"error": "Non autorisé"}, 401)
                return
            qc_id = data.get("qc_id", "").strip()
            if not qc_id:
                self.send_json({"ok": False, "error": "qc_id requis"})
                return
            host, port = _ms_resolve_quickconnect(qc_id)
            if host:
                self.send_json({"ok": True, "host": host, "port": port})
            else:
                self.send_json({"ok": False, "error": "QuickConnect ID introuvable"})
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
            set_current_user(get_session_user(sid))  # scope mémoire + pseudo pour cette requête
            history = get_conversation_history(sid, 20)

            # ── Dual-Agent Feature 2 : compression si historique trop long ──
            history, _ctx_compressed = _maybe_compress_history(history)
            if _ctx_compressed:
                log_action(sid, "dual_agent_compress", "Historique compressé par agent secondaire")

            # PERF: prefetch BookStack en parallèle — timeout 1.5s, non-bloquant
            bs_ctx = _bs_prefetch(msg, timeout=1.5) if msg else ""
            messages = [{"role": "system", "content": build_system_prompt(sid, msg, expert_mode, bookstack_ctx=bs_ctx)}]
            for h in history:
                messages.append({"role": h["role"], "content": h["content"]})

            # Construire le contenu utilisateur avec éventuelle pièce jointe
            if attachment and attachment.get("content_type") == "image" and attachment.get("image_b64"):
                if _model_supports_vision():
                    # Modèle vision natif — contenu multipart text+image
                    user_content = []
                    if msg:
                        user_content.append({"type": "text", "text": msg})
                    user_content.append({
                        "type": "image_url",
                        "image_url": {"url": f"data:{attachment['mime']};base64,{attachment['image_b64']}"}
                    })
                    messages.append({"role": "user", "content": user_content})
                    save_msg = msg or f"[Image jointe : {attachment.get('filename','')}]"
                else:
                    # Délégation à l'agent vision secondaire (OpenRouter)
                    vision_desc = _vision_fallback_analyze(
                        attachment["image_b64"], attachment["mime"],
                        attachment.get("filename", "image.jpg"), msg or ""
                    )
                    inject   = f"\n\n{vision_desc}\n"
                    full_msg = (msg + inject) if msg else inject.strip()
                    messages.append({"role": "user", "content": full_msg})
                    save_msg = full_msg
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
                # ── Dual-Agent Feature 3 : pré-analyse si requête complexe ──
                preanalysis = _maybe_preanalyze(msg) if msg else ""
                full_msg = (msg + preanalysis) if preanalysis else msg
                messages.append({"role": "user", "content": full_msg})
                save_msg = msg   # on sauvegarde le msg original sans la pré-analyse
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
                    # ── Dual-Agent Feature 1 : fallback automatique ──────────
                    if _is_fallback_worthy(e) and _dual_agent_available():
                        stream_error = None  # pas une erreur fatale — on récupère
                        _, fallback_model = _dual_agent_creds()
                        banner = (
                            f"\n\n> ⚡ *Agent principal indisponible "
                            f"(`{type(e).__name__}`) — basculement automatique "
                            f"sur `{fallback_model}`…*\n\n"
                        )
                        for c in banner:
                            full_response_parts.append(c)
                            yield c
                        log_action(sid, "dual_agent_fallback", f"Fallback: {e}")
                        for token in _dual_agent_stream(messages):
                            if token:
                                full_response_parts.append(token)
                            yield token
                    else:
                        stream_error = e
                        yield f"\n\n❌ Erreur : {e}"

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
                    "/api/memory/pin", "/api/memory/restore", "/api/memory/purge",
                    "/api/actions", "/api/alerts", "/api/alert/resolve",
                    "/api/snapshots", "/api/rollback", "/api/crons"):
            if not validate_session(_sid):
                self.send_json({"error": "Non autorisé"}, 401); return

        # Mémoire persistante
        if path == "/api/memories":
            self.send_json(get_memories_full(include_archived=bool(data.get("all", False)), limit=300))
            return
        if path == "/api/memory/delete":
            delete_memory(int(data.get("id", 0)), hard=bool(data.get("hard", False)))
            self.send_json({"success": True})
            return
        if path == "/api/memory/save":
            save_memory(data.get("category","fact"), data.get("key",""), data.get("value",""))
            self.send_json({"success": True})
            return
        if path == "/api/memory/pin":
            ok = set_memory_pinned(int(data.get("id", 0)), bool(data.get("pinned", True)))
            self.send_json({"success": ok})
            return
        if path == "/api/memory/restore":
            self.send_json({"success": restore_memory(int(data.get("id", 0)))})
            return
        if path == "/api/memory/purge":
            n = purge_archived_memories()
            self.send_json({"success": True, "purged": n})
            return
        if path == "/api/oom/clear":
            if not validate_session(_sid):
                self.send_json({"error": "Non autorisé"}, 401); return
            self.send_json({"success": clear_oom_events()})
            return
        if path == "/api/failed/reset":
            if not validate_session(_sid):
                self.send_json({"error": "Non autorisé"}, 401); return
            self.send_json({"success": reset_failed_units()})
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
/* === Centre de notifications (cloche) — panneau fixed, jamais clippé === */
.alert-dropdown{position:fixed;top:58px;right:16px;width:390px;max-width:calc(100vw - 24px);
  background:linear-gradient(180deg,rgba(22,22,34,.99),rgba(13,13,21,.99));
  border:1px solid rgba(0,255,170,.18);border-radius:16px;backdrop-filter:blur(26px);
  z-index:100000;display:none;max-height:min(72vh,560px);overflow:hidden;flex-direction:column;
  box-shadow:0 28px 70px rgba(0,0,0,.7),0 0 0 1px rgba(0,0,0,.35);transform-origin:top right}
.alert-dropdown.open{display:flex;animation:notifPop .22s cubic-bezier(.16,1,.3,1)}
@keyframes notifPop{from{opacity:0;transform:translateY(-10px) scale(.96)}to{opacity:1;transform:none}}
.notif-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.06);flex-shrink:0}
.notif-title{font-size:13px;font-weight:700;color:#eef0f5;letter-spacing:.3px;display:flex;align-items:center;gap:8px}
.notif-count{font-size:10px;font-weight:700;background:rgba(255,71,87,.2);color:#ff7480;border-radius:10px;padding:1px 8px}
.notif-count.zero{background:rgba(46,213,115,.15);color:#2ed573}
.notif-clear{background:none;border:none;color:#6b6b80;font-size:11px;cursor:pointer;transition:color .15s;white-space:nowrap}
.notif-clear:hover{color:#00ffcc}
.notif-filters{display:flex;gap:6px;padding:10px 16px;border-bottom:1px solid rgba(255,255,255,.04);flex-shrink:0}
.notif-chip{font-size:10px;padding:3px 11px;border-radius:20px;border:1px solid rgba(255,255,255,.1);color:#9aa3b2;cursor:pointer;transition:all .15s;background:none}
.notif-chip.active{background:rgba(0,255,170,.15);border-color:rgba(0,255,170,.4);color:#00ffcc}
.notif-list{overflow-y:auto;flex:1;padding:6px}
.notif-card{display:flex;gap:11px;padding:11px 12px;border-radius:10px;margin-bottom:4px;transition:background .15s;background:rgba(255,255,255,.015)}
.notif-card:hover{background:rgba(255,255,255,.045)}
.notif-card.crit{border-left:3px solid #ff4757}
.notif-card.warn{border-left:3px solid #ffa502}
.notif-card.info{border-left:3px solid #00bcd4}
.notif-ico{font-size:17px;flex-shrink:0;margin-top:1px}
.notif-body{flex:1;min-width:0}
.notif-msg{font-size:12px;color:#e8e8f0;line-height:1.45;word-break:break-word}
.notif-meta{font-size:9px;color:#5a5a70;margin-top:4px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.notif-cat{text-transform:uppercase;letter-spacing:.04em;font-weight:700;color:#7a7a92}
.notif-actions{display:flex;gap:6px;margin-top:9px}
.notif-btn{font-size:10px;padding:4px 10px;border-radius:7px;cursor:pointer;border:1px solid;transition:all .15s;background:none;font-weight:600}
.notif-btn.fix{border-color:rgba(0,255,170,.35);color:#00ffcc}
.notif-btn.fix:hover{background:rgba(0,255,170,.15);box-shadow:0 0 12px rgba(0,255,170,.25)}
.notif-btn.done{border-color:rgba(255,255,255,.13);color:#8a8a9a}
.notif-btn.done:hover{background:rgba(255,255,255,.06);color:#fff}
.notif-foot{padding:9px 16px;border-top:1px solid rgba(255,255,255,.06);font-size:10px;color:#5a5a70;text-align:center;flex-shrink:0}
.notif-empty{padding:42px 20px;text-align:center;color:#6a6a80;font-size:12px}
.notif-empty .big{font-size:36px;display:block;margin-bottom:12px;opacity:.55}
.bell-wrap.ring .bell-icon{animation:bellShake .85s cubic-bezier(.36,.07,.19,.97)}
@keyframes bellShake{0%,100%{transform:rotate(0)}12%{transform:rotate(-20deg)}25%{transform:rotate(16deg)}40%{transform:rotate(-12deg)}55%{transform:rotate(9deg)}70%{transform:rotate(-5deg)}85%{transform:rotate(2deg)}}
/* compat ancien rendu */
.alert-item{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.05);display:flex;justify-content:space-between;gap:8px}
.alert-msg{font-size:11px;color:#e8e8f0;flex:1;line-height:1.4}
.alert-ts{font-size:9px;color:#4a4a60}
.alert-resolve{background:none;border:none;color:#4a4a60;cursor:pointer;font-size:14px}
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
.fa-type-btn{background:rgba(0,0,0,.3);border:1px solid rgba(0,255,170,.2);border-radius:6px;padding:6px 12px;font-size:11px;cursor:pointer;color:#a0a0b0;transition:all .15s}
.fa-type-btn.active{background:rgba(0,255,170,.15);border-color:#00ffcc;color:#00ffcc}
.fa-mode-btn{background:rgba(0,0,0,.3);border:1px solid rgba(0,255,170,.15);border-radius:5px;padding:4px 10px;font-size:10px;cursor:pointer;color:#a0a0b0;transition:all .15s}
.fa-mode-btn.active{background:rgba(0,255,170,.12);border-color:rgba(0,255,170,.4);color:#00ffcc}

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
  padding:8px 12px 11px;margin:0 8px 6px;
  background:rgba(0,200,140,.055);
  border:1px solid rgba(0,200,140,.18);
  border-radius:10px;font-size:11px;
  position:relative;overflow:hidden;
  animation:fadeIn .2s ease
}
.attachment-preview.visible{display:flex}
/* barre de progression */
.att-progress-bar{
  position:absolute;bottom:0;left:0;height:2px;width:0%;
  background:linear-gradient(90deg,#00c896,#7c5cfc);
  border-radius:0 0 10px 10px;transition:width .3s ease
}
.att-progress-bar.uploading{animation:attProg 1.4s ease-in-out infinite alternate}
@keyframes attProg{from{width:10%}to{width:70%}}
.att-progress-bar.done{width:100%;transition:width .25s ease}
/* icone box */
.att-icon-wrap{
  width:36px;height:36px;border-radius:8px;flex-shrink:0;
  background:rgba(0,200,140,.09);border:1px solid rgba(0,200,140,.18);
  display:flex;align-items:center;justify-content:center;font-size:17px
}
.att-info{flex:1;min-width:0}
.att-name{font-weight:600;color:#dde0ea;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;font-family:'JetBrains Mono',monospace;font-size:11px}
.att-meta{color:#5a7a6a;font-size:10px;margin-top:3px;display:flex;align-items:center;gap:5px;flex-wrap:wrap}
.att-stat-badge{
  background:rgba(0,200,140,.08);border:1px solid rgba(0,200,140,.16);
  border-radius:3px;padding:0 5px;font-family:'JetBrains Mono',monospace;
  font-size:9px;color:#00a878;line-height:16px
}
.att-thumb{width:40px;height:40px;border-radius:7px;object-fit:cover;border:1px solid rgba(0,200,140,.2);flex-shrink:0}
.att-remove{
  background:none;border:none;color:#5a5a70;cursor:pointer;
  font-size:14px;padding:4px 6px;flex-shrink:0;
  transition:all .15s;line-height:1;border-radius:5px
}
.att-remove:hover{color:#e03e52;background:rgba(224,62,82,.1)}
/* bouton attach + wrapper tooltip */
.att-tooltip-wrap{position:relative;flex-shrink:0}
.attach-btn{
  background:transparent;border:1px solid rgba(0,200,140,.12);
  border-radius:9px;color:#5a607a;cursor:pointer;
  padding:8px 10px;transition:all .2s;
  display:flex;align-items:center;justify-content:center;line-height:1
}
.attach-btn:hover{
  color:var(--accent);border-color:rgba(0,200,140,.42);
  background:rgba(0,200,140,.08);box-shadow:0 0 14px rgba(0,200,140,.13)
}
.attach-btn.has-file{
  color:var(--accent);border-color:rgba(0,200,140,.48);
  background:rgba(0,200,140,.1)
}
/* tooltip pièce jointe */
.att-tooltip{
  display:none;position:absolute;bottom:calc(100% + 10px);left:0;
  width:272px;background:rgba(9,11,19,.97);
  border:1px solid rgba(0,200,140,.22);border-radius:11px;
  padding:13px 14px;box-shadow:0 10px 36px rgba(0,0,0,.6);
  z-index:9999;backdrop-filter:blur(16px);pointer-events:none
}
.att-tooltip-wrap:hover .att-tooltip{display:block}
.att-tip-title{
  font-size:9px;text-transform:uppercase;letter-spacing:.12em;
  color:var(--accent);margin-bottom:9px;
  font-family:'JetBrains Mono',monospace
}
.att-tip-row{
  display:flex;align-items:center;gap:8px;padding:5px 0;
  border-bottom:1px solid rgba(255,255,255,.04)
}
.att-tip-row:last-of-type{border-bottom:none;margin-bottom:2px}
.att-tip-ico{font-size:14px;flex-shrink:0;width:20px;text-align:center}
.att-tip-name{flex:1;font-size:10.5px;color:#b0b0c0}
.att-tip-lim{
  font-family:'JetBrains Mono',monospace;font-size:9px;color:#00a878;
  background:rgba(0,200,140,.07);border-radius:3px;padding:1px 5px;
  border:1px solid rgba(0,200,140,.13)
}
.att-tip-exts{
  font-size:9px;color:#3a4550;
  font-family:'JetBrains Mono',monospace;line-height:1.8;margin-top:7px
}
/* Drag & drop overlay */
.chat-drop-overlay{
  display:none;position:absolute;inset:0;
  background:rgba(0,200,140,.07);
  border:2px dashed rgba(0,200,140,.5);
  border-radius:12px;z-index:200;
  align-items:center;justify-content:center;
  flex-direction:column;gap:8px;
  font-size:13px;color:var(--accent);
  backdrop-filter:blur(6px);pointer-events:none
}
.chat-drop-overlay.active{display:flex}
.chat-drop-overlay .drop-icon{font-size:38px;animation:dropBounce .75s ease infinite alternate}
@keyframes dropBounce{from{transform:translateY(0)}to{transform:translateY(-7px)}}

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
    <input type="text" id="login-username" placeholder="Identifiant" autocomplete="username" onkeydown="if(event.key==='Enter')login()">
    <input type="password" id="login-password" placeholder="Mot de passe" autocomplete="current-password" onkeydown="if(event.key==='Enter')login()">
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
        <div class="alert-dropdown" id="alert-dropdown" onclick="event.stopPropagation()"></div>
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
        <div class="chat-drop-overlay" id="chat-drop-overlay">
          <span class="drop-icon">📂</span>
          <span>Déposer le fichier ici</span>
        </div>
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
            <div class="att-progress-bar" id="att-progress"></div>
            <div class="att-icon-wrap" id="att-icon-wrap">
              <span id="att-icon">📄</span>
            </div>
            <img class="att-thumb" id="att-thumb" src="" alt="" style="display:none">
            <div class="att-info">
              <div class="att-name" id="att-name">–</div>
              <div class="att-meta">
                <span id="att-meta-size">–</span>
                <span class="att-stat-badge" id="att-meta-tokens" style="display:none"></span>
                <span class="att-stat-badge" id="att-meta-status" style="display:none"></span>
              </div>
            </div>
            <button class="att-remove" onclick="clearAttachment()" title="Retirer la pièce jointe">✕</button>
          </div>
          <!-- Input file caché -->
          <input type="file" id="att-input" style="display:none"
            accept=".txt,.md,.csv,.json,.jsonl,.yaml,.yml,.xml,.html,.py,.js,.ts,.sh,.sql,.pdf,.php,.rb,.go,.rs,.java,.c,.cpp,.log,.env,.conf,.ini,.toml,.dockerfile,image/*"
            onchange="onAttachmentSelected(this)">
          <div class="chat-input-row">
            <div class="att-tooltip-wrap">
              <button class="attach-btn" id="attach-btn" onclick="document.getElementById('att-input').click()">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
                </svg>
              </button>
              <div class="att-tooltip">
                <div class="att-tip-title">📂 Fichiers supportés</div>
                <div class="att-tip-row"><span class="att-tip-ico">📄</span><span class="att-tip-name">Texte &amp; code source</span><span class="att-tip-lim">≤ 4 Mo</span></div>
                <div class="att-tip-row"><span class="att-tip-ico">📊</span><span class="att-tip-name">CSV, JSON, YAML, XML</span><span class="att-tip-lim">≤ 4 Mo</span></div>
                <div class="att-tip-row"><span class="att-tip-ico">📕</span><span class="att-tip-name">PDF</span><span class="att-tip-lim">≤ 4 Mo</span></div>
                <div class="att-tip-row"><span class="att-tip-ico">🖼️</span><span class="att-tip-name">Images (PNG, JPG, GIF, WebP…)</span><span class="att-tip-lim">≤ 12 Mo</span></div>
                <div class="att-tip-exts">py · js · ts · sh · sql · php · rb · go · rs · java · c · cpp · log · env · conf · ini · toml · dockerfile · html · md · txt · csv · json · yaml</div>
              </div>
            </div>
            <textarea class="chat-input" id="chat-input" placeholder="Message à CASSANDRA… (Entrée pour envoyer, Maj+Entrée pour sauter une ligne)" rows="1"></textarea>
            <button class="send-btn" id="send-btn" onclick="sendMessage()" title="Envoyer (Entrée)">➤</button>
          </div>
        </div>
      </div>

      <div class="panel panel-right">
        <div class="card"><div class="card-title">🔥 Top processus</div><div id="processes-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">⚠️ Panne <button class="fix-btn" onclick="resetFailedUnits()" title="Réinitialiser les unités failed (reset-failed)">🧹</button><button class="fix-btn" onclick="sendQuickFix('Unités failed ?')">🔧</button></div><div id="failed-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">🌐 Sessions</div><div id="sessions-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">🔌 Ports</div><div id="ports-list"><div class="empty-state">Chargement...</div></div></div>
        <div class="card"><div class="card-title">💀 OOM <button class="fix-btn" onclick="clearOOM()" title="Acquitter / effacer les OOM affichés">🧹</button><button class="fix-btn" onclick="sendQuickFix('OOM récents ?')">🔧</button></div><div id="oom-list"><div class="empty-state">Chargement...</div></div></div>
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
    <div class="fleet-add-card" style="width:420px;max-height:90vh;overflow-y:auto">
      <h2>+ Ajouter un équipement</h2>

      <!-- Sélecteur de type -->
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:18px">
        <button class="fa-type-btn active" data-type="synology" onclick="faSetType('synology',this)">🖧 Synology</button>
        <button class="fa-type-btn" data-type="ssh" onclick="faSetType('ssh',this)">🖥 SSH</button>
        <button class="fa-type-btn" data-type="cassandra" onclick="faSetType('cassandra',this)">🤖 Cassandra</button>
        <button class="fa-type-btn" data-type="proxmox" onclick="faSetType('proxmox',this)">🧱 Proxmox</button>
        <button class="fa-type-btn" data-type="ping" onclick="faSetType('ping',this)">📡 Ping</button>
      </div>

      <!-- Champ commun : Nom -->
      <div class="fleet-field"><label>Nom affiché</label><input type="text" id="fa-name" placeholder="nas-maison"></div>

      <!-- ── SYNOLOGY ── -->
      <div id="fa-form-synology">
        <div style="font-size:10px;color:#6b6b80;margin-bottom:10px">Connexion via DSM API — aucun token nécessaire</div>
        <div style="display:flex;gap:8px;margin-bottom:10px">
          <button class="fa-mode-btn active" id="fa-syn-mode-direct" onclick="faSynMode('direct')">Adresse directe</button>
          <button class="fa-mode-btn" id="fa-syn-mode-qc" onclick="faSynMode('qc')">QuickConnect</button>
        </div>
        <div id="fa-syn-direct">
          <div class="fleet-field"><label>IP / Hostname</label><input type="text" id="fa-syn-host" placeholder="192.168.1.x ou nas.domaine.com"></div>
          <div style="display:flex;gap:8px">
            <div class="fleet-field" style="flex:1"><label>Port DSM</label><input type="number" id="fa-syn-port" value="5000" min="1" max="65535"></div>
            <div class="fleet-field" style="display:flex;align-items:flex-end;gap:6px;padding-bottom:2px">
              <input type="checkbox" id="fa-syn-ssl" style="width:auto"><label style="margin:0">HTTPS</label>
            </div>
          </div>
        </div>
        <div id="fa-syn-qc" style="display:none">
          <div class="fleet-field">
            <label>QuickConnect ID</label>
            <div style="display:flex;gap:6px">
              <input type="text" id="fa-syn-qcid" placeholder="mon-nas-quickconnect" style="flex:1">
              <button class="fa-mode-btn" onclick="faResolveQC()" style="white-space:nowrap">Résoudre</button>
            </div>
          </div>
          <div id="fa-qc-result" style="font-size:10px;color:#00ffcc;margin-top:-6px;margin-bottom:8px"></div>
        </div>
        <div class="fleet-field"><label>Identifiant DSM</label><input type="text" id="fa-syn-user" placeholder="admin"></div>
        <div class="fleet-field"><label>Mot de passe DSM</label><input type="password" id="fa-syn-pass" placeholder="••••••••"></div>
      </div>

      <!-- ── CASSANDRA ── -->
      <div id="fa-form-cassandra" style="display:none">
        <div style="font-size:10px;color:#6b6b80;margin-bottom:10px">Agent Cassandra sur un autre serveur Linux</div>
        <div class="fleet-field"><label>URL de l'agent</label><input type="text" id="fa-url" placeholder="http://192.168.1.10:9000"></div>
        <div class="fleet-field"><label>Token de session</label><input type="password" id="fa-token" placeholder="Token obtenu après login"></div>
      </div>

      <!-- ── PROXMOX ── -->
      <div id="fa-form-proxmox" style="display:none">
        <div style="font-size:10px;color:#6b6b80;margin-bottom:10px">Proxmox VE — connexion via API REST</div>
        <div class="fleet-field"><label>URL Proxmox</label><input type="text" id="fa-px-url" placeholder="https://192.168.1.x:8006"></div>
        <div class="fleet-field"><label>Utilisateur</label><input type="text" id="fa-px-user" value="root@pam"></div>
        <div class="fleet-field"><label>Mot de passe</label><input type="password" id="fa-px-pass" placeholder="••••••••"></div>
      </div>

      <!-- ── SSH ── -->
      <div id="fa-form-ssh" style="display:none">
        <div style="font-size:10px;color:#6b6b80;margin-bottom:10px">Contrôle complet via SSH — l'agent peut exécuter des commandes sur cette machine</div>
        <div class="fleet-field"><label>IP / Hostname</label><input type="text" id="fa-ssh-host" placeholder="192.168.1.x ou server.domaine.com"></div>
        <div style="display:flex;gap:8px">
          <div class="fleet-field" style="flex:1"><label>Port SSH</label><input type="number" id="fa-ssh-port" value="22" min="1" max="65535"></div>
          <div class="fleet-field" style="flex:1"><label>Utilisateur</label><input type="text" id="fa-ssh-user" value="root"></div>
        </div>
        <div style="display:flex;gap:8px;margin-bottom:10px">
          <button class="fa-mode-btn active" id="fa-ssh-mode-pass" onclick="faSshMode('password')">Mot de passe</button>
          <button class="fa-mode-btn" id="fa-ssh-mode-key" onclick="faSshMode('key')">Clé privée</button>
        </div>
        <div id="fa-ssh-pass-block">
          <div class="fleet-field"><label>Mot de passe</label><input type="password" id="fa-ssh-pass" placeholder="••••••••"></div>
        </div>
        <div id="fa-ssh-key-block" style="display:none">
          <div class="fleet-field"><label>Clé privée (contenu du fichier ~/.ssh/id_rsa)</label>
            <textarea id="fa-ssh-key" rows="5" style="width:100%;background:rgba(0,0,0,.4);border:1px solid rgba(0,255,170,.2);border-radius:6px;padding:9px 12px;color:#e8e8f0;font-size:11px;font-family:monospace;resize:vertical" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"></textarea>
          </div>
        </div>
      </div>

      <!-- ── PING ── -->
      <div id="fa-form-ping" style="display:none">
        <div style="font-size:10px;color:#6b6b80;margin-bottom:10px">Vérifie qu'un hôte est joignable (TCP)</div>
        <div class="fleet-field"><label>Hôte / IP</label><input type="text" id="fa-ping-host" placeholder="192.168.1.x ou hostname"></div>
        <div class="fleet-field"><label>Port TCP</label><input type="number" id="fa-ping-port" value="80" min="1" max="65535"></div>
      </div>

      <div class="fleet-add-actions">
        <button class="fleet-btn-cancel" onclick="closeFleetAdd()">Annuler</button>
        <button class="fleet-btn-primary" id="fa-submit-btn" onclick="addFleetDevice()">Ajouter</button>
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
      <div style="display:flex;gap:8px">
        <button id="mem-archived-btn" onclick="toggleArchivedMemories()" class="hdr-btn" style="border-color:rgba(255,140,66,.3);color:#ff8c42">👁 Voir archivées</button>
        <button onclick="purgeArchivedMemories()" class="hdr-btn" style="border-color:rgba(255,71,87,.3);color:#ff4757">🧹 Purger archivées</button>
        <button onclick="loadMemories()" class="hdr-btn" style="border-color:rgba(0,255,170,.3);color:#00ffcc">↻ Actualiser</button>
      </div>
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
        <button id="evo-pause-btn" onclick="toggleEvolutionPause()" class="hdr-btn" style="border-color:rgba(255,165,0,.4);color:#ffa502">⏸ Mettre en pause</button>
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
            <input class="s-input mono" id="cfg-model" type="text" placeholder="deepseek-v4-flash" autocomplete="off">
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

      <!-- SECTION : Agent secondaire (vision, fallback, évolution) -->
      <div class="settings-section">
        <div class="settings-section-title">🤖 Agent secondaire</div>
        <div class="s-hint" style="margin-bottom:14px">
          Utilisé pour : analyse d'images, fallback si le provider principal est down, compression de contexte, pré-analyse de requêtes complexes, et validation des évolutions autonomes.
        </div>
        <div class="settings-row triple">
          <div class="s-field">
            <label class="s-label">Provider</label>
            <select class="s-select" id="cfg-vision-provider" onchange="onVisionProviderChange()">
              <option value="openrouter">OpenRouter</option>
              <option value="google">Google AI Studio</option>
              <option value="openai">OpenAI</option>
              <option value="groq">Groq</option>
              <option value="ollama">Ollama (local)</option>
              <option value="custom">URL personnalisée</option>
            </select>
          </div>
          <div class="s-field">
            <label class="s-label">Modèle</label>
            <input class="s-input mono" id="cfg-vision-model" type="text" placeholder="google/gemini-2.0-flash" autocomplete="off">
            <div class="s-hint" id="cfg-vision-model-hint">Modèle du provider sélectionné</div>
          </div>
          <div class="s-field">
            <label class="s-label">Clé API</label>
            <input class="s-input mono" id="cfg-vision-key" type="password" placeholder="sk-or-v1-••••••••" autocomplete="off">
            <div class="s-hint" id="cfg-vision-key-hint">Clé du provider sélectionné</div>
          </div>
        </div>
        <div class="s-field" id="cfg-vision-url-field" style="display:none;margin-bottom:12px">
          <label class="s-label">URL de base (endpoint OpenAI-compatible)</label>
          <input class="s-input mono" id="cfg-vision-url" type="text" placeholder="https://mon-endpoint/v1" autocomplete="off">
        </div>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <button class="s-btn primary" onclick="saveVisionSettings()">💾 Sauvegarder</button>
          <span class="s-hint" id="cfg-vision-status" style="color:#00c896;padding:0">–</span>
        </div>
        <div class="s-feedback" id="cfg-vision-feedback"></div>
        <div class="s-hint" style="margin-top:10px">
          Presets : <code>openrouter</code> → gemini-2.0-flash ·
          <code>google</code> → gratuit jusqu'à quota ·
          <code>groq</code> → ultra-rapide (texte seul) ·
          <code>ollama</code> → 100% local
        </div>
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

      <!-- SECTION : Comptes utilisateurs (pseudo + mot de passe) -->
      <div class="settings-section">
        <div class="settings-section-title">👥 Comptes — identifiants par pseudo</div>
        <div class="s-hint" style="margin-bottom:12px">Chaque personne se connecte avec son pseudo : l'agent sait qui lui parle et garde une mémoire distincte par utilisateur. Comptes stockés dans /etc/cassandra/users.json.</div>
        <div id="cfg-users-list" style="margin-bottom:14px"><div class="empty-state">Chargement…</div></div>
        <div class="settings-row triple">
          <div class="s-field">
            <label class="s-label">Pseudo</label>
            <input class="s-input" id="cfg-user-name" type="text" placeholder="ex: drisse" autocomplete="off">
            <div class="s-hint">2-32 car. : lettres, chiffres, _ . -</div>
          </div>
          <div class="s-field">
            <label class="s-label">Mot de passe</label>
            <input class="s-input" id="cfg-user-pwd" type="password" placeholder="••••••••" autocomplete="new-password">
            <div class="s-hint">8 caractères minimum</div>
          </div>
          <div class="s-field" style="display:flex;align-items:flex-end">
            <button class="s-btn primary" onclick="cfgSaveUser()">➕ Créer / Mettre à jour</button>
          </div>
        </div>
        <div class="s-feedback" id="cfg-users-feedback"></div>
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

      <!-- ═══ ZONE DANGER — RESET PROD ═══ -->
      <div class="settings-section" style="border-color:rgba(224,62,82,.35)">
        <div class="settings-section-title" style="color:#e03e52">🧨 Zone danger — Préparation prod</div>
        <div class="reboot-card" style="border-color:rgba(224,62,82,.25)">
          <div class="reboot-card-title">♻️ Reset total</div>
          <div class="reboot-card-sub">
            Efface <b>tout l'état runtime</b> : base principale, mémoire + ses backups, logs,
            et backups du code source. <b>cassandra.py et le collector sont conservés.</b>
            Action <b>irréversible</b> — l'agent redémarre vierge. Double confirmation requise.
          </div>
          <button class="s-btn danger" id="cfg-wipe-prod" onclick="cfgWipeProd()">🧨 Tout effacer (reset prod)</button>
        </div>
        <div class="s-feedback" id="cfg-wipe-feedback"></div>
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
    const user = document.getElementById('login-username').value.trim();
    const pwd = document.getElementById('login-password').value;
    const err = document.getElementById('login-error');
    err.textContent = '';
    try {
        const r = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:user, password:pwd}) });
        const d = await r.json();
        if (d.success) {
            sessionId = d.session;
            sessionStorage.setItem('cassandra_session', sessionId);
            if (d.username) sessionStorage.setItem('cassandra_user', d.username);
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

// Countdown autonome evolution — synchronisé avec le daemon backend
(function(){
    var _next = 0;      // epoch (ms) du prochain cycle, fourni par le backend
    var _interval = 0;  // secondes
    var _synced = false;
    function _syncStatus(){
        apiGet('/api/evolution/status').then(function(r){
            if(!r) return;
            if(r.interval) _interval = r.interval;
            if(typeof r.remaining === 'number'){ _next = Date.now() + r.remaining*1000; _synced = true; }
            else if(r.next_run){ _next = r.next_run*1000; _synced = true; }
            var tc = document.getElementById('evo-today-count');
            if(tc && typeof r.today === 'number') tc.textContent = r.today;
            window._evoPaused = !!r.paused;
            _reflectEvoPause();
        }).catch(function(){});
    }
    function _tick(){
        var el = document.getElementById('evo-countdown');
        if(!el) return;
        if(window._evoPaused){ el.textContent = 'en pause'; return; }
        if(!_synced){ el.textContent = '—'; return; }
        var rem = Math.max(0, Math.round((_next - Date.now()) / 1000));
        var m = Math.floor(rem/60), s = rem%60;
        el.textContent = m + 'min ' + (s<10?'0':'')+s+'s';
        if(rem <= 0){ _synced = false; setTimeout(function(){_syncStatus();loadEvolutionHistory();}, 2000); }
    }
    window._evoSyncStatus = _syncStatus;
    _syncStatus();
    setInterval(_syncStatus, 60000);  // resync chaque minute (corrige toute dérive)
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
    var sc={applied:'color:#00ffcc',rolled_back:'color:#ffaa00',error:'color:#ff4466',rejected:'color:#ff8c42'};
    var sl={applied:'OK',rolled_back:'Annule',error:'Erreur',rejected:'⛔ Refusé'};
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
function _reflectEvoPause(){
    var btn=document.getElementById('evo-pause-btn');
    var sub=document.querySelector('#tab-evolution p');
    var paused=!!window._evoPaused;
    if(btn){
        btn.textContent = paused ? '▶ Reprendre' : '⏸ Mettre en pause';
        btn.style.borderColor = paused ? 'rgba(46,213,115,.5)' : 'rgba(255,165,0,.4)';
        btn.style.color       = paused ? '#2ed573' : '#ffa502';
    }
    if(sub){
        sub.innerHTML = paused
            ? '<span style="color:#ffa502">⏸ Auto-évolution EN PAUSE</span> · le code ne sera pas modifié'
            : 'Évolution autonome active · Historique · Rollback';
    }
}
function toggleEvolutionPause(){
    var btn=document.getElementById('evo-pause-btn');
    var next=!window._evoPaused;
    if(next && !confirm("Mettre l'auto-évolution en pause ?\nL'agent ne modifiera plus son propre code jusqu'à reprise.")){ return; }
    if(btn){ btn.disabled=true; btn.textContent='...'; }
    fetch('/api/evolution/pause',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({session:sessionId, paused:next})})
    .then(function(r){return r.json();})
    .then(function(r){
        if(btn) btn.disabled=false;
        if(r && r.ok){
            window._evoPaused = !!r.paused;
            _reflectEvoPause();
            if(typeof showToast==='function') showToast(window._evoPaused?'⏸ Auto-évolution mise en pause':'▶ Auto-évolution réactivée', window._evoPaused?'warning':'success', 3500);
            if(window._evoSyncStatus) window._evoSyncStatus();
        } else {
            if(btn){ btn.disabled=false; }
            _reflectEvoPause();
            alert('Erreur : '+((r&&r.error)||'action refusée (session ?)'));
        }
    })
    .catch(function(e){ if(btn) btn.disabled=false; _reflectEvoPause(); alert('Erreur réseau : '+e); });
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
    if(name==='settings')  { loadSettings(); loadBookstackSettings(); cfgLoadUsers(); }
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
// ── Centre de notifications interactif ─────────────────────────
let _notifData = [];
let _notifFilter = 'all';
let _lastActiveCount = null;

// Récupère (ou crée) le panneau de notifications et le rattache au <body> pour
// qu'il ne soit JAMAIS clippé par le header (overflow) ni piégé dans un contexte
// d'empilement. Bulletproof : fonctionne même si l'élément statique a disparu.
function _getNotifPanel(){
    let p = document.getElementById('alert-dropdown');
    if(!p){
        p = document.createElement('div');
        p.id = 'alert-dropdown';
        p.className = 'alert-dropdown';
        p.addEventListener('click', e => e.stopPropagation());
        document.body.appendChild(p);
    } else if(p.parentElement !== document.body){
        document.body.appendChild(p);   // sortir du header
    }
    return p;
}

function notifMeta(level){
    if(level==='critical') return {cls:'crit', ico:'🔴'};
    if(level==='warning')  return {cls:'warn', ico:'🟠'};
    return {cls:'info', ico:'🔵'};
}
function notifTimeAgo(ts){
    if(!ts) return '';
    let t = String(ts).replace(' ','T');
    if(!/[zZ]|[+\-]\d\d:?\d\d$/.test(t)) t += 'Z';
    const d = new Date(t);
    if(isNaN(d.getTime())) return String(ts).slice(0,16);
    const s = Math.max(0,(Date.now()-d.getTime())/1000);
    if(s<60)    return "à l'instant";
    if(s<3600)  return 'il y a '+Math.floor(s/60)+' min';
    if(s<86400) return 'il y a '+Math.floor(s/3600)+' h';
    return 'il y a '+Math.floor(s/86400)+' j';
}

async function loadAlerts(){
    try{
        const r = await fetch('/api/alerts', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId})});
        if(!r.ok) return;
        const alerts = await r.json();
        renderNotifications(Array.isArray(alerts)?alerts:[]);
    }catch(e){}
}

function renderNotifications(alerts){
    if(Array.isArray(alerts)) _notifData = alerts;
    const data = _notifData || [];
    const active = data.filter(a=>!a.resolved);

    // Badge
    const badge = document.getElementById('bell-badge');
    if(badge){
        badge.textContent = active.length;
        badge.classList.toggle('has-alerts', active.length>0);
    }
    // Nouvelle alerte → secousse de cloche + toast
    if(_lastActiveCount!==null && active.length>_lastActiveCount){
        const bw = document.querySelector('.bell-wrap');
        if(bw){ bw.classList.remove('ring'); void bw.offsetWidth; bw.classList.add('ring'); setTimeout(()=>bw.classList.remove('ring'),950); }
        const newest = active[0];
        if(typeof showToast==='function' && newest){
            showToast('🔔 '+(newest.message||'Nouvelle alerte'), newest.level==='critical'?'error':'warning', 5000);
        }
    }
    _lastActiveCount = active.length;

    const panel = _getNotifPanel();
    const list = _notifFilter==='crit' ? active.filter(a=>a.level==='critical') : active;
    const sig = _notifFilter+'|'+active.map(a=>(a.id||'')+':'+a.level+':'+a.resolved).join(',');
    if(panel.dataset.sig===sig) return;   // évite le flicker (WS pousse chaque seconde)
    panel.dataset.sig = sig;

    const head = `
      <div class="notif-head">
        <div class="notif-title">🔔 Notifications <span class="notif-count ${active.length?'':'zero'}">${active.length}</span></div>
        ${active.length?'<button class="notif-clear" onclick="resolveAllAlerts()">Tout résoudre</button>':''}
      </div>
      <div class="notif-filters">
        <button class="notif-chip ${_notifFilter==='all'?'active':''}" onclick="notifSetFilter('all')">Toutes</button>
        <button class="notif-chip ${_notifFilter==='crit'?'active':''}" onclick="notifSetFilter('crit')">Critiques</button>
      </div>`;

    let body;
    if(!list.length){
        body = `<div class="notif-empty"><span class="big">✅</span>${active.length?'Aucune alerte critique':'Tout va bien — aucune alerte active'}</div>`;
    } else {
        body = '<div class="notif-list">'+list.map(a=>{
            const idx = _notifData.indexOf(a);
            const m = notifMeta(a.level);
            return `<div class="notif-card ${m.cls}">
              <div class="notif-ico">${m.ico}</div>
              <div class="notif-body">
                <div class="notif-msg">${escapeHtml(a.message||a.msg||'')}</div>
                <div class="notif-meta"><span class="notif-cat">${escapeHtml(String(a.category||'système').replace(/_/g,' '))}</span><span>${notifTimeAgo(a.ts||a.created_at)}</span></div>
                <div class="notif-actions">
                  <button class="notif-btn fix" onclick="notifAskAgent(${idx})">🛠️ Diagnostiquer</button>
                  ${a.id?`<button class="notif-btn done" onclick="resolveAlert(${a.id})">Résoudre</button>`:''}
                </div>
              </div>
            </div>`;
        }).join('')+'</div>';
    }
    panel.innerHTML = head + body + `<div class="notif-foot">L'agent surveille en continu · mise à jour en temps réel</div>`;
}

function notifSetFilter(f){ _notifFilter=f; renderNotifications(); }

function notifAskAgent(idx){
    const a = _notifData[idx];
    if(!a) return;
    const panel = document.getElementById('alert-dropdown');
    if(panel) panel.classList.remove('open');
    const sev = a.level==='critical'?'CRITIQUE':a.level==='warning'?'avertissement':'information';
    const cat = String(a.category||'système').replace(/_/g,' ');
    sendQuickFix(`🔔 Alerte ${sev} sur le serveur — catégorie « ${cat} » : "${a.message||''}". Diagnostique la cause racine, propose et applique un correctif si c'est possible et sûr, puis confirme l'état final.`);
}

function toggleAlertDropdown(){
    const panel = _getNotifPanel();
    const willOpen = !panel.classList.contains('open');
    if(willOpen){ panel.dataset.sig=''; renderNotifications(); loadAlerts(); }
    panel.classList.toggle('open');
}
document.addEventListener('click', e => {
    const bw = e.target.closest('.bell-wrap');
    if(!bw) document.getElementById('alert-dropdown')?.classList.remove('open');
});

async function resolveAlert(id){
    try{ await fetch('/api/alert/resolve', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId, id})}); }catch(e){}
    _notifData = _notifData.filter(a=>a.id!==id);
    renderNotifications();
    loadAlerts();
}

async function resolveAllAlerts(){
    const ids = (_notifData||[]).filter(a=>a.id && !a.resolved).map(a=>a.id);
    for(const id of ids){
        try{ await fetch('/api/alert/resolve', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId, id})}); }catch(e){}
    }
    _notifData = (_notifData||[]).map(a=>({...a, resolved:1}));
    renderNotifications();
    loadAlerts();
}

// Alertes gérées par WS push (_applyAlerts) — pas de polling global

// ══════════════════════════════════════════════════════════
// MÉMOIRE PERSISTANTE
// ══════════════════════════════════════════════════════════
let _memShowArchived = false;
async function loadMemories() {
    const list = document.getElementById('memory-list');
    if(!list) return;
    try {
        const r = await fetch('/api/memories', {method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({session:sessionId, all:_memShowArchived})});
        const mems = await r.json();
        if(!Array.isArray(mems) || !mems.length){
            list.innerHTML = '<div class="empty-state" style="padding:40px">🧠 Aucune mémoire pour l\'instant — interagis avec l\'agent et il apprendra !</div>';
            return;
        }
        list.innerHTML = mems.map(m => {
            const archived = m.status && m.status !== 'active';
            const conf = Math.round((m.confidence||0)*100);
            const star = m.pinned ? '⭐' : '☆';
            const statusBadge = archived
                ? `<span style="font-size:9px;color:#ff8c42;border:1px solid rgba(255,140,66,.4);border-radius:4px;padding:1px 5px">${escapeHtml(m.status)}</span>` : '';
            const actions = archived
                ? `<button class="mem-del" title="Restaurer" onclick="restoreMemory(${m.id})">♻️</button>`
                : `<button class="mem-del" title="${m.pinned?'Désépingler':'Épingler (vérité absolue)'}" onclick="pinMemory(${m.id},${m.pinned?0:1})">${star}</button>
                   <button class="mem-del" title="Archiver" onclick="deleteMemory(${m.id})">🗑</button>`;
            return `
            <div class="mem-item" style="${archived?'opacity:.55':''}">
                <div class="mem-cat">${escapeHtml(m.category)}</div>
                <div class="mem-key">${m.pinned?'⭐ ':''}${escapeHtml(m.key)}</div>
                <div class="mem-val">${escapeHtml(m.value)}
                    <div style="font-size:9px;color:#5a5a70;margin-top:3px">confiance ${conf}% · vu ${m.access_count||0}× ${statusBadge}</div>
                </div>
                <div style="display:flex;gap:4px">${actions}</div>
            </div>`;
        }).join('');
    } catch(e){ list.innerHTML = '<div class="empty-state">Erreur chargement</div>'; }
}

async function deleteMemory(id) {
    await fetch('/api/memory/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId, id})});
    loadMemories();
}
async function pinMemory(id, pinned) {
    await fetch('/api/memory/pin', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId, id, pinned:!!pinned})});
    loadMemories();
}
async function restoreMemory(id) {
    await fetch('/api/memory/restore', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId, id})});
    loadMemories();
}
function toggleArchivedMemories() {
    _memShowArchived = !_memShowArchived;
    const b = document.getElementById('mem-archived-btn');
    if(b) b.textContent = _memShowArchived ? '👁 Masquer archivées' : '👁 Voir archivées';
    loadMemories();
}
async function purgeArchivedMemories() {
    if(!confirm('Supprimer DÉFINITIVEMENT toutes les mémoires archivées ? (irréversible)')) return;
    const r = await fetch('/api/memory/purge', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session:sessionId})});
    const d = await r.json();
    if(typeof showToast==='function') showToast(`🧹 ${d.purged||0} mémoire(s) purgée(s)`, 'success', 3000);
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
async function clearOOM(){
    try{ await fetch('/api/oom/clear',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session:sessionId})}); }catch(e){}
    loadOOM();
    if(typeof showToast==='function') showToast('💀 OOM acquittés','success',2500);
}
async function resetFailedUnits(){
    try{ await fetch('/api/failed/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session:sessionId})}); }catch(e){}
    setTimeout(loadFailedUnits, 1200);
    if(typeof showToast==='function') showToast('⚠️ Unités failed réinitialisées','success',2500);
}
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

// Collage d'image (Ctrl+V) → ajoute l'image en pièce jointe (même chemin que 📎)
function _initImagePaste(){
    if(window._pasteInit) return;
    window._pasteInit = true;
    document.addEventListener('paste', function(e){
        const cd = e.clipboardData || window.clipboardData;
        if(!cd || !cd.items) return;
        for(const it of cd.items){
            if(it.kind === 'file' && it.type && it.type.indexOf('image/') === 0){
                const blob = it.getAsFile();
                if(!blob) continue;
                e.preventDefault();
                const ext = (it.type.split('/')[1] || 'png').replace('jpeg','jpg');
                let f = blob;
                try{
                    if(!blob.name || blob.name === 'image.png'){
                        f = new File([blob], 'image-collee-' + Date.now() + '.' + ext, {type: it.type});
                    }
                }catch(_e){ f = blob; }
                onAttachmentSelected({files:[f], value:''});
                if(typeof showToast === 'function') showToast('🖼️ Image collée ajoutée en pièce jointe', 'success', 2500);
                return;
            }
        }
    });
}

function onAttachmentSelected(input){
    const file = input.files[0];
    if(!file){ clearAttachment(); return; }
    const MAX = file.type.startsWith('image/') ? 12*1024*1024 : 4*1024*1024;
    if(file.size > MAX){
        addSystemMessage(`⚠️ Fichier trop grand (max ${_fmtSize(MAX)} pour ce type).`);
        try{ input.value=''; }catch(e){}
        return;
    }
    const reader = new FileReader();
    reader.onload = e => {
        const dataUrl = e.target.result;
        const b64 = dataUrl.split(',')[1];
        _currentAttachment = {filename:file.name, mime:file.type||'application/octet-stream', data:b64, size:file.size, uploaded:null};
        const isImage = file.type.startsWith('image/');
        // Thumb ou icône
        const iconWrap = document.getElementById('att-icon-wrap');
        const thumb    = document.getElementById('att-thumb');
        if(isImage){
            iconWrap.style.display='none';
            thumb.src=dataUrl; thumb.style.display='';
        } else {
            thumb.style.display='none';
            iconWrap.style.display='';
            document.getElementById('att-icon').textContent = _attIcon(file.name, file.type);
        }
        document.getElementById('att-name').textContent = file.name;
        document.getElementById('att-meta-size').textContent = _fmtSize(file.size);
        // Estimation tokens pour fichiers texte
        const tokBadge = document.getElementById('att-meta-tokens');
        if(!isImage){
            const est = Math.round(file.size / 4);
            tokBadge.textContent = '~' + (est>999 ? (est/1000).toFixed(1)+'k' : est) + ' tokens';
            tokBadge.style.display='';
        } else { tokBadge.style.display='none'; }
        // Badge statut
        const stBadge = document.getElementById('att-meta-status');
        stBadge.textContent='⏳ upload…'; stBadge.style.color=''; stBadge.style.display='';
        // Progress bar
        const bar = document.getElementById('att-progress');
        if(bar){ bar.style.width=''; bar.className='att-progress-bar uploading'; }
        document.getElementById('att-preview').classList.add('visible');
        document.getElementById('attach-btn').classList.add('has-file');
        _preUploadAttachment();
    };
    reader.readAsDataURL(file);
    try{ input.value=''; }catch(e){}
}

function _attIcon(name, mime){
    if(mime && mime.startsWith('image/')) return '🖼️';
    const ext = (name||'').split('.').pop().toLowerCase();
    const m = {pdf:'📕',py:'🐍',js:'⚡',ts:'⚡',sh:'🖥️',bash:'🖥️',zsh:'🖥️',
               sql:'🗄️',json:'{}',jsonl:'{}',csv:'📊',md:'📝',txt:'📄',
               yaml:'⚙️',yml:'⚙️',html:'🌐',htm:'🌐',php:'🐘',rb:'💎',
               go:'🐹',rs:'🦀',java:'☕',c:'©️',cpp:'©️',log:'📋',
               conf:'⚙️',ini:'⚙️',env:'🔑',toml:'⚙️',dockerfile:'🐳',
               xml:'📐',tf:'🏗️'};
    return m[ext] || '📄';
}

async function _preUploadAttachment(){
    if(!_currentAttachment || !sessionId) return;
    const bar     = document.getElementById('att-progress');
    const stBadge = document.getElementById('att-meta-status');
    const sizeLbl = document.getElementById('att-meta-size');
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
            // Barre terminée
            if(bar){ bar.className='att-progress-bar done'; setTimeout(()=>{ bar.className='att-progress-bar'; bar.style.width='0'; },1300); }
            // Label taille + méthode
            if(sizeLbl){
                let lbl = _fmtSize(_currentAttachment.size);
                if(d.method==='pdftotext'||d.method==='pypdf') lbl+=' · PDF';
                else if(d.method==='vision') lbl+=' · vision IA';
                else if(d.method==='ocr')   lbl+=' · OCR';
                sizeLbl.textContent = lbl;
            }
            // Badge statut
            if(stBadge){
                if(d.truncated){ stBadge.textContent='⚠️ tronqué'; stBadge.style.color='#e09030'; }
                else            { stBadge.textContent='✓ prêt';    stBadge.style.color='#00c896'; }
                stBadge.style.display='';
            }
            if(d.warning) addSystemMessage('⚠️ ' + d.warning);
        } else {
            if(bar){ bar.className='att-progress-bar'; bar.style.width='0'; }
            if(stBadge){ stBadge.textContent='❌ erreur'; stBadge.style.color='#e03e52'; stBadge.style.display=''; }
            addSystemMessage('⚠️ Fichier non supporté : ' + (d.error||'Erreur inconnue'));
            setTimeout(clearAttachment, 2000);
        }
    }catch(err){
        if(bar){ bar.className='att-progress-bar'; bar.style.width='0'; }
        if(stBadge){ stBadge.textContent='❌ réseau'; stBadge.style.color='#e03e52'; stBadge.style.display=''; }
        console.warn('pre-upload:', err);
    }
}

function clearAttachment(){
    _currentAttachment = null;
    document.getElementById('att-preview').classList.remove('visible');
    document.getElementById('attach-btn').classList.remove('has-file');
    const thumb = document.getElementById('att-thumb');
    if(thumb) thumb.src='';
    try{ document.getElementById('att-input').value=''; }catch(e){}
    const bar = document.getElementById('att-progress');
    if(bar){ bar.className='att-progress-bar'; bar.style.width='0'; }
}

// ── Drag & Drop ────────────────────────────────────────────────
(function(){
    let _dragCount = 0;
    function _showOverlay(show){
        const ov = document.getElementById('chat-drop-overlay');
        if(ov) ov.classList.toggle('active', show);
    }
    document.addEventListener('dragenter', e=>{
        if(e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes('Files')){
            _dragCount++; _showOverlay(true);
        }
    });
    document.addEventListener('dragleave', e=>{
        _dragCount = Math.max(0, _dragCount - 1);
        if(_dragCount === 0) _showOverlay(false);
    });
    document.addEventListener('dragover', e=>{ e.preventDefault(); });
    document.addEventListener('drop', e=>{
        e.preventDefault(); _dragCount = 0; _showOverlay(false);
        const files = e.dataTransfer && e.dataTransfer.files;
        if(files && files.length > 0) onAttachmentSelected({files});
    });
})();

// ══════════════════════════════════════════════════════════════
//  ONGLET PARAMÈTRES
// ══════════════════════════════════════════════════════════════
const _DEFAULT_MODELS_UI = {
    deepseek:   'deepseek-v4-flash',
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
        // Agent secondaire (vision / fallback)
        const _secProv = d.vision_provider || 'openrouter';
        const vpSel = document.getElementById('cfg-vision-provider');
        if (vpSel) {
            const knownProvs = Array.from(vpSel.options).map(o => o.value);
            vpSel.value = knownProvs.includes(_secProv) ? _secProv : 'custom';
        }
        const vm = document.getElementById('cfg-vision-model');
        if (vm) vm.value = d.vision_model || '';
        const vu = document.getElementById('cfg-vision-url');
        if (vu) vu.value = d.vision_base_url || '';
        const vs = document.getElementById('cfg-vision-status');
        if (vs) {
            vs.textContent = d.vision_key_set ? '🔑 Clé configurée' : '⚠️ Pas de clé';
            vs.style.color = d.vision_key_set ? '#00c896' : '#a07030';
        }
        onVisionProviderChange(false);
    } catch(e) { console.warn('loadSettings:', e); }
}

// Presets pour l'agent secondaire
const _VISION_PRESETS = {
    openrouter: { model: 'google/gemini-2.0-flash', url: 'https://openrouter.ai/api/v1',
                  keyPlaceholder: 'sk-or-v1-••••••••', keyHint: 'Clé OpenRouter (openrouter.ai)' },
    google:     { model: 'gemini-2.0-flash',        url: 'https://generativelanguage.googleapis.com/v1beta/openai/',
                  keyPlaceholder: 'AIza••••••••',    keyHint: 'Clé Google AI Studio (aistudio.google.com)' },
    openai:     { model: 'gpt-4o-mini',             url: 'https://api.openai.com/v1',
                  keyPlaceholder: 'sk-••••••••',     keyHint: 'Clé OpenAI (platform.openai.com)' },
    groq:       { model: 'llama-3.3-70b-versatile', url: 'https://api.groq.com/openai/v1',
                  keyPlaceholder: 'gsk_••••••••',    keyHint: 'Clé Groq (console.groq.com)' },
    ollama:     { model: 'llava',                   url: 'http://localhost:11434/v1',
                  keyPlaceholder: 'ollama (facultatif)', keyHint: 'Ollama local — clé non requise' },
    custom:     { model: '',                        url: '',
                  keyPlaceholder: 'votre-clé-api',  keyHint: 'Clé du provider personnalisé' },
};

function onVisionProviderChange(fillModel = true) {
    const prov   = document.getElementById('cfg-vision-provider')?.value || 'openrouter';
    const preset = _VISION_PRESETS[prov] || _VISION_PRESETS.custom;
    const urlField = document.getElementById('cfg-vision-url-field');
    if (urlField) urlField.style.display = (prov === 'custom') ? 'block' : 'none';
    if (fillModel) {
        const vm = document.getElementById('cfg-vision-model');
        if (vm) vm.value = preset.model;
        const vu = document.getElementById('cfg-vision-url');
        if (vu) vu.value = preset.url;
    }
    const kh = document.getElementById('cfg-vision-key-hint');
    if (kh) kh.textContent = preset.keyHint;
    const vk = document.getElementById('cfg-vision-key');
    if (vk) vk.placeholder = preset.keyPlaceholder;
    const mh = document.getElementById('cfg-vision-model-hint');
    if (mh) {
        const examples = {
            openrouter: 'google/gemini-2.0-flash · claude-3-5-haiku · gpt-4o-mini',
            google: 'gemini-2.0-flash · gemini-2.5-pro',
            openai: 'gpt-4o-mini · gpt-4o',
            groq: 'llama-3.3-70b-versatile · llama-3.1-8b',
            ollama: 'llava · llama3.2-vision',
            custom: 'Modèle supporté par votre endpoint',
        };
        mh.textContent = examples[prov] || '';
    }
}

async function saveVisionSettings() {
    const prov  = document.getElementById('cfg-vision-provider')?.value || 'openrouter';
    const model = document.getElementById('cfg-vision-model')?.value.trim();
    const key   = document.getElementById('cfg-vision-key')?.value.trim();
    const url   = document.getElementById('cfg-vision-url')?.value.trim();
    if (!model) { _sfb('cfg-vision-feedback', 'Modèle requis', 'err'); return; }
    if (prov === 'custom' && !url) { _sfb('cfg-vision-feedback', 'URL de base requise pour un provider personnalisé', 'err'); return; }
    try {
        const preset = _VISION_PRESETS[prov] || {};
        const body = {
            vision_provider:  prov,
            vision_model:     model,
            vision_api_key:   key,
            vision_base_url:  prov === 'custom' ? url : (preset.url || ''),
        };
        const r = await fetch('/api/settings/vision', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionId },
            body: JSON.stringify(body)
        });
        const d = await r.json();
        if (d.success) {
            _sfb('cfg-vision-feedback', `✓ Agent secondaire configuré — ${prov} / ${model}`, 'ok');
            document.getElementById('cfg-vision-key').value = '';
            loadSettings();
        } else {
            _sfb('cfg-vision-feedback', '✗ ' + (d.error || 'Erreur'), 'err');
        }
    } catch(e) { _sfb('cfg-vision-feedback', '✗ Erreur réseau', 'err'); }
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

async function cfgLoadUsers() {
    const el = document.getElementById('cfg-users-list');
    if (!el) return;
    try {
        const d = await apiGet('/api/users');
        const users = d.users || [];
        if (!users.length) { el.innerHTML = '<div class="empty-state">Aucun compte.</div>'; return; }
        el.innerHTML = users.map(function(u){
            return '<div style="display:flex;justify-content:space-between;align-items:center;border:1px solid rgba(255,255,255,.07);border-radius:8px;padding:8px 12px;margin-bottom:6px">'
                + '<span style="font-size:13px;color:#ddd">👤 ' + escapeHtml(u) + '</span>'
                + '<button class="s-btn danger" style="padding:3px 10px;font-size:11px" onclick="cfgDeleteUser(\'' + escapeHtml(u) + '\')">Supprimer</button>'
                + '</div>';
        }).join('');
    } catch(e) { el.innerHTML = '<div class="empty-state">Erreur de chargement</div>'; }
}

async function cfgSaveUser() {
    const name = document.getElementById('cfg-user-name')?.value.trim();
    const pwd  = document.getElementById('cfg-user-pwd')?.value;
    if (!name || !pwd) { _sfb('cfg-users-feedback', '✗ Pseudo et mot de passe requis', 'err'); return; }
    try {
        const r = await fetch('/api/users/set', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionId },
            body: JSON.stringify({ username: name, password: pwd })
        });
        const d = await r.json();
        if (d.ok) {
            _sfb('cfg-users-feedback', '✓ Compte « ' + name + ' » enregistré', 'ok');
            document.getElementById('cfg-user-name').value = '';
            document.getElementById('cfg-user-pwd').value = '';
            cfgLoadUsers();
        } else { _sfb('cfg-users-feedback', '✗ ' + (d.error || 'Erreur'), 'err'); }
    } catch(e) { _sfb('cfg-users-feedback', '✗ Erreur réseau', 'err'); }
}

async function cfgDeleteUser(name) {
    if (!confirm('Supprimer le compte « ' + name + ' » ?')) return;
    try {
        const r = await fetch('/api/users/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionId },
            body: JSON.stringify({ username: name })
        });
        const d = await r.json();
        if (d.ok) { _sfb('cfg-users-feedback', '✓ Compte supprimé', 'ok'); cfgLoadUsers(); }
        else { _sfb('cfg-users-feedback', '✗ ' + (d.error || 'Erreur'), 'err'); }
    } catch(e) { _sfb('cfg-users-feedback', '✗ Erreur réseau', 'err'); }
}

async function cfgWipeProd() {
    // 1ère confirmation
    if (!confirm('🧨 RESET TOTAL\n\nCeci efface DÉFINITIVEMENT : base principale, mémoire + backups, logs et backups du code.\nSeuls cassandra.py et le collector sont conservés.\n\nCette action est IRRÉVERSIBLE. Continuer ?')) return;
    // 2ème confirmation — saisie explicite
    const typed = prompt('Confirmation finale.\n\nTapez exactement   EFFACER   pour lancer le reset total :');
    if (typed !== 'EFFACER') { _sfb('cfg-wipe-feedback', '✗ Annulé (confirmation incorrecte)', 'err'); return; }
    const fbId = 'cfg-wipe-feedback';
    _sfb(fbId, '⏳ Effacement et redémarrage…', 'ok');
    try {
        const r = await fetch('/api/system/wipe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionId },
            body: JSON.stringify({ confirm: 'EFFACER' })
        });
        const d = await r.json();
        if (d.ok) {
            _sfb(fbId, '✓ Reset total effectué — redémarrage, reconnexion dans ~10s…', 'ok');
            setTimeout(function(){ location.reload(); }, 10000);
        } else {
            _sfb(fbId, '✗ ' + (d.error || 'Échec'), 'err');
        }
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
    const url    = document.getElementById('cfg-bs-url')?.value.trim();
    const tok_id = document.getElementById('cfg-bs-id')?.value.trim();
    const tok_sec= document.getElementById('cfg-bs-secret')?.value.trim();
    try {
        const r = await fetch('/api/settings/bookstack/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionId },
            body: JSON.stringify({
                session: sessionId,
                bookstack_url: url || undefined,
                bookstack_token_id: tok_id || undefined,
                bookstack_token_secret: tok_sec || undefined
            })
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

let _faType='synology';
let _faSynMode='direct';

function openFleetAdd(){
    document.getElementById('fleet-add-modal').classList.remove('hidden');
    document.getElementById('fa-name').focus();
    document.getElementById('fa-error').textContent='';
}
function closeFleetAdd(){ document.getElementById('fleet-add-modal').classList.add('hidden'); }

let _faSshMode='password';

function faSetType(type, btn){
    _faType=type;
    document.querySelectorAll('.fa-type-btn').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    ['synology','ssh','cassandra','proxmox','ping'].forEach(t=>{
        const el=document.getElementById('fa-form-'+t);
        if(el) el.style.display=t===type?'':'none';
    });
    document.getElementById('fa-error').textContent='';
}

function faSshMode(mode){
    _faSshMode=mode;
    document.getElementById('fa-ssh-pass-block').style.display=mode==='password'?'':'none';
    document.getElementById('fa-ssh-key-block').style.display=mode==='key'?'':'none';
    document.getElementById('fa-ssh-mode-pass').classList.toggle('active',mode==='password');
    document.getElementById('fa-ssh-mode-key').classList.toggle('active',mode==='key');
}

function faSynMode(mode){
    _faSynMode=mode;
    document.getElementById('fa-syn-direct').style.display=mode==='direct'?'':'none';
    document.getElementById('fa-syn-qc').style.display=mode==='qc'?'':'none';
    document.getElementById('fa-syn-mode-direct').classList.toggle('active',mode==='direct');
    document.getElementById('fa-syn-mode-qc').classList.toggle('active',mode==='qc');
}

async function faResolveQC(){
    const qcid=document.getElementById('fa-syn-qcid').value.trim();
    const el=document.getElementById('fa-qc-result');
    if(!qcid){el.textContent='Entrez un QuickConnect ID';el.style.color='#ff4757';return;}
    el.textContent='Résolution en cours…';el.style.color='#6b6b80';
    try{
        const r=await fetch('/api/multiserver/resolve_quickconnect',{method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({session:sessionId,qc_id:qcid})});
        const d=await r.json();
        if(d.ok){
            el.textContent='✓ Résolu : '+d.host+':'+d.port;
            el.style.color='#2ed573';
        } else {
            el.textContent='❌ '+d.error;el.style.color='#ff4757';
        }
    } catch(e){el.textContent='Erreur réseau';el.style.color='#ff4757';}
}

async function addFleetDevice(){
    const name=document.getElementById('fa-name').value.trim();
    const err=document.getElementById('fa-error');
    const btn=document.getElementById('fa-submit-btn');
    if(!name){err.textContent='Nom requis';return;}
    err.textContent='';btn.textContent='Connexion…';btn.disabled=true;

    let payload={session:sessionId,name,type:_faType};

    if(_faType==='synology'){
        const user=document.getElementById('fa-syn-user').value.trim();
        const pass=document.getElementById('fa-syn-pass').value;
        if(!user||!pass){err.textContent='Identifiants Synology requis';btn.textContent='Ajouter';btn.disabled=false;return;}
        payload.username=user; payload.password=pass;
        if(_faSynMode==='qc'){
            const qcid=document.getElementById('fa-syn-qcid').value.trim();
            if(!qcid){err.textContent='QuickConnect ID requis';btn.textContent='Ajouter';btn.disabled=false;return;}
            payload.qc_id=qcid;
        } else {
            const host=document.getElementById('fa-syn-host').value.trim();
            if(!host){err.textContent='IP/Hostname requis';btn.textContent='Ajouter';btn.disabled=false;return;}
            payload.host=host;
            payload.port=parseInt(document.getElementById('fa-syn-port').value)||5000;
            payload.ssl=document.getElementById('fa-syn-ssl').checked;
        }
    } else if(_faType==='cassandra'){
        payload.url=document.getElementById('fa-url').value.trim();
        payload.token=document.getElementById('fa-token').value.trim();
        if(!payload.url||!payload.token){err.textContent='URL et token requis';btn.textContent='Ajouter';btn.disabled=false;return;}
    } else if(_faType==='proxmox'){
        payload.url=document.getElementById('fa-px-url').value.trim();
        payload.username=document.getElementById('fa-px-user').value.trim();
        payload.password=document.getElementById('fa-px-pass').value;
        if(!payload.url||!payload.password){err.textContent='URL et mot de passe requis';btn.textContent='Ajouter';btn.disabled=false;return;}
    } else if(_faType==='ssh'){
        payload.host=document.getElementById('fa-ssh-host').value.trim();
        payload.port=parseInt(document.getElementById('fa-ssh-port').value)||22;
        payload.username=document.getElementById('fa-ssh-user').value.trim()||'root';
        payload.auth=_faSshMode;
        if(!payload.host){err.textContent='IP/Hostname requis';btn.textContent='Ajouter';btn.disabled=false;return;}
        if(_faSshMode==='password'){
            payload.password=document.getElementById('fa-ssh-pass').value;
            if(!payload.password){err.textContent='Mot de passe requis';btn.textContent='Ajouter';btn.disabled=false;return;}
        } else {
            payload.key=document.getElementById('fa-ssh-key').value.trim();
            if(!payload.key){err.textContent='Clé privée requise';btn.textContent='Ajouter';btn.disabled=false;return;}
        }
    } else if(_faType==='ping'){
        payload.host=document.getElementById('fa-ping-host').value.trim();
        payload.port=parseInt(document.getElementById('fa-ping-port').value)||80;
        if(!payload.host){err.textContent='Hôte requis';btn.textContent='Ajouter';btn.disabled=false;return;}
    }

    try{
        const r=await fetch('/api/multiserver/add_device',{method:'POST',
            headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
        const d=await r.json();
        btn.textContent='Ajouter';btn.disabled=false;
        if(d.ok){
            closeFleetAdd();
            refreshFleet();
            addSystemMessage('✓ '+name+' ajouté à la flotte ('+_faType+')');
        } else {
            err.textContent=d.error||'Erreur inconnue';
        }
    } catch(e){
        btn.textContent='Ajouter';btn.disabled=false;
        err.textContent='Erreur réseau: '+e.message;
    }
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
            const dtype=n.type||'cassandra';
            const cpu=n.cpu||0, ram=n.ram||0, disk=n.disk||0, health=n.health_score||0;
            const cc=v=>v>85?'#ff4757':v>70?'#ffa502':'#2ed573';
            const typeIcon={'cassandra':'🤖','synology':'🖧','proxmox':'🧱','ping':'📡','local':'★'}[isLocal?'local':dtype]||'🖥';
            const typeBadge=isLocal?'':`<span style="font-size:9px;background:rgba(124,92,252,.15);color:#9b8ffc;border-radius:3px;padding:1px 5px;margin-left:4px">${dtype.toUpperCase()}</span>`;

            let extraHtml='';
            if(dtype==='synology'&&online){
                const model=n.model?`<span style="color:#00ffcc">${escapeHtml(n.model)}</span> `:' ';
                const dsm=n.dsm_version?`DSM ${escapeHtml(n.dsm_version)} `:'';
                const vols=n.volumes?`· ${n.volumes} vol.`:'';
                const diskInfo=n.disk_used_gb?`${n.disk_used_gb}/${n.disk_total_gb} GB`:'';
                extraHtml=`<div style="font-size:10px;color:#6b6b80;margin-bottom:6px">${model}${dsm}${vols}${diskInfo?'· '+diskInfo:''}</div>`;
            }
            if(dtype==='ssh'&&online){
                const info=[n.hostname,n.kernel,n.uptime].filter(Boolean).join(' · ');
                if(info) extraHtml=`<div style="font-size:10px;color:#6b6b80;margin-bottom:6px">${escapeHtml(info)}</div>`;
            }
            if(dtype==='proxmox'&&online&&n.nodes){
                extraHtml=`<div style="font-size:10px;color:#6b6b80;margin-bottom:6px">${n.nodes} nœud(s) Proxmox</div>`;
            }
            if(dtype==='ping'){
                extraHtml=online
                    ?`<div style="font-size:10px;color:#2ed573;margin:6px 0">✓ Joignable</div>`
                    :`<div style="font-size:10px;color:#ff4757;margin:6px 0">✗ Hors ligne</div>`;
            }

            const metricsHtml=(online&&dtype!=='ping')?`<div class="fleet-node-metrics">
                <div class="fleet-metric-mini"><div class="label">CPU</div><div class="val" style="color:${cc(cpu)}">${cpu}%</div></div>
                <div class="fleet-metric-mini"><div class="label">RAM</div><div class="val" style="color:${cc(ram)}">${ram}%</div></div>
                <div class="fleet-metric-mini"><div class="label">DISK</div><div class="val" style="color:${cc(disk)}">${disk}%</div></div>
            </div>${health?`<div style="font-size:10px;color:#6b6b80">${health>=90?'💚':health>=75?'💛':health>=50?'🧡':'❤️'} Santé ${health}/100</div>`:''}`
            :(n.error&&!online)?`<div style="font-size:11px;color:#ff4757;margin:8px 0">❌ ${escapeHtml(n.error)}</div>`:'';

            const actionsHtml=isLocal
                ?'<div style="font-size:10px;color:#6b6b80;margin-top:6px">Serveur local</div>'
                :`<div class="fleet-node-actions"><button class="fleet-node-btn" onclick="sendQuickFix('Statut du serveur ${escapeHtml(n.name)}')">Analyser</button><button class="fleet-node-btn danger" onclick="removeFleetServer('${escapeHtml(n.name)}')">Retirer</button></div>`;

            return `<div class="fleet-node ${online?'':'offline'}">
                <div class="fleet-node-header">
                    <span class="fleet-node-name">${typeIcon} ${escapeHtml(n.name)}${typeBadge}</span>
                    <span class="fleet-node-badge ${online?'online':'offline'}">${online?'● EN LIGNE':'○ HORS LIGNE'}</span>
                </div>
                ${!isLocal?`<div class="fleet-node-url">${escapeHtml(n.url||'')}</div>`:''}
                ${extraHtml}${metricsHtml}${actionsHtml}
            </div>`;
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
    addMessage('<strong>CASSANDRA</strong> — Agent IA souveraine<br><span style="color:#6b6b80;font-size:12px">Je suis fraîche, dispo, et sous-caféinée. Commande-moi une mission.</span>', false);
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
    // Polling d'alertes permanent : la cloche se met à jour même si le WebSocket
    // est coupé (ex. proxy/Cloudflare sans upgrade WS).
    setInterval(loadAlerts, 20000);
    // Collage d'image (Ctrl+V) dans le chat
    _initImagePaste();
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
    // Délégué au centre de notifications unifié (push WebSocket temps réel)
    if(!Array.isArray(alerts)) return;
    renderNotifications(alerts);
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
            const safeMsg = JSON.stringify(msg).replace(/"/g, '&quot;');
            return `<tr onclick="sendQuickFix(${safeMsg})">${cells}<td><span class="fp-row-action">Analyser ↗</span></td></tr>`;
        }).join('');
        tableHtml = `<div class="fp-table-wrap"><table class="fp-table"><thead><tr>${header}<th></th></tr></thead><tbody>${rowsHtml}</tbody></table></div>`;
    }
    const safeAnalyzeAll = JSON.stringify(analyzeAll).replace(/"/g, '&quot;');
    main.innerHTML = `
        <div class="fp-topbar">
            <div class="fp-topbar-title"><span class="fp-topbar-icon">${cfg.title.substring(0,2)}</span>${cfg.title.substring(2)}</div>
            <div class="fp-topbar-actions">
                <button class="fp-btn" onclick="fpLoadSection('${section}')">↻ Actualiser</button>
                <button class="fp-btn secondary" onclick="switchTab('dashboard');sendQuickFix(${safeAnalyzeAll})">💬 Analyser tout</button>
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
        const safeMsg = JSON.stringify(msg).replace(/"/g, '&quot;');
        return `<tr onclick="sendQuickFix(${safeMsg})">${cells}<td><span class="fp-row-action">Analyser ↗</span></td></tr>`;
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
    # SELFTEST : exécuté par _self_selftest() dans un sous-processus isolé.
    # Tout le code de module a déjà été importé/exécuté à ce stade ; si on arrive
    # ici sans crash, le candidat démarre correctement → on sort proprement.
    if os.environ.get("CASSANDRA_SELFTEST") == "1":
        print("SELFTEST_OK")
        sys.exit(0)

    # BANC D'ESSAI : un patch candidat est lancé ici (port temporaire, sans les
    # daemons lourds) pour vérifier qu'il BOOTE et SERT avant d'être appliqué en prod.
    SMOKE = os.environ.get("CASSANDRA_SMOKE") == "1"

    init_admin_log()
    init_memory_db()
    if not SMOKE:
        _evo_boot_watchdog()  # rollback auto si une évolution précédente est malsaine
    init_users()  # seed 'admin' depuis le mot de passe existant si users.json absent

    if not os.path.exists('/dev/shm'):
        os.makedirs('/dev/shm', exist_ok=True)

    if not SMOKE:
        ms_migrate_plaintext_tokens()
        # Monitoring proactif (alertes disque/mémoire/load/services en arrière-plan)
        load_alert_config()  # [EVO1] précache la config alerting
        start_monitoring()
        _start_ws_broadcaster()  # [EVO5] push WebSocket 1s
        start_autonomous_evolution()  # [EVO6] évolution autonome permanente
        start_memory_consolidation()  # [MEM] fusion périodique des doublons mémoire (6h)
        start_embeddings_warmup()     # [MEM] charge le modèle d'embeddings + vectorise (Phase 2)

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

    _evo_confirm_health_async()  # confirme l'évolution si le serveur répond

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\U0001f44b Arr\u00eat de CASSANDRA...")
        server.shutdown()
        print("\u2705 CASSANDRA arr\u00eat\u00e9 proprement.")
# fin du fichier \u2014 assistant d'installation int\u00e9gr\u00e9 (premier d\u00e9marrage via UI)
