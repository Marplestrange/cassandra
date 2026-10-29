#!/usr/bin/env python3
"""
CASSANDRA v9.2 - Agent unifié (TEMPS RÉEL via socket collector)
- Lecture des métriques via socket UNIX pour du temps réel (<10ms)
- Fallback sur DB si socket indisponible
- Chat, commandes, mémoire conversationnelle
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
import threading
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse

# ============================================================
# 1. CONFIGURATION
# ============================================================
DB_PATH = "/var/lib/cassandra/cassandra.db"
MEMORY_DB_PATH = "/var/lib/cassandra/cassandra_memory.db"
COLLECTOR_SOCKET = "/tmp/cassandra_knowledge.sock"
PORT = 9000

# ============================================================
# 2. CHARGEMENT DE LA CLÉ API
# ============================================================
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
if not DEEPSEEK_API_KEY:
    try:
        with open('/root/.env') as f:
            for line in f:
                if line.startswith('DEEPSEEK_API_KEY='):
                    DEEPSEEK_API_KEY = line.split('=', 1)[1].strip().strip('"').strip("'")
                    break
    except:
        pass
    os.environ["DEEPSEEK_API_KEY"] = DEEPSEEK_API_KEY

print(f"[API] DeepSeek: {DEEPSEEK_API_KEY[:15] if DEEPSEEK_API_KEY else 'NON TROUVEE'}...")

from openai import OpenAI
client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1")

# ============================================================
# 3. LECTURE TEMPS RÉEL VIA SOCKET COLLECTOR
# ============================================================
def get_metrics_from_socket():
    """Récupère les métriques temps réel via le socket UNIX du collector"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(COLLECTOR_SOCKET)
        sock.send(b"GET_METRICS\n")
        response = sock.recv(65536)
        sock.close()
        data = json.loads(response.decode())
        # Le socket retourne déjà les métriques formatées
        return data
    except Exception as e:
        print(f"[SOCKET] Erreur: {e}")
        return None

def get_dashboard_from_socket():
    """Récupère le dashboard complet via le socket"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(COLLECTOR_SOCKET)
        sock.send(b"GET_DASHBOARD\n")
        response = sock.recv(65536)
        sock.close()
        return json.loads(response.decode())
    except Exception:
        return None

def get_entity_from_socket(entity_type):
    """Récupère une entité via le socket"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(COLLECTOR_SOCKET)
        sock.send(f"GET_ENTITY:{entity_type}\n".encode())
        response = sock.recv(65536)
        sock.close()
        return json.loads(response.decode())
    except Exception:
        return None

# ============================================================
# 4. FALLBACK DB (si socket indisponible)
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
    rows = query_db("""
        SELECT cpu_pct, ram_pct, disk_pct, swap_pct,
               load_1m, load_5m, load_15m,
               ram_total_gb, ram_used_gb,
               disk_total_gb, disk_used_gb, disk_free_gb
        FROM metrics_realtime ORDER BY id DESC LIMIT 1
    """)
    if rows:
        r = rows[0]
        return {
            "cpu": r.get("cpu_pct", 0),
            "ram": r.get("ram_pct", 0),
            "disk": r.get("disk_pct", 0),
            "swap": r.get("swap_pct", 0),
            "load_1m": r.get("load_1m", 0),
            "load_5m": r.get("load_5m", 0),
            "load_15m": r.get("load_15m", 0),
            "ram_total_gb": r.get("ram_total_gb", 0),
            "ram_used_gb": r.get("ram_used_gb", 0),
            "disk_total_gb": r.get("disk_total_gb", 0),
            "disk_used_gb": r.get("disk_used_gb", 0),
            "disk_free_gb": r.get("disk_free_gb", 0),
        }
    return {"cpu": 0, "ram": 0, "disk": 0, "swap": 0, "load_1m": 0, "load_5m": 0, "load_15m": 0,
            "ram_total_gb": 0, "ram_used_gb": 0, "disk_total_gb": 0, "disk_used_gb": 0, "disk_free_gb": 0}

def get_metrics():
    """Métriques avec priorité socket, fallback DB"""
    data = get_metrics_from_socket()
    if data:
        return data
    return get_metrics_fallback()

def get_dashboard():
    """Dashboard avec priorité socket"""
    data = get_dashboard_from_socket()
    if data:
        return data
    # Fallback DB
    sites = query_db("SELECT COUNT(*) as count FROM web_sites")
    remotes = query_db("SELECT COUNT(*) as count FROM rclone_remotes")
    ssl_expiring = query_db("SELECT COUNT(*) as count FROM ssl_certificates WHERE days_left <= 30")
    fail2ban = query_db("SELECT COUNT(*) as count FROM fail2ban_banned_ips")
    tailscale = query_db("SELECT COUNT(*) as count FROM tailscale_peers WHERE online=1")
    oom = query_db("SELECT COUNT(*) as count FROM oom_events WHERE ts > datetime('now', '-24 hours')")
    failed = query_db("SELECT COUNT(*) as count FROM failed_units")
    health = query_db("SELECT score, status FROM health_scores ORDER BY id DESC LIMIT 1")
    return {
        "sites": sites[0]["count"] if sites else 0,
        "remotes": remotes[0]["count"] if remotes else 0,
        "ssl_expiring": ssl_expiring[0]["count"] if ssl_expiring else 0,
        "fail2ban_banned": fail2ban[0]["count"] if fail2ban else 0,
        "tailscale_peers": tailscale[0]["count"] if tailscale else 0,
        "oom_events_24h": oom[0]["count"] if oom else 0,
        "failed_units": failed[0]["count"] if failed else 0,
        "health_score": health[0]["score"] if health else 0,
        "health_status": health[0]["status"] if health else "unknown",
    }

def get_rclone_remotes():
    data = get_entity_from_socket("rclone_remotes")
    if data:
        return data
    return query_db("SELECT name, type FROM rclone_remotes")

def get_ssl_certificates():
    data = get_entity_from_socket("ssl_certificates")
    if data:
        return data
    return query_db("SELECT domain, days_left, status FROM ssl_certificates ORDER BY days_left ASC LIMIT 20")

def get_active_sessions():
    data = get_entity_from_socket("active_sessions")
    if data:
        return data
    return query_db("SELECT user, ip, login_time FROM ssh_sessions ORDER BY id DESC LIMIT 10")

def get_open_ports():
    data = get_entity_from_socket("open_ports")
    if data:
        return data
    return query_db("SELECT port, protocol, process FROM open_ports ORDER BY port")

def get_top_processes(limit=10):
    data = get_metrics_from_socket()
    if data and data.get("top_processes"):
        return data["top_processes"][:limit]
    rows = query_db("SELECT top_processes FROM metrics_realtime ORDER BY id DESC LIMIT 1")
    if rows and rows[0].get("top_processes"):
        try:
            return json.loads(rows[0]["top_processes"])[:limit]
        except:
            return []
    return []

def get_tailscale_peers():
    data = get_entity_from_socket("tailscale_peers")
    if data:
        return data
    return query_db("SELECT name, online FROM tailscale_peers")

def get_fail2ban_banned():
    data = get_entity_from_socket("fail2ban_banned_ips")
    if data:
        return data
    return query_db("SELECT jail, ip FROM fail2ban_banned_ips LIMIT 20")

def get_oom_events():
    data = get_entity_from_socket("oom_events")
    if data:
        return data
    return query_db("SELECT ts, killed_process, memory_used_mb FROM oom_events ORDER BY id DESC LIMIT 10")

def get_failed_units():
    data = get_entity_from_socket("failed_units")
    if data:
        return data
    return query_db("SELECT unit, active_state FROM failed_units")

def get_web_sites():
    data = get_entity_from_socket("web_sites")
    if data:
        return data
    return query_db("SELECT domain, ssl_enabled, php_version FROM web_sites")

def get_health_score():
    data = get_dashboard()
    if data:
        return {"score": data.get("health_score", 0), "status": data.get("health_status", "unknown")}
    rows = query_db("SELECT score, status FROM health_scores ORDER BY id DESC LIMIT 1")
    return rows[0] if rows else {"score": 0, "status": "unknown"}

# ============================================================
# 5. MÉMOIRE CONVERSATIONNELLE
# ============================================================
def init_memory_db():
    Path(MEMORY_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS conversation_summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            summary TEXT NOT NULL,
            msg_range TEXT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_conversation(session_id, role, content):
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.execute(
        "INSERT INTO conversations (session_id, role, content) VALUES (?,?,?)",
        (session_id, role, content[:4000])
    )
    conn.commit()
    conn.close()

def get_conversation_history(session_id, limit=20):
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT role, content FROM conversations WHERE session_id = ? ORDER BY id DESC LIMIT ?",
        (session_id, limit)
    ).fetchall()
    conn.close()
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]

def get_summaries(session_id):
    conn = sqlite3.connect(MEMORY_DB_PATH)
    rows = conn.execute(
        "SELECT summary FROM conversation_summaries WHERE session_id = ? ORDER BY id DESC LIMIT 5",
        (session_id,)
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]

# ============================================================
# 6. PROMPT SYSTÈME
# ============================================================
def build_system_prompt(session_id):
    metrics = get_metrics()
    remotes = get_rclone_remotes()
    ssl_certs = get_ssl_certificates()
    sessions = get_active_sessions()
    ports = get_open_ports()
    processes = get_top_processes()
    health = get_health_score()
    banned = get_fail2ban_banned()
    tailscale = get_tailscale_peers()
    oom = get_oom_events()
    failed = get_failed_units()
    sites = get_web_sites()
    summaries = get_summaries(session_id)

    remotes_text = "\n".join([f"  • {r['name']} ({r.get('type', '?')})" for r in remotes])
    ssl_text = "\n".join([f"  • {c['domain']} : expire dans {c['days_left']}j" for c in ssl_certs if c.get('days_left', 999) <= 30])
    sessions_text = "\n".join([f"  • {s['user']} depuis {s.get('ip', 'local')}" for s in sessions])
    ports_text = "\n".join([f"  • {p['port']}/{p['protocol']} : {p.get('process', '?')}" for p in ports[:15]])
    processes_text = "\n".join([f"  • {str(p.get('command', '?'))[:50]} — {p.get('cpu', 0)}%" for p in processes])
    tailscale_text = "\n".join([f"  • {t['name']} : {'🟢' if t.get('online') else '🔴'}" for t in tailscale])
    oom_text = "\n".join([f"  • {o['killed_process']} ({o['memory_used_mb']}MB)" for o in oom])
    failed_text = "\n".join([f"  • {f['unit']} : {f['active_state']}" for f in failed])
    sites_text = "\n".join([f"  • {s['domain']} (SSL:{'✅' if s.get('ssl_enabled') else '❌'} PHP:{s.get('php_version','?')})" for s in sites])
    memory_context = "\n".join([f"• Résumé: {s[:200]}" for s in summaries]) if summaries else "Aucun historique"

    return f"""Tu es CASSANDRA, agent IA souverain de l'infrastructure.

## 📊 ÉTAT ACTUEL (temps réel)
• CPU : {metrics['cpu']}% | RAM : {metrics['ram']}% | DISK : {metrics['disk']}%
• LOAD : {metrics['load_1m']} {metrics['load_5m']} {metrics['load_15m']}
• Health score : {health['score']}/100 ({health['status']})

## 🌐 SITES WEB
{sites_text or '  • Aucun'}

## ☁️ REMOTES RCLONE
{remotes_text or '  • Aucun'}

## 🔒 SSL EXPIRANT (<30j)
{ssl_text or '  • Aucun'}

## 🔥 TOP PROCESSUS
{processes_text or '  • Aucune donnée'}

## 🌐 SESSIONS ACTIVES
{sessions_text or '  • Aucune'}

## 🔌 PORTS OUVERTS
{ports_text or '  • Aucun'}

## 🚫 FAIL2BAN : {len(banned)} IP(s)

## 🦎 TAILSCALE
{tailscale_text or '  • Aucun peer'}

## 💀 OOM EVENTS
{oom_text or '  • Aucun'}

## ⚠️ FAILED UNITS
{failed_text or '  • Aucune'}

## 🧠 MÉMOIRE
{memory_context}

## RÈGLES
1. Utilise TOUJOURS les données ci-dessus (temps réel via socket collector)
2. Formate en HTML : <h2>/<h3>, <ul>/<li>, <table>, classes .ok/.warning/.critical
3. Pour les commandes : ```bash ... ```"""

# ============================================================
# 7. DEEPSEEK STREAM
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
# 8. COMMANDES SÉCURISÉES
# ============================================================
ALLOWED_BINARIES = {
    "df", "free", "uptime", "who", "ps", "top", "systemctl",
    "journalctl", "tail", "cat", "ls", "du", "ss", "netstat",
    "docker", "nginx", "mysql", "php", "ping", "rclone"
}

def secure_execute(cmd):
    parts = cmd.strip().split()
    if not parts:
        return "Commande vide"
    binary = parts[0].split("/")[-1]
    if binary not in ALLOWED_BINARIES:
        return f"Commande '{binary}' non autorisée"
    dangerous = ["&&", "||", ";", "|", "`", "$("]
    for d in dangerous:
        if d in cmd:
            return f"Injection détectée"
    try:
        result = subprocess.run(parts, capture_output=True, text=True, timeout=15)
        return result.stdout + result.stderr
    except Exception as e:
        return f"Erreur: {e}"

# ============================================================
# 9. SERVEUR HTTP
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

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/" or path == "/index.html":
            self.send_html(HTML_TEMPLATE)
            return
        if path == "/api/metrics":
            self.send_json(get_metrics())
            return
        if path == "/api/metrics/history":
            self.send_json(get_metrics_history())
            return
        if path == "/api/dashboard":
            self.send_json(get_dashboard())
            return
        if path == "/api/remotes":
            self.send_json(get_rclone_remotes())
            return
        if path == "/api/ssl":
            self.send_json(get_ssl_certificates())
            return
        if path == "/api/sessions":
            self.send_json(get_active_sessions())
            return
        if path == "/api/ports":
            self.send_json(get_open_ports())
            return
        if path == "/api/processes":
            self.send_json(get_top_processes())
            return
        if path == "/api/health":
            self.send_json(get_health_score())
            return
        if path == "/api/fail2ban":
            self.send_json(get_fail2ban_banned())
            return
        if path == "/api/tailscale":
            self.send_json(get_tailscale_peers())
            return
        if path == "/api/oom":
            self.send_json(get_oom_events())
            return
        if path == "/api/failed":
            self.send_json(get_failed_units())
            return
        if path == "/api/sites":
            self.send_json(get_web_sites())
            return
        self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode() if length else "{}"
        try:
            data = json.loads(body)
        except:
            data = {}

        if path == "/api/login":
            pwd = data.get("password", "")
            expected = os.environ.get("CASSANDRA_PASSWORD_HASH", "")
            if not expected or hashlib.sha256(pwd.encode()).hexdigest() == expected:
                sid = secrets.token_hex(32)
                self.send_json({"success": True, "session": sid})
            else:
                self.send_json({"success": False, "error": "Mot de passe incorrect"}, 401)
            return

        if path == "/api/chat/stream":
            msg = data.get("message", "")
            sid = data.get("session", "")
            if not sid:
                self.send_json({"error": "Session invalide"}, 401)
                return
            if not msg:
                self.send_json({"error": "Message vide"}, 400)
                return
            save_conversation(sid, "user", msg)
            history = get_conversation_history(sid, 20)
            messages = [{"role": "system", "content": build_system_prompt(sid)}]
            for h in history:
                messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": msg})
            self.send_sse(call_deepseek_stream(messages))
            return

        if path == "/api/exec":
            sid = data.get("session", "")
            if not sid:
                self.send_json({"error": "Non autorisé"}, 401)
                return
            cmd = data.get("cmd", "")
            if not cmd:
                self.send_json({"error": "Commande vide"}, 400)
                return
            self.send_json({"success": True, "output": secure_execute(cmd)})
            return

        self.send_json({"error": "Not found"}, 404)

# ============================================================
# 10. TEMPLATE HTML (version complète avec polling rapide)
# ============================================================
HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CASSANDRA v9.2 - Infrastructure AI (Temps réel)</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e8e8f0;height:100vh;overflow:hidden;position:relative}
#particles-canvas{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0}
.hex-grid{position:fixed;top:0;left:0;width:100%;height:100%;background-image:linear-gradient(to right,rgba(0,255,170,.03) 1px,transparent 1px),linear-gradient(to bottom,rgba(0,255,170,.03) 1px,transparent 1px);background-size:50px 50px;pointer-events:none;z-index:0;animation:gridMove 20s linear infinite}
@keyframes gridMove{0%{transform:translate(0,0)}100%{transform:translate(50px,50px)}}
.app-container{position:relative;z-index:1;height:100vh;display:flex;flex-direction:column}
.header{background:rgba(17,17,24,.9);backdrop-filter:blur(10px);border-bottom:1px solid rgba(0,255,170,.2);padding:12px 24px;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'JetBrains Mono',monospace;font-weight:700;font-size:18px;background:linear-gradient(135deg,#00ffcc,#7c5cfc);-webkit-background-clip:text;background-clip:text;color:transparent}
.logo-badge{background:rgba(0,255,170,.15);border-radius:4px;padding:2px 8px;font-size:9px;color:#00ffcc;margin-left:8px}
.status{display:flex;align-items:center;gap:12px}
.status-dot{width:8px;height:8px;border-radius:50%;background:#00ffcc;box-shadow:0 0 8px #00ffcc;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.session-time{font-size:11px;color:#6b6b80;font-family:'JetBrains Mono',monospace}
.logout-btn{background:rgba(255,71,87,.15);border:1px solid rgba(255,71,87,.3);border-radius:6px;padding:6px 14px;font-size:11px;color:#ff4757;cursor:pointer;transition:all .2s}
.logout-btn:hover{background:rgba(255,71,87,.25);border-color:#ff4757}
.main-layout{display:flex;flex:1;overflow:hidden;gap:1px;background:rgba(255,255,255,.03)}
.panel{background:rgba(17,17,24,.8);backdrop-filter:blur(10px);overflow-y:auto;padding:16px}
.panel-left{width:320px;border-right:1px solid rgba(0,255,170,.1)}
.panel-right{width:320px;border-left:1px solid rgba(0,255,170,.1)}
.panel-center{flex:1;display:flex;flex-direction:column;padding:0}
.panel::-webkit-scrollbar{width:3px}
.panel::-webkit-scrollbar-thumb{background:#00ffcc;border-radius:2px}
.card{background:rgba(28,28,37,.8);border-radius:12px;padding:14px;margin-bottom:14px;border:1px solid rgba(0,255,170,.1);transition:border-color .3s}
.card:hover{border-color:rgba(0,255,170,.3)}
.card-title{font-size:10px;text-transform:uppercase;letter-spacing:.2em;color:#00ffcc;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.metric-bar{margin-bottom:12px}
.metric-label{font-size:11px;color:#a0a0b0;display:flex;justify-content:space-between;margin-bottom:4px}
.bar-track{background:rgba(255,255,255,.1);border-radius:4px;height:6px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .3s ease}
.bar-fill.cpu{background:linear-gradient(90deg,#00ffcc,#7c5cfc)}
.bar-fill.ram{background:linear-gradient(90deg,#7c5cfc,#00ffcc)}
.bar-fill.disk{background:linear-gradient(90deg,#00ffcc,#2ed573)}
.chart-container{height:110px;margin:8px 0}
.remote-item{padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:11px;font-family:'JetBrains Mono',monospace;display:flex;justify-content:space-between;align-items:center}
.remote-name{color:#00ffcc;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px}
.remote-type{font-size:9px;color:#7c5cfc;flex-shrink:0}
.ssl-item{padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:11px}
.ssl-domain{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ssl-days{font-size:10px}
.ssl-days.critical{color:#ff4757}
.ssl-days.warning{color:#ffa502}
.ssl-days.ok{color:#2ed573}
.score-ring{display:flex;align-items:center;gap:12px}
.score-big{font-size:36px;font-weight:700;font-family:'JetBrains Mono',monospace}
.score-big.excellent{color:#00ffcc}
.score-big.good{color:#2ed573}
.score-big.warning{color:#ffa502}
.score-big.critical{color:#ff4757}
.chat-messages{flex:1;overflow-y:auto;padding:16px}
.chat-messages::-webkit-scrollbar{width:3px}
.chat-messages::-webkit-scrollbar-thumb{background:#7c5cfc;border-radius:2px}
.message{margin-bottom:16px;display:flex;flex-direction:column}
.message.user{align-items:flex-end}
.message.bot{align-items:flex-start}
.message-bubble{max-width:85%;padding:10px 14px;border-radius:12px;font-size:13px;line-height:1.6}
.message.user .message-bubble{background:linear-gradient(135deg,#7c5cfc,#00ffcc);color:#0a0a0f;border-radius:12px 12px 2px 12px}
.message.bot .message-bubble{background:rgba(28,28,37,.9);border:1px solid rgba(0,255,170,.2);border-radius:12px 12px 12px 2px}
.message.bot .message-bubble h2{font-size:13px;color:#00ffcc;margin:6px 0 4px}
.message.bot .message-bubble h3{font-size:12px;color:#7c5cfc;margin:5px 0 3px}
.message.bot .message-bubble ul{margin:5px 0;padding-left:18px}
.message.bot .message-bubble li{margin:2px 0}
.message.bot .message-bubble table{font-size:10px;border-collapse:collapse;width:100%;margin:8px 0}
.message.bot .message-bubble th{background:rgba(0,255,170,.1);padding:4px 8px;text-align:left}
.message.bot .message-bubble td{padding:3px 8px;border-bottom:1px solid rgba(255,255,255,.05)}
.message.bot .message-bubble .ok{color:#2ed573;font-weight:600}
.message.bot .message-bubble .warning{color:#ffa502;font-weight:600}
.message.bot .message-bubble .critical{color:#ff4757;font-weight:600}
.command-block{background:#0a0a0f;border-radius:6px;margin:8px 0;border:1px solid rgba(0,255,170,.2)}
.command-header{padding:6px 10px;background:rgba(0,255,170,.05);font-size:10px;font-family:monospace;display:flex;justify-content:space-between;align-items:center}
.exec-btn{background:rgba(0,255,170,.15);border:none;border-radius:4px;padding:2px 8px;color:#00ffcc;cursor:pointer;font-size:9px}
.exec-btn:hover{background:rgba(0,255,170,.3)}
.command-result{padding:8px 10px;font-size:10px;font-family:monospace;white-space:pre-wrap;max-height:200px;overflow-y:auto;color:#a0a0b0}
.chat-input-area{padding:16px;border-top:1px solid rgba(0,255,170,.1);display:flex;gap:10px}
.chat-input{flex:1;background:rgba(28,28,37,.9);border:1px solid rgba(0,255,170,.2);border-radius:8px;padding:10px 14px;color:#e8e8f0;font-family:'Inter',sans-serif;font-size:13px;resize:none;outline:none;transition:border-color .2s}
.chat-input:focus{border-color:#00ffcc}
.send-btn{background:linear-gradient(135deg,#00ffcc,#7c5cfc);border:none;border-radius:8px;width:42px;height:42px;cursor:pointer;font-size:18px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.send-btn:disabled{opacity:.4;cursor:not-allowed}
.typing{display:flex;gap:4px;padding:8px 12px;align-items:center}
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
.login-error{color:#ff4757;font-size:12px;margin-top:12px;min-height:16px}
.hidden{display:none!important}
.empty-state{font-size:10px;color:#6b6b80;padding:4px 0}
.changelog-item{padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:10px;font-family:'JetBrains Mono',monospace}
.chg-appeared{color:#2ed573}
.chg-disappeared{color:#ff4757}
.chg-expiring{color:#ffa502}
</style>
</head>
<body>
<canvas id="particles-canvas"></canvas>
<div class="hex-grid"></div>

<!-- LOGIN -->
<div id="login-modal" class="login-modal">
  <div class="login-card">
    <h1>🔐 CASSANDRA</h1>
    <p>Infrastructure AI v9.2 — Temps réel</p>
    <input type="password" id="login-password" placeholder="Mot de passe"
           onkeydown="if(event.key==='Enter')login()">
    <button onclick="login()">Se connecter</button>
    <div id="login-error" class="login-error"></div>
  </div>
</div>

<!-- APP -->
<div id="app-container" class="app-container hidden">
  <div class="header">
    <div>
      <span class="logo">CASSANDRA</span>
      <span class="logo-badge">v9.2 · TEMPS RÉEL</span>
    </div>
    <div class="status">
      <div class="status-dot"></div>
      <span id="status-text">SYSTEM ONLINE</span>
      <span class="session-time" id="session-time">0 min</span>
      <button class="logout-btn" onclick="logout()">Déconnexion</button>
    </div>
  </div>

  <div class="main-layout">
    <!-- GAUCHE -->
    <div class="panel panel-left">
      <div class="card">
        <div class="card-title">📊 MÉTRIQUES SYSTÈME</div>
        <div class="metric-bar">
          <div class="metric-label"><span>CPU</span><span id="cpu-val">–</span></div>
          <div class="bar-track"><div class="bar-fill cpu" id="cpu-bar" style="width:0%"></div></div>
        </div>
        <div class="metric-bar">
          <div class="metric-label"><span>RAM</span><span id="ram-val">–</span></div>
          <div class="bar-track"><div class="bar-fill ram" id="ram-bar" style="width:0%"></div></div>
        </div>
        <div class="metric-bar">
          <div class="metric-label"><span>DISQUE</span><span id="disk-val">–</span></div>
          <div class="bar-track"><div class="bar-fill disk" id="disk-bar" style="width:0%"></div></div>
        </div>
        <div class="metric-label" style="margin-top:6px">
          <span>LOAD avg</span><span id="load-val">–</span>
        </div>
        <div class="chart-container">
          <canvas id="cpu-chart"></canvas>
        </div>
      </div>

      <div class="card">
        <div class="card-title">💚 HEALTH SCORE</div>
        <div class="score-ring">
          <div class="score-big" id="health-score">–</div>
          <div>
            <div id="health-status" style="font-size:11px;color:#7c5cfc;text-transform:uppercase"></div>
            <div id="health-details" style="font-size:10px;color:#6b6b80;margin-top:4px"></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">☁️ REMOTES RCLONE</div>
        <div id="remotes-list"><div class="empty-state">Chargement…</div></div>
      </div>

      <div class="card">
        <div class="card-title">🔒 CERTIFICATS SSL</div>
        <div id="ssl-list"><div class="empty-state">Chargement…</div></div>
      </div>

      <div class="card">
        <div class="card-title">🦎 TAILSCALE PEERS</div>
        <div id="tailscale-list"><div class="empty-state">Chargement…</div></div>
      </div>

      <div class="card">
        <div class="card-title">🚫 FAIL2BAN</div>
        <div id="fail2ban-count" style="font-size:13px;font-family:'JetBrains Mono'">–</div>
      </div>
    </div>

    <!-- CENTRE CHAT -->
    <div class="panel panel-center">
      <div class="chat-messages" id="chat-messages">
        <div class="message bot">
          <div class="message-bubble">
            👋 Bonjour, je suis <strong>CASSANDRA v9.2</strong>.<br>
            Je connais toute ton infrastructure en <strong>temps réel</strong>. Que veux-tu savoir ?
          </div>
        </div>
      </div>
      <div class="chat-input-area">
        <textarea class="chat-input" id="chat-input"
                  placeholder="Pose ta question… (Entrée pour envoyer)" rows="1"></textarea>
        <button class="send-btn" id="send-btn" onclick="sendMessage()">➤</button>
      </div>
    </div>

    <!-- DROITE -->
    <div class="panel panel-right">
      <div class="card">
        <div class="card-title">🔥 TOP PROCESSUS</div>
        <div id="processes-list"><div class="empty-state">Chargement…</div></div>
      </div>
      <div class="card">
        <div class="card-title">🌐 SESSIONS ACTIVES</div>
        <div id="sessions-list"><div class="empty-state">Chargement…</div></div>
      </div>
      <div class="card">
        <div class="card-title">🔌 PORTS OUVERTS</div>
        <div id="ports-list"><div class="empty-state">Chargement…</div></div>
      </div>
      <div class="card">
        <div class="card-title">💀 OOM EVENTS</div>
        <div id="oom-list"><div class="empty-state">Chargement…</div></div>
      </div>
      <div class="card">
        <div class="card-title">⚠️ FAILED UNITS</div>
        <div id="failed-list"><div class="empty-state">Chargement…</div></div>
      </div>
    </div>
  </div>
</div>

<script>
// ============================================================
// ÉTAT
// ============================================================
let sessionId      = localStorage.getItem('cassandra_session') || '';
let isAuthenticated = false;
let sessionStart   = Date.now();
let cpuChart       = null;
let cpuHistory     = [];
let ramHistory     = [];
let isStreaming    = false;

// ============================================================
// AUTH
// ============================================================
async function login() {
    const password = document.getElementById('login-password').value;
    const errorDiv = document.getElementById('login-error');
    errorDiv.textContent = '';
    try {
        const r = await fetch('/api/login', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({password})
        });
        const d = await r.json();
        if (d.success) {
            sessionId = d.session;
            localStorage.setItem('cassandra_session', sessionId);
            isAuthenticated = true;
            document.getElementById('login-modal').classList.add('hidden');
            document.getElementById('app-container').classList.remove('hidden');
            startApp();
        } else {
            errorDiv.textContent = d.error || 'Mot de passe incorrect';
        }
    } catch(e) {
        errorDiv.textContent = 'Erreur de connexion';
    }
}

function logout() {
    localStorage.removeItem('cassandra_session');
    isAuthenticated = false;
    document.getElementById('login-modal').classList.remove('hidden');
    document.getElementById('app-container').classList.add('hidden');
}

// ============================================================
// API
// ============================================================
async function apiGet(endpoint) {
    const r = await fetch(endpoint);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
}

// ============================================================
// UTILS
// ============================================================
function escapeHtml(t) {
    if (t == null) return '';
    return String(t).replace(/[&<>"]/g, m =>
        ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));
}

function colorClass(pct) {
    if (pct > 85) return 'critical';
    if (pct > 70) return 'warning';
    return 'ok';
}

// ============================================================
// MÉTRIQUES (rafraîchissement 1s)
// ============================================================
async function loadMetrics() {
    try {
        const d = await apiGet('/api/metrics');
        const cpu  = Math.round(d.cpu  || 0);
        const ram  = Math.round(d.ram  || 0);
        const disk = Math.round(d.disk || 0);

        document.getElementById('cpu-val').textContent  = cpu  + '%';
        document.getElementById('ram-val').textContent  = ram  + '%';
        document.getElementById('disk-val').textContent = disk + '%';
        document.getElementById('cpu-bar').style.width  = cpu  + '%';
        document.getElementById('ram-bar').style.width  = ram  + '%';
        document.getElementById('disk-bar').style.width = disk + '%';
        document.getElementById('load-val').textContent =
            (d.load_1m||0) + ' ' + (d.load_5m||0) + ' ' + (d.load_15m||0);

        cpuHistory.push(cpu);
        ramHistory.push(ram);
        if (cpuHistory.length > 60) cpuHistory.shift();
        if (ramHistory.length > 60) ramHistory.shift();
        updateCharts();
    } catch(e) { console.warn('Metrics:', e.message); }
}

async function loadMetricsHistory() {
    try {
        const data = await apiGet('/api/metrics/history?limit=60');
        cpuHistory = data.map(d => Math.round(d.cpu_pct || 0));
        ramHistory = data.map(d => Math.round(d.ram_pct || 0));
        updateCharts();
    } catch(e) { console.warn('History:', e.message); }
}

function initCharts() {
    const ctx = document.getElementById('cpu-chart').getContext('2d');
    cpuChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: 'CPU %', data: [], borderColor: '#00ffcc', backgroundColor: 'rgba(0,255,204,.06)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 2 },
                { label: 'RAM %', data: [], borderColor: '#7c5cfc', backgroundColor: 'rgba(124,92,252,.06)', fill: true, tension: 0.4, pointRadius: 0, borderWidth: 2 }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: {legend:{display:false}},
            scales: { x:{display:false}, y:{ beginAtZero: true, max: 100, grid:{color:'rgba(255,255,255,.04)'}, ticks:{color:'#6b6b80', font:{size:9}} } }
        }
    });
}

function updateCharts() {
    if (!cpuChart) return;
    cpuChart.data.labels = cpuHistory.map((_, i) => i);
    cpuChart.data.datasets[0].data = cpuHistory;
    cpuChart.data.datasets[1].data = ramHistory;
    cpuChart.update('none');
}

// ============================================================
// DASHBOARD
// ============================================================
async function loadDashboard() {
    try {
        const d = await apiGet('/api/dashboard');
        const score = d.health_score || 0;
        const el    = document.getElementById('health-score');
        el.textContent = score + '/100';
        el.className   = 'score-big ' + (score >= 90 ? 'excellent' : score >= 75 ? 'good' : score >= 50 ? 'warning' : 'critical');
        document.getElementById('health-status').textContent = d.health_status || 'unknown';
        document.getElementById('health-details').textContent = `${d.sites||0} sites · ${d.ssl_expiring||0} SSL · ${d.failed_units||0} failed`;
    } catch(e) { console.warn('Dashboard:', e.message); }
}

// ============================================================
// PANNEAUX GAUCHE
// ============================================================
async function loadRemotes() {
    try {
        const data = await apiGet('/api/remotes');
        const el   = document.getElementById('remotes-list');
        el.innerHTML = data.length
            ? data.map(r => `<div class="remote-item"><span class="remote-name">${escapeHtml(r.name)}</span><span class="remote-type">${escapeHtml(r.type||'?')}</span></div>`).join('')
            : '<div class="empty-state">Aucun remote</div>';
    } catch(e) { console.warn('Remotes:', e.message); }
}

async function loadSSLCerts() {
    try {
        const data = await apiGet('/api/ssl');
        const el   = document.getElementById('ssl-list');
        el.innerHTML = data.length
            ? data.slice(0, 10).map(c => {
                const days = c.days_left;
                const cls  = days <= 7 ? 'critical' : days <= 30 ? 'warning' : 'ok';
                return `<div class="ssl-item"><div class="ssl-domain">${escapeHtml(c.domain)}</div><div class="ssl-days ${cls}">${days}j restants</div></div>`;
              }).join('')
            : '<div class="empty-state">Aucun certificat</div>';
    } catch(e) { console.warn('SSL:', e.message); }
}

async function loadTailscale() {
    try {
        const data = await apiGet('/api/tailscale');
        const el   = document.getElementById('tailscale-list');
        el.innerHTML = data.length
            ? data.map(p => `<div class="remote-item"><span class="remote-name">${escapeHtml(p.name||'?')}</span><span class="remote-type">${p.online ? '🟢' : '🔴'}</span></div>`).join('')
            : '<div class="empty-state">Aucun peer</div>';
    } catch(e) { console.warn('Tailscale:', e.message); }
}

async function loadFail2ban() {
    try {
        const data = await apiGet('/api/fail2ban');
        document.getElementById('fail2ban-count').textContent = data.length + ' IP bannie' + (data.length > 1 ? 's' : '');
    } catch(e) { console.warn('Fail2ban:', e.message); }
}

// ============================================================
// PANNEAUX DROITE
// ============================================================
async function loadProcesses() {
    try {
        const data = await apiGet('/api/processes');
        const el   = document.getElementById('processes-list');
        el.innerHTML = data.length
            ? data.map(p => `<div class="remote-item"><span class="remote-name">${escapeHtml(String(p.command||'?').substring(0,35))}</span><span class="remote-type ${colorClass(p.cpu||0)}">${p.cpu||0}%</span></div>`).join('')
            : '<div class="empty-state">Aucun processus</div>';
    } catch(e) { console.warn('Processes:', e.message); }
}

async function loadSessions() {
    try {
        const data = await apiGet('/api/sessions');
        const el   = document.getElementById('sessions-list');
        el.innerHTML = data.length
            ? data.map(s => `<div class="remote-item"><span class="remote-name">${escapeHtml(s.user||'?')}</span><span class="remote-type">${escapeHtml(s.ip||'local')}</span></div>`).join('')
            : '<div class="empty-state">Aucune session</div>';
    } catch(e) { console.warn('Sessions:', e.message); }
}

async function loadPorts() {
    try {
        const data = await apiGet('/api/ports');
        const el   = document.getElementById('ports-list');
        el.innerHTML = data.length
            ? data.slice(0, 15).map(p => `<div class="remote-item"><span class="remote-name">${p.port}/${escapeHtml(p.protocol||'?')}</span><span class="remote-type">${escapeHtml(p.process||'?')}</span></div>`).join('')
            : '<div class="empty-state">Aucun port</div>';
    } catch(e) { console.warn('Ports:', e.message); }
}

async function loadOOM() {
    try {
        const data = await apiGet('/api/oom');
        const el   = document.getElementById('oom-list');
        el.innerHTML = data.length
            ? data.slice(0, 5).map(o => `<div class="remote-item"><span class="remote-name">${escapeHtml(o.killed_process||'?')}</span><span class="remote-type critical">${o.memory_used_mb||0} MB</span></div>`).join('')
            : '<div class="empty-state">Aucun OOM</div>';
    } catch(e) { console.warn('OOM:', e.message); }
}

async function loadFailedUnits() {
    try {
        const data = await apiGet('/api/failed');
        const el   = document.getElementById('failed-list');
        el.innerHTML = data.length
            ? data.slice(0, 5).map(f => `<div class="remote-item"><span class="remote-name">${escapeHtml(f.unit||'?')}</span><span class="remote-type critical">${escapeHtml(f.active_state||'failed')}</span></div>`).join('')
            : '<div class="empty-state">Aucune unité failed</div>';
    } catch(e) { console.warn('Failed:', e.message); }
}

// ============================================================
// CHAT STREAMING
// ============================================================
function addMessage(content, isUser=false) {
    const c   = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = 'message ' + (isUser ? 'user' : 'bot');
    div.innerHTML = `<div class="message-bubble">${content}</div>`;
    c.appendChild(div);
    c.scrollTop = c.scrollHeight;
    return div;
}

function addTypingIndicator() {
    const c   = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = 'message bot';
    div.id = 'typing-indicator';
    div.innerHTML = `<div class="message-bubble"><div class="typing"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div></div>`;
    c.appendChild(div);
    c.scrollTop = c.scrollHeight;
}

function removeTypingIndicator() {
    const t = document.getElementById('typing-indicator');
    if (t) t.remove();
}

function formatResponse(text) {
    let out = text.replace(/```bash\n([\s\S]*?)\n```/g, (_, code) => {
        const safe = escapeHtml(code);
        const esc  = code.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
        return `<div class="command-block"><div class="command-header"><span>💻 ${safe}</span><button class="exec-btn" onclick="executeCommand('${esc}')">▶ EXÉCUTER</button></div><div class="command-result" id="res-${Date.now()}">En attente…</div></div>`;
    });
    out = out.replace(/^## (.+)$/gm,  '<h2>$1</h2>');
    out = out.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    out = out.replace(/^[•\-] (.+)$/gm, '<li>$1</li>');
    out = out.replace(/(<li>[\s\S]*?<\/li>)+/g, m => '<ul>' + m + '</ul>');
    out = out.replace(/\b(\d{1,3})%/g, (match, pct) => {
        const p = parseInt(pct);
        if (p > 100) return match;
        const color = p > 85 ? '#ff4757' : p > 70 ? '#ffa502' : '#2ed573';
        return `<span style="color:${color};font-weight:bold">${p}%</span>`;
    });
    return out;
}

async function executeCommand(cmd) {
    if (!confirm('Exécuter :\n' + cmd + '\n\nConfirmer ?')) return;
    const resultDivs = document.querySelectorAll('.command-result');
    const resultDiv  = resultDivs[resultDivs.length - 1];
    if (resultDiv) resultDiv.innerHTML = '<div class="loader"></div> Exécution…';
    try {
        const r = await fetch('/api/exec', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({cmd, session: sessionId}) });
        const d = await r.json();
        if (resultDiv) resultDiv.innerHTML = `<pre style="margin:0;font-size:10px;white-space:pre-wrap">${escapeHtml(d.output||'Aucune sortie')}</pre>`;
    } catch(e) {
        if (resultDiv) resultDiv.innerHTML = '<span style="color:#ff4757">❌ ' + e.message + '</span>';
    }
}

async function sendMessage() {
    const input   = document.getElementById('chat-input');
    const message = input.value.trim();
    if (!message || isStreaming) return;

    input.value = '';
    input.style.height = 'auto';
    document.getElementById('send-btn').disabled = true;

    addMessage(escapeHtml(message), true);
    addTypingIndicator();
    isStreaming = true;

    try {
        const response = await fetch('/api/chat/stream', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({message, session: sessionId})
        });
        removeTypingIndicator();

        const reader  = response.body.getReader();
        const decoder = new TextDecoder();
        let fullText  = '';
        let msgDiv    = null;
        let buf       = '';

        while (true) {
            const {done, value} = await reader.read();
            if (done) break;
            buf += decoder.decode(value, {stream: true});
            const lines = buf.split('\n');
            buf = lines.pop();
            for (const line of lines) {
                if (!line.startsWith('data: ')) continue;
                try {
                    const d = JSON.parse(line.slice(6));
                    if (d.done) break;
                    if (d.token) {
                        fullText += d.token;
                        if (!msgDiv) {
                            const wrapper = addMessage('', false);
                            msgDiv = wrapper.querySelector('.message-bubble');
                        }
                        msgDiv.innerHTML = formatResponse(fullText);
                        const c = document.getElementById('chat-messages');
                        c.scrollTop = c.scrollHeight;
                    }
                } catch(_) {}
            }
        }
    } catch(e) {
        removeTypingIndicator();
        addMessage('<span style="color:#ff4757">❌ ' + escapeHtml(e.message) + '</span>', false);
    }

    isStreaming = false;
    document.getElementById('send-btn').disabled = false;
}

// ============================================================
// HORLOGE + SESSION
// ============================================================
function updateClock() {
    const mins = Math.floor((Date.now() - sessionStart) / 60000);
    document.getElementById('session-time').textContent = mins + ' min';
}
setInterval(updateClock, 30000);

// ============================================================
// PARTICULES
// ============================================================
function initParticles() {
    const canvas = document.getElementById('particles-canvas');
    const ctx    = canvas.getContext('2d');
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    const pts = Array.from({length: 80}, () => ({
        x:  Math.random() * canvas.width,
        y:  Math.random() * canvas.height,
        r:  Math.random() * 1.5 + 0.5,
        a:  Math.random() * 0.4 + 0.1,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
    }));
    (function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (const p of pts) {
            p.x += p.vx; p.y += p.vy;
            if (p.x < 0) p.x = canvas.width;
            if (p.x > canvas.width) p.x = 0;
            if (p.y < 0) p.y = canvas.height;
            if (p.y > canvas.height) p.y = 0;
            ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(0,255,204,${p.a})`;
            ctx.fill();
        }
        requestAnimationFrame(animate);
    })();
    window.addEventListener('resize', () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; });
}

// ============================================================
// DÉMARRAGE (RAFRAÎCHISSEMENT RAPIDE)
// ============================================================
async function startApp() {
    initCharts();
    initParticles();

    await Promise.allSettled([
        loadMetricsHistory(),
        loadMetrics(),
        loadDashboard(),
        loadRemotes(),
        loadSSLCerts(),
        loadTailscale(),
        loadFail2ban(),
        loadProcesses(),
        loadSessions(),
        loadPorts(),
        loadOOM(),
        loadFailedUnits(),
    ]);

    // 🔥 RAFRAÎCHISSEMENT RAPIDE (1s pour les métriques)
    setInterval(loadMetrics,      1000);   // temps réel
    setInterval(loadProcesses,    2000);
    setInterval(loadSessions,     2000);
    setInterval(loadTailscale,    5000);
    setInterval(loadRemotes,     10000);
    setInterval(loadFail2ban,    10000);
    setInterval(loadDashboard,   10000);
    setInterval(loadSSLCerts,    30000);
    setInterval(loadPorts,       30000);
    setInterval(loadOOM,         30000);
    setInterval(loadFailedUnits, 30000);
}

document.getElementById('chat-input').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});
document.getElementById('chat-input').addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 100) + 'px';
});

if (sessionId) {
    isAuthenticated = true;
    document.getElementById('login-modal').classList.add('hidden');
    document.getElementById('app-container').classList.remove('hidden');
    startApp();
}
</script>
</body>
</html>'''

# ============================================================
# 11. DÉMARRAGE
# ============================================================
if __name__ == "__main__":
    init_memory_db()
    
    # Test du socket collector
    test = get_metrics_from_socket()
    if test:
        print(f"[SOCKET] ✅ Connecté au collector — métriques temps réel")
    else:
        print(f"[SOCKET] ⚠️ Socket indisponible, fallback sur DB")
    
    server = ThreadedHTTPServer(("0.0.0.0", PORT), CassandraHandler)
    print(f"\n{'='*55}")
    print(f"  CASSANDRA v9.2 — Infrastructure AI (Temps réel)")
    print(f"  Port    : {PORT}")
    print(f"  DB      : {DB_PATH}")
    print(f"  Socket  : {COLLECTOR_SOCKET}")
    print(f"  DeepSeek: {'✅ OK' if DEEPSEEK_API_KEY else '❌ MANQUANTE'}")
    print(f"  URL     : http://localhost:{PORT}")
    print(f"{'='*55}\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Arrêt de CASSANDRA...")
        server.shutdown()