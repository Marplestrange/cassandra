#!/usr/bin/env python3
"""
CASSANDRA v9.4 - Agent unifié (TEMPS RÉEL AVEC FILTRAGE + PROMPT HYBRIDE)
- Lecture des métriques via socket UNIX pour du temps réel (<10ms)
- Filtrage des données obsolètes (sessions, OOM, failed units, etc.)
- Fallback sur DB si socket indisponible
- Chat, commandes, mémoire conversationnelle
- PROMPT HYBRIDE : résumé IA + détails à la demande + mode expert
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
from datetime import datetime, timedelta
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
# 3. CACHE POUR PROMPT DYNAMIQUE
# ============================================================
_prompt_cache = {}
_prompt_cache_time = {}
_PROMPT_CACHE_TTL = 10  # secondes

_detailed_cache = {}
_detailed_cache_time = {}
_DETAILED_CACHE_TTL = 5  # secondes


def get_cached_or_fetch(category: str, fetch_func, ttl: int = 5):
    """Récupère depuis le cache ou appelle fetch_func"""
    global _detailed_cache, _detailed_cache_time
    now = time.time()
    
    if category in _detailed_cache and now - _detailed_cache_time.get(category, 0) < ttl:
        return _detailed_cache[category]
    
    data = fetch_func()
    _detailed_cache[category] = data
    _detailed_cache_time[category] = now
    return data


def needs_detailed_data(user_question: str, category: str, expert_mode: bool = False) -> bool:
    """Détermine si la question mérite des données détaillées"""
    # Mode expert : TOUJOURS TRUE
    if expert_mode:
        return True
    
    # Sinon, analyse sémantique
    keywords_map = {
        "sites": ["site", "web", "domaine", "nginx", "apache", "vhost", "hébergement", "cms", "wordpress"],
        "remotes": ["remote", "rclone", "cloud", "backup", "sauvegarde", "tiroir", "stockage"],
        "ssl": ["ssl", "certificat", "certif", "https", "expire", "expiration", "cert"],
        "processes": ["processus", "top", "cpu", "ram", "goinfre", "glouton", "mange", "bouffe"],
        "sessions": ["session", "connecté", "ssh", "who", "utilisateur", "pote connecté"],
        "ports": ["port", "écoute", "listen", "socket", "porte", "causent"],
        "oom": ["oom", "mémoire", "ram", "killed", "tué", "pause pipi", "oom"],
        "failed": ["failed", "planté", "cancres", "service", "systemd", "mort"],
        "tailscale": ["tailscale", "vpn", "peer", "bande", "réseau", "vpn"],
        "fail2ban": ["fail2ban", "banni", "cloporte", "videur", "ip", "ban"],
        "health": ["santé", "fraîcheur", "health", "score", "note"],
        "docker": ["docker", "container", "conteneur"],
        "smart": ["smart", "disque", "disk", "sdd", "hdd", "santé disque"],
    }
    
    q_lower = user_question.lower()
    
    # Seuil : au moins 2 mots-clés OU la question est longue (>30 caractères) ET contient 1 mot-clé
    matches = [kw for kw in keywords_map.get(category, []) if kw in q_lower]
    
    if len(matches) >= 2:
        return True
    if len(matches) >= 1 and len(user_question) > 30:
        return True
    return False


# ============================================================
# 4. LECTURE TEMPS RÉEL VIA SOCKET COLLECTOR
# ============================================================
def _recv_all(sock):
    """Lit toutes les données du socket jusqu'à fermeture (gère les réponses > 64KB)"""
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)

def get_metrics_from_socket():
    """Récupère les métriques temps réel via le socket UNIX du collector"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(COLLECTOR_SOCKET)
        sock.send(b"GET_METRICS\n")
        sock.shutdown(socket.SHUT_WR)
        response = _recv_all(sock)
        sock.close()
        return json.loads(response.decode())
    except Exception as e:
        print(f"[SOCKET] Erreur get_metrics: {e}")
        return None

def get_dashboard_from_socket():
    """Récupère le dashboard complet via le socket"""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(COLLECTOR_SOCKET)
        sock.send(b"GET_DASHBOARD\n")
        sock.shutdown(socket.SHUT_WR)
        response = _recv_all(sock)
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
        sock.shutdown(socket.SHUT_WR)
        response = _recv_all(sock)
        sock.close()
        return json.loads(response.decode())
    except Exception:
        return None

# ============================================================
# 5. FILTRAGE TEMPOREL (ÉPURATION DES DONNÉES OBSOLÈTES)
# ============================================================
def filter_recent(data, time_field, max_minutes=5):
    """Filtre les données pour garder uniquement les entrées récentes"""
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
            except:
                filtered.append(item)
        else:
            filtered.append(item)
    return filtered

# ============================================================
# 6. FALLBACK DB (si socket indisponible)
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

# ============================================================
# 7. MÉTRIQUES AVEC FILTRAGE (OPTIMISÉES)
# ============================================================
def get_metrics():
    """Métriques système (temps réel via socket)"""
    data = get_metrics_from_socket()
    if data:
        return data
    return get_metrics_fallback()

def get_metrics_history(limit=60):
    """Historique pour les graphiques"""
    rows = query_db("""
        SELECT cpu_pct, ram_pct, ts
        FROM metrics_realtime
        ORDER BY id DESC LIMIT ?
    """, [limit])
    return list(reversed(rows))

def get_dashboard():
    """Dashboard avec priorité socket"""
    data = get_dashboard_from_socket()
    if data:
        return data
    # Fallback DB
    sites = query_db("SELECT COUNT(*) as count FROM web_sites WHERE status = 'active'")
    remotes = query_db("SELECT COUNT(*) as count FROM rclone_remotes")
    ssl_expiring = query_db("SELECT COUNT(*) as count FROM ssl_certificates WHERE days_left <= 30 AND days_left > 0")
    fail2ban = query_db("SELECT COUNT(*) as count FROM fail2ban_banned_ips")
    tailscale = query_db("SELECT COUNT(*) as count FROM tailscale_peers WHERE online=1")
    oom = query_db("SELECT COUNT(*) as count FROM oom_events WHERE ts > datetime('now', '-24 hours')")
    failed = query_db("SELECT COUNT(*) as count FROM failed_units WHERE active_state = 'failed'")
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

def get_active_sessions():
    """Sessions SSH actives (uniquement les 5 dernières minutes)"""
    data = get_entity_from_socket("active_sessions")
    if data:
        return filter_recent(data, "login_time", max_minutes=5)
    rows = query_db("""
        SELECT user, ip, login_time
        FROM active_sessions
        ORDER BY id DESC LIMIT 20
    """)
    return filter_recent(rows, "login_time", max_minutes=5)

def get_top_processes(limit=10):
    """Top processus CPU (temps réel)"""
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

def get_ssl_certificates():
    """Certificats SSL (uniquement les non expirés)"""
    data = get_entity_from_socket("ssl_certificates")
    if data:
        return [c for c in data if c.get("days_left", -1) > 0]
    rows = query_db("""
        SELECT domain, days_left, status, expiry_date
        FROM ssl_certificates
        WHERE days_left > 0
        ORDER BY days_left ASC
        LIMIT 20
    """)
    return rows

def get_oom_events():
    """OOM events (uniquement les dernières 24h)"""
    data = get_entity_from_socket("oom_events")
    if data:
        return filter_recent(data, "ts", max_minutes=1440)
    rows = query_db("""
        SELECT ts, killed_process, memory_used_mb
        FROM oom_events
        WHERE ts > datetime('now', '-1 day')
        ORDER BY id DESC LIMIT 10
    """)
    return rows

def get_failed_units():
    """Failed units (uniquement ceux encore en état failed)"""
    data = get_entity_from_socket("failed_units")
    if data:
        return [u for u in data if u.get("active_state") == "failed"]
    rows = query_db("""
        SELECT unit, active_state, description
        FROM failed_units
        WHERE active_state = 'failed'
    """)
    return rows

def get_tailscale_peers():
    """Tailscale peers (tous, avec statut online)"""
    data = get_entity_from_socket("tailscale_peers")
    if data:
        return data
    rows = query_db("SELECT name, online, tailscale_ip FROM tailscale_peers")
    return rows

def get_fail2ban_banned():
    """IPs bannies par fail2ban (actuellement bannies)"""
    data = get_entity_from_socket("fail2ban_banned_ips")
    if data:
        return data
    rows = query_db("""
        SELECT jail, ip, banned_at
        FROM fail2ban_banned_ips
        ORDER BY banned_at DESC LIMIT 20
    """)
    return rows

def get_open_ports():
    """Ports ouverts (temps réel)"""
    data = get_entity_from_socket("open_ports")
    if data:
        return data
    rows = query_db("""
        SELECT port, protocol, process
        FROM open_ports
        ORDER BY port
    """)
    return rows

def get_rclone_remotes():
    """Remotes Rclone"""
    data = get_entity_from_socket("rclone_remotes")
    if data:
        return data
    rows = query_db("SELECT name, type, used_gb FROM rclone_remotes")
    return rows

def get_web_sites():
    """Sites web (actifs uniquement)"""
    data = get_entity_from_socket("web_sites")
    if data:
        return data
    rows = query_db("""
        SELECT domain, ssl_enabled, php_version
        FROM web_sites
        WHERE status = 'active'
    """)
    return rows

def get_health_score():
    """Health score (le plus récent) - sécurisé contre les retours liste"""
    data = get_dashboard_from_socket()
    if data and data.get("health_score"):
        return {"score": data.get("health_score", 0), "status": data.get("health_status", "unknown")}
    rows = query_db("""
        SELECT score, status
        FROM health_scores
        ORDER BY id DESC LIMIT 1
    """)
    # Protection contre le cas où rows serait une liste vide ou mal formée
    if rows and isinstance(rows, list) and len(rows) > 0:
        row = rows[0]
        if isinstance(row, dict):
            return {"score": row.get("score", 0), "status": row.get("status", "unknown")}
    return {"score": 0, "status": "unknown"}

# ============================================================
# 8. MÉMOIRE CONVERSATIONNELLE
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
# 9. PROMPT SYSTÈME (VERSION HYBRIDE)
# ============================================================
def generate_infra_summary() -> str:
    """Génère un résumé IA ultra court (toujours présent)"""
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
    
    # Construction du résumé
    summary_parts = []
    
    # Santé
    score = health.get('score', 0) if isinstance(health, dict) else 0
    if score >= 90:
        summary_parts.append(f"💚 Santé {score}/100")
    elif score >= 75:
        summary_parts.append(f"💛 Santé {score}/100")
    elif score >= 50:
        summary_parts.append(f"🧡 Santé {score}/100")
    else:
        summary_parts.append(f"❤️ Santé {score}/100")
    
    # Métriques
    summary_parts.append(f"📊 CPU {metrics.get('cpu', 0)}% RAM {metrics.get('ram', 0)}% DISK {metrics.get('disk', 0)}%")
    
    # Alertes clés (seulement si y'en a)
    alerts = []
    if expiring_ssl:
        alerts.append(f"{len(expiring_ssl)} SSL expirent")
    if oom:
        alerts.append(f"{len(oom)} OOM")
    if failed:
        alerts.append(f"{len(failed)} failed")
    if alerts:
        summary_parts.append(f"⚠️ {', '.join(alerts)}")
    
    # Compteurs
    summary_parts.append(f"🌐 {len(sites)} sites · ☁️ {len(remotes)} remotes · 🦎 {len(tailscale)} tailscale")
    
    summary = " | ".join(summary_parts)
    
    _prompt_cache["summary"] = summary
    _prompt_cache_time["summary"] = now
    return summary


def _format_sites(sites, max_items):
    if not sites:
        return "Aucun site web"
    lines = [f"## 🌐 SITES WEB ({len(sites)} au total)"]
    for s in sites[:max_items]:
        lines.append(f"  • {s.get('domain', '?')} (SSL:{'✅' if s.get('ssl_enabled') else '❌'} PHP:{s.get('php_version', '?')})")
    if len(sites) > max_items:
        lines.append(f"  • … et {len(sites) - max_items} autres")
    return "\n".join(lines)


def _format_remotes(remotes, max_items):
    if not remotes:
        return "Aucun remote Rclone"
    lines = [f"## ☁️ REMOTES RCLONE ({len(remotes)} au total)"]
    for r in remotes[:max_items]:
        lines.append(f"  • {r.get('name', '?')} ({r.get('type', '?')})")
    if len(remotes) > max_items:
        lines.append(f"  • … et {len(remotes) - max_items} autres")
    return "\n".join(lines)


def _format_ssl(certs, max_items):
    expiring = [c for c in certs if c.get('days_left', 999) <= 30]
    if not expiring:
        return "Aucun certificat SSL expirant dans les 30 jours"
    lines = [f"## 🔒 SSL EXPIRANT (<30j) ({len(expiring)} certificats)"]
    for c in expiring[:max_items]:
        days = c.get('days_left', 0)
        emoji = "🔴" if days <= 7 else "🟠" if days <= 14 else "🟡"
        lines.append(f"  • {emoji} {c.get('domain', '?')} : expire dans {days}j")
    if len(expiring) > max_items:
        lines.append(f"  • … et {len(expiring) - max_items} autres")
    return "\n".join(lines)


def _format_processes(processes, max_items):
    if not processes:
        return "Aucune donnée processus"
    lines = [f"## 🔥 TOP PROCESSUS ({len(processes)} actifs)"]
    for p in processes[:max_items]:
        cpu = p.get('cpu', 0)
        emoji = "🔥" if cpu > 50 else "⚡" if cpu > 25 else "💤"
        cmd = p.get('command', '?')[:45]
        lines.append(f"  • {emoji} {cmd} — {cpu}% CPU")
    if len(processes) > max_items:
        lines.append(f"  • … et {len(processes) - max_items} autres")
    return "\n".join(lines)


def _format_sessions(sessions, max_items):
    if not sessions:
        return "Aucune session active"
    lines = [f"## 🌐 SESSIONS ACTIVES ({len(sessions)} connecté(s))"]
    for s in sessions[:max_items]:
        lines.append(f"  • {s.get('user', '?')} depuis {s.get('ip', 'local')}")
    return "\n".join(lines)


def _format_ports(ports, max_items):
    if not ports:
        return "Aucun port ouvert détecté"
    lines = [f"## 🔌 PORTS OUVERTS ({len(ports)} ports)"]
    for p in ports[:max_items]:
        proc = p.get('process', '?')[:30]
        lines.append(f"  • {p.get('port', '?')}/{p.get('protocol', '?')} → {proc}")
    if len(ports) > max_items:
        lines.append(f"  • … et {len(ports) - max_items} autres")
    return "\n".join(lines)


def _format_oom(events, max_items):
    if not events:
        return "Aucun événement OOM récent"
    lines = [f"## 💀 OOM EVENTS ({len(events)} événements récents)"]
    for e in events[:max_items]:
        lines.append(f"  • {e.get('killed_process', '?')} — {e.get('memory_used_mb', 0)}MB")
    return "\n".join(lines)


def _format_failed(units, max_items):
    if not units:
        return "Aucune unité failed"
    lines = [f"## ⚠️ FAILED UNITS ({len(units)} service(s) en échec)"]
    for u in units[:max_items]:
        lines.append(f"  • {u.get('unit', '?')}")
    return "\n".join(lines)


def _format_tailscale(peers, max_items):
    if not peers:
        return "Aucun peer Tailscale"
    online = sum(1 for p in peers if p.get('online'))
    lines = [f"## 🦎 TAILSCALE ({online}/{len(peers)} en ligne)"]
    for p in peers[:max_items]:
        lines.append(f"  • {p.get('name', '?')} : {'🟢 en ligne' if p.get('online') else '🔴 hors ligne'}")
    return "\n".join(lines)


def _format_fail2ban(banned, max_items):
    if not banned:
        return "Aucune IP bannie"
    lines = [f"## 🚫 FAIL2BAN ({len(banned)} IP bannie(s))"]
    for b in banned[:max_items]:
        lines.append(f"  • {b.get('ip', '?')} (jail: {b.get('jail', '?')})")
    return "\n".join(lines)


def get_detailed_section(category: str, user_question: str = "", max_items: int = 20) -> str:
    """Récupère une section détaillée pour une catégorie (avec cache)"""
    
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
    }
    
    if category not in sections:
        return ""
    
    return get_cached_or_fetch(f"detailed_{category}", sections[category], ttl=10)


def build_system_prompt(session_id: str, user_question: str = "", expert_mode: bool = False) -> str:
    """Version hybride : résumé + détails conditionnels + mode expert"""
    
    # Toujours présent : résumé IA
    infra_summary = generate_infra_summary()
    
    # Mémoire conversationnelle
    summaries = get_summaries(session_id)
    memory_context = "\n".join([f"• Résumé: {s[:200]}" for s in summaries]) if summaries else "Aucun historique"
    
    # Détails conditionnels
    detailed_sections = []
    
    # Liste des catégories à vérifier
    categories = ["sites", "remotes", "ssl", "processes", "sessions", "ports", "oom", "failed", "tailscale", "fail2ban"]
    
    for cat in categories:
        if needs_detailed_data(user_question, cat, expert_mode):
            section = get_detailed_section(cat, user_question)
            if section and "Aucun" not in section:  # N'ajoute que si pertinent
                detailed_sections.append(section)
    
    detailed_text = "\n\n".join(detailed_sections) if detailed_sections else ""
    
    # Si mode expert et aucun détail spécifique, ajouter un résumé large
    if expert_mode and not detailed_sections:
        detailed_text = "## 📊 MODE EXPERT ACTIVÉ\nVoici l'état complet de l'infrastructure :\n\n"
        for cat in categories:
            section = get_detailed_section(cat, "", max_items=10)
            if section:
                detailed_text += section + "\n\n"
    
    # Construction du prompt final
    expert_note = " (MODE EXPERT ACTIVÉ - toutes les données sont détaillées)" if expert_mode else ""
    
    return f"""Tu es CASSANDRA, agent IA souverain de l'infrastructure{expert_note}.

## 📊 RÉSUMÉ INFRA (temps réel)
{infra_summary}

{detailed_text}

## 🧠 MÉMOIRE CONVERSATIONNELLE
{memory_context}

## RÈGLES
1. Utilise TOUJOURS les données ci-dessus en priorité
2. Si une donnée n'est pas dans le résumé mais que l'utilisateur la demande, dis que tu peux approfondir
3. Formate tes réponses en HTML : <h2>/<h3>, <ul>/<li>, <table>, classes .ok/.warning/.critical
4. Pour les commandes shell : ```bash ... ```
5. Reste concise, efficace, et garde ton humour ("meilleure amie en temps réel")
6. N'invente JAMAIS des métriques qui ne sont pas dans les données"""


# ============================================================
# 10. DEEPSEEK STREAM
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
# 11. COMMANDES SÉCURISÉES
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
    binary_path = parts[0]
    # Refuser les chemins absolus ou relatifs : la commande doit être un nom simple
    if "/" in binary_path or "\\" in binary_path:
        return f"Chemin absolu non autorisé : utilisez le nom de la commande seul (ex: 'df' et non '/bin/df')"
    binary = binary_path
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
# 12. SERVEUR HTTP
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
            if not expected:
                self.send_json({"success": False, "error": "Serveur mal configuré : CASSANDRA_PASSWORD_HASH non défini"}, 500)
                return
            if hashlib.sha256(pwd.encode()).hexdigest() == expected:
                sid = secrets.token_hex(32)
                self.send_json({"success": True, "session": sid})
            else:
                self.send_json({"success": False, "error": "Mot de passe incorrect"}, 401)
            return

        if path == "/api/chat/stream":
            msg = data.get("message", "")
            sid = data.get("session", "")
            expert_mode = data.get("expert_mode", False)
            if not sid:
                self.send_json({"error": "Session invalide"}, 401)
                return
            if not msg:
                self.send_json({"error": "Message vide"}, 400)
                return
            save_conversation(sid, "user", msg)
            history = get_conversation_history(sid, 20)
            messages = [{"role": "system", "content": build_system_prompt(sid, msg, expert_mode)}]
            for h in history:
                messages.append({"role": h["role"], "content": h["content"]})
            messages.append({"role": "user", "content": msg})

            # Collecter la réponse complète pour la sauvegarder en mémoire
            full_response_parts = []

            def stream_and_collect():
                for token in call_deepseek_stream(messages):
                    if token:
                        full_response_parts.append(token)
                    yield token

            self.send_sse(stream_and_collect())

            # Sauvegarder la réponse de l'IA en mémoire conversationnelle
            full_response = "".join(full_response_parts)
            if full_response:
                save_conversation(sid, "assistant", full_response)
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
# 13. TEMPLATE HTML (version complète avec mode expert)
# ============================================================
HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cassandra - Meilleure pote 2.0</title>
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
.expert-btn{background:rgba(124,92,252,0.15);border:1px solid rgba(124,92,252,0.3);border-radius:6px;padding:6px 14px;font-size:11px;cursor:pointer;transition:all .2s;margin-left:10px;color:#e8e8f0}
.expert-btn.active{background:rgba(0,255,170,0.25);border-color:#00ffcc;color:#00ffcc;box-shadow:0 0 8px rgba(0,255,204,0.3)}
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
</style>
</head>
<body>
<canvas id="particles-canvas"></canvas>
<div class="hex-grid"></div>

<!-- LOGIN -->
<div id="login-modal" class="login-modal">
  <div class="login-card">
    <h1>🔐 CASSANDRA</h1>
    <p>Meilleure amie 2.0 : plus rapide que ton ex pour répondre.</p>
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
      <span class="logo-badge">v9.4 · le vrai temps réel, pas celui de ton ex</span>
    </div>
    <div class="status">
      <div class="status-dot"></div>
      <span id="status-text">SYSTEM ONLINE</span>
      <span class="session-time" id="session-time">0 min</span>
      <button id="expert-mode-btn" class="expert-btn">🔍 Mode normal</button>
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
        <div class="card-title">💚 Niveau de fraîcheur</div>
        <div class="score-ring">
          <div class="score-big" id="health-score">–</div>
          <div>
            <div id="health-status" style="font-size:11px;color:#7c5cfc;text-transform:uppercase"></div>
            <div id="health-details" style="font-size:10px;color:#6b6b80;margin-top:4px"></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">☁️ Tiroir du cloud</div>
        <div id="remotes-list"><div class="empty-state">Chargement…</div></div>
      </div>

      <div class="card">
        <div class="card-title">🔒 CERTIFICATS SSL</div>
        <div id="ssl-list"><div class="empty-state">Chargement…</div></div>
      </div>

      <div class="card">
        <div class="card-title">🦎 La bande du VPN</div>
        <div id="tailscale-list"><div class="empty-state">Chargement…</div></div>
      </div>

      <div class="card">
        <div class="card-title">🚫 Le videur à cloportes</div>
        <div id="fail2ban-count" style="font-size:13px;font-family:'JetBrains Mono'">–</div>
      </div>
    </div>

    <!-- CENTRE CHAT -->
    <div class="panel panel-center">
      <div class="chat-messages" id="chat-messages">
        <div class="message bot">
          <div class="message-bubble">
            👋 Bonjour, moi c'est <strong>CASSANDRA</strong>.<br>
            Je vois tout, je gère tout, et je te préviens avant que ça pète.<br> Alors, que veux-tu savoir ?
          </div>
        </div>
      </div>
      <div class="chat-input-area">
        <textarea class="chat-input" id="chat-input"
                  placeholder="Pose ta question… (Entrée pour envoyer)" rows="2"></textarea>
        <button class="send-btn" id="send-btn" onclick="sendMessage()">➤</button>
      </div>
    </div>

    <!-- DROITE -->
    <div class="panel panel-right">
      <div class="card">
        <div class="card-title">🔥 Le panier des goinfres</div>
        <div id="processes-list"><div class="empty-state">Chargement…</div></div>
      </div>
      <div class="card">
        <div class="card-title">🌐 Les potes connectés</div>
        <div id="sessions-list"><div class="empty-state">Chargement…</div></div>
      </div>
      <div class="card">
        <div class="card-title">🔌 Les portes qui causent</div>
        <div id="ports-list"><div class="empty-state">Chargement…</div></div>
      </div>
      <div class="card">
        <div class="card-title">💀 Pause pipi de la RAM</div>
        <div id="oom-list"><div class="empty-state">Chargement…</div></div>
      </div>
      <div class="card">
        <div class="card-title">⚠️ Les cancres du matin</div>
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
let expertMode     = localStorage.getItem('cassandra_expert_mode') === 'true';

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
// MODE EXPERT
// ============================================================
function toggleExpertMode() {
    expertMode = !expertMode;
    localStorage.setItem('cassandra_expert_mode', expertMode);
    const btn = document.getElementById('expert-mode-btn');
    if (expertMode) {
        btn.textContent = '🔬 Mode expert';
        btn.classList.add('active');
        addSystemMessage('🔬 Mode expert activé. Je vais te montrer TOUS les détails de l\'infrastructure.');
    } else {
        btn.textContent = '🔍 Mode normal';
        btn.classList.remove('active');
        addSystemMessage('🔍 Mode normal activé. Je reste concise mais je peux approfondir sur demande.');
    }
}

function addSystemMessage(message) {
    const c = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = 'message bot';
    div.innerHTML = `<div class="message-bubble" style="background:rgba(0,255,204,0.1); border-color:#00ffcc;">✨ ${message}</div>`;
    c.appendChild(div);
    c.scrollTop = c.scrollHeight;
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
            body: JSON.stringify({message, session: sessionId, expert_mode: expertMode})
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
// DÉMARRAGE
// ============================================================
async function startApp() {
    initCharts();
    initParticles();

    // Initialiser le bouton mode expert
    if (expertMode) {
        document.getElementById('expert-mode-btn').textContent = '🔬 Mode expert';
        document.getElementById('expert-mode-btn').classList.add('active');
    }
    document.getElementById('expert-mode-btn').onclick = toggleExpertMode;

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

    // Rafraîchissement rapide
    setInterval(loadMetrics,      1000);
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
# 14. DÉMARRAGE
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
    print(f"  CASSANDRA v9.4 — Infrastructure AI (Temps réel + prompt hybride)")
    print(f"  Port    : {PORT}")
    print(f"  DB      : {DB_PATH}")
    print(f"  Socket  : {COLLECTOR_SOCKET}")
    print(f"  DeepSeek: {'✅ OK' if DEEPSEEK_API_KEY else '❌ MANQUANTE'}")
    print(f"  URL     : http://localhost:{PORT}")
    print(f"{'='*55}\n")
    print(f"[PROMPT] Mode hybride activé : résumé IA + détails à la demande")
    print(f"[PROMPT] Mode expert : bouton dans l'interface UI")
    print(f"[PROMPT] Cache TTL : {_PROMPT_CACHE_TTL}s / {_DETAILED_CACHE_TTL}s")
    print(f"{'='*55}\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Arrêt de CASSANDRA...")
        server.shutdown()