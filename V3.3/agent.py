#!/usr/bin/env python3
"""
CASSANDRA — Agent Infrastructure v3.3
Sécurité renforcée + Mémoire contextuelle + Dashboard SSE
"""

import os
import sys
import subprocess
import json
import re
import logging
import sqlite3
import time
import hashlib
import tempfile
from datetime import datetime
from pathlib import Path

# ============================================================
# CONFIGURATION — lecture .env sans dépendance externe
# ============================================================
def load_env():
    """Charge un fichier .env avec la stdlib Python uniquement."""
    candidates = [
        Path("/root/.env"),
        Path(__file__).parent / ".env",
        Path.home() / ".env",
    ]
    for env_path in candidates:
        if env_path.exists():
            try:
                for raw in env_path.read_text(encoding="utf-8").splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k and not os.environ.get(k):
                        os.environ[k] = v
            except Exception as e:
                # Rediriger les erreurs vers stderr seulement
                print(f"[CASSANDRA] Avertissement lecture .env ({env_path}): {e}", file=sys.stderr)
            break

load_env()

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")

# ============================================================
# GESTION ROBUSTE DE LA BASE DE DONNÉES
# ============================================================
def get_db_path():
    """Retourne un chemin valide pour la base de données SQLite"""
    # 1. Essayer /var/lib/cassandra/ (persistant)
    db_path = "/var/lib/cassandra/cassandra.db"
    try:
        parent = Path(db_path).parent
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o777)
        return db_path
    except Exception:
        pass
    
    # 2. Essayer depuis variable d'environnement
    db_path = os.environ.get("CASSANDRA_DB", "")
    if db_path:
        try:
            parent = Path(db_path).parent
            parent.mkdir(parents=True, exist_ok=True)
            test_file = parent / ".write_test"
            test_file.touch()
            test_file.unlink()
            return db_path
        except Exception:
            pass
    
    # 3. Fallback: /tmp/cassandra.db (temporaire)
    db_path = "/tmp/cassandra.db"
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
        return db_path
    except Exception:
        pass
    
    # 4. Dernier recours: mémoire (ne persiste pas)
    return ":memory:"

DB_PATH = get_db_path()
LOG_PATH = os.environ.get("CASSANDRA_LOG", "/tmp/cassandra_audit.log")
MAX_OUTPUT_CHARS = 5000
CMD_TIMEOUT = 15

# Ne pas imprimer de debug sur stdout (cassait le JSON)
# Le debug va sur stderr uniquement
print(f"[CASSANDRA] Base de données: {DB_PATH}", file=sys.stderr)

if not DEEPSEEK_API_KEY:
    print(
        "[CASSANDRA] ERREUR : clé API introuvable.\n"
        "  → Vérifiez que /root/.env contient : DEEPSEEK_API_KEY=sk-xxxx",
        file=sys.stderr
    )
    sys.exit(1)

# ============================================================
# LOGGING AUDIT
# ============================================================
try:
    logging.basicConfig(
        filename=LOG_PATH,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )
except PermissionError:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

audit = logging.getLogger("cassandra.audit")

# ============================================================
# CLIENT DEEPSEEK
# ============================================================
from openai import OpenAI

client = OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com/v1"
)

# ============================================================
# FONCTIONS BASE DE DONNÉES AVEC GESTION D'ERREURS
# ============================================================

def get_db_connection():
    """Retourne une connexion SQLite avec gestion d'erreur"""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    except Exception as e:
        audit.error(f"Erreur connexion DB: {e}")
        return sqlite3.connect(":memory:")

def init_db():
    """Initialise la base de données de mémoire contextuelle."""
    try:
        conn = get_db_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT NOT NULL,
                category  TEXT NOT NULL,
                severity  TEXT NOT NULL,
                title     TEXT NOT NULL,
                detail    TEXT,
                cmd       TEXT,
                resolved  INTEGER DEFAULT 0,
                note      TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics_history (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT NOT NULL,
                cpu_pct   REAL,
                ram_pct   REAL,
                disk_pct  REAL,
                load_avg  TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS conversation_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT NOT NULL,
                session   TEXT,
                role      TEXT,
                content   TEXT
            )
        """)
        conn.commit()
        conn.close()
        audit.info(f"Base de données initialisée: {DB_PATH}")
        return True
    except Exception as e:
        audit.error(f"Erreur initialisation DB: {e}")
        return False

def save_incident(category: str, severity: str, title: str,
                  detail: str = "", cmd: str = "") -> int:
    try:
        conn = get_db_connection()
        cur = conn.execute(
            "INSERT INTO incidents (ts, category, severity, title, detail, cmd) VALUES (?,?,?,?,?,?)",
            (datetime.now().isoformat(), category, severity, title, detail, cmd)
        )
        inc_id = cur.lastrowid
        conn.commit()
        conn.close()
        audit.info("INCIDENT | id=%d | severity=%s | %s", inc_id, severity, title)
        return inc_id
    except Exception as e:
        audit.error(f"Erreur sauvegarde incident: {e}")
        return 0

def get_recent_incidents(n: int = 10) -> list:
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT ts, severity, category, title, detail, resolved FROM incidents "
            "ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()
        conn.close()
        return rows
    except Exception as e:
        audit.error(f"Erreur lecture incidents: {e}")
        return []

def save_metrics(cpu: float, ram: float, disk: float, load: str):
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO metrics_history (ts, cpu_pct, ram_pct, disk_pct, load_avg) VALUES (?,?,?,?,?)",
            (datetime.now().isoformat(), cpu, ram, disk, load)
        )
        conn.execute(
            "DELETE FROM metrics_history WHERE id NOT IN "
            "(SELECT id FROM metrics_history ORDER BY id DESC LIMIT 2880)"
        )
        conn.commit()
        conn.close()
    except Exception as e:
        audit.error(f"Erreur sauvegarde metrics: {e}")

def get_context_summary() -> str:
    """Résumé de la mémoire contextuelle injecté dans le prompt système."""
    rows = get_recent_incidents(5)
    if not rows:
        return "Aucun incident enregistré."
    lines = []
    for ts, sev, cat, title, detail, resolved in rows:
        status = "résolu" if resolved else "actif"
        lines.append(f"• [{ts[:16]}] [{sev.upper()}] {title} ({status})")
    return "\n".join(lines)

def log_conversation(session: str, role: str, content: str):
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO conversation_log (ts, session, role, content) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), session, role, content[:2000])
        )
        conn.commit()
        conn.close()
    except Exception as e:
        audit.error(f"Erreur log conversation: {e}")

# ============================================================
# COLLECTE DE MÉTRIQUES SYSTÈME
# ============================================================

def _run_raw(args: list, timeout: int = 5) -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, shell=False,
                           env={"PATH": "/bin:/usr/bin:/sbin:/usr/sbin"})
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""

def collect_metrics() -> dict:
    """Collecte CPU, RAM, disque — utilisé par le dashboard SSE."""
    metrics = {"ts": datetime.now().isoformat(), "cpu": 0, "ram": 0,
               "disk": 0, "load": "0.0", "services": {}, "alerts": []}

    def read_cpu_stat():
        try:
            line = open("/proc/stat").readline()
            vals = list(map(int, line.split()[1:]))
            idle = vals[3]
            total = sum(vals)
            return idle, total
        except Exception:
            return 0, 1

    i1, t1 = read_cpu_stat()
    time.sleep(0.5)
    i2, t2 = read_cpu_stat()
    cpu = round(100.0 * (1 - (i2 - i1) / max(t2 - t1, 1)), 1)
    metrics["cpu"] = cpu

    try:
        mi = {}
        for line in open("/proc/meminfo"):
            k, v = line.split(":", 1)
            mi[k.strip()] = int(v.strip().split()[0])
        total_ram = mi.get("MemTotal", 1)
        avail_ram = mi.get("MemAvailable", total_ram)
        ram_pct = round(100.0 * (total_ram - avail_ram) / total_ram, 1)
        metrics["ram"] = ram_pct
        metrics["ram_total_gb"] = round(total_ram / 1024 / 1024, 1)
        metrics["ram_used_gb"] = round((total_ram - avail_ram) / 1024 / 1024, 1)
    except Exception:
        pass

    out = _run_raw(["/bin/df", "-h", "/"])
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            pct_str = parts[4].replace("%", "")
            try:
                metrics["disk"] = int(pct_str)
                metrics["disk_total"] = parts[1]
                metrics["disk_used"] = parts[2]
                metrics["disk_avail"] = parts[3]
            except ValueError:
                pass

    try:
        load_raw = open("/proc/loadavg").read().split()
        metrics["load"] = f"{load_raw[0]} {load_raw[1]} {load_raw[2]}"
    except Exception:
        pass

    for svc in ["nginx", "php8.1-fpm", "mysql", "docker"]:
        out = _run_raw(["/bin/systemctl", "is-active", svc], timeout=3)
        metrics["services"][svc] = out.strip() == "active"

    if cpu > 85:
        metrics["alerts"].append({"level": "critical", "msg": f"CPU à {cpu}%"})
        save_incident("cpu", "critical", f"CPU critique : {cpu}%")
    elif cpu > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"CPU à {cpu}%"})

    if metrics["ram"] > 80:
        metrics["alerts"].append({"level": "critical", "msg": f"RAM à {metrics['ram']}%"})
        save_incident("ram", "critical", f"RAM critique : {metrics['ram']}%")
    elif metrics["ram"] > 70:
        metrics["alerts"].append({"level": "warning", "msg": f"RAM à {metrics['ram']}%"})

    if metrics["disk"] > 85:
        metrics["alerts"].append({"level": "critical", "msg": f"Disque à {metrics['disk']}%"})
        save_incident("disk", "critical", f"Disque critique : {metrics['disk']}%")

    save_metrics(cpu, metrics["ram"], metrics["disk"], metrics["load"])

    return metrics

# ============================================================
# SÉCURITÉ — WHITELIST + VALIDATION
# ============================================================

ALLOWED_BINARIES = {
    "/bin/df":            ["-h", "-H", "/"],
    "/usr/bin/free":      ["-h", "-m", "-g"],
    "/usr/bin/uptime":    [],
    "/usr/bin/who":       [],
    "/bin/ps":            ["aux", "-ef"],
    "/usr/bin/top":       ["-bn1"],
    "/bin/systemctl":     ["status", "list-units", "--type=service",
                           "--state=running", "is-active"],
    "/bin/journalctl":    ["-n", "-u", "--since", "--no-pager", "--lines"],
    "/usr/bin/tail":      ["-n", "--lines"],
    "/bin/cat":           [],
    "/bin/ls":            ["-la", "-lh", "-lht"],
    "/usr/bin/du":        ["-sh", "-h", "--max-depth"],
    "/bin/ss":            ["-tulnp", "-s"],
    "/usr/bin/netstat":   ["-tulnp"],
    "/usr/bin/docker":    ["ps", "stats", "--no-stream", "images", "info",
                           "container", "ls"],
    "/usr/bin/nginx":     ["-t"],
    "/usr/bin/mysql":     ["--version"],
    "/usr/bin/php":       ["--version"],
    "/usr/bin/wc":        ["-l"],
}

ALLOWED_READ_PATHS = [
    "/var/log/",
    "/etc/nginx/",
    "/tmp/cassandra/",
    "/proc/",
]

BINARY_ALIASES = {
    "df": "/bin/df", "free": "/usr/bin/free", "uptime": "/usr/bin/uptime",
    "who": "/usr/bin/who", "ps": "/bin/ps", "top": "/usr/bin/top",
    "systemctl": "/bin/systemctl", "journalctl": "/bin/journalctl",
    "tail": "/usr/bin/tail", "cat": "/bin/cat", "ls": "/bin/ls",
    "du": "/usr/bin/du", "ss": "/bin/ss", "netstat": "/usr/bin/netstat",
    "docker": "/usr/bin/docker", "nginx": "/usr/bin/nginx",
    "mysql": "/usr/bin/mysql", "php": "/usr/bin/php", "wc": "/usr/bin/wc",
}

INJECTION_RE = re.compile(
    r'[;&|`]|'
    r'\$\(|'
    r'\$\{|'
    r'>\s*\S|'
    r'<\s*\S|'
    r'\.\.[/\\]|'
    r'\\[nrxt]',
    re.IGNORECASE
)

def validate_path_arg(path: str) -> bool:
    try:
        resolved = str(Path(path).resolve())
        return any(resolved.startswith(p) for p in ALLOWED_READ_PATHS)
    except Exception:
        return False

def secure_execute(cmd: str) -> str:
    """Parse, valide et exécute une commande shell de façon sécurisée."""
    parts = cmd.strip().split()
    if not parts:
        return "Commande vide."

    binary_name = parts[0]
    args = parts[1:]

    abs_bin = BINARY_ALIASES.get(binary_name)
    if abs_bin is None:
        if binary_name.startswith("/") and binary_name in ALLOWED_BINARIES:
            abs_bin = binary_name
        else:
            audit.warning("REFUS_BINAIRE | cmd=%s", cmd)
            return f"Commande refusée : '{binary_name}' n'est pas dans la liste autorisée."

    if abs_bin not in ALLOWED_BINARIES:
        audit.warning("REFUS_BINAIRE | bin=%s", abs_bin)
        return f"Commande refusée : binaire non autorisé."

    for arg in args:
        if INJECTION_RE.search(arg):
            audit.warning("REFUS_INJECTION | cmd=%s | arg=%s", cmd, arg)
            return f"Commande refusée : argument dangereux détecté ('{arg}')."

    if binary_name in ("cat", "tail"):
        for arg in args:
            if arg.startswith("/") and not validate_path_arg(arg):
                audit.warning("REFUS_CHEMIN | cmd=%s | path=%s", cmd, arg)
                return f"Chemin non autorisé : '{arg}'."

    final_cmd = [abs_bin] + args
    audit.info("EXEC | %s", " ".join(final_cmd))

    try:
        result = subprocess.run(
            final_cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT,
            env={"PATH": "/bin:/usr/bin:/sbin:/usr/sbin"},
        )
        output = result.stdout + result.stderr
        audit.info("OK | exit=%d | chars=%d", result.returncode, len(output))
        return output[:MAX_OUTPUT_CHARS] if output else "[Succès — aucune sortie]"
    except subprocess.TimeoutExpired:
        audit.warning("TIMEOUT | cmd=%s", " ".join(final_cmd))
        return f"Commande interrompue : délai de {CMD_TIMEOUT}s dépassé."
    except FileNotFoundError:
        audit.error("BINAIRE_INTROUVABLE | %s", abs_bin)
        return f"Binaire introuvable : {abs_bin}"
    except Exception as e:
        audit.error("ERREUR | %s | %s", " ".join(final_cmd), e)
        return f"Erreur : {e}"

# ============================================================
# FORMATAGE HTML DE LA RÉPONSE
# ============================================================

def execute_command(cmd: str) -> str:
    """Alias public — appelle secure_execute."""
    return secure_execute(cmd)

def parse_table_output(text: str) -> str:
    """Convertit une sortie de commande en tableau HTML sans échappement double"""
    lines = text.strip().split('\n')
    if len(lines) < 2:
        return f'<pre class="command-output">{text}</pre>'
    
    first_line = lines[0]
    if re.match(r'^[\w\s/%]+$', first_line) and len(first_line.split()) >= 3:
        headers = first_line.split()
        rows = []
        for line in lines[1:]:
            if line.strip() and not line.startswith('total'):
                cells = line.split()
                if len(cells) >= len(headers):
                    rows.append(cells[:len(headers)])
        if rows:
            html = '<table class="data-table"><thead><tr>'
            for h in headers:
                html += f'<th>{h}</th>'
            html += '</tr></thead><tbody>'
            for row in rows:
                html += '<tr>'
                for cell in row:
                    if '%' in cell:
                        try:
                            pct = int(cell.replace('%', ''))
                            css = 'critical' if pct > 85 else ('warning' if pct > 70 else 'ok')
                            cell = f'<span class="{css}">{cell}</span>'
                        except ValueError:
                            pass
                    html += f'<td>{cell}</td>'
                html += '</tr>'
            html += '</tbody></table>'
            return html
    return f'<pre class="command-output">{text}</pre>'

def format_response_for_web(reply: str) -> str:
    """Formate la réponse pour le web sans échappement excessif"""
    
    # Traiter les titres
    reply = re.sub(r'^## (.+)$', r'<h2 class="section-title">\1</h2>', reply, flags=re.MULTILINE)
    reply = re.sub(r'^### (.+)$', r'<h3 class="subsection-title">\1</h3>', reply, flags=re.MULTILINE)

    def process_code_block(match):
        code = match.group(1).strip()
        result = secure_execute(code)
        formatted = parse_table_output(result)
        return f'''<div class="command-block">
            <div class="command-header"><span class="command-icon">💻</span> <span class="command-label">{code}</span></div>
            <div class="result-header"><span class="result-icon">📋</span> Résultat</div>
            <div class="result-content">{formatted}</div>
        </div>'''

    reply = re.sub(r'```(?:bash|shell)?\n(.*?)\n```', process_code_block, reply, flags=re.DOTALL)
    
    # Traiter les listes
    reply = re.sub(r'^- (.+)$', r'<li>\1</li>', reply, flags=re.MULTILINE)
    reply = re.sub(r'(<li>.*?</li>)+', lambda m: f'<ul class="info-list">{m.group(0)}</ul>', reply, flags=re.DOTALL)

    # Traiter les paragraphes
    lines = reply.split('\n')
    out = []
    in_block = False
    for line in lines:
        if 'command-block' in line:
            in_block = True
        if '</div>' in line and in_block:
            in_block = False
        if not in_block and line.strip() and not line.startswith('<'):
            out.append(f'<p class="message-text">{line}</p>')
        else:
            out.append(line)
    reply = '\n'.join(out)

    # Colorer les pourcentages
    def color_pct(m):
        p = int(m.group(1))
        css = 'critical' if p > 85 else ('warning' if p > 70 else 'ok')
        return f'<span class="{css}">{p}%</span>'
    reply = re.sub(r'\b(\d{1,3})%', color_pct, reply)
    
    return reply

# ============================================================
# PROMPT SYSTÈME
# ============================================================

def build_system_prompt() -> str:
    context = get_context_summary()
    return f"""Tu es CASSANDRA, agent IA souverain de l'infrastructure.

## ACCÈS SERVEUR
- Hetzner VPS, 8 Go RAM, 105 Go disque
- Services : Nginx, PHP-FPM, MySQL, Nextcloud, Docker
- Commandes autorisées : df, free, uptime, who, ps, top, systemctl, journalctl, tail, cat, ls, du, ss, netstat, docker, nginx, mysql, php

## MÉMOIRE CONTEXTUELLE — incidents récents
{context}

## RÈGLES IMPORTANTES
- Vérifie disque >85% ou RAM >80% → alerte immédiate
- Affiche les commandes à exécuter entre ```bash ... ```
- Structure avec des titres ## et des listes
- Utilise des tableaux pour les données chiffrées
- Demande confirmation pour toute action destructive
- Rappelle les incidents similaires passés si pertinent

## STYLE
- Titres ## pour les sections
- Listes à puces pour les points clés
- Tableaux pour les métriques
- Termine par une proposition d'action concrète"""

# ============================================================
# MODES D'EXÉCUTION
# ============================================================

# Initialiser la base de données au démarrage (silencieux)
init_db()

# Mode métriques — sortie JSON uniquement
if len(sys.argv) > 1 and sys.argv[1] == "--metrics":
    metrics = collect_metrics()
    # Uniquement le JSON sur stdout
    sys.stdout.write(json.dumps(metrics))
    sys.exit(0)

# Mode incidents — sortie JSON uniquement
if len(sys.argv) > 1 and sys.argv[1] == "--incidents":
    rows = get_recent_incidents(20)
    data = []
    for ts, sev, cat, title, detail, resolved in rows:
        data.append({"ts": ts[:16], "severity": sev, "category": cat,
                     "title": title, "resolved": bool(resolved)})
    sys.stdout.write(json.dumps(data))
    sys.exit(0)

# Mode API — appelé par chat.php
if len(sys.argv) > 1 and sys.argv[1] not in ("--metrics", "--incidents"):
    try:
        data = json.loads(sys.argv[1])
        prompt = data.get("message", "")
        history = data.get("history", [])
        session_id = data.get("session", "default")

        log_conversation(session_id, "user", prompt)

        messages = [{"role": "system", "content": build_system_prompt()}]
        messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=messages,
            temperature=0.4,
            max_tokens=2000
        )

        reply = response.choices[0].message.content
        log_conversation(session_id, "assistant", reply)

        formatted = format_response_for_web(reply)
        # ensure_ascii=False pour préserver les caractères Unicode
        sys.stdout.write(json.dumps({"success": True, "response": formatted}, ensure_ascii=False))
        sys.exit(0)

    except Exception as e:
        audit.error("API_ERROR | %s", e)
        sys.stdout.write(json.dumps({"success": False, "error": str(e)}))
        sys.exit(1)

# ============================================================
# MODE INTERACTIF — terminal (conservé pour le debug)
# ============================================================
print("=" * 60, file=sys.stderr)
print("CASSANDRA — Agent Infrastructure v3.3 (mode interactif)", file=sys.stderr)
print(f"Base de données: {DB_PATH}", file=sys.stderr)
print("=" * 60, file=sys.stderr)
print("💬 Mode interactif. Tapez 'exit' pour quitter.", file=sys.stderr)

messages = [{"role": "system", "content": build_system_prompt()}]

while True:
    try:
        user_input = input("> ").strip()
        if user_input.lower() in ("exit", "quit"):
            break
        if not user_input:
            continue
        messages.append({"role": "user", "content": user_input})
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=messages,
            temperature=0.4,
            max_tokens=2000
        )
        reply = response.choices[0].message.content

        def exec_inline(m):
            result = secure_execute(m.group(1).strip())
            return f"```\n{m.group(1).strip()}\n```\nRésultat :\n{result}"

        reply_displayed = re.sub(r'```(?:bash|shell)?\n(.*?)\n```',
                                  exec_inline, reply, flags=re.DOTALL)
        print(f"\n{reply_displayed}\n")
        messages.append({"role": "assistant", "content": reply})
        if len(messages) > 12:
            messages = [messages[0]] + messages[-10:]

    except KeyboardInterrupt:
        print("\nAu revoir !")
        break
    except Exception as e:
        print(f"Erreur : {e}")