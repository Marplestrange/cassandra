#!/usr/bin/env python3
"""
Micro-benchmark : cassandra_knowledge_collector v_old vs v_opt
==============================================================
Mesure les 5 optimisations les plus impactantes de façon isolée.

Usage :
    python3 benchmark_collector.py
    python3 benchmark_collector.py --runs 20   # plus de passages
"""

import os
import sys
import time
import sqlite3
import subprocess
import tempfile
import argparse
from pathlib import Path
from statistics import mean, stdev

# ── Couleurs terminal ─────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def hdr(title: str):
    print(f"\n{CYAN}{BOLD}{'─'*60}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'─'*60}{RESET}")

def bench(label: str, fn, runs: int):
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    avg = mean(times)
    sd  = stdev(times) if len(times) > 1 else 0
    return avg, sd, times

def compare(label_old, t_old, label_new, t_new):
    ratio = t_old / t_new if t_new > 0 else float("inf")
    color = GREEN if ratio >= 2 else YELLOW if ratio >= 1.2 else RED
    print(f"  {label_old:<35} {t_old:>8.2f} ms")
    print(f"  {label_new:<35} {t_new:>8.2f} ms")
    print(f"  {color}{'Gain':>35} ×{ratio:.1f}{RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
# B1 — /proc/meminfo : 2 lectures séparées vs 1 lecture partagée
# ═══════════════════════════════════════════════════════════════════════════════
def meminfo_old():
    """Version originale : 2 open() indépendants."""
    def read_once():
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    mi[k.strip()] = int(v.strip().split()[0])
        return mi
    mi1 = read_once()  # get_ram()
    mi2 = read_once()  # get_swap()
    # Simule le calcul
    _ = mi1.get("MemTotal", 1) - mi1.get("MemAvailable", 0)
    _ = mi2.get("SwapTotal", 0) - mi2.get("SwapFree", 0)

def meminfo_new():
    """Version optimisée : 1 open() partagé."""
    mi = {}
    with open("/proc/meminfo") as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
    # Simule get_ram() + get_swap() depuis le même dict
    _ = mi.get("MemTotal", 1) - mi.get("MemAvailable", 0)
    _ = mi.get("SwapTotal", 0) - mi.get("SwapFree", 0)


# ═══════════════════════════════════════════════════════════════════════════════
# B2 — sysctl_security : 10 subprocesses vs 1 batch
# ═══════════════════════════════════════════════════════════════════════════════
SYSCTL_PARAMS = [
    "kernel.kptr_restrict", "kernel.dmesg_restrict",
    "kernel.randomize_va_space", "net.ipv4.conf.all.rp_filter",
    "net.ipv4.tcp_syncookies", "net.ipv4.conf.all.accept_redirects",
    "fs.protected_symlinks", "fs.protected_hardlinks",
    "fs.protected_fifos", "fs.protected_regular",
]

def sysctl_old():
    """10 appels sysctl individuels."""
    values = []
    for p in SYSCTL_PARAMS:
        try:
            r = subprocess.run(["sysctl", "-n", p], capture_output=True, text=True, timeout=3)
            values.append(r.stdout.strip())
        except Exception:
            values.append("unknown")
    return values

def sysctl_new():
    """1 seul appel sysctl avec tous les paramètres."""
    try:
        r = subprocess.run(["sysctl", "-n"] + SYSCTL_PARAMS,
                           capture_output=True, text=True, timeout=5)
        values = r.stdout.splitlines()
        if len(values) != len(SYSCTL_PARAMS):
            return sysctl_old()  # fallback
        return values
    except Exception:
        return sysctl_old()


# ═══════════════════════════════════════════════════════════════════════════════
# B3 — save_many : INSERT ligne par ligne vs executemany batch
# ═══════════════════════════════════════════════════════════════════════════════
def _make_test_db(n_rows: int):
    """Crée une DB SQLite temporaire avec une table de test."""
    db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db.close()
    conn = sqlite3.connect(db.name)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""CREATE TABLE t (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT, ssl_enabled INTEGER, php_version TEXT,
        document_root TEXT, status TEXT, last_check TEXT
    )""")
    conn.commit()
    conn.close()
    rows = [{"domain": f"site{i}.example.com", "ssl_enabled": i % 2,
             "php_version": "8.2", "document_root": f"/var/www/site{i}",
             "status": "active", "last_check": "2024-01-01"}
            for i in range(n_rows)]
    return db.name, rows

def save_many_old(db_path: str, rows: list):
    """INSERT ligne par ligne (original)."""
    conn = sqlite3.connect(db_path, timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        cols  = list(rows[0].keys())
        place = ",".join(["?"] * len(cols))
        conn.execute("BEGIN EXCLUSIVE")
        conn.execute("DELETE FROM t")
        for r in rows:
            try:
                conn.execute(f"INSERT INTO t ({','.join(cols)}) VALUES ({place})",
                             [r.get(c) for c in cols])
            except Exception:
                pass
        conn.commit()
    except Exception as e:
        conn.rollback()
    finally:
        conn.close()

def save_many_new(db_path: str, rows: list):
    """executemany batch (optimisé)."""
    conn = sqlite3.connect(db_path, timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        cols   = list(rows[0].keys())
        place  = ",".join(["?"] * len(cols))
        values = [[r.get(c) for c in cols] for r in rows]
        conn.execute("BEGIN")
        conn.execute("DELETE FROM t")
        conn.executemany(f"INSERT INTO t ({','.join(cols)}) VALUES ({place})", values)
        conn.commit()
    except Exception as e:
        conn.rollback()
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# B4 — _fp_available : Path.exists() × N vs lru_cache
# ═══════════════════════════════════════════════════════════════════════════════
FP_PARAM_FILES = [
    "/usr/local/fastpanel2/app/config/parameters.yml",
    "/usr/local/fastpanel2/app/config/parameters.yaml",
    "/usr/local/fastpanel2/config/database.yml",
]
ALT_SIGNALS = [
    "/etc/nginx/fastpanel2",
    "/usr/local/fastpanel2",
    "/var/www/fastuser",
]

def fp_available_old():
    """8 appels sans cache (comme le collecteur original)."""
    for _ in range(8):   # simuler 8 collecteurs qui appellent _fp_available()
        result = any(Path(f).exists() for f in FP_PARAM_FILES) or \
                 any(Path(p).exists() for p in ALT_SIGNALS)
    return result

from functools import lru_cache

@lru_cache(maxsize=1)
def _fp_available_cached() -> bool:
    return any(Path(f).exists() for f in FP_PARAM_FILES) or \
           any(Path(p).exists() for p in ALT_SIGNALS)

def fp_available_new():
    """8 appels avec lru_cache — 7 retours immédiats."""
    _fp_available_cached.cache_clear()   # repart de zéro pour chaque bench run
    for _ in range(8):
        result = _fp_available_cached()
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# B5 — detect_diff : N connexions DB vs 1 transaction
# ═══════════════════════════════════════════════════════════════════════════════
def _make_changelog_db():
    db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db.close()
    conn = sqlite3.connect(db.name)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE changelog (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, entity_type TEXT, entity_name TEXT,
        change_type TEXT, old_value TEXT, new_value TEXT, severity TEXT
    )""")
    conn.commit()
    conn.close()
    return db.name

def detect_diff_old(db_path: str, entity_type: str, new_names: list):
    """K changements → K connexions DB (original)."""
    def get_conn():
        conn = sqlite3.connect(db_path, timeout=15)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def record_change(et, en, ct, nv=None, sev="info"):
        conn = get_conn()
        conn.execute(
            "INSERT INTO changelog (ts,entity_type,entity_name,change_type,new_value,severity) "
            "VALUES (datetime('now'),?,?,?,?,?)", (et, en, ct, nv, sev)
        )
        conn.commit()
        conn.close()

    conn = get_conn()
    rows = conn.execute(
        "SELECT entity_name FROM changelog WHERE entity_type=? ORDER BY id DESC LIMIT 500",
        (entity_type,)
    ).fetchall()
    conn.close()
    known = {r[0] for r in rows}
    current = set(new_names)
    for name in current - known:
        record_change(entity_type, name, "added", severity="info")
    for name in known - current:
        record_change(entity_type, name, "removed", severity="warning")

def detect_diff_new(db_path: str, entity_type: str, new_names: list):
    """K changements → 1 connexion, 1 transaction (optimisé)."""
    def get_conn():
        conn = sqlite3.connect(db_path, timeout=15)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    conn = get_conn()
    rows = conn.execute(
        "SELECT entity_name FROM changelog WHERE entity_type=? ORDER BY id DESC LIMIT 500",
        (entity_type,)
    ).fetchall()
    known   = {r[0] for r in rows}
    current = set(new_names)
    inserts = []
    for name in current - known:
        inserts.append(("domains", entity_type, name, "added",   None, "info"))
    for name in known - current:
        inserts.append(("domains", entity_type, name, "removed", None, "warning"))
    if inserts:
        conn.executemany(
            "INSERT INTO changelog (ts,entity_type,entity_name,change_type,new_value,severity) "
            "VALUES (datetime('now'),?,?,?,?,?)",
            [i[1:] for i in inserts]
        )
        conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Benchmark collector v_old vs v_opt")
    parser.add_argument("--runs", type=int, default=10,
                        help="Nombre de passages par test (défaut: 10)")
    parser.add_argument("--rows", type=int, default=500,
                        help="Lignes pour le benchmark save_many (défaut: 500)")
    parser.add_argument("--changes", type=int, default=30,
                        help="Changements pour detect_diff (défaut: 30)")
    args = parser.parse_args()

    print(f"\n{BOLD}CASSANDRA — Benchmark optimisations{RESET}")
    print(f"Passes: {args.runs}  |  Lignes DB: {args.rows}  |  Changements: {args.changes}")

    # ── B1 : meminfo ──────────────────────────────────────────────────────────
    hdr("B1 — /proc/meminfo (2 lectures vs 1 partagée)")
    t_old, sd_old, _ = bench("old", meminfo_old, args.runs)
    t_new, sd_new, _ = bench("new", meminfo_new, args.runs)
    compare("2× open('/proc/meminfo')", t_old, "1× open('/proc/meminfo')", t_new)
    print(f"  Complexité: O(2×read_file) → O(1×read_file)")

    # ── B2 : sysctl ───────────────────────────────────────────────────────────
    if subprocess.run(["which","sysctl"], capture_output=True).returncode == 0:
        hdr("B2 — sysctl_security (10 subprocesses vs 1 batch)")
        t_old, _, _ = bench("old", sysctl_old, max(args.runs // 2, 3))
        t_new, _, _ = bench("new", sysctl_new, max(args.runs // 2, 3))
        compare("10 × subprocess sysctl -n param", t_old,
                "1  × subprocess sysctl -n p1 p2…", t_new)
        print(f"  Complexité: O(10 fork+exec) → O(1 fork+exec)")
    else:
        print(f"\n{YELLOW}B2 — sysctl non disponible, skippé{RESET}")

    # ── B3 : save_many ────────────────────────────────────────────────────────
    hdr(f"B3 — save_many (INSERT × {args.rows} vs executemany batch)")
    db_path, rows = _make_test_db(args.rows)
    t_old, _, _ = bench("old", lambda: save_many_old(db_path, rows), args.runs)
    t_new, _, _ = bench("new", lambda: save_many_new(db_path, rows), args.runs)
    compare(f"for r in rows: conn.execute(INSERT)", t_old,
            f"conn.executemany(INSERT, values)", t_new)
    print(f"  Complexité: O(n) appels SQLite → O(1) batch")
    os.unlink(db_path)

    # ── B4 : _fp_available ────────────────────────────────────────────────────
    hdr("B4 — _fp_available (8× Path.exists() vs lru_cache)")
    t_old, _, _ = bench("old", fp_available_old, args.runs)
    t_new, _, _ = bench("new", fp_available_new, args.runs)
    compare("8 × Path.exists() (N syscalls)", t_old,
            "lru_cache → 1 lookup + 7 cache hits", t_new)
    print(f"  Complexité: O(8×N_paths syscalls) → O(1) après 1er appel")

    # ── B5 : detect_diff ──────────────────────────────────────────────────────
    hdr(f"B5 — detect_diff ({args.changes} changements, N conn vs 1 transaction)")
    db_old = _make_changelog_db()
    db_new = _make_changelog_db()
    old_names = [f"domain_{i}.fr" for i in range(100)]
    new_names = [f"domain_{i}.fr" for i in range(70)] + \
                [f"new_{i}.fr"    for i in range(args.changes)]

    t_old, _, _ = bench("old",
        lambda: detect_diff_old(db_old, "domain", new_names), args.runs)
    t_new, _, _ = bench("new",
        lambda: detect_diff_new(db_new, "domain", new_names), args.runs)
    compare(f"{args.changes} × record_change (connexion individuelle)", t_old,
            f"1 connexion + executemany batch", t_new)
    print(f"  Complexité: O(K) connexions SQLite → O(1) connexion")
    os.unlink(db_old)
    os.unlink(db_new)

    # ── Récapitulatif ─────────────────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  Récapitulatif (gain ×N = ancien_temps / nouveau_temps){RESET}")
    print(f"{CYAN}{BOLD}{'═'*60}{RESET}")
    summary = [
        ("B1 meminfo",   meminfo_old, meminfo_new),
        ("B4 fp_avail",  fp_available_old, fp_available_new),
    ]
    for label, fn_old, fn_new in summary:
        to, _, _ = bench("", fn_old, 5)
        tn, _, _ = bench("", fn_new, 5)
        g = to / tn if tn > 0 else 0
        bar = "█" * min(int(g * 4), 40)
        color = GREEN if g >= 2 else YELLOW
        print(f"  {label:<20} {color}×{g:5.1f}  {bar}{RESET}")

    print(f"\n{BOLD}Note sur B6 (parallélisation collecteurs) :{RESET}")
    print("  Non mesurable ici sans un vrai serveur Linux.")
    print("  Gain théorique : t_total ≈ max(t_collecteur) au lieu de Σ(t_collecteurs)")
    print("  Avec 25 collecteurs à 2s chacun : 50s → ~8s (×6)")
    print()

if __name__ == "__main__":
    main()
