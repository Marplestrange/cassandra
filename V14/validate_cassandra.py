#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Valide cassandra.py SANS le déployer ni redémarrer le service.
À lancer sur le serveur :

    /opt/cassandra/venv/bin/python validate_cassandra.py /root/cassandra_new.py

Vérifie : (1) syntaxe, (2) noms non définis (faux positifs du nouveau détecteur),
(3) selftest = le module s'importe entièrement sans crash.
Ne touche à RIEN (ni /opt, ni le service).
"""
import sys, ast, builtins, subprocess, os

path = sys.argv[1] if len(sys.argv) > 1 else "cassandra.py"
try:
    src = open(path, encoding="utf-8").read()
except Exception as e:
    print("Impossible de lire %s : %s" % (path, e)); sys.exit(2)

print("== Validation de %s (%d lignes) ==" % (path, len(src.splitlines())))

# 1) Syntaxe -----------------------------------------------------------------
try:
    tree = ast.parse(src)
    print("[1] Syntaxe ........................ OK")
except SyntaxError as e:
    print("[1] Syntaxe ........................ ECHEC ligne %s : %s" % (e.lineno, e.msg))
    sys.exit(1)

# 2) Noms non définis (mêmes règles que le moteur) ---------------------------
dynamic = any(t in src for t in ("globals(", "exec(", "eval(", "setattr(", "vars("))
star = any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
           for n in ast.walk(tree))
if dynamic or star:
    print("[2] Noms non definis ............... ignore (liaison dynamique/star-import)")
else:
    bound = set(dir(builtins))
    bound.update({"__file__", "__name__", "__doc__", "__builtins__", "__spec__",
                  "__loader__", "__package__", "__class__", "__dict__"})
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            bound.add(n.id)
        elif isinstance(n, ast.Import):
            for a in n.names: bound.add((a.asname or a.name).split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            for a in n.names: bound.add(a.asname or a.name)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            for x in n.names: bound.add(x)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
    undef = sorted({n.id for n in ast.walk(tree)
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                    and n.id not in bound})
    if undef:
        print("[2] Noms non definis ............... ATTENTION (faux positifs ?) : %s" % undef[:15])
    else:
        print("[2] Noms non definis ............... OK (0 faux positif)")

# 3) Selftest : le module s'importe entierement sans crash -------------------
env = dict(os.environ, CASSANDRA_SELFTEST="1")
try:
    r = subprocess.run([sys.executable, path], env=env, capture_output=True,
                       text=True, timeout=60)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0 and "SELFTEST_OK" in out:
        print("[3] Selftest (import complet) ...... OK")
    else:
        print("[3] Selftest (import complet) ...... ECHEC (code %s) :" % r.returncode)
        print("\n".join(out.strip().splitlines()[-10:]))
        sys.exit(1)
except subprocess.TimeoutExpired:
    print("[3] Selftest ....................... TIMEOUT (blocage au demarrage)")
    sys.exit(1)

print("\n>>> VALIDATION REUSSIE — le fichier est sain, sur a deployer.")
