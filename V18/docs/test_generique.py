# -*- coding: utf-8 -*-
"""Banc du chantier générique V18 (2026-09-07). Bloc J1-1 : les quatre racines dans le code
et dans install.sh, le service sans dépendance mensongère, le récap sans « deux clés », plus
aucun nom de serveur de test ni de panneau dans install.sh. Il grandit bloc par bloc."""
import io, re, sys

CIB = r"C:\Users\Admin\Documents\Cassandra\cassandra.py"
INST = r"C:\Users\Admin\Documents\Cassandra\install.sh"
S = io.open(CIB, encoding="utf-8").read()
I = io.open(INST, encoding="utf-8").read()
N, KO = 0, []


def ok(cond, quoi):
    global N
    N += 1
    if not cond:
        KO.append(quoi)


# ── les racines dans le code ──
for r, d in (("APP", "/opt/cassandra"), ("CONF", "/etc/cassandra"), ("DATA", "/var/lib/cassandra"), ("LOG", "/var/log")):
    ok('CASSANDRA_%s_DIR%s= os.environ.get("CASSANDRA_%s_DIR")%s or "%s"' % (r, " " * (5 - len(r)), r, " " * (5 - len(r)), d) in S
       or re.search(r'CASSANDRA_%s_DIR\s*=\s*os\.environ\.get\("CASSANDRA_%s_DIR"\)\s*or\s*"%s"' % (r, r, re.escape(d)), S),
       "racine CASSANDRA_%s_DIR définie avec son défaut %s" % (r, d))
ok(S.index("CASSANDRA_DATA_DIR = ") < S.index("DB_PATH          = "), "les racines sont définies avant DB_PATH")
ok('DB_PATH          = os.environ.get("CASSANDRA_DB_PATH") or CASSANDRA_DATA_DIR + "/cassandra.db"' in S, "DB_PATH dérive de DATA_DIR")
for nom in ("CASSANDRA_AUTH_FILE", "CASSANDRA_USERS_FILE", "ALERT_CONFIG_FILE", "_MYSQL_LECTURE_CNF", "_MYSQL_KILL_CNF"):
    ok(re.search(r'^%s\s*=\s*CASSANDRA_CONF_DIR \+ "/' % nom, S, re.M), "%s dérive de CONF_DIR" % nom)
for nom in ("MEMORY_BACKUP_DIR", "_URG_FLAG", "ITARE_WORKSPACE", "_CRON_SPOOL", "_CRON_OPTS_DIR", "_CRON_LOCKS_DIR",
            "_CONF_SAUVEGARDES", "MULTISERVER_CONFIG_FILE", "_THUMB_DIR", "_EVO_PENDING_FILE", "_EVO_GOLDEN"):
    ok(re.search(r'^%s\s*=\s*CASSANDRA_DATA_DIR \+ "/' % nom, S, re.M), "%s dérive de DATA_DIR" % nom)
for nom in ("_VX_VOIX_DIR", "_CONF_APPROUVE", "_PROV_DOSSIER"):
    ok(re.search(r'^%s\s*=\s*CASSANDRA_APP_DIR \+ "/' % nom, S, re.M), "%s dérive de APP_DIR" % nom)
ok(re.search(r'^ADMIN_LOG_FILE\s*=\s*CASSANDRA_LOG_DIR \+ "/', S, re.M), "ADMIN_LOG_FILE dérive de LOG_DIR")
ok('GED_DOCS_BASE = "/srv/documents" if os.path.isdir("/srv/documents") else CASSANDRA_DATA_DIR + "/documents"' in S,
   "GED_DOCS_BASE suit DATA_DIR, /srv/documents seulement s'il existe déjà")
ok("_CAGE_ESPACES = [\"/tmp\", CASSANDRA_DATA_DIR," in S, "les espaces de la cage dérivent des racines")
# aucune dérivation par os.path.join sur une racine (« \ » sur un banc Windows, et un chemin de serveur est POSIX)
ok(not re.search(r'os\.path\.join\(CASSANDRA_(APP|CONF|DATA|LOG)_DIR', S), "aucune racine passée à os.path.join")
# les littéraux restants sont des textes (prompts, descriptions d'outils), jamais des constantes
litt = [l for l in S.splitlines() if re.search(r'^\s*[A-Za-z_]+\s*=\s*"/(var/lib|etc|opt)/cassandra', l)]
ok(not litt, "plus aucune constante de chemin en dur : %r" % litt[:3])

# ── install.sh, bloc J1-1 ──
for r in ("CASSANDRA_APP_DIR", "CASSANDRA_CONF_DIR", "CASSANDRA_DATA_DIR", "CASSANDRA_LOG_DIR"):
    ok(('${%s:-' % r) in I, "install.sh : racine %s surchargeable" % r)
    ok(("Environment=%s=" % r) in I, "install.sh : le service reçoit %s" % r)
ok('_AFTER="network-online.target cassandra-collector.service"' in I and '[ "$WITH_VAULT" = "1" ] && _AFTER="$_AFTER cassandra-vault.service"' in I
   and "After=$_AFTER" in I, "install.sh : After= ne cite le coffre que si WITH_VAULT=1")
ok("After=network-online.target cassandra-collector.service cassandra-vault.service" not in I, "install.sh : plus d'After inconditionnel sur le coffre")
ok(not re.search(r'(?i)amizo|athena|fastpanel', I), "install.sh : aucun nom de serveur de test ni de panneau")
ok("deux clés" not in I and "clé de l'agent secondaire" not in I, "install.sh : le récap ne promet plus deux clés")
ok("Ollama en local (sans clé)" in I, "install.sh : le récap annonce le parcours sans clé")
ok('compte administrateur (= ton compte coffre)' not in I and 'if [ "$WITH_VAULT" = "1" ]; then\n  echo -e "      ${c_acc}•${c_off} un compte administrateur (c\'est aussi ton compte du coffre)"' in I,
   "install.sh : « compte du coffre » seulement si le coffre est installé")
ok("Trois façons d'y accéder" in I and "ssh -L" in I and "nginx-exemple.conf" in I, "install.sh : les trois voies d'accès sur serveur nu")
ok('WANT_TAILSCALE' in I and 'tailscale up' in I, "install.sh : Tailscale en étape optionnelle")
ok('$LOG_DIR/cassandra.log' in I and '$LOG_DIR/cassandra-collector.log' in I, "install.sh : journaux dérivés de LOG_DIR")
ok('if [ -d "$SRC_DIR/docs" ]; then' in I, "install.sh : docs/ livré avec le produit")
ok("\r" not in I, "install.sh : fins de ligne LF")
import os
ok(os.path.exists(r"C:\Users\Admin\Documents\Cassandra\docs\nginx-exemple.conf"), "docs/nginx-exemple.conf existe")

# ── bloc J1-2 : les noms ──
_S2 = "\n".join(l for l in S.splitlines() if not l.startswith("FAVICON_B64"))
for mot in ("drisse", "marple", "maisonboheme", "amizo", "queenphone", "spencer", "atek", "192.168.1.10", "cassandra.center", "hermes", "athena"):
    hits = [l for l in _S2.splitlines() if mot in l.lower()]
    ok(not hits, "cassandra.py : plus aucune ligne portant « %s » : %r" % (mot, [h[:80] for h in hits[:2]]))
ok('"name": "panel_query",' in S and '"name": "panel_act",' in S, "outils d'agent nommés par leur domaine (panel_query, panel_act)")
ok('"fastpanel_query": _fp_query_impl,   # anciens noms' in S, "anciens noms des outils gardés en alias du répartiteur")
ok('"name": "fastpanel_query"' not in S and '"name": "fastpanel_act"' not in S, "aucun outil exposé au modèle ne nomme un fournisseur de panneau")
ok("fastpanel:'Hébergement'" in S and '"label": "Hébergement", "icon": "🖥"' in S, "l'onglet s'appelle Hébergement")
ok('"bookstack_url":          "",' in S, "bookstack_url sans domaine par défaut")
ok('utile à son administrateur' in S and 'utile à Drisse' not in S, "le désir de fond ne nomme personne")
ok('"Vocabulaire : serveur, Cassandra, Itare, panneau, nginx, "' in S, "vocabulaire de la dictée sans nom de labo ni de panneau")
for ph in ('placeholder="http://192.0.2.10:9000"', 'placeholder="cassandra@exemple.org"', 'placeholder="https://cassandra.exemple.org"', 'placeholder="ex : Alice"', 'placeholder="192.0.2.10:/export/docs"'):
    ok(ph in S, "espace réservé générique : %s" % ph)
ok('logging.warning("[RETRY] bash tentative %d/%d' in S, "le format de journal des nouvelles tentatives bash est valide")
for txt in ("dans FastPanel</b>", "FastPanel a refusé", "Comptes FastPanel</div>", "via FastPanel)", "Ouvrir dans FastPanel"):
    ok(txt not in S, "texte d'interface banalisé : %r" % txt)

# ── bloc J1-3 : la table FOURNISSEURS unique, api.key, _agent_ready ──
import ast
_i = S.index("FOURNISSEURS = {"); _j = S.index("}\n_PROVIDERS = {k: v", _i) + 1
try:
    FOUR = ast.literal_eval(S[_i + len("FOURNISSEURS = "):_j])
except Exception as e:
    FOUR = {}; ok(False, "FOURNISSEURS est un littéral Python valide (%s)" % e)
ok(set(FOUR) >= {"deepseek", "openrouter", "openai", "google", "groq", "ollama", "personnalise"}, "la table porte les sept fournisseurs dont « personnalisé »")
ok(all({"nom", "base_url", "defaut", "raisonneur", "cle"} <= set(v) for v in FOUR.values()), "chaque fournisseur a nom, base_url, defaut, raisonneur, cle")
ok(FOUR.get("ollama", {}).get("cle") == "aucune" and FOUR.get("personnalise", {}).get("cle") == "optionnelle", "Ollama sans clé, personnalisé à clé optionnelle")
ok(FOUR.get("ollama", {}).get("defaut", "").startswith("qwen2.5"), "le défaut Ollama est un modèle texte, plus « llava » ni « llama3 »")
ok("_SECONDARY_PROVIDERS = dict(_PROVIDERS)" in S and "_SECONDARY_DEFAULT_MODELS = dict(_DEFAULT_MODELS)" in S, "les tables de l'agent secondaire dérivent de la table unique")
ok('"deepseek":   "https://api.deepseek.com",' not in S or "_SECONDARY_DEFAULT_MODELS_ANCIENS" in S, "plus de base DeepSeek sans /v1 en usage")

ok(S.count('"deepseek-v4-flash"') == 1 and S.count("'deepseek-v4-flash'") == 1, "le défaut DeepSeek n'est écrit qu'une fois côté Python et une fois côté JS")
# la copie JS de la table est en accord avec la table Python
_k = S.index("const _DEFAULT_MODELS_UI = {"); _l = S.index("};", _k)
_js = dict(re.findall(r"(\w+):\s*'([^']*)'", S[_k:_l]))
ok(all(_js.get(p) == FOUR[p]["defaut"] for p in FOUR), "la table JS des défauts est identique à FOURNISSEURS : %r" % {p: (_js.get(p), FOUR[p]["defaut"]) for p in FOUR if _js.get(p) != FOUR[p]["defaut"]})
ok('<option value="personnalise">' in S and '<option value="google">' in S, "le sélecteur des réglages offre Google et Personnalisé")
ok("def _agent_ready() -> bool:" in S and "def _serveur_modele_repond(base_url: str) -> bool:" in S, "_agent_ready et le test de serveur existent")
ok('if not _agent_ready():\n        yield "[ERREUR] " + AGENT_NON_PRET' in S, "le chat interroge _agent_ready, pas la seule clé")
ok("Clé API DeepSeek non configurée" not in S and "Clé DeepSeek non trouvée" not in S, "aucun message ne nomme un fournisseur pour une clé absente")
ok('provider = _cfg_itare("provider", "") or MODEL_PROVIDER or "deepseek"' in S, "Itare hérite du fournisseur principal par défaut")
ok('CASSANDRA_CONF_DIR + "/api.key"' in S and '_LEGACY_KEY_FILE     = CASSANDRA_CONF_DIR + "/deepseek.key"' in S and "def _key_file_actif() -> str:" in S, "api.key avec repli de lecture sur deepseek.key")
ok("with open(_key_file_actif(), 'r') as f:" in S, "la lecture de la clé passe par le fichier actif")
ok("Placez votre clé DeepSeek" not in S and "Placez votre clé API ici" in S, "le gabarit du fichier de clé ne nomme pas un fournisseur")
ok('"-" + CASSANDRA_CONF_DIR + "/api.key", "-" + CASSANDRA_CONF_DIR + "/deepseek.key",' in S, "la cage masque api.key ET deepseek.key")
ok('"-/etc/cassandra/' not in S, "la liste de la cage ne porte plus de chemin de configuration en dur")
ok("/dev/shm/.cassandra_deepseek_key" not in S and "/dev/shm/.cassandra_api_key" in S, "le cache de clé en RAM ne nomme pas un fournisseur")
ok('if not api_key and f["cle"] == "requise":' in S, "l'assistant n'exige la clé que si le fournisseur l'exige")
ok("CLE[v('provider')]||'requise')==='requise'" in S, "la page de l'assistant laisse passer Ollama sans clé")

# ── bloc J1-4 : l'assistant en trois pas ──
_h0 = S.index("SETUP_HTML = r'''"); _h1 = S.index("'''", _h0 + 20); SETUP = S[_h0:_h1]
ok('name="voie" value="api"' in SETUP and 'name="voie" value="ollama"' in SETUP and 'name="voie" value="plus_tard"' in SETUP, "assistant : les trois voies du modèle")
ok('id="tester"' in SETUP and "fetch('/api/setup/test'" in SETUP, "assistant : le bouton Tester appelle /api/setup/test")
ok("fetch('/api/setup/ollama')" in SETUP and 'ollama pull qwen2.5:3b' in SETUP and 'id="retester"' in SETUP, "assistant : Ollama sondé, commande d'installation et Retester")
ok('id="itare_on"' in SETUP and "Itare hérite du modèle principal" in SETUP, "assistant : le second modèle est facultatif, Itare hérite")
ok("<option value=\"openrouter\">openrouter</option>" not in SETUP, "assistant : plus de liste de fournisseurs en dur pour Itare")
ok("voie:vo" in SETUP and "vo==='api'&&!k&&" in SETUP, "assistant : la clé n'est exigée que pour la voie API d'un fournisseur qui l'exige")
ok('voie     = (data.get("voie") or "api").strip().lower()' in S and 'elif voie == "plus_tard":' in S and 'if voie != "plus_tard" and not rotate_deepseek_key(' in S, "apply_setup : les trois voies, le compte se crée sans modèle")
ok("def _sonder_ollama() -> dict:" in S and "def _tester_fournisseur(data: dict) -> dict:" in S, "les deux sondes de l'assistant existent")
ok('if path == "/api/setup/ollama":\n            # sonde d\'Ollama' in S and 'if path == "/api/setup/test":\n            if not _needs_setup():' in S, "les deux routes de l'assistant sont fermées après la première configuration")
ok('def rotate_deepseek_key(new_key: str, provider: str = None, model: str = None, base_url: str = None) -> bool:' in S and "_url  = base_url or _PROVIDERS.get(_prov) or MODEL_BASE_URL" in S, "la rotation accepte l'adresse d'un serveur personnalisé")
ok('"agent_pret": _agent_ready(),' in S and 'id="agent-bandeau"' in S and "d.agent_pret===false" in S, "/api/health porte agent_pret et l'écran a son bandeau")

if KO:
    print("ECHECS (%d/%d) :" % (len(KO), N))
    for k in KO:
        print("   -", k)
    sys.exit(1)
print("OK — test_generique : %d vérifications" % N)
