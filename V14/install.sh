#!/usr/bin/env bash
# ============================================================
#  CASSANDRA — Installeur tout-en-un (Debian / Ubuntu, systemd)
# ============================================================
#  Usage :
#     sudo bash install.sh
#  (ou rendre exécutable : chmod +x install.sh puis sudo ./install.sh)
#
#  Ce script installe Cassandra comme deux services systemd
#  démarrant automatiquement au boot. AUCUNE clé / compte / mot de
#  passe n'est demandé ici : tout se configure ensuite dans le
#  navigateur via l'assistant d'installation intégré (http://IP:9000).
# ============================================================
set -euo pipefail

# --- Couleurs --------------------------------------------------
c_ok="\033[1;32m"; c_warn="\033[1;33m"; c_err="\033[1;31m"; c_inf="\033[1;36m"; c_off="\033[0m"
say()  { echo -e "${c_inf}▸${c_off} $*"; }
ok()   { echo -e "${c_ok}✔${c_off} $*"; }
warn() { echo -e "${c_warn}!${c_off} $*"; }
die()  { echo -e "${c_err}✘ $*${c_off}" >&2; exit 1; }

# --- Constantes ------------------------------------------------
APP_DIR="/opt/cassandra"
CFG_DIR="/etc/cassandra"
DATA_DIR="/var/lib/cassandra"
VENV="$APP_DIR/venv"
PORT=9000
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Réglages prod (surchargeables par variables d'environnement) ──────────────
SWAP_SIZE="${SWAP_SIZE:-5G}"                 # taille du swap si absent ("0" pour désactiver)
SWAPPINESS="${SWAPPINESS:-10}"               # privilégie la RAM, swap = filet de sécurité
ENABLE_SEMANTIC="${ENABLE_SEMANTIC:-1}"      # 1 = mémoire sémantique (embeddings) activée
EMBED_MODEL="${EMBED_MODEL:-intfloat/multilingual-e5-large}"  # qualité max par défaut

echo -e "${c_inf}============================================================${c_off}"
echo -e "${c_inf}  CASSANDRA — Installation${c_off}"
echo -e "${c_inf}============================================================${c_off}"

# --- 1. Root ---------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Ce script doit être lancé en root :  sudo bash install.sh"

# --- 2. systemd présent ---------------------------------------
command -v systemctl >/dev/null 2>&1 || die "systemd introuvable — distribution non supportée."

# --- 3. Fichiers sources présents -----------------------------
for f in cassandra.py cassandra_knowledge_collector.py; do
  [ -f "$SRC_DIR/$f" ] || die "Fichier manquant : $SRC_DIR/$f (placez install.sh à côté des sources)."
done

# --- 4. Dépendances système -----------------------------------
say "Vérification des dépendances système…"
need_apt=0
command -v python3 >/dev/null 2>&1 || need_apt=1
python3 -c 'import venv' >/dev/null 2>&1 || need_apt=1
if [ "$need_apt" -eq 1 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    say "Installation de python3 / venv / pip via apt…"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || warn "apt-get update a échoué (réseau ?) — on continue."
    apt-get install -y python3 python3-venv python3-pip || die "Impossible d'installer python3/venv."
  else
    die "python3 + venv requis et apt-get indisponible. Installez-les manuellement."
  fi
fi
ok "Python : $(python3 --version 2>&1)"

# --- 5. Arrêt des services si déjà installés (upgrade) --------
for svc in cassandra cassandra-collector; do
  if systemctl list-unit-files | grep -q "^${svc}.service"; then
    systemctl stop "$svc" 2>/dev/null || true
  fi
done

# --- 5.5 Mode : mise à jour (défaut) / propre (FRESH) / total (WIPE_ALL) ----
# Par DÉFAUT : mise à jour en place — le code est remplacé, mais la config
# (clés, comptes) et la mémoire/données sont CONSERVÉES.
#   FRESH=1     → réinstalle le code+venv à neuf, conserve config + mémoire.
#   WIPE_ALL=1  → EFFACE TOUT (code + clés/comptes + mémoire) pour repartir vierge.
_EXISTING=0
[ -f "$APP_DIR/cassandra.py" ] && _EXISTING=1

if [ "${WIPE_ALL:-0}" = "1" ] || [ "${WIPE_ALL:-0}" = "EFFACER" ]; then
  warn "WIPE_ALL → EFFACEMENT TOTAL : code, config (clés + comptes) ET mémoire/données."
  warn "Dossiers supprimés : $APP_DIR, $CFG_DIR, $DATA_DIR"
  _conf="$WIPE_ALL"
  if [ "$_conf" != "EFFACER" ]; then
    read -r -p "Confirmer l'effacement TOTAL ? (tape EFFACER) : " _conf 2>/dev/tty || _conf=""
  fi
  [ "$_conf" = "EFFACER" ] || die "Effacement annulé."
  systemctl disable cassandra cassandra-collector 2>/dev/null || true
  rm -rf "$APP_DIR" "$CFG_DIR" "$DATA_DIR"
  ok "Tout effacé — installation vierge."
  _EXISTING=0
elif [ "${FRESH:-0}" = "1" ] && [ "$_EXISTING" = "1" ]; then
  warn "FRESH=1 → réinstallation propre du code et du venv (config + mémoire conservées)."
  rm -rf "$APP_DIR"
  _EXISTING=0
fi

if [ "$_EXISTING" = "1" ]; then
  say "Install existante détectée → MISE À JOUR du code (config + mémoire conservées)."
else
  say "Installation neuve."
fi

# --- 6. Arborescence + copie des sources ----------------------
say "Copie des fichiers vers $APP_DIR…"
mkdir -p "$APP_DIR" "$CFG_DIR" "$DATA_DIR"
chmod 700 "$CFG_DIR"
install -m 0755 "$SRC_DIR/cassandra.py"                     "$APP_DIR/cassandra.py"
install -m 0755 "$SRC_DIR/cassandra_knowledge_collector.py" "$APP_DIR/cassandra_knowledge_collector.py"
[ -f "$SRC_DIR/athena_monitor.sh" ] && install -m 0755 "$SRC_DIR/athena_monitor.sh" "$APP_DIR/athena_monitor.sh" || true
ok "Sources installées."

# --- 7. Environnement Python (venv + openai) ------------------
say "Création de l'environnement Python…"
# Neutraliser un éventuel venv déjà activé dans le shell (sinon ensurepip casse)
unset VIRTUAL_ENV PYTHONHOME PYTHONPATH 2>/dev/null || true

PYBIN="$VENV/bin/python"
# (Re)créer le venv s'il est absent OU cassé (python sans pip)
need_venv=0
[ -x "$PYBIN" ] || need_venv=1
if [ "$need_venv" -eq 0 ] && ! "$PYBIN" -m pip --version >/dev/null 2>&1; then
  need_venv=1
fi
if [ "$need_venv" -eq 1 ]; then
  rm -rf "$VENV"
  python3 -m venv "$VENV" || die "Échec création du venv (paquet python3-venv manquant ?)."
fi

# Garantir pip dans le venv (ensurepip), avec repli get-pip
if ! "$PYBIN" -m pip --version >/dev/null 2>&1; then
  say "Initialisation de pip (ensurepip)…"
  "$PYBIN" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi
if ! "$PYBIN" -m pip --version >/dev/null 2>&1; then
  warn "ensurepip indisponible — tentative get-pip.py…"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py && "$PYBIN" /tmp/get-pip.py >/dev/null 2>&1 || true
  fi
fi
"$PYBIN" -m pip --version >/dev/null 2>&1 || die "Impossible d'obtenir pip dans le venv. Installez : apt install -y python3-pip python3-venv"

"$PYBIN" -m pip install --quiet --upgrade pip || warn "Mise à jour de pip ignorée."
say "Installation du paquet 'openai'…"
"$PYBIN" -m pip install --quiet openai || die "Échec installation de 'openai' (réseau ?)."
if [ "$ENABLE_SEMANTIC" = "1" ]; then
  say "Installation de la mémoire sémantique (sentence-transformers)… (peut être long)"
  "$PYBIN" -m pip install --quiet numpy sentence-transformers \
    || warn "sentence-transformers non installé — mémoire sémantique en repli FTS5."
fi
ok "Environnement prêt."

# --- 8. Units systemd -----------------------------------------
say "Création des services systemd…"
cat > /etc/systemd/system/cassandra-collector.service <<EOF
[Unit]
Description=Cassandra Knowledge Collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
ExecStart=$VENV/bin/python $APP_DIR/cassandra_knowledge_collector.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/cassandra-collector.log
StandardError=append:/var/log/cassandra-collector.log

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/cassandra.service <<EOF
[Unit]
Description=Cassandra Agent (UI port $PORT)
After=network-online.target cassandra-collector.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
ExecStart=$VENV/bin/python $APP_DIR/cassandra.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/cassandra.log
StandardError=append:/var/log/cassandra.log
# Garde-fous mémoire : Cassandra peut utiliser de la RAM + du swap (modèle sémantique
# e5-large) MAIS ne doit JAMAIS faire tomber les autres services. Sous pression mémoire,
# le noyau tue Cassandra EN PREMIER (OOMScoreAdjust élevé) ; systemd la relance.
MemoryHigh=3G
MemoryMax=4G
MemorySwapMax=4G
OOMScoreAdjust=700

[Install]
WantedBy=multi-user.target
EOF
ok "Services créés."

# --- 8.5 Ressources : swap + tuning mémoire + config sémantique ----
say "Configuration mémoire (swap, swappiness, sémantique)…"
_cur_swap_kb=$(awk '/SwapTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
if [ "$SWAP_SIZE" != "0" ] && [ "${_cur_swap_kb:-0}" -lt 2000000 ]; then
  if [ ! -f /swapfile ]; then
    say "Création d'un fichier swap de $SWAP_SIZE…"
    if ! fallocate -l "$SWAP_SIZE" /swapfile 2>/dev/null; then
      dd if=/dev/zero of=/swapfile bs=1M count=$(( ${SWAP_SIZE%G} * 1024 )) status=none
    fi
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
  fi
  swapon /swapfile 2>/dev/null || true
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  ok "Swap actif ($SWAP_SIZE)."
else
  ok "Swap déjà présent ou désactivé — rien à faire."
fi
sysctl -w vm.swappiness="$SWAPPINESS" >/dev/null 2>&1 || true
echo "vm.swappiness=$SWAPPINESS" > /etc/sysctl.d/99-cassandra.conf

# Config mémoire sémantique (merge non destructif — ne touche pas aux autres clés)
ENABLE_SEMANTIC="$ENABLE_SEMANTIC" EMBED_MODEL="$EMBED_MODEL" CFG="$CFG_DIR/config.json" \
"$PYBIN" - <<'PYCFG' || warn "config.json non mis à jour"
import json, os
p = os.environ["CFG"]
d = {}
if os.path.exists(p):
    try: d = json.load(open(p))
    except Exception: d = {}
d["memory_semantic_enabled"] = (os.environ.get("ENABLE_SEMANTIC") == "1")
d.setdefault("memory_embed_model", os.environ.get("EMBED_MODEL"))
os.makedirs(os.path.dirname(p), exist_ok=True)
tmp = p + ".tmp"
json.dump(d, open(tmp, "w"), indent=2)
os.replace(tmp, p)
print("config:", p, "| sémantique:", d["memory_semantic_enabled"], "| modèle:", d.get("memory_embed_model"))
PYCFG
ok "Mémoire configurée."

# --- 9. Activation + démarrage (persistance reboot) -----------
say "Activation et démarrage des services…"
systemctl daemon-reload
systemctl enable --now cassandra-collector.service
systemctl enable --now cassandra.service
sleep 2

# --- 10. Vérification -----------------------------------------
fail=0
for svc in cassandra-collector cassandra; do
  if systemctl is-active --quiet "$svc"; then
    ok "$svc : actif (démarrage auto activé)"
  else
    warn "$svc : NON actif — voir : journalctl -u $svc -n 40"
    fail=1
  fi
done

# --- 11. URL finale -------------------------------------------
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "${IP:-}" ] && IP="<IP_DU_SERVEUR>"
echo
echo -e "${c_inf}============================================================${c_off}"
if [ "$fail" -eq 0 ]; then
  ok "Installation terminée."
else
  warn "Installation terminée avec des avertissements (voir ci-dessus)."
fi
echo
echo -e "  ${c_ok}Ouvrez maintenant dans votre navigateur :${c_off}"
echo -e "      ${c_inf}http://${IP}:${PORT}${c_off}"
echo
echo -e "  L'assistant d'installation vous demandera :"
echo -e "    • compte administrateur (identifiant + mot de passe)"
echo -e "    • clé API du modèle d'IA"
echo -e "    • (optionnel) alertes e-mail SMTP et seuils"
echo
echo -e "  Les services redémarrent automatiquement à chaque boot."
echo -e "${c_inf}============================================================${c_off}"
