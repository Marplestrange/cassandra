#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Drisse ATEK
# ============================================================
#  CASSANDRA — Installeur tout-en-un (Debian / Ubuntu, systemd)
#  Déploie Cassandra + collecteur + coffre Vaultwarden d'un seul tenant.
#  Idempotent : le relancer sur une installation existante la MET À JOUR
#  (services arrêtés, code et dépendances rafraîchis, config et mémoire gardées).
# ============================================================
#  Usage :
#     sudo bash install.sh
#
#  Variables utiles (toutes optionnelles) :
#     WITH_VAULT=0      → ne déploie PAS le coffre Vaultwarden
#     VAULT_EMAIL=...   → e-mail du compte service coffre (def: cassandra@vault.local)
#     VAULT_DOMAIN=...  → URL publique du coffre derrière ton proxy (def: localhost)
#     FRESH=1           → réinstalle code+venv à neuf (conserve config + mémoire)
#     (par défaut, l'installeur DEMANDE si tu veux l'IA locale d'Itare : Ollama + LoRA)
#     WITH_OLLAMA=1/0   → répond à cette question sans la poser (1 = Ollama, +LoRA si GPU ; 0 = non)
#     WITH_SEARXNG=1    → déploie SearxNG (recherche web souveraine d'Itare) : Docker, JSON activé,
#                         port libre auto, URL renseignée dans la config. Zéro manip YAML.
#     WIPE_ALL=1        → EFFACE TOUT (code + clés + mémoire + coffre Vaultwarden).
#     KEEP_VAULT=1      → avec WIPE_ALL : CONSERVE le coffre Vaultwarden et ses secrets.
#
#  L'agent se configure ensuite dans le navigateur (http://IP:9000).
# ============================================================
set -euo pipefail

# --- Palette & habillage --------------------------------------
CASSANDRA_VERSION="${CASSANDRA_VERSION:-18}"
if [ -t 1 ] && [ "${NO_COLOR:-0}" != "1" ]; then
  c_off="\033[0m"; c_bold="\033[1m"; c_dim="\033[2m"
  c_ok="\033[1;38;5;48m"; c_warn="\033[1;38;5;214m"; c_err="\033[1;38;5;203m"
  c_inf="\033[38;5;111m"; c_acc="\033[1;38;5;147m"
  L1="\033[38;5;141m"; L2="\033[38;5;134m"; L3="\033[38;5;105m"
  L4="\033[38;5;75m";  L5="\033[38;5;81m";  L6="\033[38;5;51m"
else
  c_off=""; c_bold=""; c_dim=""; c_ok=""; c_warn=""; c_err=""; c_inf=""; c_acc=""
  L1=""; L2=""; L3=""; L4=""; L5=""; L6=""
fi

say()  { echo -e "   ${c_inf}▸${c_off} $*"; }
ok()   { echo -e "   ${c_ok}✔${c_off} $*"; }
warn() { echo -e "   ${c_warn}▲${c_off} ${c_warn}$*${c_off}"; }
die()  { echo -e "\n   ${c_err}✘ $*${c_off}\n" >&2; exit 1; }
hr()   { echo -e "${c_dim}   ────────────────────────────────────────────────────────────────────${c_off}"; }

# ── Chrono + spinner animé (dégrade proprement hors TTY, ne casse jamais set -e) ──
_T0=$(date +%s)
_SPIN="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
run_spin() {
  # run_spin "message" commande args… → anime pendant l'exécution, ✔/✘ à la fin.
  local msg="$1"; shift; local logf rc=0
  logf="$(mktemp 2>/dev/null || echo /tmp/cass_spin.$$)"
  if [ -t 1 ] && [ "${NO_COLOR:-0}" != "1" ]; then
    "$@" >"$logf" 2>&1 & local pid=$! i=0 n=${#_SPIN}
    while kill -0 "$pid" 2>/dev/null; do
      printf "\r   ${c_acc}%s${c_off} %s " "${_SPIN:i%n:1}" "$msg"; i=$((i + 1)); sleep 0.08
    done
    wait "$pid" || rc=$?
    if [ "$rc" -eq 0 ]; then printf "\r   ${c_ok}✔${c_off} %s\033[K\n" "$msg"
    else printf "\r   ${c_err}✘${c_off} %s\033[K\n" "$msg"; tail -4 "$logf" 2>/dev/null | sed "s/^/       /"; fi
  else
    printf "   ${c_inf}▸${c_off} %s…\n" "$msg"; "$@" >"$logf" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then ok "$msg"; else warn "$msg (échec)"; tail -4 "$logf" 2>/dev/null | sed "s/^/       /"; fi
  fi
  rm -f "$logf" 2>/dev/null || true
  return "$rc"
}
fmt_elapsed() { local s=$(( $(date +%s) - _T0 )); printf "%dm%02ds" $(( s / 60 )) $(( s % 60 )); }

STEP_N=0; STEP_TOTAL="${STEP_TOTAL:-9}"
step() {
  STEP_N=$((STEP_N + 1))
  local filled=$(( STEP_N * 18 / STEP_TOTAL )) bar="" j=0
  while [ "$j" -lt 18 ]; do
    if [ "$j" -lt "$filled" ]; then bar="${bar}▰"; else bar="${bar}▱"; fi
    j=$((j + 1))
  done
  echo ""
  echo -e "${c_acc}  ┃${c_off} ${L3}${bar}${c_off} ${c_bold}${STEP_N}${c_off}${c_dim}/${STEP_TOTAL}${c_off}  ${c_bold}$*${c_off}"
}

banner() {
  echo ""
  echo -e "${L1}      ██████╗ █████╗ ███████╗███████╗ █████╗ ███╗   ██╗██████╗ ██████╗  █████╗ ${c_off}"
  echo -e "${L2}     ██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗${c_off}"
  echo -e "${L3}     ██║     ███████║███████╗███████╗███████║██╔██╗ ██║██║  ██║██████╔╝███████║${c_off}"
  echo -e "${L4}     ██║     ██╔══██║╚════██║╚════██║██╔══██║██║╚██╗██║██║  ██║██╔══██╗██╔══██║${c_off}"
  echo -e "${L5}     ╚██████╗██║  ██║███████║███████║██║  ██║██║ ╚████║██████╔╝██║  ██║██║  ██║${c_off}"
  echo -e "${L6}      ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝${c_off}"
  echo ""
  echo -e "        ${c_bold}IA souveraine d'administration système${c_off}  ${c_dim}·${c_off}  ${c_acc}coffre intégré${c_off}  ${c_dim}·  v${CASSANDRA_VERSION}${c_off}"
  echo -e "        ${c_dim}Itare · vérificateur anti-injection · hybride local⇄cloud · veille autonome${c_off}"
  echo -e "${c_dim}      ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c_off}"
  echo ""
}

done_box() {
  local ip="$1"
  echo ""
  echo -e "${c_ok}  ╭──────────────────────────────────────────────────────────────╮${c_off}"
  echo -e "${c_ok}  │${c_off}   ${c_bold}✦  CASSANDRA EST ÉVEILLÉE${c_off}   ${c_dim}·  prête en $(fmt_elapsed)${c_off}"
  echo -e "${c_ok}  │${c_off}"
  echo -e "${c_ok}  │${c_off}      ${c_dim}Console${c_off}       ${c_acc}http://${BIND_HOST}:${PORT}${c_off}  ${c_dim}(derrière ton proxy)${c_off}"
  echo -e "${c_ok}  │${c_off}      ${c_dim}Premier pas${c_off}   crée ton compte admin + tes clés"
  echo -e "${c_ok}  │${c_off}      ${c_dim}Services${c_off}      redémarrage auto à chaque boot"
  echo -e "${c_ok}  ╰──────────────────────────────────────────────────────────────╯${c_off}"
  echo ""
}

# --- Constantes ------------------------------------------------
# Les quatre racines de l'installation, surchargeables par variable d'environnement.
# Le service reçoit les mêmes valeurs : le code ne connaît que ces racines.
APP_DIR="${CASSANDRA_APP_DIR:-/opt/cassandra}"
CFG_DIR="${CASSANDRA_CONF_DIR:-/etc/cassandra}"
DATA_DIR="${CASSANDRA_DATA_DIR:-/var/lib/cassandra}"
LOG_DIR="${CASSANDRA_LOG_DIR:-/var/log}"
VENV="$APP_DIR/venv"
PORT="${PORT:-9000}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Réglages prod (surchargeables par variables d'environnement) ──────────────
SWAP_SIZE="${SWAP_SIZE:-8G}"
SWAPPINESS="${SWAPPINESS:-10}"
ENABLE_SEMANTIC="${ENABLE_SEMANTIC:-1}"
EMBED_MODEL="${EMBED_MODEL:-intfloat/multilingual-e5-large}"
# Bind réseau : 127.0.0.1 par DÉFAUT — Cassandra se place derrière un reverse proxy (nginx, un
# panneau d'hébergement, Caddy…) qui porte le domaine et le TLS. Pour exposer le port directement :
# BIND_HOST=0.0.0.0 (déconseillé sans TLS devant). Les trois voies sont rappelées en fin d'installation.
BIND_HOST="${BIND_HOST:-127.0.0.1}"
# Plafond mémoire du service, ADAPTATIF selon la RAM (laisse ~2 Go au système + Ollama).
_ram_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 4096)
_mm=$(( _ram_mb - 2048 )); [ "$_mm" -lt 1024 ] && _mm=1024
MEM_MAX="${MEM_MAX:-${_mm}M}"; MEM_HIGH="${MEM_HIGH:-$(( _mm * 3 / 4 ))M}"

# ── Coffre Vaultwarden ────────────────────────────────────────────────────────
WITH_VAULT="${WITH_VAULT:-1}"
VAULT_DIR="${CASSANDRA_VAULT_DIR:-/opt/vaultwarden}"
VAULT_PORT="${VAULT_PORT:-8087}"          # port local du conteneur (bind 127.0.0.1)
VAULT_SERVE_PORT="${VAULT_SERVE_PORT:-8088}"  # API REST locale bw serve
VAULT_EMAIL="${VAULT_EMAIL:-cassandra@vault.local}"
VAULT_DOMAIN="${VAULT_DOMAIN:-http://127.0.0.1:${VAULT_PORT}}"
VAULT_ENV="$CFG_DIR/vault.env"

clear 2>/dev/null || true
banner

step "Pré-vol — droits, systemd, sources"
# --- 1. Root ---------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Ce script doit être lancé en root :  sudo bash install.sh"
ok "Privilèges root confirmés"

# --- 2. systemd présent ---------------------------------------
command -v systemctl >/dev/null 2>&1 || die "systemd introuvable — distribution non supportée."
ok "systemd détecté"

# --- 3. Fichiers sources présents -----------------------------
for f in cassandra.py cassandra_knowledge_collector.py; do
  [ -f "$SRC_DIR/$f" ] || die "Fichier manquant : $SRC_DIR/$f (placez install.sh à côté des sources)."
done
ok "Sources présentes"

# --- 3.5 Preflight ressources : plancher dur (bloque) + recommandations (avertit) ---
_pf_ram=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
_pf_disk=$(df -Pk / 2>/dev/null | awk 'NR==2{print int($4/1024/1024)}' || echo 0)
_pf_cpu=$(nproc 2>/dev/null || echo 1)
say "Ressources : ${_pf_ram} Mo RAM · ${_pf_disk} Go libres (/) · ${_pf_cpu} vCPU"
if [ "${_pf_ram:-0}" -ge 1 ] && [ "$_pf_ram" -lt 900 ]; then
  die "RAM insuffisante (${_pf_ram} Mo) — 1 Go minimum requis."
fi
if [ "${_pf_disk:-0}" -ge 1 ] && [ "$_pf_disk" -lt 3 ]; then
  die "Disque insuffisant (${_pf_disk} Go libres sur /) — 3 Go minimum requis."
fi
if [ "${_pf_ram:-0}" -ge 1 ] && [ "$_pf_ram" -lt 2000 ]; then
  warn "RAM faible (${_pf_ram} Mo) : 2 Go conseillés, 4-8 Go pour un modèle local."
fi
if [ "${_pf_disk:-0}" -ge 1 ] && [ "$_pf_disk" -lt 15 ]; then
  warn "Disque serré (${_pf_disk} Go) : ~15 Go conseillés (venv + swap 8G + modèles + backups)."
fi

# --- 4. Dépendances système -----------------------------------
step "Dépendances système"
say "Vérification des dépendances système…"
APT_OK=0
command -v apt-get >/dev/null 2>&1 && APT_OK=1
need_apt=0
command -v python3 >/dev/null 2>&1 || need_apt=1
python3 -c 'import venv' >/dev/null 2>&1 || need_apt=1
command -v curl >/dev/null 2>&1 || need_apt=1

# CORRECTION : vérifie explicitement si python3-venv est installé
if [ "$APT_OK" -eq 1 ]; then
    # Vérifie si le paquet python3-venv est installé via dpkg
    if ! dpkg -l python3-venv >/dev/null 2>&1; then
        need_apt=1
    fi
    # Vérifie aussi python3-pip
    if ! dpkg -l python3-pip >/dev/null 2>&1; then
        need_apt=1
    fi
fi

if [ "$need_apt" -eq 1 ]; then
  if [ "$APT_OK" -eq 1 ]; then
    say "Installation de python3 / venv / pip / curl via apt…"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || warn "apt-get update a échoué (réseau ?) — on continue."
    # CORRECTION : installe explicitement python3-venv et python3-pip
    # `build-essential`, `python3-dev` et `libffi-dev` servent à `cryptography`,
    # qui compile du Rust : sans eux, pip réussit parfois et l'import échoue
    # ensuite. Les poser d'emblée évite un aller-retour par un message d'erreur.
    apt-get install -y python3 python3-venv python3-pip curl ca-certificates \
                       build-essential python3-dev libffi-dev \
      || die "Impossible d'installer les dépendances de base."
  else
    die "python3 + venv + curl requis et apt-get indisponible. Installez-les manuellement."
  fi
fi

# --- 4bis. Lecture des documents (PDF de texte, PDF scannés) --
# `pdftotext` ET `pdftoppm` viennent tous deux de poppler-utils : le premier lit
# un PDF de TEXTE, le second rend en images les pages d'un PDF SCANNÉ, que
# `tesseract` déchiffre ensuite. Sans eux, une facture scannée arrive VIDE — et
# rien n'accuse le serveur : le fichier est parfaitement sain, c'est la machine
# qui n'a pas de quoi le lire.
#
# `.docx` et `.xlsx` ne demandent RIEN de plus : ce sont des ZIP de XML, lus par
# la bibliothèque standard de Python.
#
# Non bloquant : Cassandra démarre sans. Elle le dit à l'usage, plutôt que de
# rendre un document vide en silence.
if [ "$APT_OK" -eq 1 ]; then
  _doc_pkgs=""
  if ! command -v pdftotext >/dev/null 2>&1 || ! command -v pdftoppm >/dev/null 2>&1; then
    _doc_pkgs="poppler-utils"
  fi
  if ! command -v tesseract >/dev/null 2>&1; then
    _doc_pkgs="$_doc_pkgs tesseract-ocr tesseract-ocr-fra"
  elif ! tesseract --list-langs 2>/dev/null | grep -qx fra; then
    # Le moteur est là, la langue non : il déchiffrerait un document français
    # comme de l'anglais et rendrait une bouillie PLAUSIBLE — le pire des cas,
    # puisque personne ne relit ce qu'il croit lu.
    _doc_pkgs="$_doc_pkgs tesseract-ocr-fra"
  fi
  if [ -n "$_doc_pkgs" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    run_spin "Lecture des documents (PDF de texte, PDF scannés, OCR français)" \
      bash -c "export DEBIAN_FRONTEND=noninteractive; apt-get install -y $_doc_pkgs" \
      || warn "poppler-utils / tesseract non installés — un PDF scanné ne donnera rien."
  fi
fi

ok "Python : $(python3 --version 2>&1)"
# Preflight : le source DOIT compiler AVANT d'être déployé en service (sinon le démon ne boote pas).
if python3 -m py_compile "$SRC_DIR/cassandra.py" 2>/tmp/cass_pyc.err; then
  ok "cassandra.py compile (preflight OK)"
else
  die "cassandra.py NE COMPILE PAS — installation annulée. $(tail -2 /tmp/cass_pyc.err 2>/dev/null)"
fi

# --- 5. Arrêt des services si déjà installés (upgrade) --------
for svc in cassandra cassandra-collector cassandra-vault; do
  if systemctl list-unit-files | grep -q "^${svc}.service"; then
    systemctl stop "$svc" 2>/dev/null || true
  fi
done

# --- 5.5 Mode : mise à jour (défaut) / propre (FRESH) / total (WIPE_ALL) ----
_EXISTING=0
[ -f "$APP_DIR/cassandra.py" ] && _EXISTING=1

if [ "${WIPE_ALL:-0}" = "1" ] || [ "${WIPE_ALL:-0}" = "EFFACER" ]; then
  warn "WIPE_ALL → EFFACEMENT TOTAL : code, config (clés + comptes) ET mémoire/données."
  warn "Dossiers supprimés : $APP_DIR, $CFG_DIR, $DATA_DIR"
  if [ "${KEEP_VAULT:-0}" = "1" ]; then
    warn "KEEP_VAULT=1 → le coffre Vaultwarden et ses secrets seront CONSERVÉS."
  else
    warn "Le coffre Vaultwarden et ses secrets seront AUSSI effacés (KEEP_VAULT=1 pour le garder)."
  fi
  _conf="$WIPE_ALL"
  if [ "$_conf" != "EFFACER" ]; then
    read -r -p "Confirmer l'effacement TOTAL ? (tape EFFACER) : " _conf 2>/dev/tty || _conf=""
  fi
  [ "$_conf" = "EFFACER" ] || die "Effacement annulé."
  systemctl disable cassandra cassandra-collector 2>/dev/null || true
  # Un fichier immuable (chattr +i) ferait mourir rm -rf, et set -e arrêterait l'installeur après avoir
  # effacé le code sans le reposer (mesuré le 23-09 sur une clé rendue immuable par un ancien installeur).
  chattr -R -i "$APP_DIR" "$CFG_DIR" "$DATA_DIR" 2>/dev/null || true
  rm -rf "$APP_DIR" "$CFG_DIR" "$DATA_DIR"
  if [ "${KEEP_VAULT:-0}" != "1" ]; then
    say "Éradication du coffre Vaultwarden…"
    systemctl stop cassandra-vault 2>/dev/null || true
    systemctl disable cassandra-vault 2>/dev/null || true
    rm -f /etc/systemd/system/cassandra-vault.service 2>/dev/null || true
    pkill -f 'bw serve' 2>/dev/null || true
    (cd "$VAULT_DIR" 2>/dev/null && (docker compose down -v 2>/dev/null || docker-compose down -v 2>/dev/null)) || true
    docker rm -f vaultwarden 2>/dev/null || true
    docker rmi -f vaultwarden/server:latest 2>/dev/null || true
    rm -rf "$VAULT_DIR"
    rm -rf "/root/.config/Bitwarden CLI" /root/.config/Bitwarden* /root/.cache/Bitwarden* 2>/dev/null || true
    npm uninstall -g @bitwarden/cli >/dev/null 2>&1 || true
    rm -f "$(command -v bw 2>/dev/null)" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    ok "Coffre Vaultwarden éradiqué."
  fi
  ok "Tout effacé — installation vierge."
  _EXISTING=0
elif [ "${FRESH:-0}" = "1" ] && [ "$_EXISTING" = "1" ]; then
  warn "FRESH=1 → réinstallation propre du code et du venv (config + mémoire conservées)."
  chattr -R -i "$APP_DIR" 2>/dev/null || true
  rm -rf "$APP_DIR"
  _EXISTING=0
fi

if [ "$_EXISTING" = "1" ]; then
  say "Install existante détectée → MISE À JOUR du code (config + mémoire conservées)."
  _bk="/var/backups/cassandra/$(date +%Y%m%d-%H%M%S)"
  if mkdir -p "$_bk" 2>/dev/null; then
    [ -f "$APP_DIR/cassandra.py" ] && cp -a "$APP_DIR/cassandra.py" "$_bk/" 2>/dev/null || true
    [ -d "$CFG_DIR" ] && cp -a "$CFG_DIR" "$_bk/config" 2>/dev/null || true
    [ -d "$DATA_DIR" ] && cp -a "$DATA_DIR" "$_bk/data" 2>/dev/null || true
    ok "Backup avant update : $_bk (code + config + mémoire)"
    # Deux suffisent : chacune porte les données entières (3,3 Go mesurés le 23-09), et rien ne les purgeait.
    ls -1dt /var/backups/cassandra/[0-9]*-[0-9]* 2>/dev/null | tail -n +3 | xargs -r rm -rf 2>/dev/null || true
  fi
else
  say "Installation neuve."
fi

step "Arborescence + copie des sources"
say "Copie des fichiers vers $APP_DIR…"
mkdir -p "$APP_DIR" "$CFG_DIR" "$DATA_DIR"
chmod 700 "$CFG_DIR"
chmod 700 "$DATA_DIR"   # base de connaissance = données sensibles (mail/ftp/ssh) → root only
install -m 0755 "$SRC_DIR/cassandra.py"                     "$APP_DIR/cassandra.py"
install -m 0755 "$SRC_DIR/cassandra_knowledge_collector.py" "$APP_DIR/cassandra_knowledge_collector.py"
# Documentation livrée avec le produit (exemple nginx, configuration) : lue par le récap final.
if [ -d "$SRC_DIR/docs" ]; then
  mkdir -p "$APP_DIR/docs"
  for _d in "$SRC_DIR/docs"/*.conf "$SRC_DIR/docs"/*.md; do
    [ -f "$_d" ] && install -m 0644 "$_d" "$APP_DIR/docs/$(basename "$_d")" || true
  done
fi
# Outils auxiliaires (dont tools/itare_finetune.py : l'entraînement LoRA d'Itare piloté depuis l'UI).
if [ -d "$SRC_DIR/tools" ]; then
  mkdir -p "$APP_DIR/tools"
  cp -a "$SRC_DIR/tools/." "$APP_DIR/tools/" 2>/dev/null || true
  chmod -R u+rwX "$APP_DIR/tools" 2>/dev/null || true
fi
# Bibliothèques embarquées (vendor/ : l'éditeur ink-mde, MIT), servies par /vendor/<nom>.
if [ -d "$SRC_DIR/vendor" ]; then
  mkdir -p "$APP_DIR/vendor"
  cp -a "$SRC_DIR/vendor/." "$APP_DIR/vendor/" 2>/dev/null || true
fi
[ -f "$SRC_DIR/ITARE_AUTONOME.md" ] && install -m 0644 "$SRC_DIR/ITARE_AUTONOME.md" "$APP_DIR/ITARE_AUTONOME.md" 2>/dev/null || true
# vault_register.py : généré ICI (installeur autonome, aucune dépendance au dossier vaultwarden/)
cat > "$APP_DIR/vault_register.py" <<'PYREG'
#!/usr/bin/env python3
"""Crée (idempotent) le compte service Vaultwarden de Cassandra, en headless."""
import os, sys, json, base64, secrets, hashlib, hmac, ssl
import urllib.request, urllib.error
_SSL = ssl.create_default_context(); _SSL.check_hostname = False; _SSL.verify_mode = ssl.CERT_NONE
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except Exception as e:
    print("[register] module 'cryptography' requis: %s" % e, file=sys.stderr)
    sys.exit(2)

def b64(b): return base64.b64encode(b).decode()

def hkdf_expand(prk, info, length=32):
    out, t, i = b"", b"", 1
    info_b = info.encode()
    while len(out) < length:
        t = hmac.new(prk, t + info_b + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:length]

def enc_aes_cbc_hmac(plaintext, enc_key, mac_key):
    iv = secrets.token_bytes(16)
    pad = 16 - (len(plaintext) % 16)
    plaintext = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return "2." + b64(iv) + "|" + b64(ct) + "|" + b64(mac)

def build_payload(server, email, password, name, it):
    master_key = hashlib.pbkdf2_hmac("sha256", password.encode(), email.encode(), it, 32)
    master_pw_hash = b64(hashlib.pbkdf2_hmac("sha256", master_key, password.encode(), 1, 32))
    s_enc = hkdf_expand(master_key, "enc", 32)
    s_mac = hkdf_expand(master_key, "mac", 32)
    sym = secrets.token_bytes(64)
    protected_key = enc_aes_cbc_hmac(sym, s_enc, s_mac)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = rsa_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv = rsa_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    enc_priv = enc_aes_cbc_hmac(priv, sym[:32], sym[32:])
    return {"email": email, "name": name, "masterPasswordHash": master_pw_hash,
            "key": protected_key, "kdf": 0, "kdfIterations": it,
            "keys": {"publicKey": b64(pub), "encryptedPrivateKey": enc_priv}}

def main():
    server = os.environ["VW_SERVER"].rstrip("/")
    email = os.environ["VW_EMAIL"].strip().lower()
    password = os.environ["VW_PASSWORD"]
    name = os.environ.get("VW_NAME", "Cassandra")
    it = int(os.environ.get("VW_ITER", "600000"))
    payload = build_payload(server, email, password, name, it)
    data = json.dumps(payload).encode()
    last = None
    for ep in ("/identity/accounts/register", "/api/accounts/register"):
        req = urllib.request.Request(server + ep, data=data,
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=20, context=_SSL).read()
            print("[register] compte cree : %s" % email); return 0
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if "already exists" in body.lower() or "registered" in body.lower() or "exist" in body.lower():
                print("[register] compte deja existant — OK"); return 0
            last = (ep, e.code, body[:300])
        except Exception as e:
            last = (ep, 0, str(e))
    print("[register] echec : %r" % (last,), file=sys.stderr); return 1

if __name__ == "__main__":
    sys.exit(main())
PYREG
chmod 0755 "$APP_DIR/vault_register.py"

# vault_client.py : client Bitwarden minimal — Cassandra opère le coffre NATIF d'un user
# (login + lister/lire/créer/modifier/supprimer + changer le mdp). Importé par cassandra.py.
cat > "$APP_DIR/vault_client.py" <<'PYCLI'
#!/usr/bin/env python3
"""Client Bitwarden minimal pour Vaultwarden (login + CRUD ciphers + change_password)."""
import sys, json, base64, secrets, hashlib, hmac, ssl, uuid
import urllib.request, urllib.parse, urllib.error
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
_SSL = ssl.create_default_context(); _SSL.check_hostname = False; _SSL.verify_mode = ssl.CERT_NONE
def b64(b): return base64.b64encode(b).decode()
def ub64(s): return base64.b64decode(s + "=" * (-len(s) % 4))
def _req(method, url, data=None, headers=None, form=False):
    if form and data is not None: body = urllib.parse.urlencode(data).encode()
    elif data is not None: body = json.dumps(data).encode()
    else: body = None
    h = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
    if headers: h.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20, context=_SSL) as r:
            raw = r.read().decode("utf-8", "replace")
        return (json.loads(raw) if raw else {}), None
    except urllib.error.HTTPError as e:
        return None, "HTTP %s: %s" % (e.code, e.read().decode("utf-8", "replace")[:400])
    except Exception as e:
        return None, str(e)
def _hkdf_expand(prk, info, length=32):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info.encode() + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:length]
def _enc(plain, enc_key, mac_key):
    iv = secrets.token_bytes(16); pad = 16 - (len(plain) % 16); plain = plain + bytes([pad]) * pad
    c = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor(); ct = c.update(plain) + c.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return "2." + b64(iv) + "|" + b64(ct) + "|" + b64(mac)
def _dec_raw(s, enc_key, mac_key):
    if not s or not str(s).startswith("2."): return None
    try:
        iv_b, ct_b, mac_b = s[2:].split("|"); iv, ct, mac = ub64(iv_b), ub64(ct_b), ub64(mac_b)
        if not hmac.compare_digest(hmac.new(mac_key, iv + ct, hashlib.sha256).digest(), mac): return None
        d = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor(); pt = d.update(ct) + d.finalize()
        return pt[:-pt[-1]]
    except Exception: return None
def _dec_str(s, enc_key, mac_key):
    raw = _dec_raw(s, enc_key, mac_key); return raw.decode("utf-8", "replace") if raw is not None else None
def _prelogin_iters(server, email):
    pre, _ = _req("POST", server.rstrip("/") + "/identity/accounts/prelogin", {"email": email.strip().lower()})
    if pre is None: pre, _ = _req("POST", server.rstrip("/") + "/api/accounts/prelogin", {"email": email.strip().lower()})
    return int((pre or {}).get("kdfIterations") or (pre or {}).get("KdfIterations") or 600000)
def login(server, email, password):
    server = server.rstrip("/"); email = email.strip().lower()
    it = _prelogin_iters(server, email)
    master_key = hashlib.pbkdf2_hmac("sha256", password.encode(), email.encode(), it, 32)
    mph = b64(hashlib.pbkdf2_hmac("sha256", master_key, password.encode(), 1, 32))
    form = {"grant_type": "password", "username": email, "password": mph, "scope": "api offline_access",
            "client_id": "cli", "deviceType": "14", "deviceIdentifier": str(uuid.uuid4()), "deviceName": "cassandra"}
    tok, err = _req("POST", server + "/identity/connect/token", form, form=True)
    if tok is None: return None, "token: " + str(err)
    access = tok.get("access_token"); enc_key_str = tok.get("Key") or tok.get("key")
    s_enc = _hkdf_expand(master_key, "enc", 32); s_mac = _hkdf_expand(master_key, "mac", 32)
    sym = _dec_raw(enc_key_str, s_enc, s_mac)
    if not sym or len(sym) < 64: return None, "dechiffrement cle echoue (len=%s)" % (len(sym) if sym else None)
    return {"server": server, "access": access, "user_enc": sym[:32], "user_mac": sym[32:]}, None
def change_password(server, email, old_password, new_password):
    server = server.rstrip("/"); email = email.strip().lower()
    sess, err = login(server, email, old_password)
    if err: return False, "login (ancien mdp): " + str(err)
    it = _prelogin_iters(server, email)
    old_mk = hashlib.pbkdf2_hmac("sha256", old_password.encode(), email.encode(), it, 32)
    old_mph = b64(hashlib.pbkdf2_hmac("sha256", old_mk, old_password.encode(), 1, 32))
    new_mk = hashlib.pbkdf2_hmac("sha256", new_password.encode(), email.encode(), it, 32)
    new_mph = b64(hashlib.pbkdf2_hmac("sha256", new_mk, new_password.encode(), 1, 32))
    n_enc = _hkdf_expand(new_mk, "enc", 32); n_mac = _hkdf_expand(new_mk, "mac", 32)
    sym = sess["user_enc"] + sess["user_mac"]
    new_key = _enc(sym, n_enc, n_mac)
    body = {"masterPasswordHash": old_mph, "newMasterPasswordHash": new_mph, "key": new_key}
    _, err = _req("POST", server + "/api/accounts/password", body, headers={"Authorization": "Bearer " + sess["access"]})
    return (err is None), err
def _auth(sess): return {"Authorization": "Bearer " + sess["access"]}
def _ciphers_raw(sess):
    data, err = _req("GET", sess["server"] + "/api/ciphers", headers=_auth(sess))
    if data is None: return [], err
    return (data.get("Data") or data.get("data") or []), None
_TYPE_NAME = {1: "login", 2: "note", 3: "card", 4: "identity"}
def _decode_item(c, ek, mk):
    typ = c.get("Type") or c.get("type") or 2
    d = {"id": c.get("Id") or c.get("id"), "type": typ, "kind": _TYPE_NAME.get(typ, "note"),
         "name": _dec_str(c.get("Name") or c.get("name"), ek, mk),
         "notes": _dec_str(c.get("Notes") or c.get("notes"), ek, mk)}
    login = c.get("Login") or c.get("login")
    if login:
        d["username"] = _dec_str(login.get("Username") or login.get("username"), ek, mk)
        d["password"] = _dec_str(login.get("Password") or login.get("password"), ek, mk)
        d["totp"] = _dec_str(login.get("Totp") or login.get("totp"), ek, mk)
        uris = login.get("Uris") or login.get("uris") or []
        if uris:
            u0 = uris[0] or {}
            d["uri"] = _dec_str(u0.get("Uri") or u0.get("uri"), ek, mk)
    card = c.get("Card") or c.get("card")
    if card:
        d["card_holder"] = _dec_str(card.get("CardholderName") or card.get("cardholderName"), ek, mk)
        d["card_number"] = _dec_str(card.get("Number") or card.get("number"), ek, mk)
    return d
def list_items(sess):
    raw, err = _ciphers_raw(sess)
    return [_decode_item(c, sess["user_enc"], sess["user_mac"]) for c in raw], err
def set_login(sess, name, username, password, uri="", totp=""):
    ek, mk = sess["user_enc"], sess["user_mac"]
    existing, err = find_item(sess, name)
    if err: return None, err
    enc = lambda s: _enc(s.encode(), ek, mk) if s else None
    login = {"username": enc(username), "password": enc(password), "totp": enc(totp),
             "uris": ([{"uri": enc(uri), "match": None}] if uri else None)}
    body = {"type": 1, "name": _enc(name.encode(), ek, mk), "notes": None, "login": login,
            "favorite": False, "fields": [], "secureNote": None, "card": None, "identity": None}
    if existing: data, err = _req("PUT", sess["server"] + "/api/ciphers/" + existing["id"], body, headers=_auth(sess))
    else: data, err = _req("POST", sess["server"] + "/api/ciphers", body, headers=_auth(sess))
    if data is None: return None, err
    return (data.get("Id") or data.get("id") or (existing or {}).get("id")), None
def find_item(sess, name):
    items, err = list_items(sess)
    if err: return None, err
    for it in items:
        if it["name"] == name: return it, None
    return None, None
def _cipher_body(sess, name, value):
    return {"type": 2, "name": _enc(name.encode(), sess["user_enc"], sess["user_mac"]),
            "notes": _enc(value.encode(), sess["user_enc"], sess["user_mac"]),
            "secureNote": {"type": 0}, "favorite": False, "fields": [],
            "login": None, "card": None, "identity": None}
def set_item(sess, name, value):
    existing, err = find_item(sess, name)
    if err: return None, err
    body = _cipher_body(sess, name, value)
    if existing: data, err = _req("PUT", sess["server"] + "/api/ciphers/" + existing["id"], body, headers=_auth(sess))
    else: data, err = _req("POST", sess["server"] + "/api/ciphers", body, headers=_auth(sess))
    if data is None: return None, err
    return (data.get("Id") or data.get("id") or (existing or {}).get("id")), None
def delete_item(sess, name):
    existing, err = find_item(sess, name)
    if err: return False, err
    if not existing: return False, None
    _, err = _req("DELETE", sess["server"] + "/api/ciphers/" + existing["id"], headers=_auth(sess))
    return (err is None), err
PYCLI
chmod 0644 "$APP_DIR/vault_client.py"
ok "Sources installées."

step "Environnement Python (venv + dépendances)"
# Aucune copie des paquets téléchargés : torch et ses voisins laissaient 3 Go sous ~/.cache/pip, pour rien —
# le venv les porte déjà, et une réinstallation les retélécharge de toute façon.
export PIP_NO_CACHE_DIR=1
say "Création de l'environnement Python…"
unset VIRTUAL_ENV PYTHONHOME PYTHONPATH 2>/dev/null || true

PYBIN="$VENV/bin/python"
need_venv=0
[ -x "$PYBIN" ] || need_venv=1
if [ "$need_venv" -eq 0 ] && ! "$PYBIN" -m pip --version >/dev/null 2>&1; then
  need_venv=1
fi
if [ "$need_venv" -eq 1 ]; then
  rm -rf "$VENV"
  # CORRECTION : force l'utilisation du module venv avec le chemin absolu
  python3 -m venv "$VENV" || {
    # Tentative de secours : utiliser virtualenv si présent
    if command -v virtualenv >/dev/null 2>&1; then
      virtualenv "$VENV" || die "Échec création du venv (python3-venv manquant ?)."
    else
      die "Échec création du venv (python3-venv manquant ?). Installez : apt install python3-venv"
    fi
  }
fi

if ! "$PYBIN" -m pip --version >/dev/null 2>&1; then
  say "Initialisation de pip (ensurepip)…"
  "$PYBIN" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi
if ! "$PYBIN" -m pip --version >/dev/null 2>&1; then
  warn "ensurepip indisponible — tentative get-pip.py…"
  curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py && "$PYBIN" /tmp/get-pip.py >/dev/null 2>&1 || true
fi
"$PYBIN" -m pip --version >/dev/null 2>&1 || die "Impossible d'obtenir pip dans le venv. Installez : apt install -y python3-pip python3-venv"

"$PYBIN" -m pip install --quiet --upgrade pip || warn "Mise à jour de pip ignorée."

# Dépendances CŒUR (toujours) : LLM, crypto (coffre + tokens chiffrés), SSH flotte,
# parsing YAML (alertes/config), lecture PDF.
# Pillow : vignettes et redimensionnement des images de la GED. L'application
# dégrade proprement sans lui (elle sert l'original), mais la fonction manque
# alors sans que rien ne l'annonce — d'où sa place ici plutôt qu'en optionnel.
run_spin "Dépendances cœur (LLM · crypto · SSH · PDF · images)" \
  "$PYBIN" -m pip install --quiet openai cryptography paramiko pyyaml pypdf PyPDF2 qrcode Pillow \
  || die "Échec installation des dépendances cœur (réseau ?)."

# Telethon parle à Telegram avec le COMPTE de la personne (API client), là où
# l'API des robots ne voit ni les contacts ni les conversations. Sans lui, la
# carte Telegram le dit et refuse — mais autant l'avoir dès l'installation.
# Trafilatura tire le TEXTE d'une page web en jetant le menu, la banniere et
# les pieds de page. La porte « web » du canvas s'en sert d'abord et retombe
# sur un extracteur maison s'il manque — l'import marche alors, mais rapporte
# la navigation avec l'article, et personne ne voit pourquoi.
run_spin "Lecture des pages web (trafilatura)" \
  "$PYBIN" -m pip install --quiet trafilatura \
  || warn "trafilatura non installé : l'import web gardera menus et pieds de page."

run_spin "Telegram (compte utilisateur)" \
  "$PYBIN" -m pip install --quiet telethon \
  || warn "Telethon non installé : relier un COMPTE Telegram restera indisponible."

# LA VOIX, sur cette machine. Whisper écoute ce qu'on dicte, Piper le lit à
# voix haute — les deux EN LOCAL : la dictée du navigateur enverrait l'audio
# chez Google, celle-ci ne quitte pas le serveur.
#
# `faster-whisper` tire CTranslate2 : quelques centaines de mégaoctets, et le
# modèle lui-même se télécharge au premier usage. C'est pourquoi l'installation
# est OPTIONNELLE — sans elle, les deux boutons le disent et expliquent quoi
# faire, au lieu de rester muets.
if [ "${WITH_VOIX:-1}" = "1" ]; then
  run_spin "Voix — dictée (faster-whisper) et lecture (piper-tts)"     "$PYBIN" -m pip install --quiet faster-whisper piper-tts     || warn "Voix non installée : dicter et écouter resteront indisponibles."
  # LA VOIX FRANÇAISE. Piper ne sert à rien sans un fichier .onnx : l'installer
  # sans voix donnerait un moteur qui refuse, et un message que personne ne
  # sait interpréter.
  mkdir -p /opt/cassandra/voix
  if [ ! -f /opt/cassandra/voix/fr_FR-siwis-medium.onnx ]; then
    _VXB="https://huggingface.co/rhasspy/piper-voices/resolve/main/fr/fr_FR/siwis/medium"
    curl -fsSL -o /opt/cassandra/voix/fr_FR-siwis-medium.onnx          "$_VXB/fr_FR-siwis-medium.onnx" 2>/dev/null       && curl -fsSL -o /opt/cassandra/voix/fr_FR-siwis-medium.onnx.json               "$_VXB/fr_FR-siwis-medium.onnx.json" 2>/dev/null       || warn "Voix française non téléchargée : posez un .onnx dans /opt/cassandra/voix."
  fi
fi

# Installé n'est pas importable. `cryptography` compile du Rust : sur une machine
# sans compilateur, ou avec une roue incompatible, pip réussit et l'import lève.
# Chaque module dit ici CE QUI CASSE sans lui — un nom de paquet seul n'aide
# personne à décider si c'est grave.
_dep_ko=0
_verifier_import() {
  # $1 = module, $2 = ce qui cesse de fonctionner sans lui
  if "$PYBIN" -c "import $1" >/dev/null 2>&1; then
    return 0
  fi
  warn "Module « $1 » installé mais non importable — $2"
  _dep_ko=1
}
_verifier_import cryptography "les clés de sécurité (WebAuthn) et le chiffrement des jetons seront indisponibles."
_verifier_import openai       "les modèles distants ne répondront pas."
_verifier_import yaml         "les alertes et la configuration YAML ne se liront pas."
_verifier_import paramiko     "la flotte SSH sera hors service."
_verifier_import pypdf        "les PDF ne seront pas lus."
_verifier_import PIL          "les vignettes d'images de la GED ne seront pas générées."
if [ "$_dep_ko" = "1" ]; then
  warn "Sur Debian/Ubuntu, il manque en général les outils de compilation :"
  warn "   apt install -y build-essential python3-dev libffi-dev  &&  relance ce script."
else
  ok "Dépendances cœur vérifiées (importables, pas seulement installées)."
fi

# LES OUTILS SYSTÈME ne s'importent pas : ils s'appellent. Leur absence ne se
# voit qu'au premier document déposé, et sous la forme d'un document VIDE —
# d'où ce contrôle ici, et un drapeau SÉPARÉ : conseiller les outils de
# compilation pour un paquet apt manquant enverrait chercher au mauvais endroit.
_doc_ko=0
_verifier_outil() {
  # $1 = binaire, $2 = ce qui cesse de fonctionner sans lui
  command -v "$1" >/dev/null 2>&1 && return 0
  warn "Outil « $1 » absent — $2"
  _doc_ko=1
}
_verifier_outil pdftotext "le texte des PDF ne sera pas extrait."
_verifier_outil pdftoppm  "un PDF scanné ne pourra pas être rendu en images."
_verifier_outil tesseract "les PDF scannés resteront illisibles."
if command -v tesseract >/dev/null 2>&1 && ! tesseract --list-langs 2>/dev/null | grep -qx fra; then
  warn "Langue « fra » absente de tesseract — un document français serait déchiffré comme de l'anglais."
  _doc_ko=1
fi
if [ "$_doc_ko" = "1" ]; then
  warn "   apt install -y poppler-utils tesseract-ocr tesseract-ocr-fra"
  warn "   (Word et Excel, eux, se lisent sans rien de plus.)"
else
  ok "Lecture des documents vérifiée (PDF de texte, PDF scannés, OCR français)."
fi

# Mémoire sémantique (lourde, optionnelle) : numpy + sentence-transformers (+torch).
if [ "$ENABLE_SEMANTIC" = "1" ]; then
  run_spin "Mémoire sémantique (sentence-transformers + torch)" \
    "$PYBIN" -m pip install --quiet numpy sentence-transformers \
    || warn "sentence-transformers non installé — mémoire sémantique en repli FTS5."
fi

# ── IA locale d'Itare : Ollama + apprentissage LoRA ──────────────────────────
# Procédure normale : on DEMANDE à l'admin. Réponse forçable via WITH_OLLAMA
# (1 = oui, 0 = non) pour les installs non-interactives. Si « oui », on installe
# Ollama PUIS, logiquement, la pile d'entraînement LoRA (Itare apprend en local).
WANT_LOCAL_AI=0
if [ -n "${WITH_OLLAMA:-}" ]; then
  [ "${WITH_OLLAMA}" = "1" ] && WANT_LOCAL_AI=1
elif [ -e /dev/tty ]; then
  _ans=""
  read -r -p "   > Activer l'IA locale d'Itare (Ollama + apprentissage LoRA, ~plusieurs Go) ? [o/N] " _ans </dev/tty 2>/dev/tty || _ans=""
  case "${_ans:-}" in [oOyY]*) WANT_LOCAL_AI=1 ;; esac
fi

if [ "$WANT_LOCAL_AI" = "1" ]; then
  # Ollama : modèles locaux (Itare local, panel, modèle du vérificateur, ollama create du LoRA)
  if ! command -v ollama >/dev/null 2>&1; then
    run_spin "Installation d'Ollama (modèles locaux)" \
      bash -c 'curl -fsSL https://ollama.com/install.sh | sh >/dev/null 2>&1' \
      || warn "Ollama non installé — installe-le manuellement pour faire tourner Itare en local."
  fi
  command -v ollama >/dev/null 2>&1 && ok "Ollama présent." || true
  # Dépendances d'entraînement LoRA : UNIQUEMENT si un GPU est détecté. Sur CPU, unsloth ne
  # fonctionne pas (4-bit/CUDA) et l'entraînement serait impraticable → on ne les installe pas.
  if command -v nvidia-smi >/dev/null 2>&1; then
    run_spin "GPU détecté — pile d'entraînement LoRA (unsloth/peft/trl, plusieurs Go)" \
      "$PYBIN" -m pip install --quiet unsloth peft trl datasets accelerate \
      || warn "Dépendances LoRA non installées — voir le panneau « Apprentissage » dans l'UI."
  else
    warn "Pas de GPU détecté : pile d'entraînement LoRA IGNORÉE (ne tourne pas sur CPU)."
    say "→ Itare tourne en local via Ollama. Pour le LoRA : entraîne sur une machine GPU, puis"
    say "  déploie le modèle ici (le panneau « Apprentissage » exporte le dataset et déploie via Ollama)."
  fi
else
  say "IA locale ignorée — Itare fonctionnera via ton agent secondaire (cloud ou Ollama déjà présent)."
fi
ok "Environnement prêt."

step "Services systemd"
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
RuntimeDirectory=cassandra
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ExecStart=$VENV/bin/python $APP_DIR/cassandra_knowledge_collector.py
Restart=always
RestartSec=5
# Priorité basse : la collecte (≈60 sources + subprocess + ThreadPool) ne doit jamais
# affamer Cassandra ni Ollama sur un serveur partagé.
Nice=10
CPUWeight=20
IOSchedulingClass=idle
MemoryHigh=768M
MemoryMax=1024M
StandardOutput=append:$LOG_DIR/cassandra-collector.log
StandardError=append:$LOG_DIR/cassandra-collector.log

[Install]
WantedBy=multi-user.target
EOF

# L'ordre After= ne cite le coffre que s'il est installé : une unité absente n'est pas une
# dépendance, et un service qui en nomme une inexistante ment à qui le lit.
_AFTER="network-online.target cassandra-collector.service"
[ "$WITH_VAULT" = "1" ] && _AFTER="$_AFTER cassandra-vault.service"
cat > /etc/systemd/system/cassandra.service <<EOF
[Unit]
Description=Cassandra Agent (UI port $PORT)
After=$_AFTER
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
RuntimeDirectory=cassandra
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ExecStart=$VENV/bin/python $APP_DIR/cassandra.py
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/cassandra.log
StandardError=append:$LOG_DIR/cassandra.log
# Garde-fous mémoire (ADAPTATIFS selon la RAM) : sous pression, le noyau tue Cassandra EN
# PREMIER ; systemd la relance. L'entraînement LoRA tourne hors cgroup (systemd-run), non bridé.
MemoryHigh=$MEM_HIGH
MemoryMax=$MEM_MAX
MemorySwapMax=$MEM_MAX
OOMScoreAdjust=700
# Bind réseau (127.0.0.1 par défaut, derrière reverse proxy) + port.
Environment=CASSANDRA_BIND=$BIND_HOST
Environment=CASSANDRA_PORT=$PORT
# Les racines de l'installation : le code les lit, jamais un chemin en dur.
Environment=CASSANDRA_APP_DIR=$APP_DIR
Environment=CASSANDRA_CONF_DIR=$CFG_DIR
Environment=CASSANDRA_DATA_DIR=$DATA_DIR
Environment=CASSANDRA_LOG_DIR=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF
ok "Services créés."

# Rotation des logs (sinon $LOG_DIR/cassandra*.log grossit sans fin via append: systemd).
cat > /etc/logrotate.d/cassandra <<LROT
$LOG_DIR/cassandra.log $LOG_DIR/cassandra-collector.log $LOG_DIR/cassandra_admin.log {
    weekly
    rotate 8
    size 20M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LROT
chmod 644 /etc/logrotate.d/cassandra 2>/dev/null || true
ok "Rotation des logs configurée (/etc/logrotate.d/cassandra)."

# ── fail2ban : anti-brute-force SSH + anti-scanners nginx ────────────────────────
# La jail sshd protège le port 22 (SSH ET SFTP) MAIS ne bannit QUE les IP qui ÉCHOUENT
# plusieurs fois à s'authentifier — un accès légitime (bonne clé/mot de passe) n'est
# JAMAIS banni. localhost est en liste blanche, le ban est temporaire (1 h). Non bloquant.
if [ "$APT_OK" -eq 1 ]; then
  if ! command -v fail2ban-server >/dev/null 2>&1; then
    run_spin "Installation de fail2ban (anti-brute-force SSH + anti-scanners)" \
      bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get install -y fail2ban python3-systemd' \
      || warn "fail2ban non installé (apt) — protection SSH ignorée."
  fi
  if command -v fail2ban-server >/dev/null 2>&1; then
    # Le backend systemd de la jail sshd (Debian 12+) lit le journal par python3-systemd : sans lui, le service meurt.
    python3 -c "import systemd.journal" >/dev/null 2>&1 || apt-get install -y python3-systemd >/dev/null 2>&1 || true
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/cassandra.local <<'F2B'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
# Debian 12+ : plus de /var/log/auth.log, sshd écrit au journal — sans ce backend la jail meurt au démarrage.
backend = systemd
F2B
    # Jail anti-scanners nginx (bots qui fouinent .env / phpinfo / .git…) si les logs existent.
    if ls /var/log/nginx/*access*.log >/dev/null 2>&1; then
      cat >> /etc/fail2ban/jail.d/cassandra.local <<'F2BN'

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/*access*.log
maxretry = 3
F2BN
    fi
    systemctl enable fail2ban >/dev/null 2>&1 || true
    if systemctl restart fail2ban >/dev/null 2>&1; then
      ok "fail2ban actif (SSH/SFTP protégés · localhost en liste blanche · ban 1 h)."
    else
      warn "fail2ban installé mais non démarré — voir : journalctl -u fail2ban -n 30"
    fi
  fi
fi

# ── Tailscale : le réseau privé de la Flotte ─────────────────────────────────────
# La Flotte de Cassandra lit `tailscale status --json` pour voir ses machines ; sans le
# binaire elle reste vide (proprement, jamais un faux « en ligne »). Optionnel, demandé à
# l'admin comme Ollama ; forçable par WITH_TAILSCALE (1 = oui, 0 = non) pour les installs
# non interactives. L'authentification (`tailscale up`) ouvre un lien dans le navigateur :
# elle reste à l'admin, le script ne la fait jamais à sa place.
WANT_TAILSCALE=0
if command -v tailscale >/dev/null 2>&1; then
  ok "Tailscale déjà présent."
elif [ -n "${WITH_TAILSCALE:-}" ]; then
  [ "${WITH_TAILSCALE}" = "1" ] && WANT_TAILSCALE=1
elif [ -e /dev/tty ]; then
  _ans=""
  read -r -p "   > Installer Tailscale (réseau privé entre tes machines, pour la Flotte) ? [o/N] " _ans </dev/tty 2>/dev/tty || _ans=""
  case "${_ans:-}" in [oOyY]*) WANT_TAILSCALE=1 ;; esac
fi
if [ "$WANT_TAILSCALE" = "1" ]; then
  run_spin "Installation de Tailscale (script officiel)" \
    bash -c 'curl -fsSL https://tailscale.com/install.sh | sh >/dev/null 2>&1' \
    || warn "Tailscale non installé — voir https://tailscale.com/download/linux ; la Flotte restera vide."
  if command -v tailscale >/dev/null 2>&1; then
    systemctl enable --now tailscaled >/dev/null 2>&1 || true
    ok "Tailscale installé. Pour rejoindre ton réseau : ${c_acc}tailscale up${c_off} (ouvre un lien d'authentification)."
  fi
elif ! command -v tailscale >/dev/null 2>&1; then
  say "Tailscale ignoré — la Flotte ne verra que cette machine tant qu'il n'est pas installé."
fi

step "Coffre Vaultwarden (Docker + sidecar)"
# --- 8.6 COFFRE VAULTWARDEN (non bloquant) --------------------
if [ "$WITH_VAULT" = "1" ]; then
  echo
  say "── Coffre Vaultwarden (secrets souverains) ──"
  _vault_ok=1

  # 8.6.1 Docker (moteur)
  if ! command -v docker >/dev/null 2>&1; then
    say "Installation de Docker…"
    [ "$APT_OK" -eq 1 ] && apt-get install -y docker.io apparmor >/dev/null 2>&1 || true
    command -v docker >/dev/null 2>&1 || { curl -fsSL https://get.docker.com | sh >/dev/null 2>&1 || true; }
    command -v docker >/dev/null 2>&1 || { warn "Docker non installé — coffre ignoré."; _vault_ok=0; }
  fi
  # 8.6.1b docker compose (v2 plugin de préférence, sinon v1)
  if [ "$_vault_ok" = "1" ]; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    DCOMPOSE=""
    if docker compose version >/dev/null 2>&1; then DCOMPOSE="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then DCOMPOSE="docker-compose"
    fi
    if [ -z "$DCOMPOSE" ] && [ "$APT_OK" -eq 1 ]; then
      say "Installation du plugin docker compose…"
      apt-get install -y docker-compose-v2 >/dev/null 2>&1 \
        || apt-get install -y docker-compose-plugin >/dev/null 2>&1 \
        || apt-get install -y docker-compose >/dev/null 2>&1 || true
      if docker compose version >/dev/null 2>&1; then DCOMPOSE="docker compose"
      elif command -v docker-compose >/dev/null 2>&1; then DCOMPOSE="docker-compose"
      fi
    fi
    [ -z "$DCOMPOSE" ] && { warn "docker compose indisponible — coffre ignoré."; _vault_ok=0; }
  fi

  # 8.6.2 Node.js >= 20 (bw serve utilise Array.toReversed, Node 20+) + bw CLI
  if [ "$_vault_ok" = "1" ]; then
    _node_maj() { node -v 2>/dev/null | sed 's/^v//; s/\..*//'; }
    NODE_OK=0
    [ "$(_node_maj || echo 0)" -ge 20 ] 2>/dev/null && NODE_OK=1
    if [ "$NODE_OK" -eq 0 ] && [ "$APT_OK" -eq 1 ]; then
      say "Installation de Node.js 20 (requis par bw serve)…"
      curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1 \
        && apt-get install -y nodejs >/dev/null 2>&1 || true
      [ "$(_node_maj || echo 0)" -ge 20 ] 2>/dev/null && NODE_OK=1
    fi
    if [ "$NODE_OK" -eq 1 ]; then
      if ! command -v bw >/dev/null 2>&1; then
        say "Installation du CLI Bitwarden (bw)…"
        npm install -g @bitwarden/cli >/dev/null 2>&1 || { warn "Échec installation 'bw' — coffre ignoré."; _vault_ok=0; }
      fi
      # ── Autoriser la boucle locale en HTTP dans le CLI ────────────────────
      # Depuis la version 2026.6, `bw` refuse TOUTE URL non-HTTPS, y compris
      # 127.0.0.1, et son `isDev()` est compilé à `false` : aucune variable
      # d'environnement ne lève le blocage. Le coffre tourne pourtant en clair
      # sur la boucle locale, où le trafic ne quitte jamais la machine.
      # Sans ce correctif, le sidecar échoue au login et boucle indéfiniment.
      if [ "$_vault_ok" = "1" ]; then
        mkdir -p "$APP_DIR/scripts"
        cat > "$APP_DIR/scripts/ensure-bw-loopback-patch.sh" <<'BWPATCH'
#!/usr/bin/env bash
# Autorise les URL HTTP en BOUCLE LOCALE dans le CLI Bitwarden. Idempotent :
# à relancer après chaque mise à jour de @bitwarden/cli, qui écrase le fichier.
set -euo pipefail
# On part de la COMMANDE, en suivant les liens : c'est le seul fichier dont on
# soit sûr qu'il s'exécutera. Un chemin deviné peut désigner une AUTRE
# installation — c'est ce qui est arrivé, l'installeur patchant un bw.js pendant
# que `bw` en exécutait un second.
_BWJS_CANDIDATS=""
_bw_bin="$(command -v bw 2>/dev/null || true)"
if [ -n "$_bw_bin" ]; then
  _reel="$(readlink -f "$_bw_bin" 2>/dev/null || echo "$_bw_bin")"
  case "$_reel" in *bw.js) _BWJS_CANDIDATS="$_reel" ;; esac
  # `bw` est souvent un lanceur : le vrai fichier est à côté, dans build/.
  if [ -z "$_BWJS_CANDIDATS" ]; then
    _d="$(dirname "$_reel")"
    for _c in "$_d/bw.js" "$_d/../lib/node_modules/@bitwarden/cli/build/bw.js"; do
      [ -f "$_c" ] && _BWJS_CANDIDATS="$_BWJS_CANDIDATS $_c"
    done
  fi
fi
# Puis les emplacements habituels : DEUX installations peuvent coexister, et
# rien ne dit laquelle servira après la prochaine mise à jour de npm.
for _r in "$(npm root -g 2>/dev/null)" /usr/lib/node_modules /usr/local/lib/node_modules; do
  [ -n "$_r" ] || continue
  _c="$_r/@bitwarden/cli/build/bw.js"
  [ -f "$_c" ] && _BWJS_CANDIDATS="$_BWJS_CANDIDATS $_c"
done
# Dédoublonnage par chemin réel.
_BWJS_LISTE=""
for _c in $_BWJS_CANDIDATS; do
  _c="$(readlink -f "$_c" 2>/dev/null || echo "$_c")"
  case " $_BWJS_LISTE " in *" $_c "*) ;; *) _BWJS_LISTE="$_BWJS_LISTE $_c" ;; esac
done
[ -n "$_BWJS_LISTE" ] || { echo "[bw-patch] aucun bw.js trouvé" >&2; exit 1; }

_bw_ok=0
for BWJS in $_BWJS_LISTE; do
  echo "[bw-patch] $BWJS"
  # Règle : on détecte par l'EFFET (la tolérance à la boucle locale), jamais par
  # le marqueur seul — un fichier déjà assoupli par une autre main ou une version
  # antérieure du correctif ne porte pas forcément le marqueur, et conclure
  # « motif trouvé 0 fois » ferait croire à une panne du coffre.
  if grep -q 'CASSANDRA_LOOPBACK_OK' "$BWJS"      || grep -q '127\.0\.0\.1.*localhost.*::1' "$BWJS"; then
    echo "[bw-patch]   déjà appliqué (boucle locale tolérée)"; continue
  fi
  cp -a "$BWJS" "${BWJS}.bak-$(date +%Y%m%d-%H%M%S)"
  if python3 - "$BWJS" <<'PYEOF'
import io, re, sys

chemin = sys.argv[1]
src = io.open(chemin, encoding="utf-8").read()

# Le garde-fou de bw : il refuse toute URL non-HTTPS. On ne le supprime pas —
# on l'assouplit pour la SEULE boucle locale, dont le trafic ne quitte pas la
# machine. Le blocage reste entier pour toute adresse distante.
#
# Le motif est une EXPRESSION RÉGULIÈRE, pas une chaîne : l'indentation, les
# espaces et le style de guillemets changent d'une version de bw à l'autre, et
# c'est exactement ce qui a fait échouer la version précédente de ce correctif.
MOTIF = re.compile(
    r"if\s*\(\s*!\s*request\.url\.startsWith\(\s*['\"]https://['\"]\s*\)\s*"
    r"&&\s*!\s*this\.platformUtilsService\.isDev\(\)\s*\)\s*\{\s*"
    r"throw\s+new\s+InsecureUrlNotAllowedError\(\)\s*;?\s*\}")

REMPLACEMENT = (
    "if (!request.url.startsWith(\"https://\") && !this.platformUtilsService.isDev()) {"
    "\n                /* CASSANDRA_LOOPBACK_OK : le trafic vers 127.0.0.1 ne quitte"
    "\n                   pas la machine ; le blocage reste entier pour toute"
    "\n                   adresse distante. */"
    "\n                let _u = null;"
    "\n                try { _u = new URL(request.url); } catch (_e) {}"
    "\n                const _lb = _u !== null && [\"127.0.0.1\", \"localhost\", \"::1\", \"[::1]\"]"
    "\n                    .indexOf(_u.hostname) !== -1;"
    "\n                if (!_lb) { throw new InsecureUrlNotAllowedError(); }"
    "\n            }")

n = len(MOTIF.findall(src))
if n == 1:
    io.open(chemin, "w", encoding="utf-8").write(MOTIF.sub(REMPLACEMENT, src, count=1))
    sys.exit(0)

# ÉCHEC : on montre ce qu'on a trouvé. Abandonner sans un mot oblige à ouvrir
# un fichier de plusieurs mégaoctets pour comprendre ce qui a changé.
print("[bw-patch] motif trouvé %d fois — version de bw inattendue." % n)
occ = [m.start() for m in re.finditer(r"InsecureUrlNotAllowedError", src)]
if not occ:
    print("[bw-patch] « InsecureUrlNotAllowedError » est ABSENT de ce fichier :")
    print("[bw-patch] soit bw a renommé son garde-fou, soit le fichier n'est pas le bon.")
    print("[bw-patch] cherchez :  grep -n 'https://' %s | head" % chemin)
else:
    print("[bw-patch] %d occurrence(s) du garde-fou. Contexte de la première :" % len(occ))
    d = max(0, occ[0] - 320)
    for ligne in src[d:occ[0] + 120].splitlines()[1:-1]:
        print("[bw-patch]   | " + ligne.rstrip()[:120])
    print("[bw-patch] adaptez MOTIF dans install.sh à cette forme, puis relancez :")
    print("[bw-patch]   %s" % chemin)
sys.exit(2)
PYEOF
  then :; else echo "[bw-patch]   non appliqué"; continue; fi
  if node --check "$BWJS"; then
    echo "[bw-patch]   appliqué et validé"
    _bw_ok=1
  else
    echo "[bw-patch]   syntaxe invalide — restauration" >&2
    cp -a "$(ls -1t "${BWJS}.bak-"* | head -1)" "$BWJS"
  fi
done
# Un seul fichier assoupli suffit à faire tourner le coffre : on compte donc les
# RÉUSSITES, pas les échecs. Et surtout pas `[ ... ] && exit 1` : sous `set -e`,
# un test FAUX rend 1 et fait sortir le script — l'inverse de ce qu'on veut.
if [ "$_bw_ok" = "1" ]; then
  exit 0
fi
# Aucun fichier n'avait besoin d'être patché : c'est le cas normal quand tout
# était déjà en place.
if grep -lq 'CASSANDRA_LOOPBACK_OK' $_BWJS_LISTE 2>/dev/null; then
  exit 0
fi
exit 1
BWPATCH
        chmod 700 "$APP_DIR/scripts/ensure-bw-loopback-patch.sh"
        if "$APP_DIR/scripts/ensure-bw-loopback-patch.sh" 2>&1 | sed 's/^/  /'; then :; else
          warn "Le CLI bw n'a pas pu être adapté à la boucle locale — le coffre risque de boucler."
        fi
      fi
    else
      warn "Node.js >= 20 indisponible — coffre ignoré (bw serve l'exige)."; _vault_ok=0
    fi
  fi

  # 8.6.3 Secret zéro (généré une fois, conservé ensuite)
  if [ "$_vault_ok" = "1" ]; then
    if [ ! -f "$VAULT_ENV" ]; then
      say "Génération du secret zéro (mot de passe maître du coffre)…"
      _VW_PASS="$(openssl rand -base64 32)"
      cat > "$VAULT_ENV" <<EOF
# SECRET ZÉRO de Cassandra — root only. Déverrouille le coffre au boot.
BW_SERVER="https://127.0.0.1:${VAULT_PORT}"
BW_EMAIL="${VAULT_EMAIL}"
BW_PASSWORD="${_VW_PASS}"
VAULT_SERVE_PORT="${VAULT_SERVE_PORT}"
EOF
      chmod 600 "$VAULT_ENV"; chown root:root "$VAULT_ENV"
    fi
    # Le port et l'hôte sont réalignés, PAS le schéma : le conteneur sert en
    # HTTPS si ROCKET_TLS a trouvé ses certificats, en clair sinon. Forcer
    # `https` ici remettait le défaut à chaque installation — `bw` échouait
    # ensuite sur « wrong version number » et bouclait. Le sidecar sonde le
    # serveur au démarrage et corrige le fichier si besoin.
    sed -i 's#^BW_SERVER="\(https\?\)://.*#BW_SERVER="\1://127.0.0.1:'"${VAULT_PORT}"'"#' "$VAULT_ENV"
    # shellcheck disable=SC1090
    source "$VAULT_ENV"
  fi

  # 8.6.4 Conteneur Vaultwarden (bind localhost, HTTPS — bw refuse le HTTP)
  if [ "$_vault_ok" = "1" ]; then
    mkdir -p "$VAULT_DIR/vw-data/tls"
    # cert auto-signé pour le coffre (localhost) — bw l'accepte via NODE_TLS_REJECT_UNAUTHORIZED=0
    if [ ! -f "$VAULT_DIR/vw-data/tls/cert.pem" ]; then
      say "Génération du certificat TLS local du coffre…"
      openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$VAULT_DIR/vw-data/tls/key.pem" -out "$VAULT_DIR/vw-data/tls/cert.pem" \
        -days 3650 -subj "/CN=cassandra-vault" >/dev/null 2>&1 || warn "openssl cert: échec"
      chmod 644 "$VAULT_DIR/vw-data/tls/"*.pem 2>/dev/null || true
    fi
    _ADMIN_TOKEN="$(openssl rand -base64 48)"
    cat > "$VAULT_DIR/docker-compose.yml" <<EOF
services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: vaultwarden
    restart: unless-stopped
    environment:
      DOMAIN: "https://127.0.0.1:${VAULT_PORT}"
      ROCKET_TLS: '{certs="/data/tls/cert.pem",key="/data/tls/key.pem"}'
      SIGNUPS_ALLOWED: "true"
      ADMIN_TOKEN: "${_ADMIN_TOKEN}"
      WEBSOCKET_ENABLED: "true"
      SHOW_PASSWORD_HINT: "false"
      PASSWORD_ITERATIONS: "600000"
    volumes:
      - ./vw-data:/data
    ports:
      - "127.0.0.1:${VAULT_PORT}:80"
EOF
    say "Démarrage de Vaultwarden…"
    ( cd "$VAULT_DIR" && $DCOMPOSE up -d ) >/dev/null 2>&1 || { warn "Démarrage Vaultwarden échoué — coffre ignoré."; _vault_ok=0; }
  fi

  # 8.6.5 Attente readiness + création du compte service (idempotent)
  if [ "$_vault_ok" = "1" ]; then
    for _ in $(seq 1 40); do
      curl -ksf "https://127.0.0.1:${VAULT_PORT}/alive" >/dev/null 2>&1 && break
      sleep 1
    done
    if [ -f "$APP_DIR/vault_register.py" ]; then
      say "Création du compte service ${VAULT_EMAIL}…"
      VW_SERVER="$BW_SERVER" VW_EMAIL="$BW_EMAIL" VW_PASSWORD="$BW_PASSWORD" \
        "$PYBIN" "$APP_DIR/vault_register.py" \
        || warn "Création de compte non confirmée — crée-le si besoin sur ${VAULT_DOMAIN}, mdp dans $VAULT_ENV."
    else
      warn "vault_register.py absent — crée le compte ${VAULT_EMAIL} sur ${VAULT_DOMAIN} (mdp dans $VAULT_ENV)."
    fi
    # Inscriptions : laissées OUVERTES — c'est Cassandra qui crée le compte coffre de chaque
    # user à la création de son compte Cassandra (modèle « 1 compte = 1 coffre »). Le coffre
    # est lié à 127.0.0.1 et Cassandra est le seul inscripteur (valide l'e-mail, détient le mdp).
    # ⚠ Si tu EXPOSES le coffre publiquement via un proxy, restreins les inscriptions :
    #   pose SIGNUPS_ALLOWED:"false" + SIGNUPS_DOMAINS_WHITELIST, ou un proxy authentifié.
    sed -i 's/SIGNUPS_ALLOWED: "false"/SIGNUPS_ALLOWED: "true"/' "$VAULT_DIR/docker-compose.yml"
    ( cd "$VAULT_DIR" && $DCOMPOSE up -d ) >/dev/null 2>&1 || true
  fi

  # 8.6.6 Sidecar bw serve + auto-déverrouillage
  if [ "$_vault_ok" = "1" ]; then
    cat > "$APP_DIR/vault-sidecar.sh" <<'SIDECAR'
#!/usr/bin/env bash
# Lance `bw serve` (API REST locale) et déverrouille le coffre au boot depuis le secret zéro.
set -euo pipefail
ENV_FILE="${CASSANDRA_CONF_DIR:-/etc/cassandra}/vault.env"
[ -r "$ENV_FILE" ] || { echo "[vault] $ENV_FILE introuvable" >&2; exit 1; }
# shellcheck disable=SC1090
source "$ENV_FILE"
PORT="${VAULT_SERVE_PORT:-8088}"
BW="$(command -v bw)"
export NODE_TLS_REJECT_UNAUTHORIZED=0   # accepte le certificat auto-signé local du coffre

# Le conteneur sert en HTTPS si ROCKET_TLS a trouvé ses certificats, en clair
# sinon — et rien ne le dit de l'extérieur. Une valeur écrite en dur dans
# vault.env se trompe une fois sur deux : `bw` échoue alors sur
# « wrong version number » (TLS parlé à un serveur en clair) ou sur EPROTO,
# boucle, et le coffre n'est jamais joignable. On demande donc au serveur.
_scheme_du_coffre() {
  local hote="${BW_SERVER#*://}"
  if curl -ksf --max-time 4 "https://${hote}/alive" >/dev/null 2>&1; then
    echo "https"
  elif curl -sf --max-time 4 "http://${hote}/alive" >/dev/null 2>&1; then
    echo "http"
  else
    echo ""                       # injoignable : on garde ce qui est configuré
  fi
}
_vu="$(_scheme_du_coffre)"
if [ -n "$_vu" ] && [ "${BW_SERVER%%://*}" != "$_vu" ]; then
  echo "[vault] le coffre répond en ${_vu}, pas en ${BW_SERVER%%://*} — correction" >&2
  BW_SERVER="${_vu}://${BW_SERVER#*://}"
  # On corrige aussi le fichier : sinon la détection recommence à chaque
  # démarrage, et le journal répète une anomalie déjà connue.
  sed -i "s#^BW_SERVER=.*#BW_SERVER=\"${BW_SERVER}\"#" "$ENV_FILE" 2>/dev/null || true
fi

# `bw` ne lit PAS vault.env : il garde sa propre configuration de serveur, et
# REFUSE de la changer tant qu'une session est ouverte. L'échec était avalé par
# `|| true`, si bien qu'une adresse périmée survivait à toutes les corrections
# du fichier — le symptôme, lui, apparaissait plus loin sous forme d'erreur TLS
# incompréhensible. On vérifie donc ce que `bw` a réellement retenu.
_bw_serveur_actuel() { "$BW" config server 2>/dev/null | tr -d '\r' | tail -n1; }
if [ "$(_bw_serveur_actuel)" != "$BW_SERVER" ]; then
  if ! "$BW" config server "$BW_SERVER" >/dev/null 2>&1; then
    # Refus le plus courant : session ouverte. On la ferme et on réessaie.
    echo "[vault] changement d'adresse refusé — fermeture de la session" >&2
    "$BW" logout >/dev/null 2>&1 || true
    "$BW" config server "$BW_SERVER" >/dev/null 2>&1 \
      || echo "[vault] impossible de fixer l'adresse ${BW_SERVER}" >&2
  fi
  echo "[vault] adresse du coffre : $(_bw_serveur_actuel)"
fi

if ! "$BW" login --check >/dev/null 2>&1; then
  "$BW" login "$BW_EMAIL" "$BW_PASSWORD" --quiet 2>&1 | sed 's/^/[vault][login] /' || true
fi
"$BW" login --check >/dev/null 2>&1 && echo "[vault] connecté au coffre" || echo "[vault] NON connecté (login KO)" >&2
"$BW" serve --hostname 127.0.0.1 --port "$PORT" &
SERVE_PID=$!
trap 'kill "$SERVE_PID" 2>/dev/null || true' TERM INT EXIT
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:${PORT}/status" >/dev/null 2>&1 && break; sleep 1; done
curl -sf -X POST "http://127.0.0.1:${PORT}/unlock" -H 'Content-Type: application/json' \
  -d "{\"password\":$(printf '%s' "$BW_PASSWORD" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')}" \
  >/dev/null 2>&1 || echo "[vault] déverrouillage échoué — vérifie BW_PASSWORD" >&2
echo "[vault] coffre prêt sur 127.0.0.1:${PORT}"
wait "$SERVE_PID"
SIDECAR
    chmod 700 "$APP_DIR/vault-sidecar.sh"
    cat > /etc/systemd/system/cassandra-vault.service <<EOF
[Unit]
Description=Cassandra Vault sidecar (bw serve + auto-unlock)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=CASSANDRA_CONF_DIR=$CFG_DIR
ExecStart=$APP_DIR/vault-sidecar.sh
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    ok "Coffre Vaultwarden provisionné."
  fi
else
  say "WITH_VAULT=0 → coffre non déployé."
fi

step "SearxNG : recherche web souveraine d'Itare"
# --- Recherche web SOUVERAINE pour Itare (Phase 1, non bloquant) ------------------
# Auto-hébergé (Docker), JSON activé, limiteur off, port libre auto (8888 est souvent
# pris par un panneau d'hébergement), et l'URL est écrite toute seule dans config.json.
if [ "${WITH_SEARXNG:-0}" = "1" ]; then
  echo
  say "── SearxNG (recherche web souveraine d'Itare) ──"
  _sx_ok=1
  if ! command -v docker >/dev/null 2>&1; then
    say "Installation de Docker (requis par SearxNG)…"
    [ "$APT_OK" -eq 1 ] && apt-get install -y docker.io apparmor >/dev/null 2>&1 || true
    command -v docker >/dev/null 2>&1 || { curl -fsSL https://get.docker.com | sh >/dev/null 2>&1 || true; }
    command -v docker >/dev/null 2>&1 || { warn "Docker indisponible — SearxNG ignoré."; _sx_ok=0; }
  fi
  if [ "$_sx_ok" = "1" ]; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    # Port libre (8888 est souvent pris par un panneau d'hébergement) : on scanne et on prend le 1er dispo.
    SEARX_PORT=""
    for _p in 8890 8891 8892 8093 8080 8181; do
      ss -ltn 2>/dev/null | grep -q ":$_p " || { SEARX_PORT=$_p; break; }
    done
    [ -z "$SEARX_PORT" ] && SEARX_PORT=8890
    mkdir -p /opt/searxng
    # settings minimal : hérite des défauts SearxNG + JSON + limiteur off + secret.
    # (use_default_settings = pattern officiel : on n'override QUE le nécessaire.)
    if [ ! -f /opt/searxng/settings.yml ]; then
      _sx_secret="$(openssl rand -hex 32 2>/dev/null || echo "chg-$(date +%s)-$RANDOM")"
      cat > /opt/searxng/settings.yml <<SXNG
use_default_settings: true
server:
  secret_key: "$_sx_secret"
  limiter: false
search:
  formats:
    - html
    - json
SXNG
      chmod 600 /opt/searxng/settings.yml 2>/dev/null || true
    fi
    say "Démarrage de SearxNG sur 127.0.0.1:${SEARX_PORT}…"
    docker rm -f searxng >/dev/null 2>&1 || true
    if docker run -d --name searxng --restart unless-stopped \
         -p 127.0.0.1:${SEARX_PORT}:8080 -v /opt/searxng:/etc/searxng \
         searxng/searxng >/dev/null 2>&1; then
      # Écrit l'URL dans la config de Cassandra (source de vérité au runtime).
      SXURL="http://127.0.0.1:${SEARX_PORT}" CFG="$CFG_DIR/config.json" \
      "$PYBIN" - <<'PYSX' || warn "searxng_url non écrit dans config.json"
import json, os
p = os.environ["CFG"]; d = {}
if os.path.exists(p):
    try: d = json.load(open(p))
    except Exception: d = {}
d["searxng_url"] = os.environ["SXURL"]
os.makedirs(os.path.dirname(p), exist_ok=True)
tmp = p + ".tmp"; json.dump(d, open(tmp, "w"), indent=2); os.replace(tmp, p)
print("searxng_url:", d["searxng_url"])
PYSX
      # Test de l'API JSON (laisse le conteneur démarrer).
      sleep 5
      if curl -s --max-time 8 "http://127.0.0.1:${SEARX_PORT}/search?q=test&format=json" 2>/dev/null | grep -q '"results"'; then
        ok "SearxNG actif (JSON) sur 127.0.0.1:${SEARX_PORT} — URL renseignée dans Cassandra."
      else
        warn "SearxNG démarré mais l'API JSON ne répond pas encore (démarrage lent) — réessaie dans 15 s : curl 'http://127.0.0.1:${SEARX_PORT}/search?q=test&format=json'"
      fi
    else
      warn "Démarrage SearxNG échoué — voir : docker logs searxng"
    fi
  fi
else
  say "WITH_SEARXNG=0 → recherche web d'Itare non déployée (active-la : sudo WITH_SEARXNG=1 bash install.sh)."
fi

step "Ressources : swap, tuning mémoire, sémantique"
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
# DURCISSEMENT NOYAU (24-09) : ce que le collecteur signalait « critique » sur une Debian neuve. rp_filter en mode
# SOUPLE (2) : le strict (1) casse Tailscale et Docker. Fichier à part, retiré par la désinstallation.
cat > /etc/sysctl.d/98-cassandra-securite.conf <<'SYSCTL'
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.tcp_syncookies=1
SYSCTL
sysctl -p /etc/sysctl.d/98-cassandra-securite.conf >/dev/null 2>&1 || warn "durcissement noyau non appliqué (sysctl)"

ENABLE_SEMANTIC="$ENABLE_SEMANTIC" EMBED_MODEL="$EMBED_MODEL" CFG="$CFG_DIR/config.json" \
"$PYBIN" - <<'PYCFG' || warn "config.json non mis à jour"
import json, os
p = os.environ["CFG"]
d = {}
if os.path.exists(p):
    try: d = json.load(open(p))
    except Exception: d = {}
d["embeddings_enabled"] = (os.environ.get("ENABLE_SEMANTIC") == "1")
d.setdefault("memory_embed_model", os.environ.get("EMBED_MODEL"))
os.makedirs(os.path.dirname(p), exist_ok=True)
tmp = p + ".tmp"
json.dump(d, open(tmp, "w"), indent=2)
os.replace(tmp, p)
print("config:", p, "| embeddings:", d["embeddings_enabled"], "| modèle:", d.get("memory_embed_model"))
PYCFG
ok "Mémoire configurée."

step "Activation + démarrage (persistance reboot)"
say "Activation et démarrage des services…"
systemctl daemon-reload
if [ "$WITH_VAULT" = "1" ] && [ -f /etc/systemd/system/cassandra-vault.service ]; then
  systemctl enable cassandra-vault.service 2>/dev/null || true
  systemctl restart cassandra-vault.service 2>/dev/null || warn "cassandra-vault non démarré (voir journalctl -u cassandra-vault)."
fi
systemctl enable --now cassandra-collector.service
systemctl enable --now cassandra.service
sleep 2

step "Vérification finale"
fail=0
for svc in cassandra-collector cassandra; do
  if systemctl is-active --quiet "$svc"; then
    ok "$svc : actif (démarrage auto activé)"
  else
    warn "$svc : NON actif — voir : journalctl -u $svc -n 40"
    fail=1
  fi
done
# Health check HTTP : le service ÉCOUTE-t-il vraiment (au-delà de « is-active ») ?
_hc=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://${BIND_HOST}:${PORT}/" 2>/dev/null || true)
if [ -n "$_hc" ] && [ "$_hc" != "000" ]; then
  ok "Cassandra répond en HTTP sur ${BIND_HOST}:${PORT} (code $_hc)"
else
  warn "Cassandra ne répond pas encore sur ${BIND_HOST}:${PORT} — voir : journalctl -u cassandra -n 40"
  fail=1
fi
if [ "$WITH_VAULT" = "1" ] && [ -f /etc/systemd/system/cassandra-vault.service ]; then
  # Le sidecar met ~6 s à se connecter puis à ouvrir son écoute. Interroger une
  # seule fois juste après le démarrage, c'est mesurer une course, pas un état :
  # l'installation annonçait une panne là où il n'y avait qu'une attente.
  _vok=0
  for _i in $(seq 1 10); do
    if curl -sf "http://127.0.0.1:${VAULT_SERVE_PORT}/status" >/dev/null 2>&1; then
      _vok=1; break
    fi
    sleep 2
  done
  if [ "$_vok" = "1" ]; then
    ok "coffre : API locale prête (127.0.0.1:${VAULT_SERVE_PORT})"
  else
    warn "coffre : API toujours muette après 20 s — journalctl -u cassandra-vault -n 40"
    warn "         (le service peut être actif et le coffre verrouillé : vérifiez BW_PASSWORD)"
  fi
fi

# --- URL finale + récapitulatif -------------------------------
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "${IP:-}" ] && IP="<IP_DU_SERVEUR>"

banner
if [ "$fail" -ne 0 ]; then
  warn "Installation terminée avec des avertissements (voir ci-dessus)."
fi
done_box "$IP"

if [ "$BIND_HOST" = "127.0.0.1" ]; then
  echo -e "   ${c_warn}▲${c_off} Cassandra écoute sur ${c_acc}127.0.0.1:${PORT}${c_off} — ${c_bold}non exposé directement${c_off}."
  echo -e "      Trois façons d'y accéder :"
  echo -e "      ${c_acc}1.${c_off} un reverse proxy (nginx, Caddy, ton panneau d'hébergement) qui porte le domaine et le TLS"
  echo -e "         et proxifie vers ${c_acc}http://127.0.0.1:${PORT}${c_off} — exemple nginx : ${c_dim}$APP_DIR/docs/nginx-exemple.conf${c_off}"
  echo -e "      ${c_acc}2.${c_off} depuis ton poste, un tunnel SSH : ${c_acc}ssh -L ${PORT}:127.0.0.1:${PORT} root@${IP}${c_off} puis http://127.0.0.1:${PORT}"
  echo -e "      ${c_acc}3.${c_off} exposer le port en direct : réinstalle avec ${c_acc}BIND_HOST=0.0.0.0${c_off} ${c_dim}(déconseillé sans TLS devant)${c_off}"
  echo ""
fi

if [ "$_dep_ko" = "1" ]; then
  echo -e "   ${c_warn}▲${c_off} ${c_bold}Des dépendances ne s'importent pas${c_off} — voir les avertissements plus haut."
  echo -e "      ${c_dim}Les clés de sécurité, en particulier, resteront indisponibles.${c_off}"
  echo ""
fi

echo -e "   ${c_bold}Au premier lancement, l'assistant web te demande :${c_off}"
if [ "$WITH_VAULT" = "1" ]; then
  echo -e "      ${c_acc}•${c_off} un compte administrateur (c'est aussi ton compte du coffre)"
else
  echo -e "      ${c_acc}•${c_off} un compte administrateur"
fi
echo -e "      ${c_acc}•${c_off} le modèle d'IA : la clé d'un fournisseur, un serveur compatible OpenAI, ou Ollama en local (sans clé)"
echo -e "      ${c_dim}•${c_off} ${c_dim}optionnel : un second modèle pour Itare (sinon il hérite du principal)${c_off}"
command -v tailscale >/dev/null 2>&1 && ! tailscale status >/dev/null 2>&1 \
  && echo -e "      ${c_acc}•${c_off} rejoindre ton réseau Tailscale : ${c_acc}tailscale up${c_off} (la Flotte s'en sert)"
echo -e "      ${c_dim}•${c_off} ${c_dim}optionnel : alertes e-mail SMTP et seuils${c_off}"
if [ "$WITH_VAULT" = "1" ]; then
  echo ""
  echo -e "   ${c_ok}Coffre Vaultwarden${c_off}  ${c_dim}·${c_off}  secret zéro : ${c_inf}$VAULT_ENV${c_off}"
  echo -e "      ${c_dim}API locale Cassandra : 127.0.0.1:${VAULT_SERVE_PORT}  ·  app/web : publie 127.0.0.1:${VAULT_PORT} via ton proxy${c_off}"
fi
echo ""
echo -e "   ${c_dim}Les services redémarrent automatiquement à chaque boot.${c_off}"
hr
echo ""
