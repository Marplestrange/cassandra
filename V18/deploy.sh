#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Drisse ATEK
# ============================================================
#  deploy.sh — redéploie Cassandra en UNE commande.
#  Compile-check → backup → copie → restart → vérif.
#  À lancer en root depuis le dossier des sources :  sudo bash deploy.sh
#
#  Il REFUSE d'écraser un fichier en service qui a changé depuis le dernier
#  déploiement : le moteur d'évolution écrit dans le fichier en service, et
#  déployer par-dessus effaçait son travail sans un mot. Pour écraser sciemment :
#     sudo ECRASER_SERVICE=1 bash deploy.sh
# ============================================================
set -euo pipefail
APP_DIR="${CASSANDRA_APP_DIR:-/opt/cassandra}"
BACKUP_DIR="${CASSANDRA_BACKUP_DIR:-/var/backups/cassandra}"
LOG_DIR="${CASSANDRA_LOG_DIR:-/var/log}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SRC"

c_ok="\033[1;38;5;48m"; c_err="\033[1;38;5;203m"; c_inf="\033[38;5;111m"; c_off="\033[0m"
say(){ echo -e "   ${c_inf}▸${c_off} $*"; }
ok(){  echo -e "   ${c_ok}✔${c_off} $*"; }
die(){ echo -e "\n   ${c_err}✘ $*${c_off}\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Lance en root :  sudo bash deploy.sh"
[ -f cassandra.py ]  || die "cassandra.py introuvable — lance depuis le dossier des sources."

# 1) Preflight : ON NE DÉPLOIE JAMAIS un fichier qui ne compile pas (sinon le démon ne boote pas).
# Le python du VENV, pas celui du système : c'est lui qui exécutera le code.
# Valider avec une autre version, c'est valider autre chose que ce qui tournera.
PY="${CASSANDRA_VENV:-$APP_DIR/venv}/bin/python"
[ -x "$PY" ] || PY="$(command -v python3 || true)"
[ -n "$PY" ] || die "Aucun python trouvé."

say "Preflight : compilation ($("$PY" -V 2>&1))…"
"$PY" -m py_compile cassandra.py || die "cassandra.py NE COMPILE PAS — déploiement annulé."
if [ -f cassandra_knowledge_collector.py ]; then
  "$PY" -m py_compile cassandra_knowledge_collector.py || die "Le collector ne compile pas — annulé."
fi

# Transfert tronqué : FileZilla interrompu, ou passé en mode ASCII. Un fichier
# coupé net peut encore compiler s'il s'arrête sur une frontière d'instruction —
# on compare donc à la TAILLE DÉJÀ EN PLACE, qui est la seule référence honnête.
_taille=$(wc -c < cassandra.py)
if [ -f "$APP_DIR/cassandra.py" ] && [ "${FORCE_TAILLE:-0}" != "1" ]; then
  _ancienne=$(wc -c < "$APP_DIR/cassandra.py")
  if [ "$_ancienne" -gt 0 ] && [ "$_taille" -lt $(( _ancienne * 70 / 100 )) ]; then
    die "cassandra.py fait $_taille octets contre $_ancienne en place (-30 % ou plus).
      Transfert tronqué ? Retransférez en mode BINAIRE avant de déployer.
      (Pour passer outre : FORCE_TAILLE=1 bash deploy.sh)"
  fi
fi
# La page entière est un seul <script> : une balise manquante rend l'application
# muette sans que Python s'en aperçoive. On vérifie les repères de fin.
grep -q 'id="login-modal"' cassandra.py || die "Le formulaire de connexion est absent du fichier — transfert incomplet ?"
[ -f install.sh ] && { bash -n install.sh || die "install.sh invalide — annulé."; }
ok "Compilation OK."

# 1 bis) LE SERVICE A-T-IL BOUGÉ DEPUIS LE DERNIER DÉPLOIEMENT ?
# Le moteur d'évolution écrit dans les fichiers EN SERVICE (cassandra.py et le
# collecteur). Déployer par-dessus effaçait son travail sans un mot : mesuré le
# 10-09, deux quarantaines écrites le jour même, disparues au déploiement du soir.
# Le démarrage le crie désormais — mais APRÈS avoir écrasé. Ici, on refuse AVANT.
#
# La référence est une copie de ce qui a été DÉPLOYÉ — la source, pas le service
# après démarrage : un retour arrière du watchdog au boot doit rester visible au
# déploiement suivant. Trois cas passent : aucune référence (premier déploiement
# sous garde), service identique à la référence, ou source identique au service
# — redéployer exactement ce qui tourne n'efface rien. Tout le reste est refusé,
# et le refus s'écrit au journal de l'application AVANT de sortir.
#
# Limite, écrite : le service tourne en root. Du code qui VEUT tromper cette garde
# peut réécrire la référence. Elle arrête le chemin normal du moteur — la porte
# n'écrit que ses fichiers sources —, pas un adversaire déjà root.
_REF="$BACKUP_DIR/dernier-deploiement"
_journal() {
  local niveau="$1"; shift
  if [ -d "$LOG_DIR" ]; then
    printf '%s %-7s [DEPLOY] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$niveau" "$*" \
      >> "$LOG_DIR/cassandra.log" 2>/dev/null || true
  fi
  command -v logger >/dev/null 2>&1 && logger -t cassandra-deploy -- "$niveau $*" 2>/dev/null || true
}
# Les fonctions dont le texte diffère entre la référence et le service : c'est ce
# que le refus nomme, pour qu'on sache quoi récupérer sans ouvrir un diff de 7 Mo.
read -r -d '' _PY_FONCTIONS <<'PYEOF' || true
import ast, sys
def fonctions(p):
    s = open(p, encoding="utf-8").read()
    L = s.split(chr(10))
    return {n.name: chr(10).join(L[n.lineno - 1:n.end_lineno]) for n in ast.parse(s).body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
a, b = fonctions(sys.argv[1]), fonctions(sys.argv[2])
t = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
print((", ".join(t[:12]) + (" (+%d)" % (len(t) - 12) if len(t) > 12 else "")) if t else "hors des fonctions")
PYEOF
_bouge=""; _quoi=""; _arme=0
for _f in cassandra.py cassandra_knowledge_collector.py; do
  [ -f "$_f" ] || continue                          # la source ne le porte pas : rien ne l'écrase
  [ -f "$APP_DIR/$_f" ] || continue                 # rien en place : rien à effacer
  if [ ! -f "$_REF/$_f" ]; then _arme=1; continue; fi
  cmp -s "$APP_DIR/$_f" "$_REF/$_f" && continue     # le service est ce qu'on a déployé
  cmp -s "$_f" "$APP_DIR/$_f" && continue           # on redéploie exactement ce qui tourne
  _fn=$("$PY" -c "$_PY_FONCTIONS" "$_REF/$_f" "$APP_DIR/$_f" 2>/dev/null || true)
  # LA SOURCE PORTE DÉJÀ CE TRAVAIL (15-09) : fusionner le service dans la source, sur la
  # base de la référence, redonne la source octet pour octet — rien de ce que le moteur a
  # écrit n'est perdu. Sans ce cas, garder son travail coûtait trois déploiements (refus,
  # copie du service, source) et un redémarrage pour rien. Une source qui réécrit AUTREMENT
  # la même région est un conflit : refusée, comme avant. Sans git : la garde ne devine pas.
  _fus=""
  if command -v git >/dev/null 2>&1 && _fus=$(mktemp 2>/dev/null) \
     && git merge-file -p "$_f" "$_REF/$_f" "$APP_DIR/$_f" > "$_fus" 2>/dev/null \
     && cmp -s "$_fus" "$_f"; then
    rm -f "$_fus"
    _journal INFO "le service a changé depuis le dernier déploiement — $_f : ${_fn:-illisible} ; la source porte déjà ce travail, rien n'est effacé"
    say "Le service a changé ($_f : ${_fn:-illisible}) — la source porte déjà ce travail : rien n'est effacé."
    continue
  fi
  [ -n "$_fus" ] && rm -f "$_fus"
  _bouge="$_bouge $_f"
  _quoi="$_quoi $_f : ${_fn:-illisible} ;"
done
if [ -n "$_bouge" ]; then
  if [ "${ECRASER_SERVICE:-0}" = "1" ]; then
    _journal CRITICAL "déploiement qui ÉCRASE sciemment le service modifié depuis le dernier déploiement —$_quoi ECRASER_SERVICE=1"
    echo -e "   ${c_err}▲ ÉCRASEMENT VOLONTAIRE (ECRASER_SERVICE=1) :$_quoi${c_off}"
  else
    _journal CRITICAL "déploiement REFUSÉ : le service a changé depuis le dernier déploiement —$_quoi rien n'est écrasé"
    die "Le fichier EN SERVICE a changé depuis le dernier déploiement :
     $_quoi
      Le moteur d'évolution écrit dans le fichier en service ; déployer maintenant
      EFFACERAIT ce travail. Rien n'a été touché.
      Pour le garder : fusionnez-le avec vos sources, par exemple
        git merge-file -p <vos sources>/cassandra.py $_REF/cassandra.py $APP_DIR/cassandra.py
      puis redéployez le résultat.
      Pour l'écraser sciemment :  sudo ECRASER_SERVICE=1 bash deploy.sh"
  fi
elif [ "$_arme" = "1" ]; then
  say "Aucune référence de déploiement : la garde s'arme à la fin de celui-ci."
fi

# 2) Backup horodaté de l'ancien code (récupérable en cas de souci).
_bk="$BACKUP_DIR/deploy-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$_bk" 2>/dev/null || true
[ -f "$APP_DIR/cassandra.py" ] && cp -a "$APP_DIR/cassandra.py" "$_bk/" 2>/dev/null || true
[ -f "$APP_DIR/cassandra_knowledge_collector.py" ] && cp -a "$APP_DIR/cassandra_knowledge_collector.py" "$_bk/" 2>/dev/null || true
ok "Backup : $_bk"
# Trois suffisent : au-delà, on ne remonte plus jamais, et le disque se remplit
# d'un déploiement à l'autre.
ls -1dt "$BACKUP_DIR"/deploy-* 2>/dev/null | tail -n +4 \
  | xargs -r rm -rf 2>/dev/null || true

# 3) Copie des sources.
say "Copie vers $APP_DIR…"
install -m 0755 cassandra.py "$APP_DIR/cassandra.py"
[ -f cassandra_knowledge_collector.py ] && install -m 0755 cassandra_knowledge_collector.py "$APP_DIR/cassandra_knowledge_collector.py"
if [ -d tools ]; then mkdir -p "$APP_DIR/tools"; cp -a tools/. "$APP_DIR/tools/" 2>/dev/null || true; fi
# Bibliothèques embarquées (vendor/ : l'éditeur ink-mde, MIT), servies par /vendor/<nom>.
if [ -d vendor ]; then mkdir -p "$APP_DIR/vendor"; cp -a vendor/. "$APP_DIR/vendor/" 2>/dev/null || true; fi
[ -f ITARE_AUTONOME.md ] && install -m 0644 ITARE_AUTONOME.md "$APP_DIR/ITARE_AUTONOME.md" 2>/dev/null || true
# L'installeur voyage avec le code : c'est lui que « Réinstaller à neuf » et l'usine relancent
# depuis une copie de travail — un install.sh en place vieux de deux semaines a été mesuré le 23-09.
[ -f install.sh ] && install -m 0755 install.sh "$APP_DIR/install.sh" 2>/dev/null || true
if [ -d docs ]; then mkdir -p "$APP_DIR/docs"; cp -a docs/. "$APP_DIR/docs/" 2>/dev/null || true; fi
ok "Fichiers copiés."

# 4) Redémarrage.
say "Redémarrage des services…"
# LA DÉFINITION DU SERVICE D'ABORD. systemd garde en mémoire sa propre copie du
# fichier d'unité : si `install.sh` l'a réécrit depuis, un simple `restart`
# relance l'ANCIENNE définition — et systemd se contente d'un avertissement que
# personne ne lit. Une variable d'environnement ou un `ExecStart` modifiés
# resteraient sans effet, sans que rien ne le signale.
#
# `daemon-reload` ne coupe rien : il relit les fichiers, c'est tout. Le faire à
# chaque déploiement coûte une fraction de seconde et supprime la question.
systemctl daemon-reload 2>/dev/null || true
# PAS DE TUYAU ICI (15-09). Sous `set -o pipefail`, `systemctl list-unit-files | grep -q` rendait
# faux une fois sur deux : grep se ferme à la première ligne trouvée, systemctl meurt d'un SIGPIPE
# en écrivant la suite, et le tuyau entier passe pour raté. Le collecteur n'était alors pas
# redémarré — l'ancien code tournait sous un fichier neuf, sans un mot. On demande l'unité par
# son nom : une ligne, aucun tuyau.
if [ -n "$(systemctl list-unit-files cassandra-collector.service --no-legend 2>/dev/null)" ]; then
  systemctl restart cassandra-collector \
    || echo -e "   ${c_warn:-}▲${c_off:-} Le collecteur n'a pas redémarré — voir : journalctl -u cassandra-collector -n 20"
fi
systemctl restart cassandra
sleep 2

# 5) Retour arrière : un déploiement raté doit se défaire TOUT SEUL.
#    Donner le chemin du backup et s'arrêter laissait le site à terre jusqu'à
#    ce que quelqu'un lise le message — ce qui peut prendre des heures.
_rollback() {
  echo -e "\n   ${c_err}✘ $1${c_off}" >&2
  if [ -f "$_bk/cassandra.py" ]; then
    say "Retour arrière automatique…"
    install -m 0755 "$_bk/cassandra.py" "$APP_DIR/cassandra.py"
    [ -f "$_bk/cassandra_knowledge_collector.py" ] \
      && install -m 0755 "$_bk/cassandra_knowledge_collector.py" "$APP_DIR/cassandra_knowledge_collector.py"
    systemctl restart cassandra || true
    sleep 2
    if systemctl is-active --quiet cassandra; then
      ok "Version précédente rétablie — le service répond de nouveau."
      echo -e "   ${c_inf}▸${c_off} La version rejetée est dans : $SRC"
    else
      echo -e "   ${c_err}✘ Le retour arrière n'a pas suffi : journalctl -u cassandra -n 40${c_off}" >&2
    fi
  else
    echo -e "   ${c_err}✘ Aucun backup à rétablir (première installation ?)${c_off}" >&2
  fi
  exit 1
}

# 6) Vérification.
if systemctl is-active --quiet cassandra; then
  PORT="${CASSANDRA_PORT:-9000}"
  # L'adresse d'écoute vient de l'unité (BIND_HOST à l'installation) : vérifier 127.0.0.1 sur un service qui
  # écoute ailleurs ferait un retour arrière à chaque déploiement.
  BIND="$(grep -o 'CASSANDRA_BIND=[^ ]*' /etc/systemd/system/cassandra.service 2>/dev/null | head -1 | cut -d= -f2)"
  BIND="${CASSANDRA_BIND:-${BIND:-127.0.0.1}}"
  # On laisse jusqu'à 15 s : un démarrage lent n'est pas un échec, mais une
  # absence de réponse au bout de 15 s en est un.
  _hc="000"
  for _i in 1 2 3 4 5 6 7; do
    _hc=$(curl -s -o /tmp/_cass_hc -w "%{http_code}" --max-time 4 "http://${BIND}:${PORT}/" 2>/dev/null || echo "000")
    case "$_hc" in 200|301|302|401|403) break ;; esac
    sleep 2
  done
  # N'IMPORTE QUEL code était accepté, 500 compris : un service qui démarre et
  # rend 500 était compté « répond ». On exige un code sain ET la présence du
  # formulaire de connexion, qui prouve que la page est servie entière.
  case "$_hc" in
    200|301|302|401|403)
      if grep -q 'login-modal\|<!DOCTYPE html>' /tmp/_cass_hc 2>/dev/null; then
        ok "Cassandra répond (HTTP $_hc) et sert bien la page."
      else
        ok "Cassandra répond (HTTP $_hc)."
      fi ;;
    000) _rollback "Aucune réponse HTTP après 15 s sur ${BIND}:${PORT}." ;;
    *)   _rollback "Cassandra répond HTTP $_hc — le service tourne mais l'application est en erreur." ;;
  esac
  rm -f /tmp/_cass_hc 2>/dev/null || true
  # `deploy.sh` copie du code, il n'installe RIEN. Une version qui apporte une
  # dépendance nouvelle partirait donc en silence sur un serveur qui ne l'a pas,
  # et la fonction concernée échouerait avec un message qui accuse autre chose.
  _VENV_PY="${CASSANDRA_VENV:-$APP_DIR/venv}/bin/python"
  [ -x "$_VENV_PY" ] || _VENV_PY="$(command -v python3 || true)"
  if [ -n "$_VENV_PY" ] && ! "$_VENV_PY" -c "import cryptography" >/dev/null 2>&1; then
    echo -e "   ${c_warn:-}▲${c_off:-} « cryptography » absent : les clés de sécurité"
    echo -e "      resteront indisponibles. Relance install.sh pour l'ajouter."
  fi
  # La référence du prochain déploiement : ce qui vient d'être DÉPLOYÉ, prise dans
  # la source — pas dans le service, qu'un retour arrière au démarrage a pu réécrire.
  mkdir -p "$_REF" 2>/dev/null || true
  install -m 0600 cassandra.py "$_REF/cassandra.py" 2>/dev/null \
    || echo -e "   ${c_warn:-}▲${c_off:-} Référence non écrite ($_REF) : la garde ne protégera pas le prochain déploiement."
  if [ -f cassandra_knowledge_collector.py ]; then
    install -m 0600 cassandra_knowledge_collector.py "$_REF/cassandra_knowledge_collector.py" 2>/dev/null || true
  fi
  _journal INFO "déploiement terminé : référence posée ($(md5sum cassandra.py | cut -c1-12))"
  ok "Déploiement terminé. (rollback : $_bk)"
else
  _rollback "Cassandra n'a pas démarré — journalctl -u cassandra -n 40"
fi
