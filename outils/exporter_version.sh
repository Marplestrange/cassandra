#!/usr/bin/env bash
# Exporte le code de Cassandra installé sur ce serveur vers un dossier
# prêt à copier dans le dépôt GitHub (sans secrets ni données).
#
# Usage, sur le serveur :  bash exporter_version.sh V18
# Résultat : ~/cassandra-export/V18/  et  ~/cassandra-export/V18.tar.gz
set -euo pipefail

VERSION="${1:-V18}"
APP_DIR="${APP_DIR:-/opt/cassandra}"
OUT="$HOME/cassandra-export/$VERSION"

[ -d "$APP_DIR" ] || { echo "Dossier $APP_DIR introuvable. Relance avec APP_DIR=/chemin bash $0 $VERSION"; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT"

# Copie uniquement le code et les fichiers web, en excluant secrets et données.
cd "$APP_DIR"
find . -type f \
  \( -name '*.py' -o -name '*.sh' -o -name '*.html' -o -name '*.js' -o -name '*.css' \
     -o -name '*.md' -o -name '*.txt' -o -name '*.service' -o -name '*.svg' \) \
  -not -path '*/__pycache__/*' -not -path '*/venv/*' -not -path '*/.venv/*' \
  -not -path '*/node_modules/*' -not -name '.env*' \
  -print0 | while IFS= read -r -d '' f; do
    mkdir -p "$OUT/$(dirname "$f")"
    cp "$f" "$OUT/$f"
  done

# Services systemd (utile pour savoir comment l'app est lancée)
for svc in /etc/systemd/system/cassandra*.service; do
  [ -f "$svc" ] && mkdir -p "$OUT/systemd" && cp "$svc" "$OUT/systemd/"
done

tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$VERSION"

echo
echo "Export terminé :"
find "$OUT" -type f | sed "s|$OUT/|  |"
echo
echo "Archive : $OUT.tar.gz"
echo "Vérifie qu'aucune clé API n'apparaît :"
grep -rIlE "sk-[A-Za-z0-9]{20,}|api_key\"?\s*[:=]\s*\"[^\"]{12,}" "$OUT" || echo "  (rien de suspect trouvé)"
