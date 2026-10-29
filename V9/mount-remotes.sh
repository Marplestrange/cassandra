#!/bin/bash

# Configuration des variables de base
BASE_DIR="/var/www/fastuser/data/www/cloud.cassandra.center/data/Marple/files"

# Déclaration du tableau associatif des remotes (Désormais 11 au lieu de 10)
declare -A REMOTES
REMOTES["maisonboheme"]="Maison Bohème"
REMOTES["ciejayad"]="Compagnie Jayad"
REMOTES["communauteboheme"]="Communauté Bohème"
REMOTES["atekdrisse"]="Porte Document"
REMOTES["marplejones"]="Laboratoire"
REMOTES["companiebattu"]="Compagnie Battu"
REMOTES["persomega"]="Imaginarium"
REMOTES["persopcloud"]="Sauvergarde BDD"
REMOTES["persodrime"]="Citadelle"
REMOTES["persoicloud"]="La pomme"
REMOTES["persoicloudphotos"]="iCloud Photos" # <-- Ton nouveau bébé !

# Boucle pour créer les dossiers personnalisés et monter les volumes
for REMOTE in "${!REMOTES[@]}"; do
    FOLDER_NAME="${REMOTES[$REMOTE]}"
    TARGET_DIR="${BASE_DIR}/${FOLDER_NAME}"

    # Création du dossier s'il n'existe pas
    if [ ! -d "$TARGET_DIR" ]; then
        mkdir -p "$TARGET_DIR"
    fi

    # On s'assure que fastuser est bien propriétaire du dossier avant le montage
    chown -R fastuser:fastuser "$TARGET_DIR"

    # Démontage propre de sécurité
    fusermount -u "$TARGET_DIR" 2>/dev/null

    # Gestion spécifique pour iCloud Photos (besoin de PrimarySync)
    if [ "$REMOTE" = "persoicloudphotos" ]; then
        RCLONE_SOURCE="${REMOTE}:PrimarySync"
    else
        RCLONE_SOURCE="${REMOTE}:"
    fi

    # Montage Rclone optimisé et unifié
    rclone mount "$RCLONE_SOURCE" "$TARGET_DIR" \
        --allow-other \
        --dir-cache-time 1m \
        --vfs-cache-mode writes \
        --vfs-cache-max-age 24h \
        --vfs-cache-max-size 10G \
        --daemon
done
