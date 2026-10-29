#!/bin/bash
# Synchro directe entre Google Drive et le dossier Nextcloud
rclone sync ton_remote_rclone: /mnt/roscosmos/nextcloud/data/data/Marple/files/Maison\ Bohème/ --allow-other

# On remet les droits pour que Nextcloud ne plante pas
chown -R www-data:www-data /mnt/roscosmos/nextcloud/data/data/Marple/files/Maison\ Bohème/

# On force Nextcloud a voir les changements
docker exec -u www-data nextcloud-app php occ files:scan --path="/Marple/files/Maison Bohème"
