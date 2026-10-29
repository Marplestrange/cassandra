# Déploiement de Cassandra sur un serveur neuf

Plus besoin de créer une clé, un compte ou un mot de passe avant l'installation.
Tout se configure depuis le navigateur, via un assistant intégré.

## 1. Copier les fichiers sur le serveur

Copiez ces trois fichiers dans un même dossier sur le nouveau serveur :

- `install.sh`
- `cassandra.py`
- `cassandra_knowledge_collector.py`

(via SFTP, `scp`, une clé USB, le gestionnaire de fichiers de votre panel, etc.)

## 2. Lancer l'installation (une seule fois)

```
sudo bash install.sh
```

Le script, en une seule passe :

- installe Python + l'environnement nécessaire (paquet `openai`) ;
- copie l'agent dans `/opt/cassandra` ;
- crée **deux services systemd** :
  - `cassandra-collector.service` (collecteur de données),
  - `cassandra.service` (agent + interface web, port 9000) ;
- **active le démarrage automatique au boot** (`systemctl enable`) — les services
  redémarrent tout seuls après un reboot ou un plantage (`Restart=always`) ;
- démarre les deux services et affiche l'URL à ouvrir.

Aucune clé / compte / mot de passe n'est demandé à cette étape.

## 3. Configurer depuis le navigateur (mode installation)

Ouvrez l'URL affichée à la fin du script :

```
http://IP_DU_SERVEUR:9000
```

Au tout premier accès, l'agent détecte qu'il n'est pas encore configuré et affiche
l'**assistant d'installation** (au lieu de la page de connexion). Vous y renseignez :

1. **Compte administrateur** — identifiant + mot de passe (8 caractères min).
2. **Modèle d'IA** — fournisseur (DeepSeek, Groq, OpenAI, OpenRouter, Ollama…),
   modèle et clé API. La clé est stockée localement dans
   `/etc/cassandra/deepseek.key` (chmod 600).
3. *(optionnel)* **Alertes e-mail** — serveur SMTP, identifiants, destinataires.
4. *(optionnel)* **Seuils d'alerte** — disque / RAM / load.

Cliquez sur **Terminer l'installation**. La page bascule alors automatiquement sur
l'écran de connexion : vous vous connectez avec le compte que vous venez de créer.

> Une fois configuré, l'assistant ne réapparaît plus : `/api/setup` est verrouillé
> tant qu'un compte ou un mot de passe admin existe.

## Mise à jour de l'agent

Pour déployer une nouvelle version : remplacez les `.py` et relancez
`sudo bash install.sh`. La configuration (`/etc/cassandra`) et les données
(`/var/lib/cassandra`) sont **préservées** ; seuls les services redémarrent.

## Emplacements

| Élément              | Chemin                                   |
|----------------------|------------------------------------------|
| Code                 | `/opt/cassandra/`                        |
| Configuration        | `/etc/cassandra/` (config, clé, comptes) |
| Alertes (SMTP/seuils)| `/etc/cassandra/alerts.yml`              |
| Données / bases      | `/var/lib/cassandra/`                    |
| Logs                 | `/var/log/cassandra.log`, `/var/log/cassandra-collector.log` |

## Commandes utiles

```
systemctl status cassandra cassandra-collector   # état
journalctl -u cassandra -f                        # logs en direct
systemctl restart cassandra                       # redémarrer l'agent
```
