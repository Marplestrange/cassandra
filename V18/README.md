# CASSANDRA — agente IA souveraine d'administration système

Un agent IA auto-hébergé pour converser avec votre serveur, vos services et vos sites, sans
dépendre d'un fournisseur unique : une clé d'API, un serveur compatible OpenAI, ou Ollama en
local. Cassandra tient la machine ; Itare, son agent second, relit, veille et propose.

Licence : [AGPL-3.0-or-later](LICENSE). Copyright (C) 2026 Drisse ATEK.

## Pré-requis

- Debian 12 ou Ubuntu 22.04 / 24.04, avec `systemd` et `apt` ; root.
- Python 3.8 ou plus (installé par le script s'il manque).
- Mémoire et disque : **2 Go et 15 Go** avec les options par défaut (coffre en Docker,
  recherche sémantique) ; **1 Go et 3 Go** en installation allégée (voir ci-dessous).
- Un panneau d'hébergement n'est pas requis. FastPanel est pris en charge ; sans panneau,
  l'onglet Hébergement fonctionne en version allégée (sites lus dans nginx, comptes, bases,
  services, certificats, tâches planifiées, versions PHP). Plesk, cPanel, HestiaCP,
  DirectAdmin et Webmin sont détectés et signalés.

## Les trois commandes

```bash
sudo bash install.sh
```
Installe tout, crée les services, démarre Cassandra sur `127.0.0.1:9000`. Le script pose deux
questions au plus (Ollama en local ? Tailscale ?) ; chacune se force par variable
d'environnement pour une installation sans écran : `WITH_OLLAMA=0 WITH_TAILSCALE=0 WITH_VAULT=0
ENABLE_SEMANTIC=0 WITH_SEARXNG=0 sudo -E bash install.sh` donne l'installation allégée.

```bash
sudo bash banc-nu.sh
```
Prouve, dans un conteneur Debian vierge, que Cassandra s'installe et fonctionne sur un serveur
nu, sans clé ni panneau (Docker requis, cinq à dix minutes).

```bash
sudo bash deploy.sh
```
Met à jour une installation existante : copie du code, redémarrage, contrôle de santé et
retour arrière automatique si le service ne répond plus.

## Premiers pas

Une fois installée, Cassandra écoute sur `127.0.0.1:9000`. Trois façons d'y accéder :

1. un reverse proxy (nginx, Caddy, votre panneau) qui porte le domaine et le TLS et proxifie vers
   `http://127.0.0.1:9000` : exemple prêt dans [docs/nginx-exemple.conf](docs/nginx-exemple.conf) ;
2. depuis votre poste, un tunnel SSH : `ssh -L 9000:127.0.0.1:9000 root@votre-serveur`, puis
   `http://127.0.0.1:9000` ;
3. exposer le port en direct : réinstaller avec `BIND_HOST=0.0.0.0` (déconseillé sans TLS devant).

Au premier lancement, l'assistant vous demande un compte administrateur, puis le modèle d'IA :
la clé d'un fournisseur (DeepSeek, OpenRouter, OpenAI, Google, Groq), un serveur compatible
OpenAI (vLLM, LM Studio, LiteLLM…), ou Ollama en local sans clé ; ou « plus tard ». Tout le
reste (alertes e-mail, second modèle pour Itare, coffre, réseau privé) est facultatif.

Les réglages, leurs défauts et les variables d'environnement sont décrits dans
[CONFIG.md](CONFIG.md) ; un exemple de fichier de configuration dans
[config.example.json](config.example.json).

## Ce que contient ce dépôt

| Fichier | Rôle |
|---|---|
| `cassandra.py` | l'application entière : serveur web, agent, mémoire, cage d'exécution, salon des agents, modules |
| `cassandra_knowledge_collector.py` | le collecteur d'état de la machine (service à part, basse priorité) |
| `install.sh`, `deploy.sh` | installation et mise à jour |
| `banc-nu.sh`, `banc_genericite.py` | les deux bancs de publication |
| `docs/` | l'exemple nginx, les documents de conception |

Cassandra est un logiciel indépendant, sans affiliation avec les produits tiers qu'elle sait
lire ou piloter (FastPanel, Tailscale, Vaultwarden, SearxNG, Telegram, Canva, Plex).
