# CASSANDRA — agente IA souveraine d'administration système

Un agent IA auto-hébergé pour converser avec votre serveur, vos services et vos sites, sans
dépendre d'un fournisseur unique : une clé d'API, un serveur compatible OpenAI, ou Ollama en
local. Cassandra tient la machine ; Itare, son agent second, relit, veille et propose.

Licence : [AGPL-3.0-or-later](LICENSE). Copyright (C) 2026 Drisse ATEK.

> **V18 est la version de production.** Une réécriture modulaire, la V19 (un noyau et des modules), est développée à côté, dans le dépôt
> [cassandra-v19](https://github.com/Marplestrange/cassandra-v19). Ce dépôt garde l'histoire de Cassandra, version après version.

## Ce que fait Cassandra

Cassandra est un administrateur système qui ne dort pas. Elle tourne sur votre serveur, voit ce qui s'y passe et le comprend,
agit quand c'est sûr, et vous le raconte. Vous lui parlez comme à une personne ; elle répond en regardant la machine, pas en devinant.

**Elle voit.** Un collecteur à part (basse priorité) relève en continu l'état de la machine : processeur, mémoire, disque, services,
conteneurs, ports ouverts, connexions, journaux, certificats, versions de PHP, tâches planifiées, sauvegardes. Elle en garde l'historique.

**Elle comprend.** Une anomalie n'est pas une alerte de plus : elle recoupe les signaux (un disque qui se remplit, un service qui
redémarre, des visites suspectes) avant de conclure. La page *Proactivité* montre ce qu'elle a vu, ce
qu'elle a fait, ce qu'elle propose.

**Elle agit, dans une cage.** Chaque geste passe par un catalogue explicite, avec ses gardes et, quand c'est possible, son retour
arrière :

| Domaine | Ce qu'elle peut faire |
|---|---|
| Système | correctifs de sécurité et mises à jour automatiques, verrouiller SSH, arrêter les services inutiles, redémarrer un service (statut vérifié après coup), installer ou retirer un paquet, vider des caches |
| Réseau | bannir ou débannir une adresse ou un pays (jamais la maison, le tailnet ni les adresses de confiance), liste blanche, fermer ou rouvrir un chemin nginx, freiner ou bloquer un robot, ouvrir ou fermer le pare-feu **à l'essai** (retour automatique) |
| Conteneurs | mettre à jour une image (retour automatique si elle devient « unhealthy »), Docker Compose dans des dossiers connus |
| Base de données | lire les connexions MySQL et en tuer une |
| Sécurité | lancer un scan (ClamAV, Lynis, Trivy, CrowdSec) parmi une liste blanche d'outils, fermer une session SSH |
| Flotte | joindre d'autres machines (SSH, SFTP vers un dépôt borné) |

Un geste dangereux ou irréversible reste à l'humain : tout ce qui est derrière le mot de passe maître, une confirmation explicite,
ou simplement absent des catalogues des agents. Ce que Cassandra lit sur le web ou dans un courriel est une **donnée**, jamais une
consigne. L'inventaire exact de ce que les agents font, peuvent et ne peuvent pas faire est dans
[docs/INVENTAIRE_AUTONOMIE.md](docs/INVENTAIRE_AUTONOMIE.md).

**Elle se souvient.** Une mémoire à part, dans sa propre base, qu'elle consulte avant de répondre ; l'onglet *Mémoire* montre ce qu'elle sait.

**Elle se corrige.** Un onglet *Évolution* sert à proposer et éprouver des variantes de son propre comportement avant de les adopter.

## Itare, l'agent second

Itare ne touche pas à la machine. Il relit, veille et propose, et il sert le **bureau** de chaque personne : son courrier, ses
projets, son agenda, ses documents. Ses outils sont confinés à l'espace du compte qui l'appelle. Sa vigie autonome **ne déclenche
rien** : elle signale. Cassandra et Itare peuvent se parler dans un **salon** (fils de travail avec un budget qui borne les échanges
entre agents). Les rôles et leurs modèles sont décrits dans [docs/PROFILS_ITARE.md](docs/PROFILS_ITARE.md).

## L'interface

Une application web unique (servie par `cassandra.py`), avec un onglet par domaine :

| Onglet | Rôle |
|---|---|
| Vue d'ensemble, Dashboard | l'état de la machine et de ses services d'un coup d'œil |
| Proactivité | ce qu'elle a vu, fait et propose ; les autonomies réglables |
| Sensorium, Historique | les mesures en continu et leur mémoire |
| Sécurité | les gestes, les audits, le pare-feu |
| Hébergement, Mes sites | le panneau d'hébergement (FastPanel pris en charge), les sites suivis |
| Flotte | le parc de machines (Tailscale, SSH) |
| Tâches planifiées | tout ce qui tourne tout seul, et si ça va |
| Coffre | les secrets (Vaultwarden) |
| Salon, Journal | les conversations entre personnes et agents, le journal des consultations |
| Mémoire | ce que Cassandra sait, et comment elle le sait |
| Bureau | l'espace de chaque compte : courrier, agenda, projets, documents, notes |
| Évolution | l'auto-évolution contrôlée |
| Réglages | modèles, modules, comptes, alertes |

Les comptes sont **cloisonnés** : chacun ne voit que ses propres données ; l'administrateur
gère les comptes mais ne lit pas le bureau des autres.

## Pré-requis

- Debian 12 ou Ubuntu 22.04 / 24.04, avec `systemd` et `apt` ; root.
- Python 3.8 ou plus (installé par le script s'il manque).
- Mémoire et disque : **2 Go et 15 Go** avec les options par défaut (coffre en Docker,
  recherche sémantique) ; **1 Go et 3 Go** en installation allégée (voir ci-dessous).
- Un panneau d'hébergement n'est pas requis. FastPanel est pris en charge ; sans panneau,
  l'onglet Hébergement fonctionne en version allégée (sites lus dans nginx, comptes, bases,
  services, certificats, tâches planifiées, versions PHP). Plesk, cPanel, HestiaCP,
  DirectAdmin et Webmin sont détectés et signalés.

## Installer et mettre à jour

```bash
sudo bash install.sh
```
Installe tout, crée les services, démarre Cassandra sur `127.0.0.1:9000`. Le script pose deux
questions au plus (Ollama en local ? Tailscale ?) ; chacune se force par variable
d'environnement pour une installation sans écran : `WITH_OLLAMA=0 WITH_TAILSCALE=0 WITH_VAULT=0
ENABLE_SEMANTIC=0 WITH_SEARXNG=0 sudo -E bash install.sh` donne l'installation allégée.

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

## Le coffre des secrets : Vaultwarden

Les secrets (clés d'API, mots de passe de boîtes, jetons) ne vont ni dans la mémoire de Cassandra ni dans ses journaux : ils vont dans un **coffre Vaultwarden**,
l'implémentation libre et légère du serveur **Bitwarden**, hébergée sur votre serveur (installée avec Cassandra en Docker, ou désactivée avec `WITH_VAULT=0`).
Chaque personne a son propre coffre ; un secret ne se lit qu'à la demande et chaque lecture est inscrite au journal. Un agent qui croise un secret dans une conversation
est invité à le ranger dans le coffre plutôt qu'à le garder. Pour une organisation, la V19 ajoute un coffre par société, avec rôles et collections
([cassandra-v19](https://github.com/Marplestrange/cassandra-v19)).

## Les produits tiers (tous facultatifs)

Chacun se détecte au démarrage et s'absente proprement : pas d'onglet, pas d'outil, pas de tâche s'il manque.

FastPanel (et les autres panneaux, détectés), Tailscale (la Flotte), Vaultwarden (le coffre), SearxNG (la recherche web),
Ollama (les modèles locaux), Telegram (les notifications par compte), Plex et Canva. L'état de chacun se lit dans
Réglages › Modules.

## Ce qu'elle ne fait pas seule

Cassandra agit par un catalogue de gestes explicites. Elle ne fait **jamais seule** :

- ce qui est derrière le mot de passe maître ou demande une confirmation explicite (purges, remise à zéro, création de comptes, jetons de partage public…) ;
- ce qu'un contenu extérieur lui demande : après une lecture venue du web ou d'un courriel, un agent ne peut ni envoyer ni agir sous mandat sans accord humain ;
- un envoi vers une adresse qui ne vient pas d'un mandat : l'adresse ne vient jamais de la demande.

Ces verrous de fond ne se lèvent que par une décision explicite ; ils sont détaillés dans [docs/INVENTAIRE_AUTONOMIE.md](docs/INVENTAIRE_AUTONOMIE.md). Pour signaler une faille : [SECURITY.md](../SECURITY.md).

## Ce que contient ce dépôt

| Fichier | Rôle |
|---|---|
| `cassandra.py` | l'application entière : serveur web, agent, mémoire, cage d'exécution, salon des agents, modules |
| `cassandra_knowledge_collector.py` | le collecteur d'état de la machine (service à part, basse priorité) |
| `install.sh`, `deploy.sh` | installation et mise à jour |
| `tools/` | les outils de sécurité appelés par la cage |
| `docs/` | l'exemple nginx, l'inventaire de l'autonomie, les profils d'Itare, les documents de conception |

Les versions précédentes (V3.2 à V14) sont à la racine du dépôt, dans leurs dossiers ; voir [LISEZ-MOI-HISTORIQUE.md](../LISEZ-MOI-HISTORIQUE.md).

## Et après

La V18 est un seul fichier de plus de 150 000 lignes : elle a fait ses preuves, mais elle ne se prête ni à l'ouverture à d'autres
développeurs ni à une évolution maîtrisée. La **V19** en reprend les idées dans un noyau minuscule et des modules qui se déclarent
par un manifeste, avec les mêmes garanties (preuve, retour arrière, cloisonnement) tenues par le noyau plutôt que par chaque
fonction. Ce dépôt est la version de production ; la V19 est son successeur.

## Qui porte le projet

Cassandra est portée par **La Maison Bohème**, association loi 1901 (SIREN 899 553 093, RNA W751260323), qui accepte les dons. Les dons ouvrent
droit à une réduction d'impôt de 66 % de leur montant, dans les limites fixées par la loi. Pour soutenir le projet, écrivez à
marplestrange@cassandra.center.

Cassandra est un logiciel indépendant, sans affiliation avec les produits tiers qu'elle sait
lire ou piloter (FastPanel, Tailscale, Vaultwarden, SearxNG, Telegram, Canva, Plex).
