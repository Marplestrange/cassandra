---

# 🔥 CASSANDRA

### *L'agent IA souverain qui gère votre infrastructure comme un admin système augmenté*

---

[![Version](https://img.shields.io/badge/version-14.0-blue.svg)](https://github.com/Marplestrange/cassandra)
[![Python](https://img.shields.io/badge/python-3.10+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

---

## 🚀 En une phrase

> **Cassandra** est un agent IA autonome qui gère vos serveurs Linux — avec mémoire sémantique, flotte multi-serveur, terminal web, et auto-évolution. Tout tourne **sur votre infrastructure**, pas dans le cloud.

---

## 🎯 Pourquoi Cassandra ?

| Le problème | La solution Cassandra |
|-------------|----------------------|
| ❌ Les LLM cloud sont chers et lents | ✅ Local-first : Ollama, DeepSeek, ou vos propres modèles |
| ❌ Les agents IA sont des "boîtes noires" | ✅ Code open-source, vous contrôlez tout |
| ❌ Pas de mémoire inter-sessions | ✅ Mémoire sémantique avec embeddings + FTS5 |
| ❌ Un seul serveur = un seul agent | ✅ Flotte multi-serveur (SSH, Synology, Proxmox) |
| ❌ Pas de terminal web interactif | ✅ PTY réel avec xterm.js |
| ❌ Pas d'auto-évolution | ✅ L'agent modifie son propre code (AST + LLM) |

---

## ⚡ Fonctionnalités

### 🤖 Agent IA
- **Multi-providers** : DeepSeek, OpenAI, Groq, OpenRouter, Ollama
- **Tool calling** : L'agent exécute des commandes bash, crée des crons, interagit avec BookStack
- **Vision IA** : Analyse d'images (fallback agent secondaire)
- **Streaming** : Réponses en temps réel avec statut d'exécution

### 🧠 Mémoire
- **Sémantique** : Embeddings vectoriels (sentence-transformers) + recherche FTS5
- **Persistante** : Les souvenirs survivent aux sessions
- **Par utilisateur** : Chaque personne a sa propre mémoire
- **Auto-apprentissage** : Extraction automatique des faits durables

### 🌐 Flotte multi-serveur
- **SSH** : Contrôle complet de n'importe quel serveur Linux
- **Synology** : Métriques DSM via API (QuickConnect inclus)
- **Proxmox** : Métriques VE via REST API
- **Cassandra** : Communication entre agents
- **Ping** : Vérification TCP simple

### 🖥️ Administration système
- **Monitoring temps-réel** : WebSocket push toutes les secondes
- **Terminal Web** : PTY réel avec xterm.js, multi-onglets
- **Snapshots & Rollback** : Sauvegarde des fichiers avant chaque commande risquée
- **Alerting** : SMTP + Webhook (Slack/Discord/Ntfy)
- **Audit complet** : Journal des actions agent

### 🔐 Sécurité
- **Multi-utilisateurs** : Comptes avec pseudo + mot de passe
- **RBAC** : Contrôle granulaire des permissions
- **Rate limiting** : Protection anti-brute force
- **chattr** : Fichiers de clé protégés contre les modifications

### 🧬 Auto-évolution
- **AST + LLM** : L'agent analyse son propre code et s'améliore
- **Validation automatique** : Syntaxe, noms, selftest, banc d'essai
- **Watchdog** : Rollback automatique en cas de crash
- **Pause utilisateur** : Vous contrôlez quand il évolue

### 📦 Intégrations natives
- **FastPanel 2** : Lecture directe des users, domaines, bases, mails, stats
- **BookStack** : Encyclopédie d'entreprise (recherche, lecture, écriture)
- **Tailscale** : Statut des pairs en temps réel
- **Rclone** : Remotes, mounts, backups
- **Docker** : Conteneurs, stats
- **Systemd** : Services, unités failed
- **Fail2ban** : IPs bannies

### 🎨 Interface Web
- **Glassmorphism UI** : Design moderne et épuré
- **Dark/Light mode** : Thème automatique
- **Mobile responsive** : Fonctionne sur téléphone
- **Chart.js** : Historique des métriques (CPU, RAM, disque, swap)
- **xterm.js** : Terminal intégré

---

## 📊 Tableau de bord

| Métrique | Temps réel | Historique |
|----------|------------|------------|
| CPU | ✅ Jauge + barre | ✅ 1h / 24h / 7j |
| RAM | ✅ Jauge + barre | ✅ 1h / 24h / 7j |
| Disque | ✅ Jauge + barre | ✅ 1h / 24h / 7j |
| Swap | ✅ Jauge | ✅ 1h / 24h / 7j |
| Load Average | ✅ Affiché | - |
| Top processus | ✅ Liste | - |
| Services | ✅ Statut | - |
| SSL | ✅ Jours restants | - |
| Sessions | ✅ Actives | - |
| OOM | ✅ Événements | - |
| Failed units | ✅ Liste | - |
| Docker | ✅ Conteneurs | - |

---

## 🚀 Installation

### Prérequis
- Debian / Ubuntu (testé sur 22.04+)
- Python 3.10+
- 1 Go RAM (2 Go recommandé pour la mémoire sémantique)

### Une commande (recommandé)

```bash
curl -fsSL https://raw.githubusercontent.com/TON_PSEUDO/cassandra/main/install.sh | bash
```

**Ou manuellement :**

```bash
git clone https://github.com/TON_PSEUDO/cassandra.git
cd cassandra
sudo bash install.sh
```

### Ce que ça installe
- ✅ Cassandra Agent (port 9000)
- ✅ Cassandra Knowledge Collector (socket UNIX)
- ✅ Services systemd (redémarrage automatique)
- ✅ Environnement Python (venv + dépendances)
- ✅ Swap 5G (si absent)

### Premier démarrage

1. Ouvrez `http://VOTRE_IP:9000`
2. L'assistant d'installation vous guide :
   - Création du compte admin
   - Configuration du modèle IA (DeepSeek, Ollama, etc.)
   - Alertes SMTP (optionnel)
   - Seuils d'alerte (optionnel)

---

## 🛠️ Configuration

### Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `CASSANDRA_PORT` | 9000 | Port du serveur HTTP |
| `CASSANDRA_EVO_INTERVAL` | 60s | Intervalle d'auto-évolution |
| `CASSANDRA_DISABLE_EMBED` | 0 | Désactiver la mémoire sémantique |
| `CASSANDRA_EMBED_MODEL` | intfloat/multilingual-e5-large | Modèle d'embeddings |
| `CASSANDRA_EMBED_THREADS` | 2 | Threads pour les embeddings |

### Fichiers de configuration

| Fichier | Rôle |
|---------|------|
| `/etc/cassandra/deepseek.key` | Clé API du modèle principal |
| `/etc/cassandra/config.json` | Configuration générale (provider, model, bookstack, etc.) |
| `/etc/cassandra/auth.json` | Hash du mot de passe admin |
| `/etc/cassandra/users.json` | Comptes multi-utilisateurs |
| `/etc/cassandra/alerts.yml` | Alerting (SMTP, Webhook, seuils) |

---

## 🔧 Développement

### Structure du code

```
cassandra/
├── cassandra.py                    # Agent principal (4600+ lignes)
├── cassandra_knowledge_collector.py # Collecteur de données
├── install.sh                      # Script d'installation
├── README.md                       # Documentation
└── LICENSE                         # MIT
```

### Dépendances principales

```bash
# Installation manuelle des dépendances
pip install openai sentence-transformers numpy
```

---

## 📚 API

### Endpoints principaux

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/chat/stream` | POST | Chat en streaming (SSE) |
| `/api/metrics` | GET | Métriques système |
| `/api/metrics/history` | GET | Historique des métriques |
| `/api/dashboard` | GET | Résumé du tableau de bord |
| `/api/login` | POST | Authentification |
| `/api/evolution/apply` | POST | Appliquer une évolution |
| `/api/evolution/rollback` | POST | Annuler une évolution |
| `/api/exec` | POST | Exécuter une commande bash |
| `/api/upload` | POST | Uploader un fichier |

### WebSocket

| Endpoint | Description |
|----------|-------------|
| `/ws` | Métriques en temps réel (push 1s) |
| `/ws/terminal` | Terminal PTY (xterm.js) |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Navigateur                         │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────────┐  │
│  │   Chart.js  │  │  xterm.js   │  │   WebSocket UI   │  │
│  └─────────────┘  └─────────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Cassandra Agent (Python)                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │   HTTP   │ │WebSocket │ │   LLM    │ │   Mémoire    │  │
│  │  Server  │ │  Server  │ │  (API)   │ │ (Embeddings) │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │  Flotte  │ │   PTY    │ │ Auto-Evo │ │   Alerting   │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                Knowledge Collector (Python)                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │  CPU     │ │  RAM     │ │  Disque  │ │   Services   │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ FastPanel│ │ BookStack│ │ Tailscale│ │    Docker    │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🧪 Tests

Cassandra est **utilisé en production** sur des serveurs Hetzner VPS. Chaque évolution passe par un pipeline de validation :

1. ✅ Validation syntaxique (AST)
2. ✅ Validation des noms (undefined check)
3. ✅ Selftest (import du code dans un sous-processus)
4. ✅ Revue par agent secondaire (OpenRouter)
5. ✅ Banc d'essai (clone qui sert sur un port temporaire)
6. ✅ Watchdog (rollback auto si le code ne se stabilise pas)

---

## 🤝 Contribuer

Les contributions sont **très** bienvenues !

1. Forkez le projet
2. Créez une branche (`git checkout -b feature/amazing-feature`)
3. Commitez (`git commit -m 'Add amazing feature'`)
4. Poussez (`git push origin feature/amazing-feature`)
5. Ouvrez une Pull Request

---

## 📄 License

Distribué sous la licence MIT. Voir `LICENSE` pour plus d'informations.

---

## 🙏 Remerciements

- **DeepSeek** pour leur API performante
- **Ollama** pour l'IA locale
- **Sentence-Transformers** pour les embeddings
- **xterm.js** pour le terminal web
- **Chart.js** pour les graphiques

---

## 📧 Contact

- **GitHub** : [@Marplestrange](https://github.com/Marplestrange)
- **Issues** : [github.com/Marplestrange/cassandra/issues](https://github.com/Marplestrange/cassandra/issues)

---

## ⭐ Si vous aimez Cassandra...

...pensez à mettre une **étoile** sur GitHub ! Ça m'aide à continuer le développement. 🌟

---

## 🔥 Dernier mot

> Cassandra n'est pas un simple chatbot. C'est un agent autonome qui apprend, s'améliore, et gère votre infrastructure comme un administrateur système humain — mais sans dormir.

**Prêt à libérer la puissance de votre infrastructure ?** 🚀
