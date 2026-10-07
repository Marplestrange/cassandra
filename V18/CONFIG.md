# La configuration de Cassandra

Trois niveaux, du plus faible au plus fort :

1. **les défauts du code** : chaque réglage lu par le code a un défaut sûr quand il manque ;
2. **le fichier `/etc/cassandra/config.json`** (réglages) et **la base** (réglages d'écran et état) ;
3. **les variables d'environnement**, qui ont toujours le dernier mot.

Les secrets ne vivent jamais dans `config.json` : la clé du modèle est dans `api.key`, les
identifiants tiers dans le coffre. Un exemple de fichier, sans aucun secret, est fourni :
[config.example.json](config.example.json). Le fichier peut être absent : Cassandra démarre
avec ses défauts et l'assistant de première configuration.

## Les racines de l'installation (variables d'environnement, posées par install.sh dans le service)

| Variable | Défaut | Rôle |
|---|---|---|
| `CASSANDRA_APP_DIR` | `/opt/cassandra` | le code, l'environnement Python, la voix, les échanges |
| `CASSANDRA_CONF_DIR` | `/etc/cassandra` | `config.json`, `api.key`, `auth.json`, `users.json`, `alerts.yml` |
| `CASSANDRA_DATA_DIR` | `/var/lib/cassandra` | les bases, les sauvegardes, les documents, les tâches planifiées |
| `CASSANDRA_LOG_DIR` | `/var/log` | `cassandra.log`, `cassandra-collector.log`, `cassandra_admin.log` |
| `CASSANDRA_BIND`, `CASSANDRA_PORT` | `127.0.0.1`, `9000` | l'adresse d'écoute (derrière un reverse proxy) |
| `CASSANDRA_DB_PATH`, `CASSANDRA_MEMORY_DB_PATH` | dérivés de `DATA_DIR` | les deux bases SQLite |
| `CASSANDRA_KEY_FILE` | `CONF_DIR/api.key` | le fichier de la clé du modèle (`deepseek.key` reste lu s'il existe) |
| `CASSANDRA_CONFIG_FILE` | `CONF_DIR/config.json` | le fichier de réglages |
| `CASSANDRA_EMBED_MODEL` | `intfloat/multilingual-e5-large` | le modèle de recherche sémantique, si elle est activée |

Variables d'install.sh (une installation sans écran) : `WITH_OLLAMA`, `WITH_TAILSCALE`,
`WITH_VAULT`, `WITH_SEARXNG` (`1` ou `0`), `ENABLE_SEMANTIC` (`1` ou `0`), `BIND_HOST`, `PORT`,
`SWAP_SIZE`, `MEM_MAX`, `MEM_HIGH`, `CASSANDRA_VAULT_DIR`.

## Le modèle d'IA

| Clé | Défaut | Rôle |
|---|---|---|
| `provider` | `deepseek` | un des fournisseurs de la table : `deepseek`, `openrouter`, `openai`, `google`, `groq`, `ollama`, `personnalise` |
| `model` | le défaut du fournisseur | le nom du modèle |
| `base_url` | le défaut du fournisseur | l'adresse de l'API (obligatoire pour `personnalise` : tout serveur compatible OpenAI) |
| `itare_citadelle_provider`, `itare_citadelle_model`, `itare_citadelle_base_url` | hérite du principal | le modèle d'Itare Citadelle, l'agent second qui parle à Cassandra |
| `itare_provider`, `itare_model`, `itare_base_url` | hérite du principal | le modèle de l'Itare des comptes (le bureau) |
| `evo_model`, `lab_model`, `image_model`, `image_base_url`, `image_size` | vides | modèles de l'auto-évolution, du laboratoire local, de la génération d'images |
| `hybrid_enabled`, `hybrid_min_conf` | `true`, `0.65` | le repli local puis distant selon la confiance |

Les modèles qui raisonnent (DeepSeek, Gemini) comptent leur réflexion dans le budget de jetons :
Cassandra part à 12 000 jetons par tour et rejoue une fois à 20 000 si la réponse revient vide.

## Les modules (produits tiers, tous facultatifs)

Chaque module se détecte au démarrage et s'absente proprement : pas d'onglet, pas d'outil
d'agent, pas de tâche s'il manque. L'état de chacun se lit dans Réglages › Modules et par
`GET /api/modules` (administrateurs).

| Module | Détection | Réglages |
|---|---|---|
| panneau d'hébergement | marqueurs de FastPanel, Plesk, cPanel, HestiaCP, DirectAdmin, Webmin ; sinon dos nu | `panneau` (forçage : `fastpanel`, `nu`…), `fastpanel_url` |
| Tailscale (la Flotte) | binaire `tailscale` | aucun ; `tailscale up` à la main |
| coffre de secrets | Vaultwarden joignable | `vault_public_url` (un Bitwarden ou Vaultwarden existant) |
| SearxNG (recherche web) | `searxng_url` renseignée | `searxng_url` |
| Ollama (modèles locaux) | port local 11434 | aucun |
| Telegram | au moins un compte relié | par compte, depuis l'écran |
| Canva | identifiants OAuth au coffre | par compte, depuis l'écran |
| Plex | `plex_url` renseignée | `plex_url`, jeton au coffre |
| courrier (IMAP, CalDAV) | `imap_host`, `caldav_url` | `imap_host`, `imap_port`, `imap_ssl`, `imap_user`, `caldav_url`, `caldav_user` ; mots de passe au coffre |
| voix (dictée, lecture) | modèles présents dans `APP_DIR/voix` | installés par install.sh |
| Docker, nginx, MySQL | binaires | aucun |

## Le comportement

| Famille | Clés | Défaut |
|---|---|---|
| Mémoire | `embeddings_enabled` (ancien nom `memory_semantic_enabled`, encore lu), `memory_embed_model`, `memory_embed_prechargement`, `memory_decay_halflife_days`, `memory_archive_min_strength`, `memory_promote_min_strength`, `memory_dedup_threshold`, `memory_extract_min_len`, `memoire_traces` | `true`, e5-large, `true`, `30`, `0.15`, `1.2`, `0.92`, `60`, `true` |
| Veille proactive | `proactive_enabled`, `proactive_auto_remediate`, `proactive_maint_only`, `proactive_maint_start`, `proactive_maint_end`, `proactive_watch_*` (backups, db, disk, security, service, sites, ssl, updates), `metric_watch_enabled` | `true`, `true`, `true`, `2`, `6`, `true`, `true` |
| Garde-fous de la proactivité | `pf_budget_jour`, `pf_budget_sujet`, `pf_palier`, `pf_instantane`, `pf_reversible`, `pf_retrograde`, `pf_pause`, `pf_pause_debut`, `pf_pause_fin` | `25`, `4`, `raconter`, `true`, `true`, `true`, `false`, `09:00`, `18:00` |
| Itare | `itare_*_enabled` (autofilter, autonome, bash, consolidate, initiative, panel, proactive, review, speculative, triage), `itare_speculative_min_conf`, `itare_panel_models`, `chatlab_persona` | `true`, `0.6`, vides |
| Auto-évolution | `evolution_paused`, `autonomie_gelee` | `true`, `false` |
| Salon des agents | `salon_budget` | `40` (réponses d'agents payants entre deux mots humains) |
| Courrier | `mail_weekly_recap`, `mail_recap_day`, `mail_recap_hour` | `true`, `0`, `8` |
| Réseau et clôture | `app_public_url`, `hotes_maison` (les hôtes de l'instance vers lesquels une sortie est permise), `msg_html_desechappe` | vides, `[]`, `true` |

## L'état (écrit par Cassandra, jamais à la main)

`last_sleep_ts`, `proactive_last_ts`, `mail_recap_last_ts`, `weekly_review_last`,
`escalate_backlog_cleared`, `ws_proxy_installed`, `fleet_etats`, `solo_*`,
`chat_ecrit_ancienne_table` : ces clés sont de l'état d'exécution ; elles vivent encore dans
`config.json` pour les installations en place et migrent vers la base. Ne pas les recopier
dans un fichier d'exemple ni les fixer à la main.

## Les fichiers de configuration

| Fichier | Nature |
|---|---|
| `api.key` | secret : la clé du modèle, `chmod 600` |
| `auth.json`, `users.json` | configuration : les comptes et leurs droits |
| `alerts.yml` | configuration : SMTP et seuils d'alerte |
| `vault.env`, `mysql_lecture.cnf`, `mysql_kill.cnf` | secrets posés par install.sh, masqués à la cage d'exécution ; jamais dans un dépôt |
