# CASSANDRA — Suggestions d'évolution majeures

> Rédigé après analyse complète de `cassandra.py` et `cassandra_knowledge_collector_opt.py` v6.1.
> Classement par impact métier décroissant.

---

## 1. Alerting actif en temps réel (priorité critique)

**Problème actuel.** CASSANDRA collecte et stocke — mais ne réagit pas. Si un site tombe, un disque sature, ou un certificat SSL expire dans 3 jours, l'information dort dans SQLite jusqu'à ce que quelqu'un ouvre le dashboard.

**Évolution proposée.** Ajouter un moteur de règles d'alerte (fichier YAML configurable) avec des seuils sur chaque métrique collectée. Quand une règle se déclenche, CASSANDRA envoie une notification via les canaux configurés : e-mail (SMTP natif Python), webhook générique (Slack, Discord, Ntfy, Gotify), et optionnellement SMS via API Twilio.

```yaml
# cassandra_alerts.yml (exemple)
rules:
  - name: disk_critical
    metric: disk_usage_pct
    condition: "> 90"
    severity: critical
    channels: [email, slack]
    cooldown_minutes: 60

  - name: ssl_expiring
    metric: ssl_days_left
    condition: "< 14"
    severity: warning
    channels: [email]
    cooldown_minutes: 1440
```

**Gain.** Transformation de l'outil de monitoring passif en outil d'observabilité actif. C'est la feature la plus demandée sur tout outil de supervision.

---

## 2. Historisation longue durée + rétention configurable

**Problème actuel.** La base SQLite ne fait pas de rotation. Elle grossit indéfiniment ou les données les plus vieilles ne sont jamais purgées proprement. Pour les métriques temps-réel (CPU, RAM, I/O), il n'y a aucune agrégation : on garde soit tout, soit rien.

**Évolution proposée.** Implémenter un pipeline de rétention à 3 niveaux inspiré de RRDtool :

- **Chaud** (0–7 jours) : données brutes, résolution de 30 secondes
- **Tiède** (7–90 jours) : agrégats par heure (moyenne, min, max, p95)
- **Froid** (90 jours–2 ans) : agrégats journaliers

Une tâche VACUUM tourne chaque nuit pour comprimer les données tièdes/froides via `INSERT INTO ... SELECT AVG(...) GROUP BY`. La configuration de rétention est exposée dans `cassandra.conf`.

**Gain.** Tendances long terme exploitables (croissance disque projetée, saisonnalité charge CPU) sans explosion de la taille de la base. Économie de 80–95 % d'espace disque à 90 jours.

---

## 3. Multi-serveur : architecture hub-and-spoke

**Problème actuel.** CASSANDRA est mono-serveur : le collecteur et le dashboard tournent sur la même machine. Pour superviser une flotte (10, 50, 200 serveurs), il faut ouvrir autant de dashboards.

**Évolution proposée.** Scinder en deux rôles :

- **Agent** (existant, allégé) : tourne sur chaque serveur supervisé, collecte et expose ses données via une API REST minimaliste sécurisée par token (ou mTLS). N'a plus besoin de dashboard.
- **Hub** (nouveau) : agrège les données de N agents, stocke dans une base centrale (SQLite pour <20 serveurs, PostgreSQL au-delà), présente un dashboard unifié avec vue globale et drill-down par serveur.

La communication Agent→Hub peut être push (l'agent POST ses données toutes les 30s) ou pull (le hub interroge chaque agent). Le push est préférable car les agents peuvent être derrière un NAT.

**Gain.** Passage de l'outil solo à une plateforme de supervision fleet. Déblocage du cas d'usage hébergeur/sysadmin gérant plusieurs machines.

---

## 4. Inventaire de configuration et détection de drift

**Problème actuel.** CASSANDRA collecte l'état courant mais n'a pas de notion de "configuration de référence". Il est impossible de savoir si un fichier de config a changé, si une règle firewall a été ajoutée, ou si une version de PHP a été mise à jour de façon non planifiée.

**Évolution proposée.** Ajouter un module **Configuration Snapshot** qui :

1. Prend un snapshot cryptographique (SHA-256) de fichiers de config critiques à intervalles configurables : `/etc/nginx/`, `/etc/ssh/sshd_config`, `/etc/fail2ban/`, crontabs, etc.
2. Compare chaque snapshot au précédent et logue toute différence dans `changelog` avec le diff exact.
3. Permet de définir une "baseline" (état approuvé) et d'alerter sur tout écart.

```python
# Exemple de résultat dans le changelog
{
    "entity_type": "config_file",
    "entity_name": "/etc/ssh/sshd_config",
    "change_type": "modified",
    "diff": "-PermitRootLogin yes\n+PermitRootLogin no",
    "severity": "info"
}
```

**Gain.** Audit de conformité automatique, détection d'intrusion par modification de config, traçabilité complète des changements système.

---

## 5. Dashboard temps-réel via WebSocket

**Problème actuel.** Le dashboard actuel est basé sur du polling HTTP (le navigateur refraîchit toutes les N secondes). Cela génère des requêtes inutiles, introduit une latence perceptible, et ne scale pas bien si plusieurs onglets sont ouverts.

**Évolution proposée.** Remplacer le polling par un serveur WebSocket intégré (bibliothèque `websockets` en Python pur, ~500 lignes). Le serveur CASSANDRA push les nouvelles métriques à tous les clients connectés dès qu'elles sont collectées. Le frontend JavaScript passe d'un `setInterval(fetch...)` à un `new WebSocket(...)`.

Bonus : ajouter des **graphiques de tendance** avec Chart.js (déjà en CDN) pour CPU, RAM, I/O disque et trafic réseau sur les dernières 24h.

**Gain.** Dashboard réellement live, latence sub-seconde, suppression du polling (~60 requêtes/minute → 0). UX perçue comme nettement supérieure.

---

## 6. API REST publique documentée + tokens d'accès

**Problème actuel.** CASSANDRA expose ses données uniquement via le socket Unix local et le dashboard HTML. Il est impossible d'intégrer CASSANDRA dans un outil tiers (Grafana, scripts de déploiement, CI/CD) sans accès SSH à la machine.

**Évolution proposée.** Exposer une API REST JSON complète sur le port 9000 (déjà ouvert) avec :

- Authentification par Bearer token (généré et stocké dans SQLite au premier démarrage)
- Endpoints lisibles : `GET /api/v1/metrics`, `GET /api/v1/sites`, `GET /api/v1/ssl`, `GET /api/v1/changelog`
- Endpoint de déclenchement : `POST /api/v1/collect` (force une collecte immédiate)
- Documentation auto-générée (fichier OpenAPI JSON statique)

```bash
# Exemple d'usage externe
curl -H "Authorization: Bearer <token>" https://mon-serveur:9000/api/v1/metrics | jq .
```

**Gain.** Intégration native avec Grafana (datasource JSON), scripts d'automatisation, webhooks de déploiement, et tout écosystème DevOps existant.

---

## Résumé priorisation

| # | Évolution | Effort | Impact |
|---|-----------|--------|--------|
| 1 | Alerting actif (email/webhook) | Moyen (3–5j) | Critique |
| 2 | Historisation + rétention | Faible (1–2j) | Élevé |
| 3 | Multi-serveur hub-and-spoke | Élevé (2–4 sem) | Élevé |
| 4 | Détection de drift config | Moyen (2–4j) | Moyen-Élevé |
| 5 | WebSocket + graphiques | Moyen (3–5j) | Moyen |
| 6 | API REST + tokens | Faible (1–2j) | Moyen |

**Ordre recommandé si tu travailles seul :** 2 → 1 → 6 → 5 → 4 → 3.
Commencer par la rétention (2) et l'API (6) pose des fondations solides pour tout le reste.
