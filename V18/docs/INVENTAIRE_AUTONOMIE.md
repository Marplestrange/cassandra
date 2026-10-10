# Inventaire de l'autonomie — ce que les agents font, peuvent faire, ne peuvent pas faire

Établi le 2026-10-10 par lecture de `cassandra.py` (150 000 lignes) déléguée au Claude d'Orion, lecture seule.
**Réserve** : les numéros de ligne « ~71300 » sont des approximations du délégué ; l'action nommée est fiable, la ligne est à retrouver par `grep -n` avant toute modification. Les marques « réversible » sont à confirmer fonction par fonction au moment de coder.

## Trois couches, trois niveaux de pouvoir

1. **Cassandra (patron)** : catalogue de la cage + gestes de sécurité. Agit sur la machine.
2. **Itare (sous-chef)** : outils « perso », confinés à l'espace d'un compte (courrier, projets, agenda, GED). Sa vigie autonome **ne déclenche rien** (« une vigie ne déclenche rien »).
3. **Humain seul** : tout ce qui est derrière `_sys_garde` (mot de passe maître), `confirm=True`, ou absent des catalogues d'agents.

## A. Ce que Cassandra sait déjà faire (catalogue + gestes de sécurité)

| Domaine | Action | Réversible | Garde actuelle |
|---|---|---|---|
| Système | Correctifs de sécurité (`maj_securite`), mises à jour auto (`maj_auto`) | non / en partie | aucune |
| Système | Verrouiller SSH (`ssh_mdp`, `ssh_x11`) | en partie | présence d'une clé SSH |
| Système | Arrêter rpcbind, avahi, cups | en partie | liste d'unités stricte |
| Système | Redémarrer / arrêter un service | oui | statut vérifié après coup ; services intouchables listés |
| Système | Installer / retirer UN paquet | en partie | un seul paquet nommé |
| Système | Redémarrer la machine | non | à la suite d'une maj noyau |
| Système | Vider des caches (pip…) | non | caches inoffensifs |
| Système | MySQL local (`mysql_local`) | en partie | présence du dossier / my.cnf |
| Réseau | Bannir / débannir adresse ou pays | oui | exclut maison, tailnet, public, confiance |
| Réseau | Liste blanche d'adresse | oui | aucune |
| Réseau | Fermer / rouvrir un chemin nginx | oui | refus sur `/` ou si visites humaines actives |
| Réseau | Bloquer / freiner / libérer un robot | oui | fichier d'ajouts du site requis |
| Réseau | Pare-feu : ouvrir / fermer (à l'essai, retour auto) | oui | API FastPanel |
| Réseau | Couper / rétablir une interface | oui | interfaces réservées |
| Conteneurs | Mettre à jour une image | en partie | retour auto si « unhealthy » |
| Conteneurs | Docker Compose | en partie | dossiers connus |
| Base | Tuer une connexion MySQL | non | SHOW PROCESSLIST / KILL seulement |
| Flotte | Transfert SFTP | non | dépôt `/opt/cassandra/travail` seulement |
| Config | Poser une configuration | en partie | pré-approuvée, ou tour sans lecture web |
| Agent | Fermer une session SSH | non | identifiant valide |
| Agent | Lancer un scan (ClamAV, Lynis, Trivy…) | non | outils en liste blanche |
| Agent | Étendre son propre catalogue | oui | « tour propre » sans lecture extérieure |

Seule action **automatique** dans Proactivité aujourd'hui : `service.restart` (`_SAFE_ACTION_KINDS`).

## B. Ce qu'Itare fait (confiné à l'espace d'un compte)

Journal et salon des agents ; dialogue avec la Citadelle (`cassandra_conseil`, `citadelle_demander`) ; notes (corbeille) ; projets (suppression définitive) ; agenda, tâches, rappels (suppression définitive) ; carnet d'adresses ; courrier : lecture, rangement, brouillons (corbeille), **envoi** sous **mandat** et seulement si la session n'est pas « teintée » par une lecture extérieure ; fichiers distants `desk` (mot de passe via coffre + mandat) ; GED (corbeille) ; pièces jointes ; navigateur Chromium distant en cage (adresses internes refusées) ; mémoire (`remember`) ; notifications.

Itare **ne peut pas** : exécuter bash ou le catalogue ; agir en root (il demande à Cassandra) ; apprendre seul pendant ses rondes (coupé : « 34 refus et 4 leçons creuses en sept jours ») ; atteindre l'intranet.
Ses trois phases tournent seules (initiative 6 h, proactive 24 h, projets 24 h) mais ne produisent que des notes et des suggestions.

## C. Ce qui tourne seul aujourd'hui

Nettoyage des journaux de session (non réglable) · renouvellement SSL (`fp_ssl_autorenew_pass`, une fois par jour) · sauvegarde de la mémoire (1×/jour, non réglable) · passe courrier (300 s) · rappels · proactif (`proactive_enabled`) · Sensorium de la flotte (15 min) · **évolution autonome du code (05:00)** · Itare autonome (3 clés `itare_*_enabled`).

## D. Ce que l'humain seul fait aujourd'hui — candidats à l'autonomie

| Famille | Gestes |
|---|---|
| Comptes et droits | créer / modifier un compte (`set_user`), envoyer un lien de réinitialisation, passkeys |
| FastPanel et sites | créer une base (`fp_db_creer`), plans et stockages de sauvegarde (`fp_backup_plan_creer`), certificats, supprimer une base (`fp_db_supprimer`, `confirm=True`), `fp_action_run` avec `modifie=True` |
| Coffre | versionner, écrire, corbeille, transférer |
| Communication | créer un fil de salon et inviter, envoi Telegram sortant, sourdines |
| Notes et partages | créer une note, **jeton de partage public**, designs Canva |
| Machine | tout ce que `_sys_garde` protège : purges, remise à zéro (`EFFACER`) |

## E. Les verrous de fond (à ne pas lever sans décision explicite)

- **Contexte « teinté »** : un agent qui vient de lire du contenu extérieur ne peut ni envoyer ni agir sous mandat sans accord humain. C'est la défense contre l'injection.
- **Mandats d'envoi** : l'adresse ne vient jamais de la demande.
- **Cage et veto** : toute commande, non désactivable.
- **`_sys_garde`** : mot de passe maître, mot-clé saisi.

## F. Ce que l'inventaire montre

1. **Le pouvoir est très inégal.** Cassandra sait faire une vingtaine de gestes, mais Proactivité n'en déclenche qu'un seul seule.
2. **Beaucoup de gestes existent déjà et ne sont pas câblés à l'autonomie** : bannir, freiner, pare-feu à l'essai, mises à jour d'image avec retour, renouvellement SSL, scans.
3. **Les gestes d'administration de l'hébergement (bases, sauvegardes, certificats, comptes) sont humains seuls**, alors que c'est le cœur de ce qu'un souverain d'application fait.
4. **Itare est volontairement muet côté système.** Lui donner de l'autonomie système passe par Cassandra (la Citadelle), pas par ses propres outils.
