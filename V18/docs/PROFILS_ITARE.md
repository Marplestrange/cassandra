# Les deux panels — décision de l'usager, à construire

Décidé le 19 août 2026. **Rien de ceci n'est encore codé** : la session
précédente s'est arrêtée avant, plutôt que de laisser un renommage à moitié
appliqué sur un serveur en marche.

## Le renommage

| aujourd'hui | demain | rôle |
|---|---|---|
| `itare_provider` / `itare_model` / `itare_api_key` / `itare_base_url` | **`itare_citadelle_*`** | fait le lien entre `itare_user` et Cassandra |
| *(champs « vision » de Réglages, qui pointent aujourd'hui sur `itare_model`)* | **`itare_vision_*`** | à créer, propre au panel Desk |
| `user_prefs.modele` (par compte) | **`itare_user`** | l'Itare de chacun, dans le Desk |

**Le réglage « agent secondaire » disparaît.** Les champs « vision » de l'écran
Réglages sont aujourd'hui peuplés depuis `d.itare_model` — c'est la même
configuration sous deux noms, et c'est la source de la confusion. On les
sépare pour de bon.

## Qui parle à qui

- **`itare_citadelle`** est concerné par le **mode citadelle** de l'onglet
  conversation. C'est lui, et lui seul, qui parle avec Cassandra — et
  inversement.
- **`itare_user`** sert **les autres modes du Desk**.

## Les deux panels

**Panel Citadelle** — modèle de Cassandra + `itare_citadelle` + **ItareSafe**
(l'autovérification). Ils délibèrent entre eux.

**Panel Desk** — `itare_user` + `itare_vision`. Ils délibèrent entre eux.

| | admin | compte ordinaire |
|---|---|---|
| Panel Citadelle | visible | **jamais** |
| Panel Desk | visible | visible |

## Les valeurs par défaut

`itare_user` non configuré sur un compte → **le modèle local uniquement**, donc
`qwen2.5:3b` sur Amizo. Un compte sans réglage ne consomme donc rien chez un
fournisseur, et ne peut pas y envoyer ses notes sans l'avoir voulu.

## Ce qui est déjà en place et sur quoi ça s'appuie

- **Le mode citadelle se REFUSE**, il ne se dégrade plus. C'était nécessaire
  avant de lui donner les pleins droits : le serveur retirait seulement le
  sensorium, et servait quand même la directive de la Citadelle à un compte
  ordinaire qui la demandait. Désormais 403 explicite, gardé par
  `check_lab_modes.py` (rejeu 2/2).
- **Le « consultatif » n'a plus lieu d'être** : puisque le mode citadelle est
  réservé aux admins *et refusé aux autres*, `itare_citadelle` peut parler à
  Cassandra avec les pleins droits. La porte `cassandra_conseil` — sans outils,
  périmètre à l'aller et au retour — devient donc une étape intermédiaire à
  reconsidérer, pas une contrainte à conserver.

> **Ce que cela déplace, et qu'il faut regarder en face.** Donner les pleins
> droits rend **ItareSafe plus porteur, pas moins** : c'est lui qui reste entre
> une consigne cachée dans un texte importé et une commande exécutée. Le débat
> à trois sur sa révision devient donc plus urgent, pas moins.

## L'ordre de construction

1. Créer `itare_vision_*` et déplacer les champs de l'écran Réglages.
2. Renommer `itare_*` → `itare_citadelle_*`, **avec lecture de l'ancien nom en
   repli** : une machine déjà configurée ne doit pas se retrouver muette au
   redémarrage.
3. Refaire `itare_panel` en deux compositions fixes, et son contrôle de
   visibilité côté **serveur** — pas seulement à l'écran, la leçon vient d'être
   apprise.
4. Le défaut local pour `itare_user`.
5. Bancs et rejeu à chaque étape, la relecture du journal des agents avant chaque déploiement.
