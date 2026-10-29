# Sécurité

Cassandra administre des serveurs : une faille y a des conséquences réelles. Merci de la signaler avec soin.

## Signaler une vulnérabilité

Écrivez à **marplestrange@cassandra.center**, avec pour objet « Sécurité — Cassandra ». **Ne publiez pas la faille** (ticket public, forum, réseau social)
avant qu'elle soit corrigée : une divulgation coordonnée protège les installations existantes.

Pour qu'on puisse la reproduire, indiquez :

- la version (`V18` en production, `V19` en développement) et la manière dont Cassandra est installée (reverse proxy, tunnel SSH, port exposé) ;
- ce que vous avez observé et ce que vous attendiez ;
- les étapes pour la reproduire, et l'impact que vous lui voyez ;
- vous nommer ou non dans la correction (nous le faisons volontiers, si vous le souhaitez).

Le projet est porté par une association, sans équipe de sécurité dédiée : nous accusons réception, évaluons, corrigeons, puis publions ce qui doit l'être.

## Ce qui est couvert

Les versions **V18** (production) et **V19** (développement). Les dossiers `V3.2` à `V14` sont des archives : ils ne reçoivent pas de correctif.

## Comment Cassandra se protège

Ce que vous pouvez attendre du produit, et donc ce qui compterait comme une faille s'il était contourné :

- **Les gestes passent par une cage** : un catalogue explicite, avec ses gardes et, quand c'est possible, un retour arrière. Un geste dangereux ou irréversible reste à
  l'humain (mot de passe maître, confirmation explicite, ou absent des catalogues des agents). L'inventaire est dans `V18/docs/INVENTAIRE_AUTONOMIE.md`.
- **Une donnée n'est jamais une consigne** : ce qu'un agent lit sur le web ou dans un courriel ne lui donne aucun ordre ; après une lecture venue de l'extérieur, il ne peut
  ni envoyer ni agir sous mandat sans accord humain.
- **Les envois sont encadrés** : l'adresse d'un envoi ne vient jamais de la demande.
- **Les comptes sont cloisonnés** : chacun ne voit que ses propres données, y compris face à l'administrateur.
- **Les secrets restent dans le coffre**, jamais dans la mémoire ni dans le code.

## Si vous installez Cassandra

- Elle écoute sur `127.0.0.1:9000` par défaut. Pour y accéder à distance, utilisez un reverse proxy avec TLS ou un tunnel SSH ; n'exposez pas le port en direct sans TLS.
- Gardez le système à jour, activez le second facteur (clé de sécurité) pour les comptes administrateurs, et sauvegardez la base de Cassandra et celle du coffre.
- Ne publiez jamais votre fichier de configuration (clés d'API, mots de passe) : il est ignoré par git, ne le forcez pas.
