# Historique de l'évolution de Cassandra

Les versions successives, de la V3.2 à la V18, chacune dans son dossier (`V3.2`, `V4` … `V13.1`, `V14`, puis `V18` pour la version actuelle) : on y lit comment
Cassandra est passée d'un petit agent (`agent.py` et une page PHP) à un tableau de bord complet puis à un produit installable.

- Les dossiers `V3.2` à `V14` sont des archives de travail : certains gardent des copies de sauvegarde (`.bak`, `.old`) laissées par les mises à jour.
- Par prudence, tous les mots de passe, jetons et clés d'API qui figuraient dans ces fichiers ont été remplacés par `RETIRE`, et les fichiers de configuration
  de poste (`.env`, `rclone.conf`, caches) n'ont pas été repris : ces versions ne sont donc pas exécutables telles quelles.
- La V14 est celle du dossier de travail (la plus complète) ; la V14 publiée avant elle reste lisible dans l'historique git.
