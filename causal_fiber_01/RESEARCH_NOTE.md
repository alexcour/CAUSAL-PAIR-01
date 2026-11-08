# Reconstruction causale : résultat vérifié et raccord expérimental

8 novembre 2026. Base examinée : `alexcour/CAUSAL-PAIR-01`, commit
`09b23d3b5bd5213680973480fef8ec823c27d5e0`, PR en brouillon no 1.

## Résultat mathématique exact

Pour une projection d'observation p : H → O et un verdict v : H → V, un
reconstructeur exact sur l'image de p existe si et seulement si v est constant
sur chaque fibre de p. Deux historiques de même observation et de verdicts
différents rendent cette reconstruction impossible. Ce critère classique
est maintenant compilé dans Lean 4.29.1 ; aucune nouveauté n'est revendiquée.

La reconstruction porte sur un verdict, pas nécessairement sur l'historique
entier. Elle est définie sur l'image : aucun verdict n'est exigé pour une
observation inaccessible. La réciproque emploie `Classical.choice`. Les autres
axiomes rapportés pour les nouveaux lemmes finis sont `propext` et `Quot.sound`,
axiomes standards de Lean. Aucun `sorryAx` n'apparaît dans l'audit des quinze
déclarations sélectionnées. Cela ne constitue pas une revue humaine indépendante.

## Deux instanciations distinctes

Le petit modèle timely/late/stale/missing produit deux collisions. L'énumération
des seize étiquetages binaires montre que quatre compléments binaires suffisent
à reconstruire son verdict. Le minimum est un bit dans ce modèle fini. Ce bit
est un oracle de politique ; sa calculabilité par un capteur ou vérificateur
réel n'est pas établie.

Le raccord SQLite concerne un autre verdict : exécuter l'opération absente ou
restituer le résultat d'une opération déjà engagée. `causal_pair_01/experiment.py`
produit deux historiques dont le journal des reçus est restauré à vide, tandis
que la base des effets conserve respectivement zéro ou un effet. La projection
du contrôleur est le dictionnaire `evidence` : opération, autorisation, état
quiescent, validité du schéma et reçus. Les traces internes et la base des effets
ne font pas partie de cette observation de base.

`bridge.py` compare les dictionnaires complets, contrôle les cas attendus,
relit les bases SQLite en lecture seule et vérifie leurs lignes et intégrité.
Le lien entre ce schéma Python et le type abstrait Lean reste un raccord fini
documenté et testé ; aucune simulation formelle du code SQLite n'est prouvée.

| Politique | Même observation entre historiques | Effets finaux : vide / engagé |
| --- | --- | --- |
| Réexécution aveugle | Oui | 1 / 2 |
| Vérification préalable du journal restauré | Oui | 1 / 2 |
| Refus conservateur standard | Oui | 0 / 1 |
| Règle minimale étiquetée FCI | Oui | 0 / 1 |
| Contrôle avec observation autoritative supplémentaire | Non | 1 / 1 |

Les deux règles conservatrices partagent la même implémentation. L'expérience
n'établit aucun avantage FCI. Le contrôle positif reçoit explicitement l'accès
supplémentaire à la base des effets ; il ne s'agit pas d'une comparaison à
ressources identiques.

## Sûreté et reconstruction sont deux exigences différentes

`UniformlyAllowed p allowed o` signifie que tous les historiques compatibles
avec o autorisent l'action. Tout permis satisfaisant cette condition est sûr
relativement au prédicat `allowed`. Réciproquement, toute politique sûre pour
chaque historique satisfait cette condition. Sur une observation inaccessible,
la condition est vide ; les applications doivent rester sur l'image ou rejeter
les entrées hors schéma.

Dans l'instanciation Recovery, le récepteur est non idempotent et l'espace des
actions est limité à exécuter, restituer et bloquer. Une action commune aux
deux historiques ne peut garantir à la fois l'absence de doublon et l'achèvement
de l'historique vide. Bloquer préserve la première propriété mais pas la seconde.
Ce résultat ne s'étend pas à un récepteur enrichi d'un contrat atomique
d'idempotence ou de réconciliation : ce contrat change le modèle de transition.

## Validation observée

- Compilation Lean 4.29.1 réussie, sans Mathlib.
- Audit transitif des axiomes de quinze déclarations, sans `sorryAx`.
- Contrôle négatif : une égalité entre verdicts contradictoires est rejetée.
- Deux modes Python : normal et `-O`, résultats concordants.
- Vingt cas SQLite réexécutés ; soixante fichiers SQLite contrôlés en lecture seule.
- Quatre mutations rejetées sous chaque mode Python : oubli de l'ordre causal,
  oubli de la fraîcheur, complément constant et accès caché au verdict.

La version initiale échoue à la compilation Lean sur deux points. Elle échoue
aussi en Python normal par priorité d'opérateurs ; `-O` supprime ses assertions.
Les anciennes mentions de réussite du script déposé ne sont donc pas confirmées
par cette reproduction. Les corrections et reçus permettent de distinguer la
version initiale de la version validée ici.

## Conditions encore nécessaires pour un justificatif vérifiable

Le passage vers FCI doit fixer une opération, une action et un instant de
décision, puis fournir les éléments suivants :

1. Un schéma des entrées effectivement disponibles au vérificateur, sans
   introduire de variable de l'expérimentateur dans ses observations.
2. Un justificatif lié à l'opération, au contenu, au destinataire et à l'époque
   d'autorité ; préciser la source de confiance et son authentification.
3. Un ordre causal vérifiable avant l'engagement, une règle de validité et les
   hypothèses temporelles requises. Un reçu obtenu après l'effet ne suffit pas
   à attester une autorisation antérieure.
4. Un contrat de survie ou de détection de restauration de ces informations,
   et une prise en compte des requêtes anciennes encore en vol.
5. Un raccord entre acceptation du justificatif et prédicat d'autorisation,
   puis entre décision et engagement effectif au récepteur.

La fraîcheur d'un justificatif ne prouve pas, à elle seule, l'absence d'un effet
antérieur. Une lecture négative exacte à un instant ne ferme pas non plus une
ancienne requête encore en vol : le modèle existant LATE-COMMIT-02 étudie cette
frontière séparément. Ce lot ne réexécute pas cette campagne HTTP.

Le prochain jalon est donc de choisir une interface de vérification concrète,
en épingler la version, écrire sa projection d'observation et tester les cas
absent, périmé, tardif, autre opération, ancienne époque et restauration. Tant
que ce raccord n'est pas établi, le résultat reste une preuve abstraite avec
une instanciation finie mesurée, sans validation FCI native ni physique.
