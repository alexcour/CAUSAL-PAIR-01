# Activation et permis C — réception du12 novembre2026

**Quatre C activés, huit permis natifs signés et quatre refus historiques reçus sur huit nouvelles captures natives.** Les contrôles d’autorisation sont secs : aucun execute métier/natif C, constructeur normal de service natif ou réarmement n’est appelé. La consommation du permis au COMMIT C reste à qualifier séparément.

- [PR publique3](https://github.com/alexcour/CAUSAL-PAIR-01/pull/3).
- [CI43121546137 réussie](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43121546137), job130863002240, source exécutée `5fcd1e0b405603ceea94a3d535372cf248f996c6`.
- [Artefact13900343217](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43121546137/artifacts/13900343217),318758 octets,62 fichiers ; SHA256 `6e7ecf7ec5d9e10c5e6c10b5f0e3dd859f2da07464db2757c4b134f815d85183`. Octets téléchargés, taille, CRC et chemins vérifiés.
- Manifeste source75 fichiers : `3b0b94a20210e268911822ba744f709a9a63ca65a755f0a477280c44ddc8780b` ; identique au staging local avant exécution.
- Index des captures : `2ebcdd59e98e738f0e8e3885b7fb04e7045a5c678e63e92c5c970d6c4e920161`. Cet index lie les sources et noms de rapports, pas les octets complets de chaque rapport ; l’empreinte ZIP identifie l’artefact complet.
- Relecture locale normale/optimisée identique octet pour octet aux deux sorties CI archivées. Le lancement natif a lieu en CI Linux ; aucune exécution native locale Windows revendiquée.

## Nouveau contrat reçu

Après attente de la fin du propriétaire d’admission, root signe un grant distinct liant le reçu d’admission C, la portée B/C, la vue SQL complète, les identités et empreintes de fichiers d’autorité, la politique/époque du pont, le boot, le hash de politique d’activation et une fenêtre monotone de120 secondes. Grant et pin sont root-owned hors runtime, jamais fournis par RPC. Root/OS/propriétaire et absence de clones restent des hypothèses.

Sous BEGIN IMMEDIATE, le contrôleur change seulement C ADMISSION_ONLY→OPEN et ajoute certificat/événement durables. Les réservations B natives restent conservées. Quatre résultats B déjà engagés, sans C admis, refusent ADMITTED_C_REQUIRED et ne changent aucun état.

La route issue utilise la méthode gelée du pont : autorisation native signée par l’issuer et permis de pont signé par le sink. Un permis versionné supplémentaire lie cette requête au certificat d’activation, au grant, au challenge, au TTL, à la politique/époque et au boot. Deux TTL sont exercés par cellule positive :25 et2 secondes. Même challenge/mêmes paramètres retrouvent le même permis ; paramètres changés refusés, challenge expiré non renouvelé.

La route authorize_C exige le vrai UID62026 et revérifie la vue projetée, la durabilité du permis, les signatures, la liaison à la requête et le temps sous verrou SQL, puis appelle le check gelé du pont. Elle retourne C_PERMIT_VALID_AT_GATE sans invoquer l’exécution. La révocation contrôleur passe C OPEN→FENCED, inscrit REVOKED et avance l’époque du pont dans une seule transaction. L’ancien permis, l’émission et la réactivation sont ensuite refusés dans cette version.

## Contrôles reçus

| Contrôle | Observation |
|---|---|
| FCI/Standard × avant COMMIT × normal/-O |4 activations,2 permis signés par cellule,0 effet C |
| Après COMMIT B déjà engagé |4 refus historiques, aucune activation |
| Abandon avant COMMIT d’activation |4 rollbacks réels, vue complète inchangée |
| UID noyau contrôleur/C/autres |48 refus de rôles |
| Grant absent, autorité absente, portée/vue/temps/politique dégradés |24 refus sans écriture |
| Signatures/requête altérées, permis nu, paramètres de challenge changés |16 refus |
| Permis court |4 validations initiales puis expiration monotone réelle ;4 refus d’autorisation et4 refus de renouvellement |
| Redémarrage du composant d’activation |4 restitutions des mêmes certificats/permis ;4 contrôles secs valides, aucune nouvelle émission |
| Révocation |4 clôtures atomiques, répétition idempotente ;12 refus d’autorisation/émission/réactivation |
| Contrôles secs valides |12, sans execute/rearm |
| Lecteur distinct, normal/-O |64 altérations réelles rejetées par mode ; sorties CI/local identiques |

La projection finale retire uniquement les tables additives, restaure l’état C et l’incrément d’époque déclaré, puis exige l’égalité de toutes les autres tables/bases à la préimage signée. Les bases indépendantes gardent leurs empreintes ; les identités de tous les fichiers d’autorité sont conservées. Les contrôles/refus, répétitions et redémarrage n’ajoutent aucun permis. Les lecteurs hérités reçoivent toujours leurs instantanés antérieurs distincts ; leurs anciens champs sans permis C ne désignent pas l’état final.

## Limites nécessaires

Le permis versionné autorise la route contrôlée au point de vérification reçu. Il n’est pas encore consommé atomiquement avec un effet C. Le check du pont ne remplace pas l’admission et les vérifications du moteur natif au COMMIT. L’UID C est ajouté explicitement à la vue des requesters du pont pour ce check ; l’installation du rôle C dans un service natif normal n’est pas qualifiée.

Le générateur gelé conserve sa fenêtre propre d’autorisation native de30 secondes, distincte des TTL2/25 du permis de pont et de son enveloppe versionnée. Les refus d’expiration/révocation sont reçus aux routes versionnées testées ; aucune garantie sur la soumission directe arbitraire de l’autorisation native seule n’en est déduite. La médiation de toutes les routes et la revalidation au vrai COMMIT C restent ouvertes.

Des vues explicites des décodeurs/méthodes gelés sont liées aux connexions du propriétaire ; aucun constructeur normal de service natif, STARTUP ou réarmement dans la phase nouvelle. Le redémarrage reçu est celui du composant d’activation. Les données natives B ne sont pas renommées CANCELLED. Pas d’audit MAC indépendant, de protection contre propriétaire hostile, de NoBypass global, de co-restauration sûre, de borne temporelle industrielle, de benchmark ou de supériorité générale.

**Prochaine porte : service natif normal avec rôle C et consommation du permis dans le vrai chemin d’effet, puis coupures avant/après COMMIT et perte de réponse. NOT_RUN. M1 HOLD / SR02 BLOCKED.** La réception et sa publication ne modifient pas ces limites.
