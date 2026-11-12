# Exécution native C — réception de la composition2, 12 novembre 2026

**56 contrôles de base sur56 reçus ; les six échecs du lot précédent ne se reproduisent plus.** Les21 tests de contrat passent dans chaque mode Python et298 altérations réelles des preuves sont rejetées par mode. Qualification bornée aux fixtures et au contrat décrit ici. M1 HOLD / SR02 BLOCKED restent inchangés.

- [PR6](https://github.com/alexcour/CAUSAL-PAIR-01/pull/6) ; [CI native43292958500 réussie](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43292958500), job131443692557.
- Source exécutée `ca05c516877379d588e6af6bcc271d28ec68195e`. Les ajouts de reçu/documentation ultérieurs ne changent pas le code testé.
- CI synthétique43292958485 également réussie ; elle ne remplace pas la campagne native.
- Artefact13979046352 :3743671 octets,433 fichiers ; SHA256 `3ffa2f423c5a929ff5daa4b8a2f42dae5d54444e86ad8d2e74e233a1a18862de`. Téléchargement, taille, CRC et confinement vérifiés.
- Manifeste80 sources : `3b7e067deb2849af9c2fc73cacd91b60166ea84153b006f892f371680501d1d4`. Les37 sources natives gelées restent identiques. La politique2 lie les empreintes des deux modules de composition.
- Index des captures : `41e2c3f3dc77ad277e1bbfb12ac862b668169ee845aa2f0ebc371cfc136affe0`. Cet index lie sources/noms ; l’empreinte ZIP identifie les octets complets.
- Réception locale normale/optimisée identique octet pour octet aux deux sorties CI archivées. Aucune nouvelle exécution native Windows revendiquée.

## Résultats du nouveau lot

| Contrôle | Observation reçue |
|---|---|
| FCI/Standard × avant/après résultat B × normal/-O ×7 scénarios |56 nouvelles captures ;56 SIGKILL B hérités |
| Démarrage natif normal pour C |40 propriétaires, dont12 reprises ;28 réarmements de fixture supervisés |
| Effet C avec consommation du permis |12 cellules, un seul effet par clé dans chaque fixture |
| Succès sans coupure |4 effets et répétitions idempotentes |
| Coupure après COMMIT, réponse perdue |4 résultats retrouvés sans réexécution |
| Coupure avant COMMIT |4 rollbacks sans effet ni consommation ; HOLD de reprise |
| Expiration/révocation après précontrôle |8 refus exacts, dont4 FCI avec rollback vérifié et reçu durable |
| B déjà engagé, sans C admis |28 refus historiques, aucun démarrage C |
| Pause après tous les contrôles, libération après échéance |4 COMMIT tardifs, histoires natives cohérentes ; limite temporelle observée |
| Même pause puis SIGKILL avant COMMIT |4 rollbacks sans effet ni consommation |
| Probes négatives isolées |168 ; identité noyau, témoin concret, refus exact, SQL et compteur d’entrée vérifiés |
| Lecteur distinct normal/-O |56 contrôles de base reçus,298 altérations rejetées par mode |

Les298 mutations répétées dans chaque mode ne sont pas596 expériences natives indépendantes.

## Correction des causes

L’ancien adaptateur préparait l’effet SQL à tx_stage, avant les derniers finaliseurs natifs. Une pause pouvait laisser un finaliseur restaurer PENDING alors que les lignes applicatives préparées validaient ensuite. La nouvelle composition diffère l’écriture applicative jusqu’au hook after_commit_fence, après tous les finaliseurs gelés. Elle exige DONE et une clôture COMMIT_FENCE_PASS authentifiée, puis prépare effet SQL, résultat et consommation dans la même transaction. Le point d’injection before_commit est maintenant placé après ces finaliseurs. Ce déplacement est déclaré ; les anciennes captures ne sont pas réinterprétées.

Pour les seuls C_PERMIT_EXPIRED/C_REVOKED de la porte d’admission/finalisation, PolicyStop sort du chemin natif avant l’appel COMMIT du vendeur. Il ne correspond pas à un verdict UNKNOWN retourné par le moteur. La composition vérifie que la transaction reste active et n’a pas franchi le point de validation, exécute ROLLBACK, puis compare toutes les tables de la base principale à leur préimage au début de transaction via une connexion distincte en lecture seule. Elle signe et conserve le reçu dans c_policy_aborts avant d’accuser le refus exact. Toute preuve ou persistance manquante laisse l’appel non résolu. Les UNKNOWN ordinaires gardent leur sémantique précédente.

Les autorisations fraîches suivent les nouvelles époques natives après réarmement. Les grants root lient portée, activation, état retenu, identités d’autorité, propriétaire attendu, boot, temps et politique2. Le droit de lecture C reste limité à sa clé et est accordé avec le permis. Les réservations B restent conservées ; le réarmement et l’éventuelle quarantaine native sont explicites.

## Limites et provenance

La pause temporelle reste après le dernier contrôle et avant le vrai COMMIT. Les quatre COMMIT après échéance sont des observations de limite, pas une propriété de respect d’échéance. La correction n’établit ni borne physique de validation, ni clôture C004, ni protection contre la co-restauration, propriétaire hostile ou contournement par routes directes arbitraires.

OS/root/propriétaire unique fiables, autorités conservées et absence de clones demeurent des hypothèses. Les témoins de réarmement sont ceux d’une fixture synthétique. Les MAC natifs sont décodés dans le propriétaire de confiance ; le lecteur distinct ne dispose pas des clés privées et ne réalise pas un audit MAC extérieur. Aucune disponibilité industrielle ni supériorité générale sur Standard n’est établie.

Le lot PR5/CI43289235948 reste **FAILURE,50/56**, avec quatre UNKNOWN et deux INCONSISTENT_CONSUMER_EFFECT. Artefact13977245740,SHA256 `f0e4f70c7bee56075ed7daba041c66f8ef1a3a5e9bb1f059fea3a96cf393d954`, conservé. Les échecs antérieurs de PR4 et le premier défaut JSON_TYPE/EOF restent documentés séparément. Cette réception nouvelle ne les efface pas.

**Prochaine obligation : formaliser et tester le contrat temporel au point de validation effectif et étendre la qualification au-delà de la fixture retenue. M1 HOLD / SR02 BLOCKED ; aucun audit indépendant ni qualification de production.**
