# Correction de la lecture du résultat C — 12 novembre 2026

**Deux défauts corrigés ; qualification native toujours en échec.** Le droit de lecture du seul couple clé métier/UID62026 est désormais accordé atomiquement avec le permis frais. Le résultat historique convertit sa ligne SQLite en liste JSON, compatible avec l’encodeur strict. Les moteurs natifs gelés ne changent pas.

- [PR5 en brouillon](https://github.com/alexcour/CAUSAL-PAIR-01/pull/5), branche isolée issue de PR4 au commit9e117a1bfd279cb34c327404dbadcfa2ce8304b1 ; travail concurrent conservé.
- Source exécutée : `0ddbdea6efe0c796fcd4d34452d07330bd848aa1`.
- [CI native43289235948](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43289235948) : **FAILURE conservé** ; CI synthétique43289236350 réussie.
- 16 tests de contrat réussis dans chaque mode Python, localement et en CI. En local : Python3.12.14, cryptography50.0.2. CI : Python3.12.16, cryptography50.0.2. Ces tests ne remplacent pas les captures natives.
- 56 cellules capturées ;50 contrôles de base passent et6 échouent. Les12 échecs READ_ROLE observés dans le lot précédent ont disparu. Deux incohérences d’historique natif deviennent maintenant visibles, auparavant masquées par READ_ROLE. Ces50 passages ne constituent pas une réception globale.
- Artefact13977245740 :3648395 octets,430 fichiers ; SHA256 `f0e4f70c7bee56075ed7daba041c66f8ef1a3a5e9bb1f059fea3a96cf393d954`. Octets téléchargés, taille, CRC et confinement vérifiés.
- Manifeste79 sources : `a52e35069f957bcdd283f594c14ff1b0ec79c43f93a0293f72e54d3bbe435138`. Les37 fichiers natifs gelés sont inchangés.
- Les diagnostics CI/local normal/optimisé sont identiques octet pour octet. Relecture locale volontairement en échec, statut DIAGNOSTIC_ONLY, qualified=false. Les tests de mutation de la nouvelle réception ne sont pas atteints.

## Échecs restants

FCI × Python normal/-O × expiration/révocation après précontrôle : le diagnostic signé montre un échec du contrôle de permis dans admit, sous transaction native. Le moteur conserve HOLD_NATIVE/OUTCOME_UNKNOWN. Le protocole exige un refus exact C_PERMIT_EXPIRED ou C_REVOKED ; aucun de ces quatre prédicats n’a été assoupli. L’absence d’effet et de consommation dans les instantanés collectés ne réécrit pas ce verdict natif en preuve générale de non-exécution.

Deux autres échecs, FCI × normal/-O × libération après échéance au point before_commit : history_C refuse INCONSISTENT_CONSUMER_EFFECT. Le droit READ_ROLE est corrigé, mais le résultat métier engagé n’est pas suffisant pour recevoir une histoire native cohérente. Le diagnostic demeure un échec ; sa cause native doit être traitée séparément, sans supprimer cette vérification.

Les scénarios temporels hérités conservent aussi quatre validations après l’échéance lors d’une libération supervisée après le dernier contrôle, et quatre rollbacks lors d’une coupure avant COMMIT après cette échéance. Effet et consommation restent liés dans les captures ; la validité temporelle au véritable COMMIT n’est pas établie par un contrôle échantillonné.

## Provenance préservée

Le premier essai de cette correction, CI43288809740 au commitc9d961b485eb723714d7738a0c5badcaba684f16, échoue après le premier effet C : l’encodeur refuse le tuple de consommation (JSON_TYPE), le service termine et le client rapporte NATIVE_EOF_NO_ACK. Artefact13976577008,142566 octets,SHA256 `7852087e6f2c3e3bfb1af656aab3638aba336ac995e79b5a3c25c3e4ca49122c`, conservé séparément. Il n’est pas réinterprété avec les nouvelles sources.

Les échecs antérieurs de PR4 restent inchangés et documentés dans REVISION_20261112.md. La proposition locale intermédiaire fondée sur l’ancien lot40 cellules n’a pas remplacé la branche distante avancée ; la correction publiée reprend le lot56 cellules et ses critères stricts.

**M1 HOLD / SR02 BLOCKED. Aucun merge de PR5, aucune qualification industrielle, aucun audit indépendant.** OS/root/propriétaire fiables, autorités conservées, absence de clones et réarmement par témoins de fixture restent des hypothèses.

Prochaine obligation : traiter explicitement le refus du permis et l’issue native inconnue dans le protocole, avec preuve durable du résultat/rollback et conservation du verdict natif. La propriété temporelle au COMMIT demeure une obligation distincte ; ajouter un dernier échantillon ne suffit pas à établir une borne physique de validation.
