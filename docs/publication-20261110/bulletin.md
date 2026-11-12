# Couret–Unification — Bulletin public du 10 novembre 2026

## Actualisation du 12 novembre 2026 — intégration native des capacités temporelles

[API et commandes](https://github.com/alexcour/CAUSAL-PAIR-01/tree/main/native_execution_02) · [Réception](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/native_execution_02/RECEPTION.md) · [Choix de plateforme](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/native_execution_02/PLATFORM_DECISION.md).

La nouvelle composition exige SAMPLED_ADMISSION explicitement à l’émission et à l’exécution. COMMIT_DEADLINE est refusé avant toute émission de permis ou entrée dans le moteur. Les domaines signés permis/RPC version2 et la politique3 lient la capacité au code de façade ; aucun repli implicite vers un contrat plus faible n’existe.

Le lot natif56/56 reçoit196 refus de capacité sans modification SQL ni nouvelle entrée native :84 demandes COMMIT,56 capacités manquantes et56 inconnues. Douze refus COMMIT surviennent après un résultat déjà conservé. Les12 effets C échantillonnés, quatre reprises après COMMIT avec réponse perdue et quatre refus FCI avec rollback attesté restent reçus.37 tests de contrat passent par mode ;410 preuves altérées sont rejetées par lecteur. Le manifeste81 sources conserve37 fichiers natifs gelés ; la relecture locale de l’archive CI concorde octet pour octet. La capture native est Linux ; Windows effectue les contrats, le staging et la réception, pas une seconde exécution native indépendante.

**C004 reste ouvert.** Quatre COMMITs tardifs restent observés dans le mode échantillonné accepté. Le refus d’une garantie indisponible est une correction du contrat d’API, pas une implémentation de cette garantie ou une migration de production. TigerBeetle est retenu pour le prochain prototype de registre synthétique au temps de cluster ; ce contrat distinct n’est pas assimilé au COMMIT SQL physique. **M1 HOLD / SR02 BLOCKED.** Les lots et modèles précédents conservent leurs périmètres.

---

## Actualisation du 12 novembre 2026 — C004 : contrat de primitive atomique et reprises

[Contrat](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/c004_atomic_sink_03/CONTRACT.md) · [Conformité d’une future implémentation](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/c004_atomic_sink_03/CONFORMANCE.md) · [Réception](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/c004_atomic_sink_03/RECEPTION.md) · [CI43310332533 réussie](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43310332533).

Le contrat distingue un nouvel effet autorisé au point atomique et la restitution d’un résultat antérieur. Après un COMMIT avec réponse perdue, un arrêt, l’expiration et une révocation, la même requête retrouve le résultat original sans nouvel effet. Les demandes forgées ou dont le contenu diffère n’accèdent pas à ce résultat.

L’exploration complète du domaine fini reçoit218 états/3270 transitions pour la spécification atomique idéale et560/8400 pour une comparaison séparant contrôle et effet. Le premier modèle ne viole pas les propriétés dans ce domaine ; le second expose44 arêtes d’effet tardif,16 d’époque périmée et60 d’horloge non fiable. Ces catégories se recoupent : ce sont des arêtes abstraites, pas des transactions physiques à additionner. Dix parcours par modèle couvrent expiration, révocation, horloge, arrêt, redémarrage et reprise ;32 preuves altérées sont rejetées par mode. Graphes et rapports concordent octet pour octet entre Windows, Linux et relecture locale de l’archive CI.

**La transition temporelle atomique est une hypothèse du modèle, pas une primitive physique réalisée.** Le dossier liste les preuves encore nécessaires de couplage au point d’effet, horloge, autorité, rétention, sécurité des accès et raffinement. Aucun moteur SQLite ou FCI natif ne tourne dans cette étude. **C004 ouvert ; M1 HOLD / SR02 BLOCKED.** Même auteur, pas d’audit extérieur ni qualification de production.

---

## Actualisation du 12 novembre 2026 — C004 : callback COMMIT et marge conditionnelle

[Contrat candidat02](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/c004_commit_candidate_02/CONTRACT.md) · [Réception](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/c004_commit_candidate_02/RECEPTION.md) · [CI43307079935 réussie](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43307079935).

Le véritable callback C SQLite de COMMIT est testé avec marge nulle et marge nominale de500ms. Seize cas sous Windows et seize sous Linux reçoivent chacun quatre COMMITs tardifs, quatre rollbacks après expiration, quatre rollbacks après arrêt du processus et quatre COMMITs ordinaires.64 altérations de preuves sont rejetées par mode ; aucun moteur natif FCI n’est modifié ou relancé.

La condition `g + epsilon + Delta < d` est suffisante si l’erreur d’horloge est bornée par epsilon et si le délai réel du dernier échantillon au COMMIT est borné par Delta. Le modèle de14580 points abstraits compte1170 admissions sous borne sans violation et2214 contre-exemples de marge lorsque la borne de délai ne tient plus. Ce sont des points arithmétiques, pas des transactions physiques. Les rapports Windows/Linux et la relecture locale de l’archive CI concordent octet pour octet ; même auteur, pas d’audit indépendant.

**Aucune borne dure de plateforme n’est établie.** Un callback, une marge configurée, un maximum mesuré ou une alarme après effet ne qualifient pas cette garantie. Le dossier précise les preuves nécessaires pour un mécanisme borné et l’alternative d’une primitive de validation atomique au point d’effet. **C004 ouvert ; M1 HOLD / SR02 BLOCKED.** Les campagnes précédentes conservent leurs périmètres.

---

## Actualisation du 12 novembre 2026 — C004 : contrat et contre-exemples reçus

[Contrat temporel](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/c004_commit_contract_01/CONTRACT.md) · [Réception](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/c004_commit_contract_01/RECEPTION.md) · [CI43304723750 réussie](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43304723750).

Le contrat distingue autorisation au dernier échantillon, révocation effectivement commise et validité au COMMIT effectif. Un test SQLite synthétique reçoit24 cas sous Windows et24 sous Linux : six contre-exemples au COMMIT tardif par environnement, deux refus d’expiration à la préparation, huit cas d’ordre de révocation et quatre rollbacks après arrêt du processus.58 altérations synthétiques sont rejetées par mode de lecture. Les résultats JSON normalisés concordent entre environnements ; il ne s’agit pas d’un audit extérieur.

Quatre témoins natifs tardifs et quatre rollbacks associés sont relus dans le lot natif déjà reçu ;24 altérations de ces preuves sont rejetées par mode. Aucun moteur natif n’est relancé ou modifié. L’ajout d’un contrôle à la préparation de COMMIT réduit un intervalle mais ne supprime pas la pause possible après son dernier échantillon. La CI initiale échouée et la correction de précision d’horloge locale sont conservées dans l’historique de réception.

**C004 reste ouvert.** Une future solution doit justifier une borne dure jusqu’au COMMIT avec erreur d’horloge, ou une primitive de validation couplée au point d’effet. Les maxima mesurés ne démontrent pas une telle borne. **M1 HOLD / SR02 BLOCKED.** Les chiffres56/12/4 ci-dessous décrivent toujours le lot natif antérieur.

---

## Actualisation du 12 novembre 2026 — exécution native C, composition 2 reçue

[Sources et commandes](https://github.com/alexcour/CAUSAL-PAIR-01/tree/main/native_execution_01) · [Reçu complet](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/native_execution_01/RECEPTION.md) · [CI43292958500 réussie](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43292958500), source exécutée `ca05c516877379d588e6af6bcc271d28ec68195e`.

Les56 contrôles de base passent :12 effets C avec consommation durable du permis,4 récupérations après COMMIT et réponse perdue,4 refus FCI attestés par rollback vérifié,56 coupures B héritées et12 coupures C. Les21 tests de contrat passent dans chaque mode ;298 mutations de preuve réellement altérées sont rejetées par lecteur normal/optimisé. Les relectures locales correspondent octet pour octet aux deux sorties CI archivées. Les modes sont des répétitions, pas des audits indépendants.

La composition diffère l’écriture applicative jusqu’après les derniers contrôles natifs et une clôture DONE/PASS authentifiée. Elle supprime ainsi la divergence observée après COMMIT tardif. Pour deux refus précis de permis, une sortie typée avant l’appel COMMIT permet un rollback explicite, une comparaison complète à la préimage SQL via une autre connexion en lecture seule, puis la conservation d’un reçu signé avant le refus exact. Les issues natives UNKNOWN retournées par les autres chemins ne sont pas réécrites.

Artefact13979046352 :3743671 octets,433 fichiers ; SHA256 `3ffa2f423c5a929ff5daa4b8a2f42dae5d54444e86ad8d2e74e233a1a18862de`. Manifeste80 sources `3b7e067deb2849af9c2fc73cacd91b60166ea84153b006f892f371680501d1d4` ;37 fichiers natifs gelés inchangés. Le lot précédent PR5 demeure en échec50/56 avec ses propres sources et artefacts.

**Limite conservée : quatre libérations supervisées après échéance produisent encore un COMMIT tardif, cette fois avec histoire native cohérente.** Cela n’établit ni validité au point physique de COMMIT, ni borne de validation, ni clôture C004. OS/root/propriétaire fiables, autorités retenues, absence de clones et témoins de réarmement de fixture demeurent des hypothèses. Pas de garantie générale de non-contournement, de co-restauration sûre, de supériorité ou de qualification industrielle. **M1 HOLD / SR02 BLOCKED.**

Les actualisations suivantes conservent leurs états historiques antérieurs à cette nouvelle réception.

---

## Actualisation du 12 novembre 2026 — activation et permis C reçus

Une [campagne publique distincte](https://github.com/alexcour/CAUSAL-PAIR-01/tree/main/native_activation_01) reçoit quatre activations durables et huit permis natifs signés sur huit nouvelles captures FCI/Standard, avant/après COMMIT B, en Python normal/optimisé. Quatre cas historiques sans C admis refusent l’activation. Les autorisations sont vérifiées à sec : aucun effet C n’est exécuté.

[CI43121546137 réussie](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43121546137), source exécutée `5fcd1e0b405603ceea94a3d535372cf248f996c6`. Artefact13900343217 :318758 octets,62 fichiers, SHA256 `6e7ecf7ec5d9e10c5e6c10b5f0e3dd859f2da07464db2757c4b134f815d85183`. Manifeste75 sources : `3b0b94a20210e268911822ba744f709a9a63ca65a755f0a477280c44ddc8780b`. Les deux lecteurs locaux concordent avec les sorties CI archivées ;64 mutations effectivement altérées sont rejetées par mode.

Quatre rollbacks d’activation,48 refus de rôles et24 refus sur grant/autorité dégradés ont été reçus. Le permis court expire réellement ; son renouvellement est refusé. La révocation clôt C et invalide les routes versionnées testées. Quatre redémarrages du composant d’activation retrouvent les mêmes certificats/permis.

Le grant root lie admission, portée, état retenu, autorités, politique/époque, boot et temps. Le permis versionné contient l’autorisation native et le permis issus du pont gelé. Sa durée2/25s est distincte de la fenêtre native30s. Il ne prouve pas la sûreté de soumissions directes arbitraires, ni la consommation/revalidation au véritable COMMIT C. Service natif normal, rôle C et exécution restent NOT_RUN. OS/root/propriétaire fiables et absence de clones sont des hypothèses. **M1 HOLD / SR02 BLOCKED.** [Reçu complet et limites](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/native_activation_01/RECEPTION.md).

Les sections suivantes conservent l’état daté du 10 novembre, antérieur à cette activation.

---

## Actualisation — reproduction publique autonome reçue

Une [reproduction publique autonome](https://github.com/alexcour/CAUSAL-PAIR-01/tree/main/native_admission_01) est désormais disponible : sources originales conservées, lecteur versionné1.1, lanceur Linux et commandes. [CI42904156448 réussie](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/42904156448), source exécutée `c1b9167573fa849e8c1726d5c5363beacabf6995`. Huit nouveaux cas : quatre admissions sans exécution, quatre refus historiques. Sorties des lecteurs CI/local normal/optimisé identiques.

Le lecteur1.1 inverse l’indicateur du second client pour éviter qu’une mutation consistant à le remettre à true ne soit parfois sans effet. Les composants natifs et la politique d’admission restent inchangés. Les deux premiers lots publics échoués sont conservés et expliqués dans le [reçu public](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/native_admission_01/RECEPTION.md). L’artefact final,228954 octets, a pour SHA256 `bba8b852607b4fa70d47de907fa2b6a1dd9d06cdae2988e37a54199af6614100`.

Cette reproduction est exécutée par le programme, pas par un auditeur indépendant. Activation, permis, service natif normal et exécution C restent à qualifier. Les archives privées historiques ne sont pas ouvertes ; les sources du paquet et les nouveaux artefacts publics le sont. Le corps du bulletin initial ci-dessous est conservé pour sa provenance datée.

---


**Alexandre Couret · FCI, MIRAGE et recherches distinctes en mathématiques.**

Ce bulletin donne un accès aux ressources publiques et présente une synthèse bornée de travaux internes. Il distingue les expériences synthétiques ouvertes, les réceptions techniques internes et les garanties qui restent à établir.

## FCI : décider d’une reprise après incident

FCI signifie **Formal Conservative Interposition**. Le programme étudie les conditions de validité d’une autorisation d’exécution et d’une reprise après incident. Une confirmation perdue n’établit pas l’absence d’effet ; une tentative ancienne peut également être encore en cours.

Le dépôt public [CAUSAL-PAIR-01](https://github.com/alexcour/CAUSAL-PAIR-01) présente deux modèles synthétiques :

- la restauration d’une mémoire de reçus peut rendre indiscernables deux histoires dont les effets diffèrent ;
- une ancienne requête HTTP peut engager son effet après une consultation exacte retournant `NOT_FOUND`.

Les mécanismes conventionnels de protection au destinataire réussissent sous les hypothèses publiées. Le dépôt ne démontre pas de supériorité générale de FCI, de garantie universelle d’exécution unique ou de qualification industrielle. Ses commandes de reproduction et ses limites font référence.

Le [laboratoire pédagogique bilingue](https://fci-recovery-observatory.espace-de-tr-5012.chatgpt.site) rejoue les traces publiées ; il ne lance pas les expériences et n’évalue pas un moteur de production.

## Réception interne récente : admission sans exécution

La réception technique interne du 10 novembre 2026 porte sur **huit nouvelles captures natives**, FCI/Standard × avant/après validation de la transaction métier × Python normal/optimisé.

Dans quatre scénarios avant validation métier, une nouvelle tentative C est enregistrée durablement après clôture de B, à l’état `ADMISSION_ONLY`. Dans quatre scénarios où B avait déjà produit son résultat, l’admission de C est refusée et le résultat historique est conservé.

Le certificat de clôture B n’est pas un permis de transfert. Une autorisation distincte du superviseur est liée à la vue d’autorité conservée. L’ajout de C, du reçu et de l’événement forme une transaction ; les réservations historiques de B ne sont pas effacées.

Contrôles reçus dans ce lot :

| Contrôle interne | Observation |
|---|---|
| Abandon avant validation de l’admission | 4 retours arrière avec vue complète inchangée |
| Identités de contrôle fournies par le noyau | 32 refus de rôles |
| Autorisation/autorité absente, portée différente ou vue périmée | 16 refus sans écriture |
| Répétition et deux processus clients | Une seule création de C par scénario positif ; propriétaire sérialisé |
| Redémarrage du composant d’admission | 4 restitutions du même C et du même reçu |
| Ancienne fonction de délivrance de permis, avant/après ce redémarrage | 8 refus ; aucun permis natif C |
| Relectures internes en CI et localement, normal/optimisé | Sorties identiques octet pour octet |

Le terme « deux clients » ne revendique pas des transactions concurrentes. Les 60 altérations de preuves rejetées par mode du lecteur sont des vérifications hors ligne des captures, pas 60 expériences natives indépendantes.

**Aucune exécution de C n’est reçue.** L’activation, le permis C et le redémarrage du service natif normal restent à qualifier. Le redémarrage reçu concerne le seul composant d’admission.

Le contrat suppose le système d’exploitation, le superviseur et le propriétaire fiables, l’absence de clones et la conservation de l’autorité. La fraîcheur signifie égalité à la vue autorisée ; elle n’est pas une borne temporelle ni une garantie contre une restauration conjointe des preuves et du contexte. Pas d’audit extérieur, de protection démontrée contre un propriétaire hostile ou de garantie générale contre les contournements.

### Provenance et accessibilité

Les nombres ci-dessus sont rapportés à partir d’une réception interne. Les archives détaillées et les sources du moteur de ce lot ne sont pas ouvertes par ce bulletin. Cette synthèse n’est donc pas une reproduction publique ou une validation indépendante. Les expériences synthétiques publiques citées plus haut restent distinctes.

Empreinte SHA-256 de l’artefact interne reçu, 455877 octets :

`77f31b07016b7684f480447382008400828293cf911c884f786d791f2cceb1fd`

Empreinte SHA-256 de la politique d’admission exécutée :

`c0b7cfb21e3199306a99c391aa61f3924e7f6e1e1238459ccbd3c3b3f1ec6fd2`

Ces empreintes identifient les pièces conservées ; à elles seules, elles ne permettent pas d’en contrôler le contenu. 71 sources déployées ont été vérifiées en interne, dont 37 sources natives inchangées. Les lecteurs des phases antérieures ne sont pas réinterprétés comme l’état final après l’admission C.

## MIRAGE : confronter et vérifier les réponses

MIRAGE est un programme de recherche pour organiser la confrontation et la vérification des réponses. La projection publique du cockpit datée du 9 novembre 2026 décrit la réception documentaire de trois documents.

La méthode rapportée associe sources versionnées, contrôles déterministes, reçus durables et réutilisation des résultats. Ce parcours n’établit pas une vérification scientifique, une validation indépendante ou un avantage économique. Le coût monétaire n’y a pas été mesuré. La [fiche publique JSON](publication.json) reprend cette portée.

## Recherches mathématiques distinctes

Les [vérifications finies](https://github.com/alexcour/couret-finite-verifications) et le dossier [translation et cospectralité](https://github.com/alexcour/cayley-prime-translation-cospectrality) disposent de leurs propres sources et périmètres. Ils ne constituent pas une preuve des propriétés de sécurité de FCI. Les statuts détaillés sont ceux des versions citées dans chaque dépôt.

## Appel à reproduction et à objections

Un retour utile peut être une reproduction d’une expérience publique, un scénario manquant, une hypothèse insuffisamment justifiée, un mécanisme conventionnel plus fort ou une antériorité pertinente. Indiquer la version, la commande, la trace et le résultat observé ; utiliser des données synthétiques.

[Guide de contribution FCI](https://github.com/alexcour/CAUSAL-PAIR-01/blob/main/CONTRIBUTING.md) · [Contact](https://www.couretunification.fr/contact/) · [Auteur](https://www.couretunification.fr/a-propos/) · [ORCID](https://orcid.org/0009-0000-8246-7146).

## English summary

FCI (Formal Conservative Interposition) studies execution authorization and recovery after incidents. Public synthetic recovery models and traces are available in CAUSAL-PAIR-01. Conventional receiver-side protections succeed under their stated assumptions; no general FCI advantage is established.

A separate internally received study recorded four generation-C admissions without a native permit or execution, and four admission refusals after B had already committed. Restart retrieval concerns only the admission component. Normal native-service restart, C activation and execution remain unqualified. Detailed internal archives are not released by this bulletin, so it is not a public reproduction or independent audit of that study.

MIRAGE organizes the confrontation and verification of responses. Its reported three-document reception is documentary, not scientific validation. Monetary cost was not measured in that path. Mathematical research repositories have their own, separate scopes.

Publication authorized by the programme owner. This authorization does not change scientific qualification or imply an independent endorsement.
