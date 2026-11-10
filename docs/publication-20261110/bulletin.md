# Couret–Unification — Bulletin public du 10 novembre 2026

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
