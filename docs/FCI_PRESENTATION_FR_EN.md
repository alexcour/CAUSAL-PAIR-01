# FCI — Formal Conservative Interposition

## Responsable et cadre

**Alexandre Couret**  
**Président de la société CONFIANCE**  
**Porteur du programme FCI — Formal Conservative Interposition**  
Rasiguères, France.

FCI est un programme de recherche et développement consacré aux conditions de sécurité des autorisations d’exécution et des reprises après incident. La qualité de président de CONFIANCE et la responsabilité personnelle du programme sont indiquées séparément : cette présentation n’établit pas à elle seule un portage contractuel ou un transfert de propriété intellectuelle.

- [Présentation de l’auteur et de ses autres recherches](https://www.couretunification.fr/a-propos/)
- [Profil scientifique HAL](https://cv.hal.science/alexandre-couret)
- [ORCID](https://orcid.org/0009-0000-8246-7146)
- [Contact](https://www.couretunification.fr/contact/)

## La question étudiée

Après une panne, une action peut avoir eu lieu alors que sa confirmation a disparu. Une ancienne tentative peut aussi continuer après la reprise du contrôleur.

Trois questions doivent être distinguées :

1. L’autorisation de l’action est-elle encore valable ?
2. Une tentative antérieure a-t-elle déjà produit son effet ?
3. Une tentative ancienne peut-elle encore le produire ?

Relancer peut créer un doublon. Bloquer toute reprise peut laisser une opération légitime inachevée. FCI étudie quelles preuves et garanties rendent une décision justifiée, et quand les informations disponibles sont insuffisantes pour reprendre automatiquement.

## Ce que ce dépôt public permet d’examiner

[Le README](../README.md) présente deux expériences synthétiques et leurs commandes de reproduction :

- **CAUSAL-PAIR-01** : après restauration de la mémoire des reçus, deux histoires différentes exposent les mêmes informations au contrôleur.
- **LATE-COMMIT-02** : une ancienne requête HTTP peut encore engager son effet après une consultation exacte retournant `NOT_FOUND`.

Les scénarios comparent notamment une consultation préalable, le fencing, la déduplication atomique et la réconciliation au destinataire. Les mécanismes conventionnels réussissent sous les hypothèses testées. La règle conservatrice minimale et la candidate étiquetée FCI partagent volontairement leur implémentation dans la première expérience.

[Le laboratoire interactif](https://fci-recovery-observatory.espace-de-tr-5012.chatgpt.site) rejoue les traces publiées ; il ne lance pas ces expériences et n’évalue pas le moteur FCI de production.

## Portée

Ces modèles pédagogiques ne constituent ni une preuve générale de sécurité, ni un nouveau théorème d’impossibilité, ni un avantage démontré de FCI. Les effets protégés du chapitre HTTP sont des écritures SQL dans une transaction du destinataire. Les hypothèses, versions et limites détaillées figurent dans le README.

Les recherches mathématiques présentées sur le site de l’auteur sont distinctes de cette question de sécurité. Une affiliation à un laboratoire ou une validation industrielle ne sont pas revendiquées par cette présentation.

## Retours scientifiques recherchés

Un retour utile peut porter sur :

- un scénario de panne ou de concurrence manquant ;
- une hypothèse de conservation de l’autorité ou des preuves insuffisamment justifiée ;
- un mécanisme standard ou une référence répondant déjà au problème ;
- la reproduction d’un cas, avec commande, trace et nombre d’effets engagés.

[Discussion publique sur Temporal](https://community.temporal.io/t/idempotency-across-workflow-reset-operation-identity-and-durable-evidence/19866) · [Guide de contribution](../CONTRIBUTING.md).

---

## English overview

**FCI means Formal Conservative Interposition.** Alexandre Couret, President of CONFIANCE and lead of the FCI programme, studies how execution authorization and recovery decisions can remain justified after an incident.

A lost confirmation does not establish that an effect never occurred. An older request may also remain in flight. The programme distinguishes authorization validity, prior commitment and possible later commitment.

This repository publishes bounded synthetic recovery experiments, including conventional receiver-side protections. It does not establish a general security guarantee or a production FCI advantage. See the [README](../README.md) for assumptions, reproduction commands and limits.

Corrections, missing schedules, stronger conventional baselines and relevant prior work are welcome. [Contact](https://www.couretunification.fr/contact/).

Presentation dated 5 November 2026. Public material only.
