# Mandat Antigravity — reprise coordonnée du 13 novembre 2026

À la demande d’Alexandre Couret : avancer sur les fronts ouverts et reprendre les missions existantes à leur dernier reçu vérifiable. Ce document est un ordre de travail technique ; sa publication n’est ni un accusé de réception d’Antigravity, ni une preuve d’exécution ou de validation scientifique.

## Réception et règles de coordination

1. Lire ce mandat et les consignes déjà reçues dans le chat canonique. Ne pas interrompre un travail actif ni élargir ses autorisations. Produire un ACK daté avec commit effectivement lu, mission en cours, fichiers accessibles et limites. Distinguer ORDER_POSTED, RELAY_DELIVERED, ACK_RECEIVED, RUNNING, BLOCKED et RECEIVED.
2. Inventorier les livraisons et tâches déjà actives avant de modifier une branche. Ne pas relancer les calculs ou campagnes déjà reçus. En cas de travail concurrent, produire un audit ou un correctif sur une branche distincte plutôt qu’écraser le travail d’un autre opérateur.
3. Aucun secret, corpus restreint, corrigé aveugle, dossier confidentiel ou résultat privé dans ce dépôt public. Les données privées restent dans leur canal autorisé ; un titre de mission ne vaut pas autorisation de lire ou transférer son contenu.
4. Pas d’envoi de courriel, contact fournisseur, paiement, création de compte, changement de droits, migration de production ou publication de résultats privés. Les communications de cette tranche restent dans les canaux GitHub déjà autorisés et le retour au coordinateur.
5. Les HOLD et verrous de revue indépendante restent en place. Un second agent IA ne constitue pas un audit externe. Aucun faux ACK, PASS, coût nul mesuré ou expérience native ne doit être déduit d’un plan ou d’un message.

## Missions et livrables

### AG-01 — Reprise des travaux déjà confiés

Terminer d’abord l’ACK et le prévol factuel de la mission active. Si les octets originaux d’un paquet manquent, enregistrer PACKAGE_UNAVAILABLE et leur identité attendue ; ne pas fabriquer un paquet équivalent. Si une revue ou plateforme requise manque, enregistrer PREFLIGHT_BLOCKED. Ne pas contourner un verrou ni déclencher une cellule supplémentaire. Livrable : reçu local et référence au fil de coordination déjà utilisé, sans publication des pièces privées.

### AG-02 — Audit FCI de la capacité explicite

Reprendre `native_execution_02/RECEPTION.md` et l’API actuelle. Vérifier le lien entre capacité demandée, permis/RPC signés version2 et politique3 ; chercher un repli implicite de COMMIT_DEADLINE vers SAMPLED_ADMISSION, y compris sur un résultat conservé. Livrable : constats reproductibles, chemins/commit exacts et éventuel correctif isolé. Ne pas relancer la campagne native historique et ne pas promouvoir D.

### AG-03 — Contre-lecture du nouvel adaptateur TigerBeetle

Le coordinateur Codex est l’auteur du prototype dans `tigerbeetle_adapter_01` ; ne pas modifier sa branche de travail. Après disponibilité d’un commit testé, relire les captures et le récepteur : expiration dans le temps du cluster, idempotence, conflits d’ID, annulation individuelle, reprise et historique. Vérifier que la perte d’accusé applicatif simulée n’est pas décrite comme une panne réseau observée. Livrable : revue bornée avec anomalies et limites. Ce registre ne qualifie pas le COMMIT SQL physique ni l’horloge du propriétaire FCI.

### AG-04 — Mathématiques, Lean et certificats

Reprendre les derniers reçus autorisés des chantiers en cours. Séparer compilation, énoncé effectivement vérifié, axiomes audités, pont sémantique et résultat général. Pour les automates, ne pas confondre une couverture des masques encodés avec le raccord aux paires réelles ou une preuve UNSAT. Pour les manuscrits et certificats, fournir un seul prochain lemme ou témoin manquant, avec dépendances exactes. Livrable : écart de preuve ciblé ou correctif compilé sur branche isolée ; pas de `sorry`, d’axiome ajouté ou de reconstruction présentée comme générateur original.

### AG-05 — MIRAGE et InterIA hors ligne

Réconcilier les paquets déjà reçus et les diagnostics de parseurs/scoreurs. Auditer l’isolation uniquement avec des fixtures synthétiques et des canaris, sans lire les corrigés du corpus aveugle ni lancer de bras expérimentaux. Aucun appel modèle facturable ou allocation aléatoire sans le contrat et les portes propres au pilote. Livrable : trace hors ligne, entrée/sortie, empreintes et défaut précis ; pas de gain économique ou scientifique déduit.

### AG-06 — Coordination, site et conservation

Produire un registre par front : source, état constaté, action réellement faite, artefact, vérification, blocage et prochaine action. Rapprocher les statuts sans fermer automatiquement les tickets. Identifier les écarts de liens/publication dans les destinations déjà autorisées ; ne pas copier de pièces confidentielles. Livrable : bilan et reçus conservant l’historique. Les fronts dépendant d’un accord externe restent à cette porte ; préparer les critères n’autorise pas un envoi.

## Format de retour

Un reçu doit comporter : mission_id, source_commit, status, actions_executed, artifact_paths, hashes réellement calculées, checks réellement exécutés, limitations et next_action. Un chemin introuvable reste introuvable ; une capture non accessible n’est pas reçue. Les rapports privés ne doivent pas être poussés dans ce dépôt public. Fournir d’abord l’ACK du mandat, puis avancer sur les missions hors ligne accessibles et rapporter les dépendances exactes.

État scientifique conservé : C004 ouvert ; M1 HOLD ; SR02 BLOCKED. L’admission échantillonnée reste distincte de la capacité temporelle forte indisponible.
