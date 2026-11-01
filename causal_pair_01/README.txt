CAUSAL-PAIR-01 — 1 novembre 2026

Modèle local de deux historiques indiscernables après restauration du registre.
Python 3, bibliothèque standard uniquement. Aucun accès réseau nécessaire.

Reproduire dans un dossier décompressé neuf :
  python3 experiment.py --out rerun_normal
  python3 -O experiment.py --out rerun_optimized

Auditer les résultats livrés (normal/ et optimized/) :
  python3 audit.py

Le programme refuse de réutiliser un dossier de sortie existant.
Les contrôles lèvent RuntimeError et restent actifs avec python -O.

Contenu : experiment.py, audit.py, report.html, résultats JSON, bases SQLite,
audit_results.json, SHA256SUMS.txt.

Les règles conservative_standard et fci_candidate_rule sont deux noms de la
même politique minimale dans ce modèle. Ce fichier ne contient pas le moteur
FCI existant, ni le SDK Temporal. Il n'établit aucune supériorité de FCI.

Le témoin autoritaire est une information supplémentaire explicitement accordée
au contrôle positif. Il repose sur une consultation exacte d'un destinataire
au repos. Ce contrat ne représente pas une API réelle déjà qualifiée.

La coupure réelle du sous-processus os._exit(73) survient après les deux COMMIT
et avant le retour applicatif. Aucun test de panne électrique, de stockage,
de concurrence, de reset Temporal ou de corruption SQLite n'est inclus.

L'audit est un second lecteur des fichiers, écrit dans cette même session :
il ne constitue pas une validation externe indépendante.
