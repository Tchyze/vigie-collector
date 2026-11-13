# Feuille de route

La phase 1 ne couvre que des sources publiques, structurées et sans authentification. Les points
ci-dessous viendront plus tard, ou attendent une source exploitable.

## Sources écartées pour l'instant

| Sujet | Raison | Piste |
|---|---|---|
| HPE Aruba (CSAF) | les bulletins réseau HPE sont repris du flux RSS HPE, sans versions | csaf.arubanetworking.hpe.com publie des CSAF (index `changes.csv`) : versions AOS touchées |
| Dell : avis de sécurité (DSA) | dell.com/support/security répond 403 aux clients automatiques | le CERT-FR reprend les avis Dell |
| Dell et HPE : fins de support | dates Dell saisies dans overrides.yaml (iDRAC8, iDRAC9 14G) ; aucune date officielle HPE pour iLO | ajouter iDRAC9 15G/16G et iLO quand l'éditeur publie des dates |
| VMware : versions touchées | la liste Broadcom ne donne que les produits | l'avis complet est une page du portail (HTML) |
| Stormshield : CVE et versions | le flux RSS n'a ni description ni CVE ; le détail n'est que dans la page HTML de l'avis | le CERT-FR reprend les avis Stormshield avec leurs CVE |
| Dell : autres firmwares (BIOS, PERC…) | un composant par modèle de serveur, trop fin pour des branches | le catalogue Dell les contient s'il faut les suivre |
| Red Hat et Rocky : avis « important » | des milliers par an | seuls les avis critiques sont repris ; un filtre par composant (noyau, OpenSSH, OpenSSL…) pourrait en ajouter |
| Cisco openVuln API | demande une authentification OAuth | le flux RSS suffit en phase 1 |
| Scraping des notes de version | fragile, exclu en phase 1 | — |

## Améliorations identifiées

- **OpenSSH : `security_fix`.** Les tags ne disent pas si une version corrige une faille. La
  page `security.html` d'OpenSSH le dit, mais c'est du HTML : à évaluer selon la règle « pas de
  scraping ».
- **Fortinet : avis sortis du flux.** Le CSAF n'est lu que pour les avis encore présents dans
  le flux RSS (50 derniers). Les avis plus anciens gardés dans l'historique n'ont pas de CVE ;
  leur URL CSAF n'est pas prévisible (elle contient le titre).
- **Cisco IOS XE et Stormshield : dernière version.** endoflife.date ne la donne pas ; chercher
  une source éditeur structurée.
- **CERT-FR : `affected`.** Les systèmes touchés sont du texte libre (« FortiOS versions 7.4.x
  antérieures à 7.4.9 »). Une correspondance prudente vers les branches suivies reste possible,
  mais seulement avec des règles explicites et testées.
- **Historique initial des versions.** Les flux Atom d'OpenSSH et d'httpd n'exposent que
  les 10 derniers tags. L'historique se construit au fil des passages ; on pourrait l'amorcer
  une fois par `overrides.yaml`.
