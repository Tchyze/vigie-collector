# Feuille de route

La phase 1 ne couvre que des sources publiques, structurées et sans authentification. Les points
ci-dessous viendront plus tard, ou attendent une source exploitable.

## Sources écartées pour l'instant

| Sujet | Raison | Piste |
|---|---|---|
| HPE Aruba | avis diffusés par liste de diffusion, sans flux confirmé | le CERT-FR couvre déjà les avis Aruba ; chercher un flux ou une archive web |
| Stormshield : CVE et versions | le flux RSS n'a ni description ni CVE ; le détail n'est que dans la page HTML de l'avis | le CERT-FR reprend les avis Stormshield avec leurs CVE |
| Dell (iDRAC, OS10…) | pas de flux public structuré identifié | à étudier |
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
