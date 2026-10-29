# Feuille de route

La phase 1 ne couvre que des sources publiques, structurées et sans authentification. Les points
ci-dessous viendront plus tard, ou attendent une source exploitable.

## Sources écartées pour l'instant

| Sujet | Raison | Piste |
|---|---|---|
| HPE Aruba | avis diffusés par liste de diffusion, sans flux confirmé | le CERT-FR couvre déjà les avis Aruba ; chercher un flux ou une archive web |
| Stormshield (avis directs) | pas de flux structuré confirmé | le CERT-FR couvre déjà les avis Stormshield ; versions et fins de support via endoflife.date |
| Dell (iDRAC, OS10…) | pas de flux public structuré identifié | à étudier |
| Microsoft MSRC | API CVRF/CSAF riche mais volumineuse | à intégrer en phase 2 ; le CERT-FR couvre les bulletins mensuels |
| Red Hat CSAF | gros volume (un document par erratum) | indexer seulement les RHSA critiques et importants |
| Errata Rocky Linux | API errata à évaluer | à étudier |
| Cisco openVuln API | demande une authentification OAuth | le flux RSS suffit en phase 1 |
| Scraping des notes de version | fragile, exclu en phase 1 | — |

## Améliorations identifiées

- **Fortinet : CVE et `affected` depuis le CSAF.** Le flux RSS ne cite la CVE que pour 4 avis
  sur 50. Chaque entrée renvoie vers un document CSAF officiel (`csaf_link`), qui contient les
  CVE et les produits et versions touchés. Le télécharger pour les seuls avis nouveaux, comme
  le fait le CERT-FR.
- **OpenSSH : `security_fix`.** Les tags ne disent pas si une version corrige une faille. La
  page `security.html` d'OpenSSH le dit, mais c'est du HTML : à évaluer selon la règle « pas de
  scraping ».
- **FortiOS : `security_fix`.** Le croiser avec les avis FortiGuard une fois les versions
  corrigées connues (CSAF).
- **Cisco IOS XE et Stormshield : dernière version.** endoflife.date ne la donne pas ; chercher
  une source éditeur structurée.
- **CERT-FR : `affected`.** Les systèmes touchés sont du texte libre (« FortiOS versions 7.4.x
  antérieures à 7.4.9 »). Une correspondance prudente vers les branches suivies reste possible,
  mais seulement avec des règles explicites et testées.
- **Historique initial des versions.** Les flux Atom d'OpenSSH et d'httpd n'exposent que
  les 10 derniers tags. L'historique se construit au fil des passages ; on pourrait l'amorcer
  une fois par `overrides.yaml`.
