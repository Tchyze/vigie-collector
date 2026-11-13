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
| Cisco openVuln API | demande une authentification OAuth2 (compte Cisco gratuit, application déclarée dans l'API Console) ; `OS_version/OS_data` ne donne que des numéros de version, sans date | seule source structurée des premières versions corrigées par avis ; à reconsidérer si une connexion devient acceptable |
| Cisco CSAF (`www.cisco.com/.well-known/csaf/`) : versions IOS XE | public et structuré, mais `product_status` ne contient que `known_affected` : ni version corrigée, ni date de sortie | inutilisable pour la dernière version ; à revérifier si Cisco ajoute `fixed` |
| Stormshield SNS : versions | le flux RSS des versions (`mystormshield.eu/product/rss/sns`) redirige vers la connexion MyStormshield ; la documentation ne liste les versions qu'en HTML, sans date | flux MyStormshield avec un compte, ou page « Previous versions » de la documentation (scraping) |
| Scraping des notes de version | fragile, exclu en phase 1 | — |

## Améliorations identifiées

- **OpenSSH : `security_fix`.** Les tags ne disent pas si une version corrige une faille. La
  page `security.html` d'OpenSSH le dit, mais c'est du HTML : à évaluer selon la règle « pas de
  scraping ».
- **Fortinet : avis sortis du flux.** Le CSAF n'est lu que pour les avis encore présents dans
  le flux RSS (50 derniers). Les avis plus anciens gardés dans l'historique n'ont pas de CVE ;
  leur URL CSAF n'est pas prévisible (elle contient le titre).
- **Cisco IOS XE et Stormshield : dernière version.** endoflife.date ne la donne pas (aucune
  version dans ses données pour `cisco-ios-xe` et `sns-firmware`). Recherche de novembre 2026 :
  aucune source publique, structurée et sans connexion ne donne les versions publiées avec leur
  date. Pistes testées et écartées :
  - Cisco CSAF : uniquement les versions vulnérables (`known_affected`), sans version corrigée ni
    date ; la plus haute version vulnérable d'une branche n'est pas la dernière version.
  - Cisco openVuln : OAuth2 ; donne les premières versions corrigées par avis, sans date de
    sortie ni dernière version par branche.
  - Stormshield : le flux RSS des versions SNS est derrière la connexion MyStormshield ; les pages
    « Previous versions » de la documentation (v4, v5) listent les versions mais sont du HTML
    sans date ; la matrice de cycle de vie ne donne que les branches ; le flux des avis n'a
    aucun numéro de version.

  Tant qu'une règle n'est pas assouplie (connexion ou HTML), `latest_version` reste `null` pour
  ces deux produits et l'application affiche « Version inconnue ».
- **CERT-FR : `affected`.** Les systèmes touchés sont du texte libre (« FortiOS versions 7.4.x
  antérieures à 7.4.9 »). Une correspondance prudente vers les branches suivies reste possible,
  mais seulement avec des règles explicites et testées.
- **Historique initial des versions.** Les flux Atom d'OpenSSH et d'httpd n'exposent que
  les 10 derniers tags. L'historique se construit au fil des passages ; on pourrait l'amorcer
  une fois par `overrides.yaml`.
