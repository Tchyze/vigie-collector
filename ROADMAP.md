# Feuille de route

La phase 1 ne couvre que des sources publiques, structurées et sans authentification. Les points
ci-dessous viendront plus tard, ou attendent une source exploitable.

## Sources écartées pour l'instant

| Sujet | Raison | Piste |
|---|---|---|
| HPE Aruba (CSAF) | les bulletins réseau HPE sont repris du flux RSS HPE, sans versions | csaf.arubanetworking.hpe.com publie des CSAF (index `changes.csv`) : versions AOS touchées |
| Dell et HPE : fins de support | dates Dell saisies dans overrides.yaml (iDRAC8, iDRAC9 14G) ; aucune date officielle HPE pour iLO | ajouter iDRAC9 15G/16G et iLO quand l'éditeur publie des dates |
| VMware : versions touchées | la liste Broadcom ne donne que les produits | l'avis complet est une page du portail (HTML) |
| Stormshield : CVE et versions | le flux RSS n'a ni description ni CVE ; le détail n'est que dans la page HTML de l'avis | le CERT-FR reprend les avis Stormshield avec leurs CVE |
| Dell : autres firmwares (BIOS, PERC…) | un composant par modèle de serveur, trop fin pour des branches | le catalogue Dell les contient s'il faut les suivre |
| Red Hat et Rocky : avis « important » | des milliers par an | seuls les avis critiques sont repris ; un filtre par composant (noyau, OpenSSH, OpenSSL…) pourrait en ajouter |
| Stormshield SNS : versions | le flux RSS des versions (`mystormshield.eu/product/rss/sns`) redirige vers la connexion MyStormshield ; la documentation ne liste les versions qu'en HTML, sans date | flux MyStormshield avec un compte, ou page « Previous versions » de la documentation (scraping) |
| Scraping des notes de version | fragile, exclu en phase 1 | — |

## Améliorations identifiées

- **OpenSSH : `security_fix`.** Les tags ne disent pas si une version corrige une faille. La
  page `security.html` d'OpenSSH le dit, mais c'est du HTML : à évaluer selon la règle « pas de
  scraping ».
- **Fortinet : avis sortis du flux.** Le CSAF n'est lu que pour les avis encore présents dans
  le flux RSS (50 derniers). Les avis plus anciens gardés dans l'historique n'ont pas de CVE ;
  leur URL CSAF n'est pas prévisible (elle contient le titre).
- **Stormshield : dernière version.** endoflife.date ne la donne pas (aucune version dans ses
  données pour `sns-firmware`). Recherche de novembre 2026 : aucune source publique, structurée
  et sans connexion ne donne les versions SNS publiées. Pistes testées et écartées :
  - le flux RSS des versions SNS (`mystormshield.eu/product/rss/sns`, lié depuis la
    documentation) redirige vers la connexion MyStormshield ;
  - les pages « Previous versions » de la documentation (v4, v5) listent les versions
    (4.8.19 LTSB, 5.1.3 EA…) mais sont du HTML, sans date ;
  - la matrice de cycle de vie ne donne que les branches ; le flux des avis n'a aucun numéro de
    version.

  Tant qu'une règle n'est pas assouplie (connexion ou HTML), `latest_version` reste `null` pour
  Stormshield et l'application affiche « Version inconnue ».
- **Cisco IOS XE : dates de publication et `security_fix` complet.** `OS_data` ne date pas les
  versions, et seule la première version de chaque branche est interrogée. Le CSAF de Cisco
  n'aide pas : `product_status` n'y contient que `known_affected`, sans version corrigée ni date.
- **CERT-FR : `affected`.** Les systèmes touchés sont du texte libre (« FortiOS versions 7.4.x
  antérieures à 7.4.9 »). Une correspondance prudente vers les branches suivies reste possible,
  mais seulement avec des règles explicites et testées.
- **Historique initial des versions.** Les flux Atom d'OpenSSH et d'httpd n'exposent que
  les 10 derniers tags. L'historique se construit au fil des passages ; on pourrait l'amorcer
  une fois par `overrides.yaml`.
