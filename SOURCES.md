# Sources de Vigie — étude du 2026-11-13

Phase d'étude : ce document recommande, pour chaque produit et chaque type de donnée, la
meilleure source fiable, vérifiable et automatisable. Aucun collecteur n'a été modifié.

- Version machine : [`sources.yaml`](sources.yaml) (une entrée par source).
- Proposition de réorganisation des produits : [`etude-sources/REORGANISATION.md`](etude-sources/REORGANISATION.md).
- Tests d'accès : [`etude-sources/RESULTATS.md`](etude-sources/RESULTATS.md) (session et GitHub Actions),
  sonde [`etude-sources/probe.py`](etude-sources/probe.py), liste [`etude-sources/candidats.tsv`](etude-sources/candidats.tsv),
  workflow [`.github/workflows/etude-sources.yml`](.github/workflows/etude-sources.yml).

## Légende

| Type | Donnée |
|---|---|
| **A** | branches et dates de fin de support (support actif, correctifs de sécurité, fin de vie, support étendu) |
| **B** | dernière version de chaque branche, avec sa date |
| **C** | avis de sécurité : CVE, sévérité, branches touchées, versions corrigées |
| **D** | `security_fix` : « cette version corrige des failles » |

Niveau de confiance : **éditeur** (publié par l'éditeur), **référence** (CERT-FR, NVD, CVE.org,
OSV, CISA), **communautaire** (endoflife.date). Accès : code HTTP obtenu le 2026-11-13 depuis la
session (S) et depuis un runner GitHub Actions (GH). « ✔ » = 200 et contenu attendu.

## Constats transverses

1. **Les enregistrements CVE des éditeurs (CVE.org) comblent la plupart des trous d'avis.**
   Dell, HPE, VMware, Fortinet, Palo Alto, Cisco, F5 (nginx), l'ASF (httpd), Red Hat, Canonical
   et Microsoft sont autorités de numérotation (CNA) ; Stormshield passe par le CNA d'Airbus.
   L'enregistrement CVE publié par le CNA contient les produits, les versions touchées, souvent
   les versions corrigées, le score CVSS et le lien vers l'avis de l'éditeur. Exemple Dell :
   `CVE-2026-23855` → iDRAC9 14G < 7.00.00.184, 15G/16G < 7.30.10.50, iDRAC10 < 1.30.30.50, lien
   DSA-2026-392. L'API CVE.org (`cveawg.mitre.org/api/cve/<id>`) n'a pas de recherche : la
   **découverte** se fait par l'API NVD 2.0 (`sourceIdentifier=<adresse du CNA>` ou
   `keywordSearch`, fenêtre de 120 jours), puis le détail par CVE.org.
2. **OSV publie DSA, USN et RLSA en incrémental.** `modified_id.csv` (3,5 Mo pour Debian et
   Ubuntu, 0,2 Mo pour Rocky) donne la date de modification de chaque avis ; chaque avis est un
   JSON de quelques Ko. Cela remplace l'API `ubuntu.com/security/notices.json` (rafales de 503)
   sans télécharger l'archive complète (Ubuntu : 816 Mo, Debian : 82 Mo). Le flux **Red Hat**
   d'OSV est en retard (dernière modification : 2026-10-20) : ne pas l'utiliser.
3. **Le CSAF éditeur existe chez Cisco, Microsoft, Palo Alto (par CVE), Fortinet (par avis, URL
   donnée par le RSS), Red Hat et HPE Aruba.** Pas de CSAF chez Dell, HPE (serveurs), Broadcom
   (portail protégé par Cloudflare), Stormshield, Rocky.
4. **OVAL** reste la façon la plus compacte d'avoir *tous* les avis d'une version d'OS : RHEL 9
   (1,5 Mo compressé, 2 406 RHSA avec sévérité, CVE, date), Ubuntu 24.04 (1,6 Mo), Debian 12
   (9,5 Mo). Mais Red Hat **ne publie pas d'OVAL v2 pour RHEL 10** (répertoires RHEL5 à RHEL9
   seulement) : l'OVAL n'est qu'un secours pour RHEL.
5. **CISA KEV** (1 779 failles exploitées, mis à jour le 2026-11-10, domaine public) permet de
   marquer les CVE activement exploitées, tous éditeurs confondus — information absente
   aujourd'hui.
6. **endoflife.date dépend de pages HTML d'éditeurs** qu'il analyse lui-même (Palo Alto,
   Stormshield, Proxmox, Rocky, Ubuntu) ou de saisies manuelles (FortiOS, Cisco, Windows Server,
   VMware). Vigie ne lit que son API JSON : la règle « pas de HTML » est respectée, mais la
   source est communautaire et doit être marquée comme telle, avec la source éditeur dont elle
   dépend.
7. **Depuis GitHub Actions**, tout ce qui répond à la session répond aussi au runner, avec trois
   différences : `download.proxmox.com` n'a pas de certificat HTTPS valide (HTTP seulement), les
   anciens hôtes VMware (`hostupdate.vmware.com`, `vapp-updates.vmware.com`) n'existent plus en
   DNS, et la page HTML de FortiGuard renvoie 429 (non utilisée). Surtout, **l'API NVD est
   instable depuis le runner** (2 délais dépassés et un 503 sur 7 requêtes) : elle ne peut servir
   qu'à la découverte, avec nouvel essai, jamais comme source bloquante. Les API GitHub non
   authentifiées sont limitées à 60 requêtes/heure **par adresse IP partagée** du runner : le
   collecteur doit passer le `GITHUB_TOKEN` du workflow (1 000/heure, sans secret à créer).

## Synthèse par produit

| Produit | A — fins de support | B — dernière version | C — avis | D — security_fix |
|---|---|---|---|---|
| FortiOS | endoflife.date (communautaire, saisie manuelle) — **aucune source éditeur automatisable** | flux firmware Fortinet ✔ | RSS FortiGuard + CSAF ✔ ; historique : CVE.org (CNA Fortinet) | CSAF (versions corrigées) ✔ |
| PAN-OS | endoflife.date (analyse de la page EoL Palo Alto) ; **support étendu manquant** | endoflife.date ; secours : versions corrigées de l'API sécurité | API JSON sécurité ✔ + CSAF VEX / CVE 5 par CVE ✔ | API JSON (`fixed`) ✔ |
| Stormshield SNS | endoflife.date (analyse de la matrice Stormshield) | **aucune source fiable** | RSS Stormshield (signal) + **CVE.org** (CNA Airbus : versions touchées et corrigées) ✔ | CVE.org (`unaffected`) partiel |
| Cisco IOS XE | endoflife.date (bulletins EoL ; projections pour les branches sans bulletin) | **aucune source sans clé** (openVuln, OAuth) | **CSAF Cisco** (`changes.csv`) ✔ ; RSS en signal | **aucune source sans clé** (versions corrigées : openVuln) |
| Debian | **distro-info-data** (Debian) ✔ | fichiers `Release` des suites ✔ | liste DSA (salsa) ✔ ; secours OSV, OVAL | aucune (non pertinent) |
| Ubuntu | **distro-info-data** (ubuntu.csv) ✔ | `meta-release-lts` (version) ✔ — date du point release absente | **OSV (USN) incrémental** ✔ ; secours OVAL, notices.json | aucune (non pertinent) |
| RHEL | **API Product Life Cycles** Red Hat ✔ | endoflife.date (version mineure) — pas de source éditeur structurée | **API Security Data (hydra)** ✔ ; secours OVAL v2 (RHEL 8 et 9 seulement) | aucune (non pertinent) |
| Rocky Linux | endoflife.date ; source éditeur : tableau Markdown du dépôt `rocky-linux/documentation` | `.treeinfo` du dépôt officiel ✔ + date (documentation) | **OSV (RLSA) incrémental** ✔ ; secours API errata v2 | aucune (non pertinent) |
| Windows Server | endoflife.date (saisie manuelle d'après Microsoft Learn, page HTML seulement) | **CVRF/CSAF MSRC** : build corrigé de chaque version ✔ | CVRF MSRC ✔ ; complément CSAF MSRC par CVE | CVRF/CSAF ✔ |
| VMware ESXi / vCenter | endoflife.date (saisie manuelle ; portail Broadcom protégé) | endoflife.date ; partiel : builds corrigés des enregistrements CVE | API POST non documentée Broadcom ; **secours CVE.org** (CNA VMware : builds corrigés) ✔ | CVE.org partiel |
| Proxmox VE | **pve-docs (git Proxmox)**, au mois près ; endoflife.date en secours | changelog `pve-manager` (git Proxmox) ✔ ; endoflife.date | **aucune source structurée** (RSS forum = signal) ; CVE via NVD/CERT-FR | **aucune** |
| nginx | endoflife.date (règle : fin quand la stable suivante sort) | `versions.xml` (dépôt nginx.org) + CHANGES ✔ | **`security_advisories.xml`** (dépôt nginx.org) ✔ | CHANGES (« Security: ») ✔ |
| Apache httpd | endoflife.date (une seule branche 2.4) | **projects.apache.org** `releases.json` ✔ ; CHANGES_2.4 | **JSON CVE 5 de httpd.apache.org** ✔ | CHANGES_2.4 (« SECURITY: ») ✔ |
| OpenSSH | sans objet (seule la dernière version est maintenue) | tags GitHub ✔ + notes de version texte (date) ✔ | **aucun flux éditeur** ; section « Security » des notes texte + CVE.org | notes de version texte ✔ |
| Dell iDRAC | **aucune source automatisable** (KB Dell : 403) → `overrides.yaml` | Catalog.xml.gz ✔ | **CVE.org (CNA Dell)** ✔ via NVD | CVE.org (versions corrigées) ✔ |
| HPE iLO | **aucune source** (HPE ne publie pas de date) | fwrepo.json SDR ✔ | RSS bulletins HPE ✔ + CVE.org (CNA HPE : versions touchées) | **aucune** (versions corrigées absentes des CVE HPE) |
| CERT-FR | — | — | RSS + JSON par avis ✔ (`affected_systems` structuré : éditeur, produit) | — |

## Détail par produit

Chaque tableau donne la source recommandée (R) puis les secours (S) et les sources écartées (✗).

### FortiOS (Fortinet)

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | endoflife.date | `https://endoflife.date/api/v1/products/fortios` | JSON | ✔ / ✔ | saisie manuelle ; 7.4 à jour du bulletin CSB-260330-1 (report d'un an) | communautaire ; dépend du portail Fortinet |
| A — ✗ | Product Life Cycle Fortinet | `https://support.fortinet.com/Information/ProductLifeCycle.aspx` | application web | 200 mais page de connexion avec hCaptcha | — | éditeur, **inaccessible** |
| B — R | flux firmware Fortinet | `https://support.fortinet.com/rss/firmware.xml` | RSS | ✔ / ✔ | 78 images, 2026-08-13 → 2026-11-10 (toutes gammes ; 7 FortiOS) | éditeur |
| C — R | flux PSIRT FortiGuard | `https://www.fortiguard.com/rss/ir.xml` (→ filestore.fortinet.com) | RSS | ✔ / ✔ | 50 avis : **3 jours seulement** (2026-11-10 → 13, publication groupée) | éditeur |
| C — R | CSAF par avis | URL donnée par `csaf:link` dans le RSS | CSAF 2.0 | ✔ / ✔ | 5 Ko par avis ; URL non prévisible (contient le titre) | éditeur |
| C — S | CVE.org (CNA Fortinet) | NVD `sourceIdentifier=psirt@fortinet.com` puis `cveawg.mitre.org/api/cve/<id>` | JSON CVE 5 | ✔ / ✔ | tout l'historique | référence ; permet d'amorcer l'historique perdu du RSS |
| D — R | CSAF (`known_not_affected` → versions corrigées) | idem | CSAF | ✔ | — | éditeur |

Fortinet n'a pas de `provider-metadata.json` CSAF (404 sur fortiguard.com et filestore).

### PAN-OS (Palo Alto Networks)

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | endoflife.date | `.../products/panos` | JSON | ✔ / ✔ | analyse automatique de la page EoL Palo Alto | communautaire |
| A — ✗ | End-of-Life Summary | `https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary` | HTML | ✔ / ✔ | contient la colonne « Extended Support » absente d'endoflife.date | éditeur, HTML |
| B — R | endoflife.date (`latest`, hotfixes `-hN` compris) | idem | JSON | ✔ | 12.2.4-h2 du 2026-11-10 | communautaire (notes de version Palo Alto) |
| C — R | API sécurité | `https://security.paloaltonetworks.com/json/?limit=100&sort=-updated&page=N` | JSON | ✔ / ✔ | 100 avis par page (`limit` > 100 → page d'erreur) ; page 1 couvre 6 mois ; historique depuis 2016 au moins | éditeur, non documentée formellement |
| C — S | CSAF VEX et CVE 5 par CVE | `https://security.paloaltonetworks.com/csaf/<CVE>` · `/json/<CVE>` | CSAF 2.1 · CVE 5 | ✔ / ✔ | 5 Ko · 22 Ko | éditeur ; pas de `provider-metadata.json` |
| D — R | champ `fixed` de l'API (`>= 12.2.4-h2`) | idem | JSON | ✔ | — | éditeur |

Pièges : l'API refuse `limit=500` (page HTML d'erreur avec code 200) et les identifiants
`PAN-SA-…` n'ont pas de CSAF (`500 Failed to generate CSAF`) : seuls les avis par CVE en ont.

### Stormshield SNS

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | endoflife.date | `.../products/sns-firmware` | JSON | ✔ / ✔ | identique à la matrice éditeur (4.3, 4.8, 5.0) | communautaire ; dépend de la matrice HTML Stormshield |
| A — ✗ | matrice du cycle de vie | `https://documentation.stormshield.eu/PLC/SNS/en/Content/SNS_Product_Life_Cycle/Matrices_firmwares.htm` | HTML | ✔ | — | éditeur, HTML |
| B — ✗ | — | notes de version HTML ; portail MyStormshield sous connexion | — | — | — | **aucune source fiable** |
| C — R | CVE.org (CNA Airbus, produit « Stormshield Network Security ») | NVD `sourceIdentifier=cert@airbus.com` (49 CVE) puis CVE.org | JSON CVE 5 | ✔ / ✔ | versions touchées **et** corrigées (`unaffected`), CVSS, lien advisories.stormshield.eu | référence (données du CNA) ; NVD ne les analyse pas (« Deferred ») |
| C — R | flux RSS des avis | `https://advisories.stormshield.eu/feed/` | RSS | ✔ / ✔ | 10 avis (2026-10-16 → 10-30), sans description | éditeur, signal de publication |
| D — partiel | versions `unaffected` des CVE | idem | — | — | — | référence |

Ni CSAF, ni API WordPress (`/wp-json` : 404).

### Cisco IOS XE

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | endoflife.date | `.../products/cisco-ios-xe` | JSON | ✔ / ✔ | saisie manuelle d'après les bulletins EoL ; **projections** pour les branches sans bulletin (17.18, 26.1) | communautaire |
| A — ✗ | bulletins EoL | `https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-17/ios-xe-17-9-x-eol.html` | HTML | ✔ | — | éditeur, HTML |
| B — clé | openVuln API (`/OS_version/OS_data`) | `https://apix.cisco.com/security/advisories/v2/...` | JSON | 403 sans jeton / idem | — | éditeur ; **OAuth (client credentials)** |
| C — R | CSAF Cisco | `https://www.cisco.com/.well-known/csaf/changes.csv` + `/.well-known/csaf/<année>/<id>.json` | CSAF 2.0 (`csaf_trusted_provider`) | ✔ / ✔ | 2 892 avis depuis 2017, mis à jour le jour même ; jusqu'à 580 Ko par avis | éditeur |
| C — S | flux RSS | `https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml` | RSS | ✔ / ✔ | 50 avis (2026-09-23 → 11-12) | éditeur |
| D — clé | openVuln (versions corrigées, « Software Checker ») | idem | JSON | — | — | **pas de version corrigée dans le CSAF** (`known_affected` uniquement) |

Le CSAF liste les versions IOS XE touchées une à une (601 dans l'avis de durcissement d'août
2026) : la branche se déduit sans ambiguïté (`17.9.4a` → 17.9). Mention de source et usage non
commercial : inchangés.

### Debian

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | distro-info-data | `https://salsa.debian.org/debian/distro-info-data/-/raw/main/debian.csv` | CSV (dépôt git) | ✔ / ✔ | `release`, `eol`, `eol-lts`, `eol-elts` depuis 1993 | éditeur (paquet Debian) ; concorde avec endoflife.date (11, 12, 13) |
| A — S | endoflife.date | `.../products/debian` | JSON | ✔ | — | communautaire |
| B — R | fichier `Release` de chaque suite | `https://deb.debian.org/debian/dists/<suite>/Release` | texte RFC 822 | ✔ / ✔ | `Version: 12.15`, `Date:` du point release | éditeur |
| C — R | liste DSA | `https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list` | texte (git) | ✔ / ✔ | DSA-6624-1 du 2026-11-13 ; 1,2 Mo, tout l'historique | éditeur |
| C — S | OSV Debian | `https://osv-vulnerabilities.storage.googleapis.com/Debian/modified_id.csv` + `/Debian/<DSA>.json` | OSV | ✔ / ✔ | 6 246 DSA, 4 701 DLA ; à jour du jour | référence (données Debian) |
| C — S | OVAL | `https://www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2` | OVAL | ✔ / ✔ | 9,5 Mo | éditeur |
| ✗ | JSON du security tracker | `https://security-tracker.debian.org/tracker/data/json` | JSON | ✔ | **85 Mo** | trop volumineux |

### Ubuntu

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | distro-info-data | `https://salsa.debian.org/debian/distro-info-data/-/raw/main/ubuntu.csv` | CSV | ✔ / ✔ | `eol`, `eol-server`, `eol-esm`, `eol-legacy` | éditeur (paquet utilisé par Ubuntu) ; concorde avec endoflife.date |
| B — R | meta-release-lts | `https://changelogs.ubuntu.com/meta-release-lts` (et `meta-release`) | texte RFC 822 | ✔ / ✔ (4 à 5 s parfois) | `Version: 24.04.5 LTS` ; la `Date` est celle de la version initiale, **pas** du point release | éditeur |
| C — R | OSV Ubuntu (USN) | `https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/modified_id.csv` + `/Ubuntu/USN-<n>.json` | OSV | ✔ / ✔ | 8 382 USN depuis 2010, modifié le jour même ; CVE, versions corrigées par release | référence (données Canonical) |
| C — S | OVAL USN par release | `https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2` | OVAL | ✔ / ✔ | 1,6 Mo | éditeur |
| C — S | dépôt git `canonical/ubuntu-security-notices` (`osv/usn/`) | `https://api.github.com/repos/canonical/ubuntu-security-notices/...` | OSV (git) | session : non testable / ✔ | — | éditeur |
| C — actuelle | API notices.json | `https://ubuntu.com/security/notices.json?limit=20&offset=N` | JSON | ✔ / ✔ | 20 avis par page, 503 en rafale | éditeur — **à remplacer** |
| ✗ | archive OSV complète | `https://security-metadata.canonical.com/osv/osv-all.tar.xz` | tar.xz | ✔ | **60 Mo** | trop volumineux |

### Red Hat Enterprise Linux

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | API Product Life Cycles | `https://access.redhat.com/product-life-cycles/api/v1/products?name=Red%20Hat%20Enterprise%20Linux` | JSON | ✔ / ✔ | GA, Full support, Maintenance, ELS par version majeure ; v2 ajoute `final_minor_release` | éditeur ; c'est la source d'endoflife.date ; concorde (8, 9, 10) |
| B — R | endoflife.date (`latest` : 10.3, 9.9 du 2026-11-11) | `.../products/rhel` | JSON | ✔ | — | communautaire ; **pas de source éditeur structurée** pour les versions mineures |
| C — R | API Security Data (hydra, actuelle) | `https://access.redhat.com/hydra/rest/securitydata/csaf.json?severity=critical&after=…` | JSON | ✔ / ✔ | filtrable par sévérité et date ; RHSA-2026:99950 du 2026-11-12 | éditeur, documentée |
| C — S | OVAL v2 par version majeure | `https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2` | OVAL | ✔ / ✔ | 1,5 Mo (36 Mo décompressé) ; 2 406 RHSA, sévérité, CVE, date ; à jour de la veille ; **pas de RHEL 10** (404) | éditeur, CC BY 4.0 |
| ✗ | CSAF par avis | `https://security.access.redhat.com/data/csaf/v2/advisories/changes.csv` | CSAF | ✔ | 31 942 avis, ~2 Mo chacun | trop volumineux |
| ✗ | OSV « Red Hat » | bucket OSV | OSV | ✔ | **dernière modification 2026-10-20** | en retard |

### Rocky Linux

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | endoflife.date | `.../products/rocky-linux` | JSON | ✔ / ✔ | concorde | communautaire ; dépend de docs.rockylinux.org/releases |
| A — S | tableau des versions de la documentation | `https://raw.githubusercontent.com/rocky-linux/documentation/main/docs/releases/index.md` | Markdown (dépôt git) | ✔ / ✔ | à jour (10.2 du 2026-05-29) ; **le wiki `version.md` est en retard** (10.1) | éditeur ; tableau Markdown : à analyser prudemment |
| B — R | `.treeinfo` du dépôt officiel | `https://dl.rockylinux.org/pub/rocky/<majeure>/BaseOS/x86_64/os/.treeinfo` | INI | ✔ / ✔ | `version = 9.8`, `timestamp` | éditeur |
| C — R | OSV Rocky Linux | `https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/modified_id.csv` + `/<RLSA>.json` | OSV | ✔ / ✔ | 4 818 RLSA depuis 2025-05, à jour du jour ; sévérité dans le titre, CC BY 4.0 | référence (données Rocky) |
| C — S | API errata v2 | `https://errata.rockylinux.org/api/v2/advisories?...` | JSON | ✔ / ✔ | 172 Ko pour 2 avis (réponse lourde) | éditeur |
| C — S | API Apollo v3 | `https://apollo.build.resf.org/api/v3/advisories/` | JSON | ✔ / ✔ (0,3 s ce jour) | — | éditeur ; délais et 500 constatés auparavant |

### Windows Server (Microsoft)

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | endoflife.date | `.../products/windows-server` | JSON | ✔ / ✔ | concorde avec Microsoft Learn sauf ESU 2016 (voir recoupement) | communautaire ; saisie manuelle |
| A — ✗ | Microsoft Learn Lifecycle | `https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2022` | HTML | ✔ / ✔ | aucune API (`/api/lifecycle` : 404) | éditeur, HTML |
| B — R | CVRF MSRC (build corrigé par version et KB) | `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<AAAA-Mmm>` | CVRF JSON | ✔ / ✔ | 18 à 27 Mo par mois (novembre 2026 : 27 Mo) | éditeur, documentée |
| C — R | CVRF MSRC | idem | CVRF | ✔ / ✔ | depuis 2016 | éditeur |
| C — S | CSAF MSRC par CVE | `https://msrc.microsoft.com/csaf/advisories/changes.csv` + `/<année>/msrc_cve-<id>.json` | CSAF 2.0 | ✔ / ✔ (un 502 ponctuel) | 10 145 documents depuis 2019 ; 23 à 40 Ko chacun ; ~1 180 modifiés au Patch Tuesday | éditeur ; versions « Windows Server 2022 < 10.0.20348.2700 », KB, exploitation |
| D — R | `vendor_fix` (build + KB) | CVRF ou CSAF | — | — | — | éditeur |
| ✗ | flux Atom de l'historique des mises à jour | support.microsoft.com | Atom | **410 Gone** | — | arrêté |

### VMware ESXi et vCenter (Broadcom)

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | endoflife.date | `.../products/esxi`, `.../products/vcenter` | JSON | ✔ / ✔ | `technicalGuidance` en champ personnalisé | communautaire ; saisie manuelle |
| A — ✗ | Product Lifecycle Broadcom | `https://support.broadcom.com/web/ecx/productlifecycle` | portail | **403 « Just a moment… » (Cloudflare)** | — | éditeur, protégé |
| B — R | endoflife.date (`8.0 Update 3k`) | idem | JSON | ✔ | — | communautaire |
| B — ✗ | dépôts de mise à jour | `hostupdate.vmware.com`, `vapp-updates.vmware.com` (DNS supprimé), `dl.broadcom.com` (403 « Invalid token ») | XML | ✗ | — | jeton de téléchargement nominatif |
| C — actuelle | liste VMSA du portail | `POST https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList` | JSON | ✔ / ✔ | 342 avis ; sévérité, CVE, produits | éditeur, **non documentée** |
| C — S | CVE.org (CNA VMware) | NVD `sourceIdentifier=security@vmware.com` puis CVE.org | CVE 5 | ✔ / ✔ | builds corrigés par branche (`ESXi80U3f-24784735`), lien vers l'avis Broadcom | référence |
| ✗ | CSAF Broadcom | `/.well-known/csaf/…` | — | 403 Cloudflare / 404 | — | — |

### Proxmox VE

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | FAQ de pve-docs (source du wiki) | `https://git.proxmox.com/?p=pve-docs.git;a=blob_plain;f=pve-faq.adoc;hb=HEAD` | AsciiDoc (tableau, dépôt git) | ✔ / ✔ | dates **au mois** (« 2026-08 ») | éditeur |
| A — S | endoflife.date | `.../products/proxmox-ve` | JSON | ✔ / ✔ | prend le dernier jour du mois | communautaire |
| B — R | changelog de `pve-manager` | `https://git.proxmox.com/?p=pve-manager.git;a=blob_plain;f=debian/changelog;hb=HEAD` (branche 8 : `hb=refs/heads/stable-8`) | changelog Debian | ✔ / ✔ | 9.2.27 du 2026-11-10 | éditeur ; version du paquet ≠ nom commercial du point release (9.2) |
| B — S | index APT | `http://download.proxmox.com/debian/pve/dists/trixie/pve-no-subscription/binary-amd64/Packages` | Packages | HTTPS : certificat invalide ; HTTP ✔ depuis GH | 2,3 Mo | éditeur ; HTTP seulement (fichier `Release` signé GPG) |
| C — ✗ | forum « Security Advisories » | `https://forum.proxmox.com/forums/security-advisories.26/index.rss` | RSS | ✔ / ✔ | un fil par produit : seule la date du dernier message | **signal seulement** ; détail en HTML |
| C | — | — | — | — | — | **aucune source structurée** ; CVE via NVD (`cpe:…:proxmox:virtual_environment`, 8 CVE) et CERT-FR |

### nginx

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | endoflife.date | `.../products/nginx` | JSON | ✔ / ✔ | règle : une stable finit quand la suivante sort | communautaire (politique nginx) |
| B — R | CHANGES (actuel) | `https://nginx.org/en/CHANGES`, `CHANGES-1.<pair>` | texte | ✔ / ✔ | dates par version | éditeur |
| B — S | `versions.xml` du dépôt du site | `https://raw.githubusercontent.com/nginx/nginx.org/main/xml/versions.xml` | XML (git) | ✔ / ✔ | mainline et stable | éditeur |
| C — R | `security_advisories.xml` | `https://raw.githubusercontent.com/nginx/nginx.org/main/xml/en/security_advisories.xml` | XML (git) | ✔ / ✔ | 68 avis : nom, sévérité, CVE, `vulnerable`, `good`, lien F5 ; **sans date** (date par l'historique git ou CHANGES) | éditeur |
| D — R | CHANGES (« Security: ») | idem B | texte | ✔ | — | éditeur |

nginx/nginx n'a aucun avis GitHub (`security-advisories` : liste vide).

### Apache HTTP Server

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A — R | endoflife.date | `.../products/apache-http-server` | JSON | ✔ / ✔ | 2.4 seule branche | communautaire |
| B — R | releases.json de l'ASF | `https://projects.apache.org/json/foundation/releases.json` (clé `httpd`) | JSON | ✔ / ✔ | 236 versions ; **2.4.71 du 2026-11-11** (endoflife.date : encore 2.4.70) | éditeur |
| B — S | CHANGES_2.4 et tags GitHub (actuels) | `https://downloads.apache.org/httpd/CHANGES_2.4`, `https://github.com/apache/httpd/tags.atom` | texte, Atom | ✔ / ✔ | — | éditeur |
| C — R | JSON CVE 5 du site httpd | `https://httpd.apache.org/security/json/CVE-<id>.json` | CVE 5 | ✔ / ✔ | 291 fichiers ; index = listing Apache (HTML simple) ou API GitHub de `apache/httpd-site` | éditeur |
| D — R | CHANGES_2.4 (« SECURITY: CVE-… ») | idem | texte | ✔ | — | éditeur |

### OpenSSH

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A | sans objet | — | — | — | seule la dernière version est maintenue | — |
| B — R | tags `openssh-portable` | `https://github.com/openssh/openssh-portable/tags.atom` ; historique complet : `https://api.github.com/repos/openssh/openssh-portable/git/refs/tags` | Atom, JSON | GitHub non testable depuis la session / ✔ | 10 derniers tags (Atom) | éditeur (miroir officiel) |
| B — R | notes de version | `https://www.openssh.org/txt/release-<version>` | texte | ✔ / ✔ | 1re ligne : « … was released on AAAA-MM-JJ » | éditeur |
| C — partiel | section « Security » des notes ; CVE.org / NVD (`cpe:…:openbsd:openssh`, 147 CVE) | idem | texte, CVE 5 | ✔ | — | éditeur / référence ; **aucun flux d'avis** |
| D — R | section « Security » présente dans la note | idem | texte | ✔ | 10.4 à 10.6p2 en ont une | éditeur |
| ✗ | page security.html | `https://www.openssh.com/security.html` | HTML | ✔ | — | HTML |

### Dell iDRAC

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A | **aucune source automatisable** | KB 000178044 / 000178016 | HTML | **403** / 403 | — | saisie manuelle dans `overrides.yaml` (à garder) |
| B — R | catalogue Dell | `https://downloads.dell.com/catalog/Catalog.xml.gz` | XML gzip | ✔ / ✔ | 1,4 Mo, modifié le 2026-11-06 | éditeur |
| C — R | CVE.org (CNA Dell) | NVD `keywordSearch=iDRAC` (62 CVE, source `security_alert@emc.com`) puis CVE.org | CVE 5 | ✔ / ✔ | séries touchées et versions corrigées, lien DSA ; `lessThan` contient parfois « or later » | référence (données Dell) |
| C — S | CERT-FR | JSON par avis (`affected_systems.product.vendor.name = "Dell"`) | JSON | ✔ | — | référence |
| D — R | versions corrigées des CVE | idem | — | — | — | référence |
| ✗ | DSA, RSS, CSAF Dell | dell.com/support/security… ; `/.well-known/csaf/` redirige vers l'accueil | — | 403 | — | — |

### HPE iLO

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| A | **aucune source** | HPE ne publie pas de date de fin pour iLO (seulement pour les serveurs) | — | — | — | trou confirmé |
| B — R | index SDR | `https://downloads.linux.hpe.com/SDR/repo/fwpp-gen1{0,1,2}/current/fwrepodata/fwrepo.json` | JSON | ✔ / ✔ | 27 paquets iLO dans gen12 | éditeur |
| C — R | flux des bulletins | `https://support.hpe.com/hpesc/public/api/document/sec_bull_rss_feed` | RSS | ✔ / ✔ | 50 bulletins (2026-09-04 → 11-11), tous produits | éditeur |
| C — S | CVE.org (CNA HPE) | NVD `sourceIdentifier=security-alert@hpe.com` / `keywordSearch=Integrated Lights-Out` (61) puis CVE.org | CVE 5 | ✔ / ✔ | génération et version **touchées** (« iLO 7 1.25.00 »), lien bulletin ; pas de version corrigée | référence |
| D | **aucune** | — | — | — | — | — |
| ✗ | CSAF HPE (serveurs) | `support.hpe.com/.well-known/csaf/` 404 ; `www.hpe.com` délai dépassé | — | — | — | — |

Le CSAF HPE Aruba existe (`https://csaf.arubanetworking.hpe.com/changes.csv`, ✔ / ✔) mais ne couvre
que les produits réseau Aruba : hors périmètre actuel.

### CERT-FR (transverse)

| | Source | URL | Format | Accès S / GH | Fraîcheur, historique | Confiance |
|---|---|---|---|---|---|---|
| C — R | flux RSS avis et alertes | `https://www.cert.cyber.gouv.fr/avis/feed/`, `/alerte/feed/` | RSS | ✔ / ✔ | 40 avis (4 jours) ; 40 alertes (depuis 2015) | référence |
| C — R | JSON par document | `https://www.cert.cyber.gouv.fr/avis/<id>/json/` | JSON | ✔ / ✔ | `affected_systems` (éditeur, produit, description), `cves`, `vendor_advisories` | référence |

L'ancien domaine `cert.ssi.gouv.fr` n'est plus nécessaire. `affected_systems.product.vendor.name`
permet un rattachement **par éditeur** fiable (Dell, Stormshield, Proxmox) ; la correspondance
avec une branche reste du texte libre.

## Sources transverses

| Source | URL | Format | Accès S / GH | Volume | Usage | Conditions |
|---|---|---|---|---|---|---|
| endoflife.date API v1 | `https://endoflife.date/api/v1/products/<slug>` | JSON | ✔ / ✔ | 2 à 10 Ko par produit | A, B pour 14 produits | communautaire ; données sous licence MIT |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (miroir : `raw.githubusercontent.com/cisagov/kev-data/develop/...`) | JSON | ✔ / ✔ | 1,8 Mo | marquer les CVE exploitées | domaine public (CC0) |
| NVD API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0?...` | JSON | ✔ / **instable** (4 sur 7 depuis GitHub) | 1 à 15 s par requête ; délais > 30 s et 503 depuis GitHub | découverte des CVE par CNA ou mot-clé | sans clé : 5 requêtes / 30 s ; **clé gratuite** : 50 / 30 s ; mention « This product uses the NVD API but is not endorsed or certified by the NVD » |
| CVE.org (CVE Services) | `https://cveawg.mitre.org/api/cve/<id>` | JSON CVE 5 | ✔ / ✔ | 5 à 25 Ko par CVE | détail des enregistrements CNA | conditions d'utilisation CVE (reproduction libre avec mention) |
| OSV (bucket) | `https://osv-vulnerabilities.storage.googleapis.com/<écosystème>/modified_id.csv` | CSV + OSV JSON | ✔ / ✔ | 0,2 à 3,7 Mo l'index | DSA, USN, RLSA | licence propre à chaque écosystème (Rocky : CC BY 4.0) |
| OSV API | `https://api.osv.dev/v1/query` (POST), `/v1/vulns/<id>` | JSON | ✔ / ✔ | — | requêtes ponctuelles | — |
| cvelistV5 (dépôt CVE) | `raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json` | JSON (git) | ✔ / ✔ | **37 Mo et plus** | — | trop volumineux pour 4 passages par jour |

## Recoupement des dates de fin de support

Trois branches (ou plus) par produit, comparées entre la source candidate, endoflife.date et la
page officielle de l'éditeur (lue par un humain). « = » : identique.

| Produit | Branche | Source candidate | endoflife.date | Page éditeur | Écart |
|---|---|---|---|---|---|
| Debian | 11 / 12 / 13 | distro-info : sécurité 2024-08-14 / 2026-07-11 / 2028-08-09 ; LTS 2026-08-31 / 2028-06-30 / 2030-06-30 ; ELTS 2031-06-30 / 2033-06-30 / 2035-06-30 | = | debian.org/releases (=) | aucun |
| Ubuntu | 22.04 / 24.04 / 26.04 | distro-info : `eol` 2027-06-01 / 2029-05-31 / 2031-05-29 ; ESM 2032-04-21 / 2034-04-25 / 2036-04-23 | `eol` et `eoes` = ; `eoas` 22.04 = 2024-09-30 | ubuntu.com (=) | endoflife.date place la fin « Hardware & Maintenance » de 22.04 au 2024-09-30, absente de distro-info (champ différent, pas une contradiction) |
| RHEL | 8 / 9 / 10 | API Red Hat : Full 2024-05-31 / 2027-05-31 / 2030-05-31 ; Maintenance 2029-05-31 / 2032-05-31 / 2035-05-31 ; ELS 2033 / 2036 / 2039-05-31 | = | = (même API) | aucun |
| Rocky Linux | 8 / 9 / 10 | docs : actif 2024-05-31 / 2027-05-31 / 2030-05-31 ; fin 2029-05-31 / 2032-05-31 / 2035-05-31 | = | = | le wiki Rocky (`version.md`) affiche encore 10.1 comme dernière version |
| Windows Server | 2016 / 2019 / 2022 / 2025 | — (pas de source structurée) | eoas 2022-01-11 / 2024-01-09 / 2026-10-13 / 2029-11-13 ; eol 2027-01-12 / 2029-01-09 / 2031-10-14 / 2034-11-14 | Learn : mêmes dates (fin à 06:59:59 UTC le lendemain) | **ESU 2016 : endoflife.date 2030-01-12, Microsoft 2030-01-08** |
| FortiOS | 7.0 / 7.2 / 7.4 / 7.6 | — | EoES 2024-03-30 / 2025-03-31 / 2027-05-11 / 2028-07-25 ; EoS 2025-09-30 / 2026-09-30 / 2028-11-11 / 2030-01-25 | **non vérifiable** (portail sous connexion) ; bulletin CSB-260330-1 cité par la communauté Fortinet : 7.4 EoES 2027-05-11 (=) | report 7.4/7.6 bien intégré |
| PAN-OS | 10.2 / 11.1 / 11.2 / 12.1 | — | EoL 2025-08-27 / 2027-05-03 / 2027-05-02 / 2028-08-28 | standard = ; **support étendu** 2027-03-31 / 2027-08-31 / 2027-08-31 / 2029-08-28 | endoflife.date ignore le support étendu : 10.2 apparaît en fin de vie alors qu'il est supporté jusqu'au 2027-03-31 |
| Stormshield SNS | 4.3 / 4.8 / 5.0 | — | maintenance 2025-12-31 / 2029-12-31 / — ; fin 2026-03-31 / 2030-03-31 / — | matrice : = (5.0 : « date de retrait du label EA de 5.1 ») | aucun ; 5.1 EA absente d'endoflife.date |
| Cisco IOS XE | 17.9 / 17.12 / 17.15 | — | maintenance 2025-03-30 / 2026-03-30 / 2027-03-30 ; sécurité 2026-09-30 / 2027-09-30 / 2028-09-30 | bulletins EoL : = ; **Last Date of Support** 2027-03-31 / 2028-03-31 / 2029-03-31 | dernière date absente d'endoflife.date ; 17.18 et 26.1 sont des projections |
| Proxmox VE | 7 / 8 / 9 | pve-docs : 2024-07 / 2026-08 / « tba » | 2024-07-31 / 2026-08-31 / — | wiki FAQ (généré depuis pve-docs) : = | Proxmox ne donne que le mois |
| VMware ESXi / vCenter | 7.0 / 8.0 / 9.0 | — | General Support 2025-10-02 / 2027-10-11 / 2027-09-17 | **non vérifiable** (portail Broadcom 403 Cloudflare) | — |
| nginx | 1.28 / 1.30 / 1.31 | versions.xml : stable 1.30.6, mainline 1.31.8 | 1.28 fin 2026-04-14 ; derniers 1.30.6 / 1.31.8 | nginx.org : = | aucun |
| Apache httpd | 2.2 / 2.4 | ASF : 2.4.71 du 2026-11-11 | 2.2 fin 2017-07-11 ; 2.4 : dernière **2.4.70** | httpd.apache.org : 2.4.71 | endoflife.date en retard de 2 jours sur la dernière version |
| Dell iDRAC | iDRAC8 / iDRAC9 14G | `overrides.yaml` (saisie) | absent | KB Dell : **403 aux robots** ; dates reprises de la saisie précédente | non revérifiable automatiquement |
| HPE iLO | 4 à 7 | — | absent | aucune date publiée | — |

## Trous restants

| Produit | Donnée | Situation |
|---|---|---|
| FortiOS | A | dates seulement sur le portail Fortinet (connexion + hCaptcha) : dépendance totale à endoflife.date |
| PAN-OS | A (support étendu) | publié en HTML seulement ; à faire ajouter à endoflife.date |
| Stormshield SNS | B | aucune source structurée de la dernière version |
| Cisco IOS XE | B, D | uniquement par l'API openVuln (OAuth) |
| RHEL | B | versions mineures : endoflife.date seulement |
| Windows Server, VMware | A | saisies manuelles d'endoflife.date ; pages éditeur HTML ou protégées |
| VMware | C | liste VMSA : API non documentée (secours CVE.org) |
| Proxmox VE | C, D | aucun flux d'avis structuré |
| OpenSSH | C | aucun flux d'avis (notes de version + CVE.org) |
| Dell iDRAC | A | aucune source automatisable : saisie manuelle |
| HPE iLO | A, D | aucune date de fin publiée ; pas de version corrigée dans les CVE HPE |

## Décisions à prendre

### Sources à clé

| Source | Ce qu'elle apporte | Clé | Où la mettre |
|---|---|---|---|
| API NVD 2.0 | découverte des CVE par CNA (Stormshield, Dell, HPE, VMware, Fortinet) | **facultative**, gratuite (formulaire NIST) : 5 → 50 requêtes / 30 s | secret `NVD_API_KEY` ; sans clé, prévoir 6 s entre requêtes |
| Cisco openVuln | dernière version et versions corrigées IOS XE (B, D) | **obligatoire** : compte Cisco + client OAuth (client credentials), gratuit | secrets `CISCO_CLIENT_ID`, `CISCO_CLIENT_SECRET` ; conditions Cisco à relire (usage non commercial) |
| API GitHub | tags OpenSSH/httpd/nginx, dépôt `ubuntu-security-notices` | `GITHUB_TOKEN` fourni par le workflow | aucun secret à créer : passer le jeton du workflow (limite 60/h par IP partagée sinon) |

### Sources non documentées (fonctionnent, mais peuvent changer sans préavis)

| Source | Risque | Secours |
|---|---|---|
| Broadcom : `POST …/getSecurityAdvisoryList` | API interne du portail | CVE.org (CNA VMware) |
| Palo Alto : `/json/?limit=100&page=N` | pas de documentation ; `limit` > 100 renvoie une page d'erreur | CSAF / CVE 5 par CVE (même site) |
| Fortinet : URL CSAF dans le RSS (`csaf:link`) | URL imprévisible, pas de `provider-metadata.json` | CVE.org (CNA Fortinet) |
| nginx : XML du dépôt `nginx/nginx.org` | fichier source du site, pas une API | CHANGES + CVE.org (CNA F5) |
| Proxmox : `pve-faq.adoc` (git) et RSS du forum | tableau dans la documentation ; RSS = signal | endoflife.date |
| Rocky : tableau Markdown de la documentation | format de page | endoflife.date |

### Trous sans solution aujourd'hui

- **FortiOS (A)** : dates seulement sur le portail Fortinet (connexion + captcha) → endoflife.date ou rien.
- **Stormshield SNS (B)** : aucune dernière version publiée de façon structurée.
- **Cisco IOS XE (B, D)** sans clé openVuln.
- **Proxmox VE (C, D)** : aucun flux d'avis structuré.
- **Dell iDRAC (A)** : KB Dell refusées aux robots → `overrides.yaml` (saisie humaine) ou contribution à endoflife.date.
- **HPE iLO (A, D)** : aucune date de fin ; pas de version corrigée dans les CVE HPE.
- **Windows Server, VMware (A)** : pages éditeur HTML ou protégées ; endoflife.date (saisie manuelle) seule source automatisable.

### Autres choix

1. Remplacer l'API `ubuntu.com/security/notices.json` par OSV (USN) ? (recommandé)
2. Ajouter un champ facultatif « exploitée » (CISA KEV) aux avis ? (ajout compatible, `schema_version` inchangé)
3. Avis Red Hat : garder les seuls critiques (hydra) ou tout reprendre (OVAL v2 pour RHEL 8/9, hydra pour 10) ?
4. Contributions à endoflife.date (Dell iDRAC, support étendu PAN-OS, Last Date of Support Cisco, ESU Windows Server 2016) : voir `etude-sources/REORGANISATION.md`.
5. Catégories `hypervisor` / `management` (changement d'énumération du schéma).
