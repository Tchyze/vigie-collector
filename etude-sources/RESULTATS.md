# Résultats des tests d'accès — 2026-11-13

Chaque URL de [`candidats.tsv`](candidats.tsv) a été interrogée par [`probe.py`](probe.py) avec
l'identité du collecteur (`Vigie-collector/0.1`), sans authentification, au plus une requête par
seconde et par hôte, corps lu jusqu'à 40 Mo (« ≥ » : taille tronquée).

| Passage | Où | Résultat détaillé |
|---|---|---|
| session | conteneur Claude Code, proxy d'environnement (hôtes ajoutés à la liste blanche pour l'étude) | [`resultats/session.md`](resultats/session.md) |
| GitHub Actions | runner `ubuntu-latest`, workflow [`etude-sources.yml`](../.github/workflows/etude-sources.yml), run [43406085928](https://github.com/Tchyze/vigie-collector/actions/runs/43406085928) (6ᵉ passage, lancement manuel ; les 5 premiers donnent les mêmes codes, sauf NVD) | [`resultats/github.md`](resultats/github.md) |

Pour refaire le test : onglet Actions → « Étude des sources — test d'accès » → *Run workflow*.
Le tableau s'affiche dans le résumé du job (et en artefact JSON) ; le workflow n'écrit rien dans
le dépôt.

## Écarts entre la session et GitHub Actions

| URL | Session | GitHub | Explication |
|---|---|---|---|
| github.com (`*.atom`), api.github.com (dépôts tiers) | 403 | 200 | la session n'a accès qu'à ce dépôt ; aucun problème en production |
| `http://download.proxmox.com/...` | DNS (HTTP non relayé) | 200 | le proxy de session ne relaie que HTTPS ; **en HTTPS, le certificat de download.proxmox.com est invalide** (les deux côtés) |
| `www.cert.ssi.gouv.fr` | bloqué (non demandé) | 200 | ancien domaine, inutile |
| API NVD (7 requêtes) | 200 (1 à 15 s) | **5ᵉ passage : 4 sur 7 ; 6ᵉ passage : 2 sur 7** (délais dépassés à 30 s, 503) | NVD lent et instable depuis les runners GitHub, sans clé : jamais de source bloquante, toujours un secours |
| `fortiguard.com/psirt?...` (page HTML) | 429 | 429 | limitation de débit sur la page HTML ; non utilisée |

Aucune source **recommandée** ne répond à la session et échoue depuis GitHub, à l'exception de
la découverte NVD (secours : CERT-FR et flux éditeurs).

## Tableau comparatif

| id | URL | session : HTTP | taille | durée (s) | GitHub : HTTP | taille | durée (s) |
|---|---|---|---|---|---|---|---|
| eol-api-products | https://endoflife.date/api/v1/products | 200 | 85.7 Ko | 0.41 | 200 | 85.7 Ko | 0.18 |
| eol-api-fortios | https://endoflife.date/api/v1/products/fortios | 200 | 2.3 Ko | 0.18 | 200 | 2.3 Ko | 0.01 |
| eol-releasedata-panos | https://raw.githubusercontent.com/endoflife-date/release-data/main/releases/pan-os.json | 200 | 2.5 Ko | 0.14 | 200 | 2.5 Ko | 0.06 |
| eol-releasedata-nginx | https://raw.githubusercontent.com/endoflife-date/release-data/main/releases/nginx.json | 200 | 43.1 Ko | 0.2 | 200 | 43.1 Ko | 0.06 |
| eol-releasedata-sns | https://raw.githubusercontent.com/endoflife-date/release-data/main/releases/sns-firmware.json | 200 | 1.8 Ko | 0.15 | 200 | 1.8 Ko | 0.05 |
| eol-md-fortios | https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/fortios.md | 200 | 2.9 Ko | 0.16 | 200 | 2.9 Ko | 0.06 |
| kev-cisa | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 200 | 1.8 Mo | 0.34 | 200 | 1.8 Mo | 0.11 |
| kev-github | https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json | 200 | 1.8 Mo | 0.18 | 200 | 1.8 Mo | 0.02 |
| nvd-cve-cpe-idrac9 | https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:dell:idrac9_firmware&resultsPerPage=5 | 200 | 20.4 Ko | 0.19 | 503 | 1.2 Ko | 0.03 |
| nvd-cpe-ilo | https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:o:hpe:integrated_lights-out_6_firmware&resultsPerPage=5 | 200 | 1022 o | 0.43 | 503 | 1.2 Ko | 0.03 |
| osv-ecosystems | https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt | 200 | 376 o | 0.11 | 200 | 376 o | 0.02 |
| osv-debian-zip | https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip | 200 | ≥ 40.0 Mo | 1.71 | 200 | ≥ 40.0 Mo | 0.5 |
| osv-ubuntu-zip | https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip | 200 | ≥ 40.0 Mo | 1.67 | 200 | ≥ 40.0 Mo | 0.47 |
| osv-redhat-zip | https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip | 200 | 26.4 Mo | 1.22 | 200 | 26.4 Mo | 0.28 |
| osv-rocky-zip | https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip | 200 | 5.5 Mo | 0.29 | 200 | 5.5 Mo | 0.04 |
| osv-api-query | https://api.osv.dev/v1/query | 200 | 287.9 Ko | 0.5 | 200 | 287.9 Ko | 0.49 |
| osv-api-vuln | https://api.osv.dev/v1/vulns/DSA-5800-1 | 200 | 699 o | 0.19 | 200 | 699 o | 0.14 |
| cve-org-api | https://cveawg.mitre.org/api/cve/CVE-2024-6387 | 200 | 19.7 Ko | 0.22 | 200 | 19.7 Ko | 0.03 |
| cvelist-deltas | https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json | 200 | 37.3 Mo | 1.5 | 200 | 37.3 Mo | 0.22 |
| csaf-aggregator-bsi | https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json | 200 | 6.6 Ko | 0.4 | 200 | 6.6 Ko | 0.4 |
| gh-api-ratelimit | https://api.github.com/rate_limit | 200 | 1.2 Ko | 0.32 | 200 | 424 o | 0.01 |
| certfr-avis-feed | https://www.cert.cyber.gouv.fr/avis/feed/ | 200 | 22.8 Ko | 0.15 | 200 | 22.8 Ko | 0.03 |
| certfr-alerte-feed | https://www.cert.cyber.gouv.fr/alerte/feed/ | 200 | 25.5 Ko | 0.14 | 200 | 25.5 Ko | 0.01 |
| certfr-avis-json | https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1381/json/ | 200 | 1.5 Ko | 0.14 | 200 | 1.5 Ko | 0.01 |
| certfr-old-domain | https://www.cert.ssi.gouv.fr/avis/feed/ | proxy 403 Forbidden | 0 o | 0.16 | 200 | 22.8 Ko | 0.2 |
| fortinet-ir-rss | https://www.fortiguard.com/rss/ir.xml | 200 | 46.0 Ko | 1.83 | 200 | 46.0 Ko | 1.23 |
| fortinet-firmware-rss | https://support.fortinet.com/rss/firmware.xml | 200 | 36.3 Ko | 0.66 | 200 | 36.3 Ko | 0.88 |
| fortinet-csaf-pm | https://www.fortiguard.com/.well-known/csaf/provider-metadata.json | 404 | 4.0 Ko | 0.75 | 404 | 4.0 Ko | 0.37 |
| fortinet-csaf-pm2 | https://filestore.fortinet.com/.well-known/csaf/provider-metadata.json | 404 | 146 o | 1.06 | 404 | 146 o | 0.06 |
| fortinet-csaf-doc | https://filestore.fortinet.com/fortiguard/psirt/csaf_authentication-bypass-by-primary-weakness_fg-ir-26-267.json | 200 | 5.5 Ko | 0.56 | 200 | 5.5 Ko | 0.07 |
| fortinet-psirt-api | https://www.fortiguard.com/psirt?page=1&date=&severity=&product=FortiOS&component=&version= | 429 | 0 o | 0.5 | 429 | 0 o | 0.06 |
| fortinet-lifecycle | https://support.fortinet.com/Information/ProductLifeCycle.aspx | 200 | 9.6 Ko | 1.14 | 200 | 9.6 Ko | 0.41 |
| fortinet-docs-api | https://docs.fortinet.com/api/products | 404 | 96 o | 0.22 | 404 | 96 o | 0.47 |
| paloalto-json | https://security.paloaltonetworks.com/json/?limit=5&sort=-updated | 200 | 50.3 Ko | 0.24 | 200 | 50.3 Ko | 0.22 |
| paloalto-rss | https://security.paloaltonetworks.com/rss.xml | 200 | 8.1 Ko | 0.17 | 200 | 8.1 Ko | 0.15 |
| paloalto-csaf-pm | https://security.paloaltonetworks.com/.well-known/csaf/provider-metadata.json | 404 | 178 o | 0.13 | 404 | 178 o | 0.14 |
| paloalto-csaf-doc | https://security.paloaltonetworks.com/csaf/PAN-SA-2024-0015 | 500 | 35 o | 0.37 | 500 | 35 o | 0.23 |
| paloalto-eol-page | https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary | 200 | 245.1 Ko | 0.38 | 200 | 245.1 Ko | 0.08 |
| paloalto-eol-json | https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/json/eol/software-eol.json | 404 | 4.0 Ko | 0.33 | 404 | 4.0 Ko | 0.05 |
| stormshield-rss | https://advisories.stormshield.eu/feed/ | 200 | 5.8 Ko | 0.5 | 200 | 5.8 Ko | 0.34 |
| stormshield-wpjson | https://advisories.stormshield.eu/wp-json/wp/v2/posts?per_page=2 | 404 | 196 o | 0.43 | 404 | 196 o | 0.41 |
| stormshield-csaf-pm | https://advisories.stormshield.eu/.well-known/csaf/provider-metadata.json | 404 | 196 o | 0.38 | 404 | 196 o | 0.39 |
| stormshield-doc-lifecycle | https://documentation.stormshield.eu/SNS/v4/en/Content/Product_life_cycle/Network_Security_product_life_cycle.htm | 404 | 4.0 Ko | 0.4 | 404 | 4.0 Ko | 0.44 |
| cisco-rss | https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml | 200 | 141.7 Ko | 0.47 | 200 | 141.7 Ko | 0.41 |
| cisco-csaf-pm | https://www.cisco.com/.well-known/csaf/provider-metadata.json | 200 | 841 o | 0.61 | 200 | 841 o | 0.05 |
| cisco-csaf-doc | https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z/csaf/cisco-sa-iosxe-webui-privesc-j22SaA4z.json | 200 | 121.9 Ko | 0.38 | 200 | 121.9 Ko | 0.22 |
| cisco-cvrf-doc | https://sec.cloudapps.cisco.com/security/center/contentxml/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z/cvrf/cisco-sa-iosxe-webui-privesc-j22SaA4z_cvrf.xml | 200 | 84.2 Ko | 0.3 | 200 | 84.2 Ko | 0.2 |
| cisco-openvuln | https://apix.cisco.com/security/advisories/v2/latest/5 | 403 | 69 o | 1.02 | 403 | 69 o | 0.31 |
| cisco-oauth | https://id.cisco.com/oauth2/default/v1/token | 400 | 205 o | 0.35 | 400 | 205 o | 0.15 |
| debian-dsa-list | https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list | 200 | 1.2 Mo | 0.97 | 200 | 1.2 Mo | 1.25 |
| debian-dsa-long | https://www.debian.org/security/dsa-long | 200 | 28.0 Ko | 0.35 | 200 | 28.0 Ko | 0.75 |
| debian-tracker-json | https://security-tracker.debian.org/tracker/data/json | 200 | ≥ 40.0 Mo | 1.79 | 200 | ≥ 40.0 Mo | 0.12 |
| debian-distro-info | https://salsa.debian.org/debian/distro-info-data/-/raw/main/debian.csv | 200 | 1.2 Ko | 0.37 | 200 | 1.2 Ko | 0.22 |
| debian-release-file | https://deb.debian.org/debian/dists/bookworm/Release | 200 | 145.8 Ko | 0.16 | 200 | 145.8 Ko | 0.02 |
| debian-release-file-ftp | https://ftp.debian.org/debian/dists/trixie/Release | 200 | 135.4 Ko | 0.24 | 200 | 135.4 Ko | 0.1 |
| debian-oval | https://www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2 | 200 | 9.5 Mo | 0.91 | 200 | 9.5 Mo | 0.22 |
| debian-lts-dla | https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DLA/list | 200 | 936.0 Ko | 0.91 | 200 | 936.0 Ko | 1.01 |
| ubuntu-notices-json | https://ubuntu.com/security/notices.json?limit=20&offset=0 | 200 | 59.4 Ko | 0.7 | 200 | 59.4 Ko | 0.52 |
| ubuntu-distro-info | https://salsa.debian.org/debian/distro-info-data/-/raw/main/ubuntu.csv | 200 | 3.1 Ko | 0.37 | 200 | 3.1 Ko | 0.22 |
| ubuntu-meta-release | https://changelogs.ubuntu.com/meta-release | 200 | 23.2 Ko | 0.66 | 200 | 23.2 Ko | 0.33 |
| ubuntu-meta-release-lts | https://changelogs.ubuntu.com/meta-release-lts | 200 | 7.0 Ko | 3.89 | 200 | 7.0 Ko | 0.27 |
| ubuntu-osv-index | https://security-metadata.canonical.com/osv/ | 200 | 3.1 Ko | 0.6 | 200 | 3.1 Ko | 0.36 |
| ubuntu-osv-all | https://security-metadata.canonical.com/osv/osv-all.tar.xz | 200 | ≥ 40.0 Mo | 2.99 | 200 | ≥ 40.0 Mo | 1.25 |
| ubuntu-oval-noble | https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2 | 200 | 1.6 Mo | 1.36 | 200 | 1.6 Mo | 0.92 |
| ubuntu-vex | https://security-metadata.canonical.com/vex/ | 200 | 3.1 Ko | 0.58 | 200 | 3.1 Ko | 0.25 |
| ubuntu-usn-git | https://api.github.com/repos/canonical/ubuntu-security-notices/commits?per_page=1 | 403 | 378 o | 0.09 | 200 | 1.5 Ko | 0.13 |
| ubuntu-usn-git-dir | https://api.github.com/repos/canonical/ubuntu-security-notices/contents/osv | 403 | 378 o | 0.09 | 200 | 2.2 Ko | 0.09 |
| ubuntu-releases-cdimage | https://releases.ubuntu.com/noble/SHA256SUMS | 200 | 893 o | 0.62 | 200 | 893 o | 0.35 |
| redhat-hydra | https://access.redhat.com/hydra/rest/securitydata/csaf.json?severity=critical&per_page=2 | 200 | 6.8 Ko | 0.43 | 200 | 6.8 Ko | 0.18 |
| redhat-csaf-pm | https://access.redhat.com/.well-known/csaf/provider-metadata.json | 404 | 4.0 Ko | 0.38 | 404 | 4.0 Ko | 0.49 |
| redhat-csaf-changes | https://security.access.redhat.com/data/csaf/v2/advisories/changes.csv | 200 | 1.7 Mo | 0.74 | 200 | 1.7 Mo | 0.09 |
| redhat-csaf-releases | https://security.access.redhat.com/data/csaf/v2/advisories/releases.csv | 200 | 1.7 Mo | 0.4 | 200 | 1.7 Mo | 0.18 |
| redhat-oval9 | https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2 | 200 | 1.5 Mo | 0.45 | 200 | 1.5 Mo | 0.02 |
| redhat-lifecycle-api | https://access.redhat.com/product-life-cycles/api/v1/products?name=Red%20Hat%20Enterprise%20Linux | 200 | 6.0 Ko | 0.41 | 200 | 6.0 Ko | 0.16 |
| redhat-lifecycle-api2 | https://access.redhat.com/product-life-cycles/api/v2/products?name=Red%20Hat%20Enterprise%20Linux | 200 | 5.1 Ko | 0.38 | 200 | 5.1 Ko | 0.24 |
| rocky-errata-v2 | https://errata.rockylinux.org/api/v2/advisories?filters.severity=SEVERITY_CRITICAL&filters.type=TYPE_SECURITY&size=2&page=0 | 200 | 172.2 Ko | 0.77 | 200 | 172.2 Ko | 2.86 |
| rocky-apollo-v3 | https://apollo.build.resf.org/api/v3/advisories/?page=1&size=2 | 200 | 13.2 Ko | 0.44 | 200 | 13.2 Ko | 0.55 |
| rocky-apollo-csaf | https://apollo.build.resf.org/csaf/provider-metadata.json | 404 | 4.0 Ko | 0.32 | 404 | 4.0 Ko | 0.08 |
| rocky-treeinfo | https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/.treeinfo | 200 | 1.4 Ko | 0.2 | 200 | 1.4 Ko | 0.01 |
| rocky-treeinfo10 | https://dl.rockylinux.org/pub/rocky/10/BaseOS/x86_64/os/.treeinfo | 200 | 1.4 Ko | 0.18 | 200 | 1.4 Ko | 0.01 |
| rocky-vault | https://dl.rockylinux.org/vault/rocky/ | 200 | 5.7 Ko | 0.17 | 200 | 5.7 Ko | 0.04 |
| rocky-wiki-git | https://raw.githubusercontent.com/rocky-linux/wiki.rockylinux.org/development/docs/rocky/version.md | 200 | 12.7 Ko | 0.17 | 200 | 12.7 Ko | 0.06 |
| msrc-cvrf-updates | https://api.msrc.microsoft.com/cvrf/v3.0/updates | 200 | 50.4 Ko | 0.87 | 200 | 50.4 Ko | 0.63 |
| msrc-csaf-pm | https://msrc.microsoft.com/csaf/provider-metadata.json | 200 | 947 o | 0.45 | 200 | 947 o | 0.27 |
| msrc-csaf-changes | https://msrc.microsoft.com/csaf/advisories/changes.csv | 200 | 545.9 Ko | 0.52 | 200 | 545.9 Ko | 0.34 |
| ms-lifecycle-page | https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2022 | 200 | 25.3 Ko | 0.17 | 200 | 25.3 Ko | 0.05 |
| ms-lifecycle-api | https://learn.microsoft.com/api/lifecycle/products?product=windows-server-2022 | 404 | 15 o | 0.12 | 404 | 15 o | 0.04 |
| ms-release-health | https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info | 200 | 163.4 Ko | 0.17 | 200 | 163.4 Ko | 0.04 |
| ms-update-history-atom | https://support.microsoft.com/en-us/feed/atom/2e1c5ebf-5d34-4bb4-8e0b-0b3b0e6b1f0e | 410 | 337 o | 0.13 | 410 | 337 o | 0.03 |
| broadcom-vmsa | https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList | 200 | 1.3 Ko | 0.63 | 200 | 1.3 Ko | 0.36 |
| broadcom-csaf-pm | https://support.broadcom.com/.well-known/csaf/provider-metadata.json | 403 | 4.0 Ko | 0.17 | 403 | 4.0 Ko | 0.02 |
| broadcom-csaf-pm2 | https://www.broadcom.com/.well-known/csaf/provider-metadata.json | 404 | 587 o | 0.57 | 404 | 567 o | 0.39 |
| vmware-advisories-old | https://www.vmware.com/security/advisories.xml | 404 | 4.0 Ko | 0.15 | 404 | 4.0 Ko | 0.04 |
| vmware-depot-index | https://hostupdate.vmware.com/software/VUM/PRODUCTION/main/vmw-depot-index.xml | proxy 502 Bad Gateway | 0 o | 0.09 | [Errno -2] Name or service not known | 0 o | 0.0 |
| vmware-depot-broadcom | https://dl.broadcom.com/PROD/COMP/ESX_HOST/main/vmw-depot-index.xml | 403 | 22 o | 0.18 | 403 | 22 o | 0.03 |
| vmware-vcenter-vami | https://vapp-updates.vmware.com/vai-catalog/valm/vmw/8d167796-34d5-4899-be0a-6daade4005a3/8.0.3.00000/manifest/manifest-latest.xml | proxy 502 Bad Gateway | 0 o | 0.09 | [Errno -2] Name or service not known | 0 o | 0.0 |
| broadcom-lifecycle | https://support.broadcom.com/web/ecx/productlifecycle | 403 | 4.0 Ko | 0.35 | 403 | 4.0 Ko | 0.02 |
| proxmox-pve-packages | https://download.proxmox.com/debian/pve/dists/trixie/pve-no-subscription/binary-amd64/Packages | [SSL: CERTIFICATE_VERIFY_FAILED] certificate  | 0 o | 0.7 | [SSL: CERTIFICATE_VERIFY_FAILED] certificate  | 0 o | 0.49 |
| proxmox-pve-release | https://download.proxmox.com/debian/pve/dists/trixie/Release | [SSL: CERTIFICATE_VERIFY_FAILED] certificate  | 0 o | 0.79 | [SSL: CERTIFICATE_VERIFY_FAILED] certificate  | 0 o | 0.03 |
| proxmox-iso-sha | https://download.proxmox.com/iso/SHA256SUMS | [SSL: CERTIFICATE_VERIFY_FAILED] certificate  | 0 o | 0.57 | [SSL: CERTIFICATE_VERIFY_FAILED] certificate  | 0 o | 0.03 |
| proxmox-forum-rss | https://forum.proxmox.com/forums/security-advisories.29/index.rss | 404 | 127 o | 0.67 | 404 | 127 o | 0.57 |
| proxmox-git-changelog | https://git.proxmox.com/?p=pve-manager.git;a=blob_plain;f=debian/changelog;hb=HEAD | 200 | 338.6 Ko | 1.23 | 200 | 338.6 Ko | 1.1 |
| nginx-changes | https://nginx.org/en/CHANGES | 200 | 347.4 Ko | 0.34 | 200 | 347.4 Ko | 0.14 |
| nginx-security-xml | https://raw.githubusercontent.com/nginx/nginx.org/main/xml/en/security_advisories.xml | 200 | 17.7 Ko | 0.13 | 200 | 17.7 Ko | 0.05 |
| nginx-gh-releases | https://api.github.com/repos/nginx/nginx/releases?per_page=2 | 403 | 378 o | 0.09 | 200 | 19.8 Ko | 0.24 |
| nginx-gh-advisories | https://api.github.com/repos/nginx/nginx/security-advisories?per_page=5 | 403 | 378 o | 0.09 | 403 | 278 o | 0.01 |
| nginx-gh-tags-atom | https://github.com/nginx/nginx/tags.atom | 403 | 249 o | 0.25 | 200 | 5.1 Ko | 0.19 |
| httpd-changes | https://downloads.apache.org/httpd/CHANGES_2.4 | 200 | 406.6 Ko | 1.21 | 200 | 406.6 Ko | 0.78 |
| httpd-tags-atom | https://github.com/apache/httpd/tags.atom | 403 | 249 o | 0.08 | 200 | 5.0 Ko | 0.24 |
| httpd-security-json | https://httpd.apache.org/security/json/CVE-2024-38476.json | 200 | 4.2 Ko | 0.22 | 200 | 4.2 Ko | 0.01 |
| httpd-security-dir | https://httpd.apache.org/security/json/ | 200 | 62.6 Ko | 0.16 | 200 | 62.6 Ko | 0.03 |
| httpd-doap | https://httpd.apache.org/doap.rdf | 200 | 3.5 Ko | 0.11 | 200 | 3.5 Ko | 0.01 |
| apache-projects-releases | https://projects.apache.org/json/foundation/releases.json | 200 | 883.1 Ko | 0.67 | 200 | 883.1 Ko | 0.5 |
| httpd-site-git-json | https://api.github.com/repos/apache/httpd-site/contents/content/security/json?ref=main | 403 | 378 o | 0.13 | 200 | 263.5 Ko | 0.13 |
| openssh-tags-atom | https://github.com/openssh/openssh-portable/tags.atom | 403 | 249 o | 0.19 | 200 | 5.2 Ko | 0.17 |
| openssh-gh-tags | https://api.github.com/repos/openssh/openssh-portable/tags?per_page=2 | 403 | 378 o | 0.44 | 200 | 899 o | 0.1 |
| openssh-release-txt | https://www.openssh.com/txt/release-10.2 | 200 | 2.6 Ko | 1.22 | 200 | 2.6 Ko | 0.42 |
| openssh-security-page | https://www.openssh.com/security.html | 200 | 24.5 Ko | 0.92 | 200 | 24.5 Ko | 0.47 |
| openssh-cdn-release | https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/SHA256 | 404 | 494 o | 0.24 | 404 | 494 o | 0.11 |
| openssh-cdn-dir | https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/ | 200 | 52.7 Ko | 0.38 | 200 | 52.7 Ko | 0.02 |
| dell-catalog | https://downloads.dell.com/catalog/Catalog.xml.gz | 200 | 1.4 Mo | 0.51 | 200 | 1.4 Mo | 0.05 |
| dell-security-page | https://www.dell.com/support/security/en-us | 403 | 398 o | 0.22 | 403 | 398 o | 0.06 |
| dell-kb-idrac9 | https://www.dell.com/support/kbdoc/en-us/000178016/support-for-integrated-dell-remote-access-controller-9-idrac9 | 403 | 507 o | 0.19 | 403 | 507 o | 0.06 |
| dell-csaf-pm | https://www.dell.com/.well-known/csaf/provider-metadata.json | 200 | 333.1 Ko | 0.96 | 200 | 333.1 Ko | 0.38 |
| dell-security-rss | https://www.dell.com/support/security/en-us/rss | 403 | 404 o | 0.29 | 403 | 406 o | 0.06 |
| hpe-fwrepo-gen11 | https://downloads.linux.hpe.com/SDR/repo/fwpp-gen11/current/fwrepodata/fwrepo.json | 200 | 964.3 Ko | 1.45 | 200 | 964.3 Ko | 1.48 |
| hpe-bulletins-rss | https://support.hpe.com/hpesc/public/api/document/sec_bull_rss_feed | 200 | 32.5 Ko | 0.61 | 200 | 32.5 Ko | 0.07 |
| hpe-csaf-pm | https://support.hpe.com/.well-known/csaf/provider-metadata.json | 404 | 881 o | 0.52 | 404 | 881 o | 0.11 |
| hpe-csaf-pm-www | https://www.hpe.com/.well-known/csaf/provider-metadata.json | TimeoutError: The read operation timed out | 0 o | 30.26 | TimeoutError: The read operation timed out | 0 o | 30.04 |
| aruba-csaf-pm | https://csaf.arubanetworking.hpe.com/.well-known/csaf/provider-metadata.json | 404 | 162 o | 0.82 | 404 | 162 o | 0.28 |
| aruba-csaf-changes | https://csaf.arubanetworking.hpe.com/changes.csv | 200 | 7.7 Ko | 0.49 | 200 | 7.7 Ko | 0.26 |
| openssh-org-release-txt | https://www.openssh.org/txt/release-10.2 | 200 | 2.6 Ko | 0.39 | 200 | 2.6 Ko | 0.21 |
| openssh-org-releasenotes | https://www.openssh.org/releasenotes.html | 200 | 766.8 Ko | 1.07 | 200 | 766.8 Ko | 0.74 |
| proxmox-pve-packages-http | http://download.proxmox.com/debian/pve/dists/trixie/pve-no-subscription/binary-amd64/Packages | [Errno -2] Name or service not known | 0 o | 0.0 | 200 | 2.3 Mo | 0.14 |
| proxmox-pve-release-http | http://download.proxmox.com/debian/pve/dists/trixie/Release | [Errno -2] Name or service not known | 0 o | 0.0 | 200 | 3.4 Ko | 0.03 |
| nginx-tags-atom | https://github.com/nginx/nginx/releases.atom | 403 | 249 o | 0.07 | 200 | 112.3 Ko | 0.5 |
| openssh-releases-gh | https://api.github.com/repos/openssh/openssh-portable/git/refs/tags | 403 | 378 o | 0.12 | 200 | 60.1 Ko | 0.18 |
| httpd-gh-tags-api | https://api.github.com/repos/apache/httpd/tags?per_page=5 | 403 | 378 o | 0.21 | 200 | 2.0 Ko | 0.09 |
| eol-releasedata-github | https://api.github.com/repos/endoflife-date/release-data/commits?per_page=1 | 403 | 378 o | 0.19 | 200 | 5.5 Ko | 0.17 |
| msrc-csaf-doc | https://msrc.microsoft.com/csaf/advisories/2024/msrc_cve-2024-38063.json | 200 | 39.9 Ko | 0.39 | 200 | 39.9 Ko | 0.32 |
| cisco-csaf-changes | https://www.cisco.com/.well-known/csaf/changes.csv | 200 | 174.1 Ko | 0.23 | 200 | 174.1 Ko | 0.2 |
| cisco-csaf-index | https://www.cisco.com/.well-known/csaf/2026/cisco-sa-hardening-iosxe-v8nmumzj.json | 200 | 567.8 Ko | 0.62 | 200 | 567.8 Ko | 0.12 |
| paloalto-json-page | https://security.paloaltonetworks.com/json/?limit=100&sort=-updated&page=4 | 200 | 205.4 Ko | 0.33 | 200 | 205.4 Ko | 0.3 |
| paloalto-csaf-cve | https://security.paloaltonetworks.com/csaf/CVE-2026-0326 | 200 | 4.7 Ko | 0.22 | 200 | 4.7 Ko | 0.14 |
| paloalto-cve5-cve | https://security.paloaltonetworks.com/json/CVE-2026-0326 | 200 | 21.4 Ko | 0.26 | 200 | 21.4 Ko | 0.14 |
| cve-stormshield | https://cveawg.mitre.org/api/cve/CVE-2026-113465 | 200 | 3.4 Ko | 0.21 | 200 | 3.4 Ko | 0.02 |
| cve-dell-idrac | https://cveawg.mitre.org/api/cve/CVE-2026-23855 | 200 | 3.0 Ko | 0.16 | 200 | 3.0 Ko | 0.03 |
| cve-hpe-ilo | https://cveawg.mitre.org/api/cve/CVE-2026-79820 | 200 | 2.1 Ko | 0.2 | 200 | 2.1 Ko | 0.01 |
| cve-vmware-esxi | https://cveawg.mitre.org/api/cve/CVE-2025-41236 | 200 | 3.7 Ko | 0.4 | 200 | 3.7 Ko | 0.02 |
| nvd-src-airbus | https://services.nvd.nist.gov/rest/json/cves/2.0?sourceIdentifier=cert@airbus.com&resultsPerPage=5 | 200 | 2.3 Ko | 8.12 | 200 | 2.3 Ko | 11.96 |
| nvd-src-dell-idrac | https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=iDRAC&resultsPerPage=5 | 200 | 18.1 Ko | 7.16 | 200 | 18.1 Ko | 14.75 |
| osv-debian-modified | https://osv-vulnerabilities.storage.googleapis.com/Debian/modified_id.csv | 200 | 3.6 Mo | 0.3 | 200 | 3.6 Mo | 0.09 |
| osv-ubuntu-modified | https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/modified_id.csv | 200 | 3.5 Mo | 0.24 | 200 | 3.5 Mo | 0.07 |
| osv-rocky-modified | https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/modified_id.csv | 200 | 210.5 Ko | 0.22 | 200 | 210.5 Ko | 0.05 |
| osv-redhat-modified | https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/modified_id.csv | 200 | 877.8 Ko | 0.23 | 200 | 877.8 Ko | 0.03 |
| osv-rocky-entry | https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/RLSA-2026:99030.json | 200 | 4.4 Ko | 0.15 | 200 | 4.4 Ko | 0.07 |
| osv-ubuntu-usn | https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/USN-9066-1.json | 200 | 1.1 Mo | 0.25 | 200 | 1.1 Mo | 0.08 |
| nginx-versions-xml | https://raw.githubusercontent.com/nginx/nginx.org/main/xml/versions.xml | 200 | 8.5 Ko | 0.17 | 200 | 8.5 Ko | 0.05 |
| nginx-security-commits | https://api.github.com/repos/nginx/nginx.org/commits?path=xml/en/security_advisories.xml&per_page=1 | 403 | 378 o | 0.09 | 200 | 3.1 Ko | 0.33 |
| rocky-docs-releases-md | https://raw.githubusercontent.com/rocky-linux/documentation/main/docs/releases/index.md | 200 | 13.1 Ko | 0.15 | 200 | 13.1 Ko | 0.07 |
| proxmox-forum-sa-rss | https://forum.proxmox.com/forums/security-advisories.26/index.rss | 200 | 6.1 Ko | 0.9 | 200 | 6.1 Ko | 0.35 |
| proxmox-git-atom | https://git.proxmox.com/?p=pve-manager.git;a=atom | 200 | 48.9 Ko | 0.83 | 200 | 48.9 Ko | 0.78 |
| proxmox-git-changelog8 | https://git.proxmox.com/?p=pve-manager.git;a=blob_plain;f=debian/changelog;hb=refs/heads/stable-8 | 200 | 252.6 Ko | 1.08 | 200 | 252.6 Ko | 1.07 |
| redhat-csaf-advisory | https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_99030.json | 200 | 44.2 Ko | 0.36 | 200 | 44.2 Ko | 0.02 |
| ubuntu-distro-info-salsa | https://salsa.debian.org/debian/distro-info-data/-/raw/main/ubuntu.csv | 200 | 3.1 Ko | 0.31 | 200 | 3.1 Ko | 0.26 |
| openssh-org-release-10.6p2 | https://www.openssh.org/txt/release-10.6p2 | 200 | 4.5 Ko | 0.57 | 200 | 4.5 Ko | 0.21 |
| eol-api-rhel | https://endoflife.date/api/v1/products/rhel | 200 | 3.6 Ko | 0.12 | 200 | 3.6 Ko | 0.01 |
| proxmox-pve-docs-faq | https://git.proxmox.com/?p=pve-docs.git;a=blob_plain;f=pve-faq.adoc;hb=HEAD | 200 | 7.9 Ko | 0.58 | 200 | 7.9 Ko | 0.38 |
| nvd-src-fortinet | https://services.nvd.nist.gov/rest/json/cves/2.0?sourceIdentifier=psirt@fortinet.com&resultsPerPage=5 | 200 | 23.0 Ko | 1.14 | 503 | 1.2 Ko | 0.03 |
| nvd-src-hpe | https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Integrated%20Lights-Out&resultsPerPage=5 | 200 | 23.9 Ko | 0.19 | 503 | 1.2 Ko | 0.09 |
| nvd-src-vmware | https://services.nvd.nist.gov/rest/json/cves/2.0?sourceIdentifier=security@vmware.com&resultsPerPage=5 | 200 | 23.9 Ko | 0.52 | 503 | 1.2 Ko | 0.05 |
| redhat-oval10 | https://security.access.redhat.com/data/oval/v2/RHEL10/rhel-10.oval.xml.bz2 | 404 | 4.0 Ko | 0.94 | 404 | 4.0 Ko | 0.26 |
| ubuntu-oval-jammy | https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2 | 200 | 1.7 Mo | 1.21 | 200 | 1.7 Mo | 0.99 |
| msrc-cvrf-month | https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Nov | 200 | 27.3 Mo | 3.74 | 200 | 27.3 Mo | 2.47 |
| cisco-ios-xe-eol-bulletin | https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-17/ios-xe-17-9-x-eol.html | 200 | 68.0 Ko | 0.89 | 200 | 68.0 Ko | 0.47 |
| ms-lifecycle-ws2016 | https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2016 | 200 | 26.2 Ko | 1.03 | 200 | 26.2 Ko | 0.12 |

176 URL ; 2xx depuis la session : 124 ; 2xx depuis GitHub Actions : 135.
