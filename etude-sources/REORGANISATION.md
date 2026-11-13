# Proposition de réorganisation de `products.yaml`

Étude du 2026-11-13. Rien n'est appliqué : ce document propose, `SOURCES.md` et `sources.yaml`
justifient. Les changements qui touchent le format publié sont signalés **[format]**.

## 1. Principe : relier chaque produit à ses sources

Aujourd'hui, le lien entre un produit et ses sources est implicite (codé dans chaque collecteur).
Proposition : chaque produit déclare, par type de donnée, les identifiants de `sources.yaml`
qu'il utilise, dans l'ordre de priorité.

```yaml
products:
  windows-server:
    label: Windows Server
    vendor: Microsoft
    category: os
    sources:
      lifecycle: [endoflife-date]            # A : branches et fins de support
      versions:  [msrc-cvrf, endoflife-date] # B : dernière version (build) de chaque branche
      advisories: [msrc-cvrf, certfr]        # C
      security_fix: [msrc-cvrf]              # D
    endoflife: windows-server
    branches: {include: "^(2016|2019|2022|2025)$"}   # voir § 3
```

Intérêt : `index.json` peut dire, produit par produit, d'où vient chaque donnée et à quel niveau
de confiance (éditeur / organisme de référence / communautaire) — sans changer le format des
branches.

## 2. Produits à découper, renommer ou fusionner

### Dell iDRAC — découper par génération de matériel (recommandé)

Les branches actuelles portent le préfixe de firmware (`2.86`, `7.00`, `7.30`, `1.30`). Or Dell
publie ses dates de support et ses avis **par génération de serveur**, et le préfixe d'une
génération peut changer (l'iDRAC9 14G est passé de 6.x à 7.00). Les enregistrements CVE de Dell
le confirment : « iDRAC9, 14G versions prior to 7.00.00.184, 15G/16G versions prior to
7.30.10.50, and iDRAC10, 17G versions prior to 1.30.30.50 ».

| Aujourd'hui | Proposé (`id` de branche) | Libellé | Fin de support |
|---|---|---|---|
| `dell-idrac-2.86` | `dell-idrac-idrac8` | iDRAC8 (PowerEdge 13G) — 2.86.x | KB 000178044 : février 2024 (saisie manuelle) |
| `dell-idrac-7.00` | `dell-idrac-idrac9-14g` | iDRAC9 (PowerEdge 14G) — 7.00.x | KB 000178016 : février 2027 (saisie manuelle) |
| `dell-idrac-7.30` | `dell-idrac-idrac9-15g-16g` | iDRAC9 (PowerEdge 15G/16G) — 7.30.x | aucune date publiée |
| `dell-idrac-1.30` | `dell-idrac-idrac10-17g` | iDRAC10 (PowerEdge 17G) — 1.x | aucune date publiée |

Le collecteur `dell_idrac` associe déjà les composants du catalogue à des modèles de serveurs
(`SupportedSystems`) : la génération se déduit du modèle, plus sûrement que du préfixe de
version. Garder un seul produit `dell-idrac` évite de multiplier les fiches dans l'application.

Changement d'`id` de branche : pas de changement de schéma, mais l'application perd l'historique
local des anciens `id`. À faire une seule fois, annoncé dans le journal des changements.

### HPE iLO — garder tel quel

Une branche par génération (`hpe-ilo-4` … `hpe-ilo-7`) correspond déjà au découpage HPE (titres
des bulletins, produits des enregistrements CVE : « HPE Integrated Lights-Out (iLO) 7 »). Aucune
date de fin : rester `active`, mais publier `declared_eol: true` pour iLO 4 si HPE le confirme
un jour (à ce jour : aucune source).

### Windows Server — ne garder que les versions LTSC

endoflife.date mêle LTSC (2016, 2019, 2022, 2025) et canaux semestriels (`20h2-sac`,
`23h2-ac`…), tous en fin de vie sauf 23H2. Proposition : filtrer sur les LTSC (+ `23h2-ac` tant
qu'il est supporté). Le collecteur MSRC sait déjà nommer « Windows Server 2022, 23H2 Edition ».

### Ubuntu — option : ne garder que les LTS

Les versions intermédiaires (25.10…) vivent 9 mois et ne concernent pas des serveurs
d'infrastructure. Proposition : `branches: {include_lts_only: true}` (réglage), défaut à décider.

### VMware ESXi et vCenter — garder séparés, mutualiser les sources

Même éditeur, mêmes dates de fin, même flux d'avis, mais des versions (builds) distinctes. Garder
deux produits ; déclarer les mêmes sources d'avis (`broadcom-vmsa-portal`, `cve-org-vmware`).

### Rocky Linux et RHEL — garder séparés

Dates identiques (Rocky suit RHEL), mais avis distincts (RLSA / RHSA) et versions mineures
publiées avec quelques jours d'écart.

### Renommages d'éditeur (libellés, sans effet sur les `id`)

| Produit | `vendor` actuel | Proposé | Raison |
|---|---|---|---|
| `nginx` | F5 NGINX | F5 (nginx) | les avis renvoient à my.f5.com |
| `rocky-linux` | Rocky Enterprise Software Foundation | Rocky Enterprise Software Foundation (RESF) | inchangé, abréviation utile |
| `openssh` | OpenBSD | OpenBSD (OpenSSH) | — |

## 3. Catégories **[format]**

`category` est une énumération du schéma (`firewall | switch | os | service | server`).

| Proposition | Produits | Effet |
|---|---|---|
| ajouter `hypervisor` | `vmware-esxi`, `proxmox-ve` (aujourd'hui `os`) | regroupement plus juste dans l'application |
| ajouter `management` (ou garder `service`) | `vmware-vcenter` | vCenter n'est pas un service réseau |
| renommer le libellé de `switch` en « réseau » côté application | `cisco-ios-xe` (IOS XE équipe aussi des routeurs) | aucun changement d'`id` |
| garder `server` | `dell-idrac`, `hpe-ilo` | déjà défini comme « contrôleurs de gestion » |

Ajouter une valeur à l'énumération est compatible pour un lecteur tolérant, mais une application
qui valide strictement l'énumération casserait : à traiter comme un ajout annoncé (ou
`schema_version` 2 si l'application ne tolère pas les valeurs inconnues). Changer la catégorie
d'un produit existant est un changement de **sens** : le faire en même temps.

## 4. Ce qu'il faudrait ajouter à endoflife.date

endoflife.date accepte les contributions par pull request sur
`github.com/endoflife-date/endoflife.date` (un fichier `products/<produit>.md` par produit, dates
saisies à la main ou relevées automatiquement depuis une page de l'éditeur). Contribuer y comble
nos trous **et** déplace la maintenance des dates vers une communauté qui les relit.

| Contribution | Contenu | Source citée | Faisabilité |
|---|---|---|---|
| nouveau produit **Dell iDRAC** | cycles iDRAC8, iDRAC9 14G, iDRAC9 15G/16G, iDRAC10 ; `eoas`/`eol` d'après les KB Dell | KB Dell 000178044, 000178016 (lecture humaine : Dell refuse les robots) | bonne pour iDRAC8 et iDRAC9 14G ; dates 15G/16G et 17G inconnues |
| nouveau produit **HPE iLO** | générations 4 à 7, dernière version | aucune date HPE officielle | **non** tant que HPE ne publie rien (endoflife.date refuse les dates non sourcées) |
| PAN-OS : support étendu | champ `eoes` (« Extended Support ») : 10.2 → 2027-03-31, 11.1 et 11.2 → 2027-08-31, 12.1 → 2029-08-28, 12.2 → 2030-07-30 | page « End-of-Life Summary » de Palo Alto (colonne déjà relevée par leur script) | bonne : la page est déjà analysée par endoflife.date |
| Cisco IOS XE : fin de support | « Last Date of Support » de chaque bulletin (17.9 → 2027-03-31, 17.12 → 2028-03-31, 17.15 → 2029-03-31) en `eoes` ou champ dédié | bulletins EoL Cisco | bonne |
| Cisco IOS XE et Stormshield SNS : dernière version | `latest` absent (`latestColumn: false`) | Cisco : aucune source publique ; Stormshield : notes de version HTML | faible |
| Windows Server 2016 : fin des ESU | endoflife.date indique 2030-01-12, Microsoft Learn 2030-01-08 (fin de l'ESU année 3) | learn.microsoft.com | correction simple |
| OpenSSH | produit sans branches : seule la dernière version est maintenue | — | **inutile** : pas de cycle de vie à décrire |

## 5. Récapitulatif des changements proposés à `products.yaml`

1. ajouter `sources:` (A/B/C/D → identifiants de `sources.yaml`) à chaque produit ;
2. `dell-idrac` : branches par génération (`idrac8`, `idrac9-14g`, `idrac9-15g-16g`,
   `idrac10-17g`) ;
3. `windows-server` : filtre LTSC ; `ubuntu` : option LTS seulement ;
4. catégories `hypervisor` (ESXi, Proxmox VE) et `management` (vCenter) — **[format]**, à
   décider ;
5. `openssh` : inchangé (branche unique `portable`) ; `security_fix` depuis les notes de version
   texte ;
6. aucune fusion de produits.
