# Format des données Vigie — `schema_version` 1

Le collecteur publie des fichiers JSON statiques. Chaque fichier porte à sa racine un entier
`schema_version` : tant qu'il vaut `1`, les champs décrits ici ne changent ni de nom ni de sens.
Un ajout de champ facultatif ne change pas la version ; un renommage, une suppression ou un
changement de sens la fait passer à `2`.

Les JSON Schema correspondants sont dans [`schema/`](schema/) et sont publiés avec les données
(`schema/*.schema.json`). La sortie est validée contre eux à chaque build : un document non conforme
fait échouer le workflow et n'est pas publié.

Conventions :

- dates au format `AAAA-MM-JJ` ; horodatages en UTC au format `AAAA-MM-JJThh:mm:ssZ` ;
- une valeur inconnue vaut `null` (jamais une valeur devinée) ;
- les identifiants (`id` de branche, `product`) sont en minuscules : lettres, chiffres, `.` et `-`.

## Fichiers publiés

| Fichier | Contenu | Schéma |
|---|---|---|
| `index.json` | point d'entrée : produits, état des sources | `schema/index.schema.json` |
| `products/<produit>.json` | branches d'un produit | `schema/product.schema.json` |
| `advisories.json` | avis de sécurité (365 derniers jours) | `schema/advisories.schema.json` |
| `state/<source>.json` | état interne du collecteur, **non contractuel** | — |

## `index.json`

```json
{
  "schema_version": 1,
  "generated_at": "2026-10-29T12:00:00Z",
  "eol_soon_months": 6,
  "products": [
    {"id": "debian", "label": "Debian", "vendor": "Debian", "category": "os",
     "file": "products/debian.json", "branch_count": 14,
     "status_counts": {"active": 2, "eol_soon": 0, "eol": 12}}
  ],
  "advisories": {"file": "advisories.json", "count": 412},
  "sources": [
    {"name": "endoflife", "label": "endoflife.date", "kind": "versions", "status": "ok",
     "count": 180, "last_attempt": "2026-10-29T12:00:00Z", "last_success": "2026-10-29T12:00:00Z",
     "error": null, "home": "https://endoflife.date", "attribution": null}
  ]
}
```

`sources[].status` vaut `error` quand la dernière collecte a échoué. Les données de cette source
sont alors celles de son dernier succès (`last_success`), et `error` décrit l'échec.

## Objet `branch`

Une branche de version d'un produit : FortiOS 7.4, Debian 12, nginx 1.30… Un produit sans
notion de branche n'en a qu'une (OpenSSH : branche `portable`).

| Champ | Type | Description |
|---|---|---|
| `id` | chaîne | `<produit>-<branche>`, ex. `fortios-7.4`, `debian-12` |
| `product` | chaîne | identifiant du produit, ex. `fortios` |
| `vendor` | chaîne | éditeur, ex. `Fortinet` |
| `category` | `firewall` \| `switch` \| `os` \| `service` | |
| `branch` | chaîne | nom de la branche, ex. `7.4` |
| `label` | chaîne | libellé lisible, ex. `12 (Bookworm)` |
| `lts` | booléen ou `null` | branche à support long |
| `release_date` | date ou `null` | sortie de la branche |
| `status` | `active` \| `eol_soon` \| `eol` | **calculé**, voir plus bas |
| `latest_version` | chaîne ou `null` | dernière version connue de la branche |
| `latest_release_date` | date ou `null` | date de cette version |
| `eol` | objet `eol` | dates de fin de support |
| `releases` | liste d'objets `release` | versions connues, de la plus récente à la plus ancienne |
| `sources` | liste de chaînes | sources ayant contribué à la branche (`endoflife`, `nginx`, `overrides`…) |

### Objet `eol`

| Champ | Type | Description |
|---|---|---|
| `end_of_active_support` | date ou `null` | fin du support actif (corrections hors sécurité) |
| `end_of_security_support` | date ou `null` | fin des correctifs de sécurité |
| `end_of_life` | date ou `null` | fin de vie / fin de support éditeur |
| `end_of_extended_support` | date ou `null` | fin du support étendu, souvent payant (ELTS, ESU…) |
| `trigger` | nom d'une des quatre dates | date qui détermine le statut |
| `trigger_date` | date ou `null` | valeur de cette date |
| `declared_eol` | booléen | la source déclare la branche en fin de vie, même sans date |
| `labels` | objet | libellé d'origine de chaque date chez la source, ex. `{"end_of_life": "Debian LTS"}` |
| `source_url` | URL ou `null` | page de référence des dates |

Les éditeurs ne nomment pas leurs phases de support de la même façon. La correspondance entre les
dates de la source et ces quatre champs, ainsi que le choix du `trigger`, se règlent produit par
produit dans `products.yaml`. Les libellés d'origine restent visibles dans `labels`.

### Calcul de `status`

Avec `today` la date du build et `N` = `eol_soon_months` (6 par défaut, réglable dans
`products.yaml`) :

1. `trigger_date` ≤ `today` → `eol` ;
2. `trigger_date` ≤ `today` + N mois → `eol_soon` ;
3. sinon, si `trigger_date` est `null` et `declared_eol` vaut `true` → `eol` ;
4. sinon → `active`.

### Objet `release`

| Champ | Type | Description |
|---|---|---|
| `version` | chaîne | ex. `7.4.13`, `12.2.4-h1`, `10.6p1` |
| `date` | date ou `null` | date de publication |
| `security_fix` | booléen ou `null` | contient des correctifs de sécurité ; `null` si la source ne le dit pas |
| `summary` | chaîne (≤ 300 car.) ou `null` | résumé court, jamais la note de version recopiée |
| `url` | URL ou `null` | note de version ou page officielle |

## Objet `advisory`

| Champ | Type | Description |
|---|---|---|
| `id` | chaîne | identifiant d'origine : `FG-IR-26-187`, `CVE-2026-0308`, `PAN-SA-2026-0006`, `cisco-sa-…`, `CERTFR-2026-AVI-1381`, `DSA-6592-1` |
| `source` | `fortinet` \| `paloalto` \| `cisco` \| `certfr` \| `debian` | flux d'origine |
| `vendor` | chaîne | éditeur de l'avis (`CERT-FR` pour le CERT-FR) |
| `title` | chaîne | titre de l'avis |
| `published` | horodatage | première publication |
| `updated` | horodatage ou `null` | dernière mise à jour connue |
| `severity` | `critical` \| `high` \| `medium` \| `low` \| `info` \| `null` | sévérité normalisée |
| `cvss` | nombre ou `null` | score CVSS de base annoncé par l'éditeur |
| `cves` | liste de chaînes | CVE citées |
| `url` | URL | avis officiel complet |
| `summary` | chaîne (≤ 300 car.) ou `null` | résumé court |
| `affected` | liste d'`id` de branches | branches concernées **quand c'est déductible de façon fiable**, sinon vide |
| `attribution` | chaîne ou `null` | mention de source obligatoire (Cisco) |

Le couple (`source`, `id`) est unique ; `id` seul l'est aussi en pratique, le build le vérifie.

`affected` ne contient que des `id` de branches publiées. Il est rempli aujourd'hui pour :

- Palo Alto : versions PAN-OS marquées comme touchées dans l'API de l'éditeur ;
- Debian : suites corrigées par le DSA (`[trixie]` → `debian-13`).

## Fusion et surcharges

Pour chaque champ d'une branche, la priorité est : `overrides.yaml` > source éditeur
> endoflife.date. Les versions (`releases`) sont réunies par numéro de version, champ par champ avec
la même priorité. `latest_version` est la plus haute version connue, sauf surcharge.

Les versions déjà vues sont conservées d'un build à l'autre : les flux qui n'exposent que les
dernières versions construisent ainsi un historique.
