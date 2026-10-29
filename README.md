# Vigie — collecteur

Vigie suit les mises à jour des équipements et logiciels d'infrastructure : firewalls, switchs,
systèmes serveurs et services. Pour chaque produit, il dit quelles branches de version sont
encore supportées, quelle est la dernière version de chacune et quels avis de sécurité les
éditeurs ont publiés.

Ce dépôt, `vigie-collector`, est la **source de vérité** du projet. Il interroge des sources
publiques, normalise les données et les publie en fichiers JSON statiques sur GitHub Pages.
L'application `vigie-app` (Android, puis extension navigateur) ne fait que lire ces fichiers.

## Données publiées

Point d'entrée : **<https://tchyze.github.io/vigie-collector/index.json>**

| Fichier | Contenu |
|---|---|
| `index.json` | produits suivis, nombre de branches par statut, état de chaque source |
| `products/<produit>.json` | branches d'un produit : statut, dernière version, dates de fin de support, versions connues |
| `advisories.json` | avis de sécurité des 365 derniers jours |
| `schema/*.schema.json` | JSON Schema de ces fichiers |

Le format est décrit en détail dans [SCHEMA.md](SCHEMA.md). Chaque fichier porte un entier
`schema_version` (actuellement `1`) qui ne change qu'en cas de rupture de compatibilité.

Le statut d'une branche (`active`, `eol_soon`, `eol`) est calculé à partir de sa date de fin de
support. `eol_soon` signifie qu'il reste moins de 6 mois ; le seuil se règle dans `products.yaml`.

Les avis ne reprennent jamais le texte complet de l'éditeur : un titre, un résumé court et le lien
vers la page officielle.

## Produits et sources

| Produit | Catégorie | Versions et fins de support |
|---|---|---|
| FortiOS | firewall | endoflife.date + annonces de firmware Fortinet |
| PAN-OS | firewall | endoflife.date |
| Stormshield SNS | firewall | endoflife.date |
| Cisco IOS XE | switch | endoflife.date |
| Debian, RHEL, Rocky Linux, Windows Server, Proxmox VE | os | endoflife.date |
| nginx | service | endoflife.date + fichiers CHANGES de nginx.org |
| Apache HTTP Server | service | endoflife.date + tags officiels et CHANGES_2.4 |
| OpenSSH | service | tags du miroir officiel openssh-portable |

| Avis de sécurité | Source |
|---|---|
| Fortinet | flux RSS FortiGuard PSIRT |
| Palo Alto Networks | API JSON du portail sécurité (branches PAN-OS touchées) |
| Cisco | flux RSS des Cisco Security Advisories |
| CERT-FR | flux RSS des avis et alertes, JSON de chaque document |
| Debian | liste DSA du security tracker (branches corrigées) et flux dsa-long |

Toutes les sources sont publiques et sans authentification. Les avis Cisco portent la mention de
source exigée par Cisco ; leur usage doit rester non commercial.

Ce qui n'est pas encore couvert est listé dans [ROADMAP.md](ROADMAP.md).

## Fonctionnement

```
products.yaml ─┐
overrides.yaml ┤
               ├─> build.py ─> collecteurs ─> fusion ─> statuts ─> validation ─> output/
previous/ ─────┘   (dernière publication)
```

1. `build.py` exécute chaque collecteur de `collectors/`. Un collecteur interroge une source et
   renvoie des branches et/ou des avis normalisés.
2. **Un collecteur qui échoue ne bloque pas les autres.** Ses dernières données valides sont
   reprises de la publication précédente, et l'échec apparaît dans `index.json`
   (`status: "error"`, `error`, `last_success`).
3. Les branches sont fusionnées champ par champ, avec cette priorité :
   `overrides.yaml` > source éditeur > endoflife.date.
4. Les versions déjà vues sont conservées d'un passage à l'autre. Les flux qui ne montrent que
   leurs dernières entrées construisent ainsi un historique.
5. Chaque document est validé contre son JSON Schema avant d'être écrit.

`build.py` sort en erreur, et le workflow ne publie rien, dans deux cas : un document ne respecte
pas le schéma, ou une source renvoie 0 résultat alors qu'elle en renvoyait avant.

Le client HTTP s'identifie (`Vigie-collector/<version> (+https://github.com/Tchyze/vigie-collector)`),
applique un timeout de 30 s et attend au moins une seconde entre deux requêtes vers un même hôte.
Le CERT-FR ne retélécharge que les documents nouveaux ou modifiés.

### Automatisation

- `.github/workflows/publish.yml` : toutes les 6 heures, et à la demande depuis l'onglet
  Actions. Il récupère la dernière publication, lance `build.py`, puis publie `output/` sur la
  branche `gh-pages`. Celle-ci ne contient qu'un seul commit : les données ne polluent ni `main`
  ni l'historique.
- `.github/workflows/tests.yml` : lance les tests à chaque push, sans accès réseau.

GitHub Pages doit servir la branche `gh-pages`, à la racine
(*Settings → Pages → Deploy from a branch*).

## Utilisation locale

Python 3.12 ou plus récent. Si `python3 -m venv` n'est pas disponible (paquet `python3-venv`
absent), `uv venv -p 3.12 .venv` fait la même chose.

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -e ".[dev]"
```

```bash
.venv/bin/python build.py
```

Les fichiers sont écrits dans `output/`. Pour reprendre l'état d'une publication, placez-la dans
`previous/` (ou `--previous <dossier>`). `--only endoflife,nginx` limite la collecte à certaines
sources.

```bash
.venv/bin/pytest
```

Les tests ne touchent pas au réseau : ils rejouent des réponses réelles enregistrées dans
`tests/fixtures/`.

## Surcharges manuelles

`overrides.yaml` corrige ou complète les données des sources : dates de fin de support, dernière
version, versions manquantes. Une surcharge l'emporte toujours. Exemple :

```yaml
fortios:
  "7.4":
    eol:
      end_of_life: 2027-11-14
      source_url: https://support.fortinet.com/...
    latest_version: "7.4.13"
```

## Ajouter un produit

Si le produit est sur endoflife.date, il suffit d'ajouter une entrée dans `products.yaml` :
identifiant endoflife.date, catégorie, et correspondance des dates de support (`eol_fields`) si
les libellés de l'éditeur ne suivent pas la convention par défaut. Enregistrez ensuite sa réponse
pour les tests (voir plus bas).

## Ajouter une source

1. Vérifiez que la source est publique, stable et structurée : API, RSS/Atom, JSON ou texte
   versionné. Pas de scraping de pages HTML, pas de source derrière un login.
2. Créez `collectors/<source>.py` avec une classe dérivée de `collectors.base.Collector` :
   `name`, `label`, `kind` (`versions` ou `advisories`), `home`, et `attribution` si la source
   l'exige. Sa méthode `collect(ctx)` renvoie un `CollectResult` :
   - des `BranchData` (produit, branche, dates, versions `Release`) pour une source de versions ;
   - des `Advisory` pour une source d'avis. Ne remplissez `affected` que si les branches
     touchées se déduisent de façon fiable.

   `ctx.client` est le client HTTP commun, à utiliser pour toutes les requêtes. `ctx.previous`
   est le dernier état de la source, utile pour ne télécharger que les nouveautés.
3. Exposez `COLLECTOR = MaSource()` en fin de module et ajoutez-le à `collectors/__init__.py`.
   Une source d'avis nouvelle doit aussi être ajoutée à l'énumération `source` de
   `schema/advisories.schema.json`.
4. Déclarez les URL de la source dans `tests/fixtures/manifest.yaml` et enregistrez les réponses
   réelles :

   ```bash
   .venv/bin/python scripts/record_fixtures.py <motif d'URL>
   ```

5. Écrivez `tests/test_<source>.py` à partir de ces réponses.

## Licence

GPL-3.0-or-later. Les données publiées restent soumises aux conditions de leurs sources
(voir `index.json` → `sources[].attribution`).
