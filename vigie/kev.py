"""CISA KEV (Known Exploited Vulnerabilities) : marque les avis dont une CVE est activement exploitée.

https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json : catalogue
de la CISA (domaine public), environ 1 800 CVE dont l'exploitation est avérée, 1,8 Mo.

Ce n'est pas une source d'avis : build.py l'applique à tous les avis publiés, champ `exploited` :
- `true`  : au moins une CVE de l'avis est au catalogue ;
- `false` : l'avis cite des CVE, aucune n'est au catalogue ;
- `null`  : l'avis ne cite aucune CVE, ou le catalogue n'a jamais pu être lu.

Si le catalogue est inaccessible, le dernier catalogue lu (état `state/cisa_kev.json`) sert, et
la source apparaît en erreur dans index.json.
"""

import json
import logging
import re
from pathlib import Path

from vigie.http import HttpClient

NAME = "cisa_kev"
LABEL = "CISA Known Exploited Vulnerabilities (failles exploitées)"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HOME = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
log = logging.getLogger(__name__)


def fetch(client: HttpClient) -> dict[str, str]:
    """{CVE: date d'ajout au catalogue}."""
    data = client.json(URL)
    items = data.get("vulnerabilities")
    if not isinstance(items, list) or not items:
        raise ValueError("catalogue KEV vide ou illisible")
    return {v["cveID"]: v.get("dateAdded") for v in items if CVE.match(v.get("cveID") or "")}


def load(path: Path) -> dict[str, str] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8")).get("cves") or None


def save(path: Path, catalog: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"source": NAME, "cves": dict(sorted(catalog.items()))}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def exploited(cves: list[str], catalog: dict[str, str] | None) -> bool | None:
    if catalog is None or not cves:
        return None
    return any(c in catalog for c in cves)


def collect(client: HttpClient, previous_state: Path, output_state: Path, prev_entry: dict | None,
            stamp: str) -> tuple[dict[str, str] | None, dict]:
    """Lit le catalogue (ou reprend le dernier) et rend l'entrée de la source pour index.json."""
    error = None
    try:
        catalog = fetch(client)
    except Exception as exc:  # noqa: BLE001 — une source en échec ne bloque pas le build
        error = f"{type(exc).__name__}: {exc}"
        log.error("%s : %s", NAME, error)
        catalog = load(previous_state)
    if catalog is not None:
        save(output_state, catalog)
    entry = {
        "name": NAME,
        "label": LABEL,
        "kind": "enrichment",
        "status": "error" if error else "ok",
        "count": len(catalog or {}),
        "last_attempt": stamp,
        "last_success": (prev_entry or {}).get("last_success") if error else stamp,
        "error": error,
        "home": HOME,
        "attribution": None,
    }
    return catalog, entry
