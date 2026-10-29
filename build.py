"""Exécute les collecteurs, fusionne, calcule les statuts, valide et écrit output/.

Usage : python build.py [--output output] [--previous previous] [--only endoflife,nginx]

`--previous` désigne la dernière publication (copie de la branche gh-pages) : on y reprend
l'état de chaque source, pour garder les dernières données valides d'une source en échec et
prolonger l'historique des versions.

Code de sortie non nul si la validation échoue ou si une source renvoie 0 résultat alors
qu'elle en renvoyait avant ; les fichiers sont tout de même écrits, pour diagnostic.
"""

import argparse
import datetime as dt
import json
import logging
import shutil
import sys
from pathlib import Path

import collectors
from collectors.base import CollectError, Context
from vigie import SCHEMA_VERSION, state, validate
from vigie.catalog import Catalog, load_catalog, load_overrides
from vigie.http import HttpClient
from vigie.merge import Contribution, merge_branches
from vigie.models import CollectResult

ROOT = Path(__file__).resolve().parent
log = logging.getLogger("vigie")


def utc_stamp(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(
    *,
    catalog: Catalog,
    overrides: dict,
    sources: list,
    client: HttpClient,
    output: Path,
    previous: Path,
    now: dt.datetime,
) -> int:
    today = now.date()
    stamp = utc_stamp(now)
    prev_index = _read_json(previous / "index.json") or {}
    prev_sources = {s["name"]: s for s in prev_index.get("sources", [])}

    (output / "state").mkdir(parents=True, exist_ok=True)
    shutil.rmtree(output / "products", ignore_errors=True)
    (output / "products").mkdir()

    failed = False
    source_entries, contributions, advisories = [], [], []
    for collector in sources:
        prev_state = state.load(previous / "state" / f"{collector.name}.json")
        prev_entry = prev_sources.get(collector.name)
        prev_count = prev_entry["count"] if prev_entry else (prev_state.count() if prev_state else 0)
        log.info("collecte : %s", collector.name)

        error, result = None, None
        try:
            result = collector.collect(Context(client=client, catalog=catalog, today=today, previous=prev_state))
        except CollectError as exc:
            error, result = str(exc), exc.partial
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        if error is None and result.count() == 0 and prev_count > 0:
            error = f"0 résultat alors que la source en renvoyait {prev_count}"
            result = None
            failed = True
        if error:
            log.error("%s : %s", collector.name, error)

        if result is None:
            result = prev_state or CollectResult()
        else:
            result = state.accumulate(prev_state, result)
        result = state.prune_advisories(result, today, catalog.advisory_retention_days)
        state.save(output / "state" / f"{collector.name}.json", collector.name, result)

        source_entries.append({
            "name": collector.name,
            "label": collector.label,
            "kind": collector.kind,
            "status": "error" if error else "ok",
            "count": result.count(),
            "last_attempt": stamp,
            "last_success": (prev_entry or {}).get("last_success") if error else stamp,
            "error": error,
            "home": collector.home,
            "attribution": collector.attribution,
        })
        contributions += [Contribution(collector.name, collector.role, b) for b in result.branches]
        advisories += result.advisories

    products = merge_branches(catalog, contributions, overrides, today)
    known_ids = {b["id"] for branches in products.values() for b in branches}

    documents: dict[str, tuple[str, dict]] = {}
    index_products = []
    for pid, branches in products.items():
        product = catalog.products[pid]
        documents[f"products/{pid}.json"] = ("product", {
            "schema_version": SCHEMA_VERSION,
            "generated_at": stamp,
            "product": pid,
            "label": product.label,
            "vendor": product.vendor,
            "category": product.category,
            "branches": branches,
        })
        counts = {"active": 0, "eol_soon": 0, "eol": 0}
        for branch in branches:
            counts[branch["status"]] += 1
        index_products.append({
            "id": pid, "label": product.label, "vendor": product.vendor, "category": product.category,
            "file": f"products/{pid}.json", "branch_count": len(branches), "status_counts": counts,
        })

    published = []
    seen: dict[str, str] = {}
    for adv in sorted(advisories, key=lambda a: (a.published, a.id), reverse=True):
        if adv.id in seen:
            log.error("avis %s publié à la fois par %s et %s", adv.id, seen[adv.id], adv.source)
            failed = True
            continue
        seen[adv.id] = adv.source
        item = adv.__dict__ | {"affected": [b for b in adv.affected if b in known_ids]}
        published.append({key: item[key] for key in (
            "id", "source", "vendor", "title", "published", "updated", "severity", "cvss",
            "cves", "url", "summary", "affected", "attribution")})
    documents["advisories.json"] = ("advisories", {
        "schema_version": SCHEMA_VERSION,
        "generated_at": stamp,
        "retention_days": catalog.advisory_retention_days,
        "advisories": published,
    })
    documents["index.json"] = ("index", {
        "schema_version": SCHEMA_VERSION,
        "generated_at": stamp,
        "eol_soon_months": catalog.eol_soon_months,
        "products": index_products,
        "advisories": {"file": "advisories.json", "count": len(published)},
        "sources": source_entries,
    })

    for name, (kind, document) in documents.items():
        problems = validate.errors(kind, document)
        for problem in problems[:20]:
            log.error("schéma %s : %s", name, problem)
        failed |= bool(problems)
        (output / name).write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    shutil.copytree(ROOT / "schema", output / "schema", dirs_exist_ok=True)
    (output / ".nojekyll").touch()
    log.info("%d produits, %d branches, %d avis -> %s", len(products), len(known_ids), len(published), output)
    return 1 if failed else 0


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, default=ROOT / "output")
    parser.add_argument("--previous", type=Path, default=ROOT / "previous")
    parser.add_argument("--products", type=Path, default=ROOT / "products.yaml")
    parser.add_argument("--overrides", type=Path, default=ROOT / "overrides.yaml")
    parser.add_argument("--only", help="noms de collecteurs séparés par des virgules")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s : %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    catalog = load_catalog(args.products)
    overrides = load_overrides(args.overrides, catalog)
    sources = collectors.ALL
    if args.only:
        wanted = set(args.only.split(","))
        sources = [c for c in sources if c.name in wanted]
    client = HttpClient()
    try:
        return run(catalog=catalog, overrides=overrides, sources=sources, client=client,
                   output=args.output, previous=args.previous, now=dt.datetime.now(dt.timezone.utc))
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
