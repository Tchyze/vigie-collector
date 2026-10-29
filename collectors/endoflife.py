"""endoflife.date (API v1) : branches, dates de fin de support et dernière version de chaque branche.

https://endoflife.date/docs/api/v1/
"""

import logging

from collectors.base import CollectError, Collector, Context
from vigie.models import BranchData, CollectResult, Release

API = "https://endoflife.date/api/v1/products/{slug}"
log = logging.getLogger(__name__)


class EndOfLife(Collector):
    name = "endoflife"
    label = "endoflife.date"
    kind = "versions"
    role = "reference"
    home = "https://endoflife.date"

    def collect(self, ctx: Context) -> CollectResult:
        result, failures = CollectResult(), []
        for product in ctx.catalog.products.values():
            if not product.endoflife:
                continue
            try:
                data = ctx.client.json(API.format(slug=product.endoflife))["result"]
                result.branches.extend(parse_product(product, data))
            except Exception as exc:  # un produit en échec ne prive pas les autres
                log.warning("endoflife.date : %s : %s", product.endoflife, exc)
                failures.append(f"{product.endoflife} : {exc}")
        if failures:
            raise CollectError("; ".join(failures), result)
        return result


def parse_product(product, data: dict) -> list[BranchData]:
    labels = data.get("labels") or {}
    html = (data.get("links") or {}).get("html")
    branches = []
    for rel in data["releases"]:
        dates, eol_labels = {}, {}
        for source_field, target in product.eol_fields.items():
            if target is None:
                continue
            if rel.get(f"{source_field}From"):
                dates[target] = rel[f"{source_field}From"]
            if labels.get(source_field):
                eol_labels[target] = labels[source_field]
        latest = rel.get("latest")
        releases = []
        if latest and latest.get("name"):
            releases.append(Release(version=latest["name"], date=latest.get("date"), url=latest.get("link")))
        branches.append(BranchData(
            product=product.id,
            branch=rel["name"],
            label=rel.get("label") or rel["name"],
            lts=rel.get("isLts"),
            release_date=rel.get("releaseDate"),
            eol_dates=dates,
            eol_labels=eol_labels,
            eol_source_url=html,
            declared_eol=rel.get("isEol"),
            releases=releases,
        ))
    return branches


COLLECTOR = EndOfLife()
