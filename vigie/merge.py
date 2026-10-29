"""Fusion des branches de toutes les sources : overrides.yaml > source éditeur > endoflife.date."""

import datetime as dt
import logging
from dataclasses import dataclass

from vigie.catalog import Catalog
from vigie.models import EOL_KEYS, BranchData, Release, branch_id
from vigie.status import compute_status
from vigie.versions import sort_versions

log = logging.getLogger(__name__)

# Rang de priorité par rôle de source : le plus haut l'emporte.
RANKS = {"overrides": 3, "vendor": 2, "reference": 1}


@dataclass
class Contribution:
    source: str
    role: str
    data: BranchData

    @property
    def rank(self) -> int:
        return RANKS[self.role]


def merge_branches(
    catalog: Catalog,
    contributions: list[Contribution],
    overrides: dict[tuple[str, str], dict],
    today: dt.date,
) -> dict[str, list[dict]]:
    """Renvoie {produit: [branche publiée, …]} trié de la branche la plus récente à la plus ancienne."""
    contributions = contributions + [
        Contribution("overrides", "overrides", _override_data(product, branch, spec))
        for (product, branch), spec in overrides.items()
    ]
    grouped: dict[str, list[Contribution]] = {}
    for contrib in contributions:
        product = catalog.products.get(contrib.data.product)
        if product is None:
            log.warning("%s : produit %s absent du catalogue, ignoré", contrib.source, contrib.data.product)
            continue
        if product.single_branch and contrib.data.branch != product.single_branch:
            log.warning("%s : branche %s inattendue pour %s", contrib.source, contrib.data.branch, product.id)
            continue
        grouped.setdefault(contrib.data.id, []).append(contrib)

    result: dict[str, list[dict]] = {pid: [] for pid in catalog.products}
    for bid, group in grouped.items():
        group.sort(key=lambda c: c.rank, reverse=True)
        product = catalog.products[group[0].data.product]
        # Pour un produit couvert par endoflife.date, une branche inconnue de la référence
        # (ex. nginx 0.8 dans l'historique CHANGES) n'est publiée que si overrides.yaml la décrit.
        if product.endoflife and not any(c.role in ("reference", "overrides") for c in group):
            log.debug("%s : branche absente d'endoflife.date, ignorée", bid)
            continue
        spec = overrides.get((product.id, group[0].data.branch), {})
        result[product.id].append(_merge_one(product, group, spec, catalog.eol_soon_months, today))

    for pid, branches in result.items():
        result[pid] = sort_versions(branches, key=lambda b: b["branch"])
    return result


def _first(group: list[Contribution], getter):
    for contrib in group:
        value = getter(contrib.data)
        if value is not None:
            return value
    return None


def _merge_one(product, group: list[Contribution], spec: dict, eol_soon_months: int, today: dt.date) -> dict:
    data = group[0].data
    eol_spec = spec.get("eol") or {}
    trigger = eol_spec.get("trigger") or product.trigger
    dates = {key: _first(group, lambda d, k=key: d.eol_dates.get(k)) for key in EOL_KEYS}
    labels = {}
    for contrib in reversed(group):
        labels.update(contrib.data.eol_labels)
    declared = bool(_first(group, lambda d: d.declared_eol))

    releases = _merge_releases(group)
    latest = releases[0] if releases else None
    latest_version = spec.get("latest_version") or (latest["version"] if latest else None)
    latest_date = spec.get("latest_release_date")
    if latest_date is None and latest_version is not None:
        latest_date = next((r["date"] for r in releases if r["version"] == latest_version), None)

    return {
        "id": branch_id(product.id, data.branch),
        "product": product.id,
        "vendor": product.vendor,
        "category": product.category,
        "branch": data.branch,
        "label": _first(group, lambda d: d.label) or data.branch,
        "lts": _first(group, lambda d: d.lts),
        "release_date": _first(group, lambda d: d.release_date),
        "status": compute_status(dates[trigger], declared, today, eol_soon_months),
        "latest_version": latest_version,
        "latest_release_date": latest_date,
        "eol": {
            **dates,
            "trigger": trigger,
            "trigger_date": dates[trigger],
            "declared_eol": declared,
            "labels": {k: labels[k] for k in EOL_KEYS if k in labels},
            "source_url": _first(group, lambda d: d.eol_source_url),
        },
        "releases": releases,
        "sources": list(dict.fromkeys(c.source for c in group)),
    }


def _merge_releases(group: list[Contribution]) -> list[dict]:
    by_version: dict[str, dict] = {}
    for contrib in reversed(group):  # du rang le plus bas au plus haut : le plus haut écrase
        for release in contrib.data.releases:
            merged = by_version.setdefault(release.version, {
                "version": release.version, "date": None, "security_fix": None, "summary": None, "url": None,
            })
            for key in ("date", "security_fix", "summary", "url"):
                value = getattr(release, key)
                if value is not None:
                    merged[key] = value
    return sort_versions(by_version.values(), key=lambda r: r["version"])


def _override_data(product: str, branch: str, spec: dict) -> BranchData:
    eol = spec.get("eol") or {}
    return BranchData(
        product=product,
        branch=branch,
        label=spec.get("label"),
        lts=spec.get("lts"),
        release_date=spec.get("release_date"),
        eol_dates={k: eol[k] for k in EOL_KEYS if eol.get(k)},
        eol_source_url=eol.get("source_url"),
        declared_eol=eol.get("declared_eol"),
        releases=[Release(**r) for r in spec.get("releases") or []],
    )
