"""Lecture de products.yaml (catalogue des produits suivis) et d'overrides.yaml (surcharges manuelles)."""

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from vigie.models import EOL_KEYS

CATEGORIES = ("firewall", "switch", "os", "service")

# Champ endoflife.date -> date Vigie, sauf réglage contraire du produit.
DEFAULT_EOL_FIELDS = {
    "eoas": "end_of_active_support",
    "eol": "end_of_life",
    "eoes": "end_of_extended_support",
}


class CatalogError(ValueError):
    pass


@dataclass
class Product:
    id: str
    label: str
    vendor: str
    category: str
    endoflife: str | None = None
    eol_fields: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_EOL_FIELDS))
    trigger: str = "end_of_life"
    single_branch: str | None = None


@dataclass
class Catalog:
    products: dict[str, Product]
    eol_soon_months: int = 6
    advisory_retention_days: int = 365


def load_catalog(path: Path) -> Catalog:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    settings = raw.get("settings") or {}
    products = {}
    for pid, spec in (raw.get("products") or {}).items():
        spec = dict(spec or {})
        for key in ("label", "vendor", "category"):
            if not spec.get(key):
                raise CatalogError(f"products.yaml : {pid} : champ « {key} » manquant")
        if spec["category"] not in CATEGORIES:
            raise CatalogError(f"products.yaml : {pid} : catégorie inconnue « {spec['category']} »")
        eol_fields = dict(DEFAULT_EOL_FIELDS)
        eol_fields.update(spec.pop("eol_fields", None) or {})
        for source_field, target in eol_fields.items():
            if source_field not in DEFAULT_EOL_FIELDS or (target is not None and target not in EOL_KEYS):
                raise CatalogError(f"products.yaml : {pid} : eol_fields {source_field} -> {target} invalide")
        trigger = spec.pop("trigger", None) or eol_fields.get("eol") or "end_of_life"
        if trigger not in EOL_KEYS:
            raise CatalogError(f"products.yaml : {pid} : trigger « {trigger} » invalide")
        unknown = set(spec) - {"label", "vendor", "category", "endoflife", "single_branch"}
        if unknown:
            raise CatalogError(f"products.yaml : {pid} : champs inconnus {sorted(unknown)}")
        products[pid] = Product(id=pid, eol_fields=eol_fields, trigger=trigger, **spec)
    return Catalog(
        products=products,
        eol_soon_months=int(settings.get("eol_soon_months", 6)),
        advisory_retention_days=int(settings.get("advisory_retention_days", 365)),
    )


OVERRIDE_BRANCH_KEYS = {"label", "lts", "release_date", "latest_version", "latest_release_date", "eol", "releases"}
OVERRIDE_EOL_KEYS = set(EOL_KEYS) | {"trigger", "declared_eol", "source_url"}
OVERRIDE_RELEASE_KEYS = {"version", "date", "security_fix", "summary", "url"}


def load_overrides(path: Path, catalog: Catalog) -> dict[tuple[str, str], dict]:
    """Renvoie {(produit, branche): surcharge}, dates converties en chaînes AAAA-MM-JJ."""
    path = Path(path)
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    result = {}
    for pid, branches in raw.items():
        if pid not in catalog.products:
            raise CatalogError(f"overrides.yaml : produit inconnu « {pid} »")
        for branch, spec in (branches or {}).items():
            where = f"overrides.yaml : {pid} {branch}"
            spec = _dates_to_str(spec or {})
            _check_keys(where, spec, OVERRIDE_BRANCH_KEYS)
            _check_keys(f"{where} eol", spec.get("eol") or {}, OVERRIDE_EOL_KEYS)
            if spec.get("eol", {}).get("trigger") not in (None, *EOL_KEYS):
                raise CatalogError(f"{where} : trigger invalide")
            for release in spec.get("releases") or []:
                _check_keys(f"{where} releases", release, OVERRIDE_RELEASE_KEYS)
                if not release.get("version"):
                    raise CatalogError(f"{where} : release sans « version »")
                release["version"] = str(release["version"])
            if spec.get("latest_version") is not None:
                spec["latest_version"] = str(spec["latest_version"])
            result[(pid, str(branch))] = spec
    return result


def _check_keys(where: str, spec: dict, allowed: set[str]) -> None:
    unknown = set(spec) - allowed
    if unknown:
        raise CatalogError(f"{where} : champs inconnus {sorted(unknown)}")


def _dates_to_str(value):
    if isinstance(value, dict):
        return {k: _dates_to_str(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_dates_to_str(v) for v in value]
    if isinstance(value, dt.date):
        return value.isoformat()
    return value
