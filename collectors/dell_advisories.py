"""Dell iDRAC : avis de sécurité (DSA), depuis les enregistrements CVE publiés par Dell.

Le portail Dell (dell.com/support/security) refuse les clients automatiques. Dell est autorité
de numérotation CVE (CNA) : l'enregistrement qu'il publie sur CVE.org contient les produits, les
versions corrigées par génération et le lien vers l'avis DSA. Deux étapes :

1. découverte : API NVD 2.0, `keywordSearch=iDRAC` (une requête, environ 70 CVE, sans clé). On
   garde les CVE publiées par le CNA Dell (`sourceIdentifier`), dans la période de rétention,
   dont la description cite une génération d'iDRAC (« iDRAC9 », « iDRAC10 ») : l'iDRAC Service
   Module, les iDRAC Tools ou les modules Ansible sont d'autres produits ;
2. détail : https://cveawg.mitre.org/api/cve/<CVE>, pour chaque CVE encore inconnue.

Les CVE d'un même avis Dell (lien « dsa-2026-392 » dans les références) forment un seul avis
`DSA-2026-392`, comme chez l'éditeur ; sans lien DSA, l'avis porte l'identifiant de la CVE.

`affected` : branche du produit `dell-idrac` déduite de chaque version corrigée (« 7.30.10.50 or
later » → `dell-idrac-7.30`) ; build.py ne garde que les branches publiées. Les versions corrigées
sont aussi données dans `summary`.

L'API NVD est lente et instable depuis GitHub Actions : un échec rend la source « en erreur » et
build.py garde les avis déjà connus. Dell ne fournit pas de titre : il est composé à partir des
produits et de la faiblesse (CWE).
"""

import datetime as dt
import logging
import re

from collectors._text import iso_utc, normalize_severity, short_summary
from collectors.base import CollectError, Collector, Context
from vigie.models import Advisory, CollectResult

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=iDRAC"
CVE_RECORD = "https://cveawg.mitre.org/api/cve/{id}"
CVE_PAGE = "https://www.cve.org/CVERecord?id={id}"
DELL_CNA = {"security_alert@emc.com", "secure@dell.com"}
PRODUCT = "dell-idrac"
IDRAC_IN_TEXT = re.compile(r"\biDRAC\s?\d+\b")
IDRAC_PRODUCT = re.compile(r"^iDRAC\s?(\d+)$")
DSA = re.compile(r"\bdsa-(\d{4})-(\d+)\b", re.I)
VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)*")
MAX_RECORDS_PER_RUN = 40
log = logging.getLogger(__name__)


class DellAdvisories(Collector):
    name = "dell_advisories"
    label = "Dell iDRAC — avis DSA (enregistrements CVE de Dell)"
    kind = "advisories"
    home = "https://www.dell.com/support/security/"
    attribution = "This product uses the NVD API but is not endorsed or certified by the NVD."

    def collect(self, ctx: Context) -> CollectResult:
        cutoff = (ctx.today - dt.timedelta(days=ctx.catalog.advisory_retention_days)).isoformat()
        previous = {a.id: a for a in (ctx.previous.advisories if ctx.previous else [])}
        known_cves = {c for a in previous.values() for c in a.cves}

        todo = [c for c in discover(ctx.client.json(NVD), cutoff) if c not in known_cves]
        records = []
        try:
            for cve_id in todo[:MAX_RECORDS_PER_RUN]:
                record = ctx.client.json(CVE_RECORD.format(id=cve_id))
                if idrac_products(record):
                    records.append(record)
        except Exception as exc:
            if not records:
                raise
            raise CollectError(f"collecte interrompue : {exc}", merge(previous, records)) from exc
        return merge(previous, records)


def discover(nvd: dict, cutoff: str) -> list[str]:
    """CVE iDRAC publiées par Dell depuis la date limite, de la plus récente à la plus ancienne."""
    found = []
    for item in nvd.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        text = " ".join(d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en")
        if (cve.get("sourceIdentifier") in DELL_CNA and (cve.get("published") or "")[:10] >= cutoff
                and IDRAC_IN_TEXT.search(text)):
            found.append((cve["published"], cve["id"]))
    return [cve_id for _, cve_id in sorted(found, reverse=True)]


def idrac_products(record: dict) -> list[tuple[str, list[str]]]:
    """[(« iDRAC9 », [versions corrigées])] pour les produits iDRAC de l'enregistrement."""
    products = []
    for affected in (record.get("containers") or {}).get("cna", {}).get("affected") or []:
        match = IDRAC_PRODUCT.match((affected.get("product") or "").strip())
        if not match or "dell" not in (affected.get("vendor") or "").lower():
            continue
        fixed = []
        for version in affected.get("versions") or []:
            bound = version.get("lessThan") or ""
            if version.get("status") == "affected" and (m := VERSION.match(bound.strip())):
                fixed.append(m.group(0))
        products.append((f"iDRAC{match.group(1)}", fixed))
    return products


def merge(previous: dict[str, Advisory], records: list[dict]) -> CollectResult:
    """Avis connus, plus les nouveaux enregistrements regroupés par DSA."""
    groups: dict[str, list[dict]] = {}
    for record in records:
        groups.setdefault(advisory_id(record), []).append(record)
    advisories = dict(previous)
    for group_id, group in groups.items():
        if group_id in advisories:  # nouvelle CVE d'un avis déjà connu : on le reconstruit
            old = advisories[group_id]
            group = group + [{"_known": old}]
        advisories[group_id] = build(group_id, group)
    return CollectResult(advisories=list(advisories.values()))


def advisory_id(record: dict) -> str:
    for ref in (record.get("containers") or {}).get("cna", {}).get("references") or []:
        if match := DSA.search(ref.get("url") or ""):
            return f"DSA-{match.group(1)}-{int(match.group(2)):03d}"
    return record["cveMetadata"]["cveId"]


def build(group_id: str, group: list[dict]) -> Advisory:
    old = next((g["_known"] for g in group if "_known" in g), None)
    records = [g for g in group if "_known" not in g]
    cna = [r["containers"]["cna"] for r in records]
    meta = [r["cveMetadata"] for r in records]

    cve_ids = sorted({m["cveId"] for m in meta} | set(old.cves if old else []))
    products: dict[str, list[str]] = {}
    for record in records:
        for product, fixed in idrac_products(record):
            products.setdefault(product, [])
            products[product] += [v for v in fixed if v not in products[product]]

    scores = []
    for c in cna:
        for metric in c.get("metrics") or []:
            for key, value in metric.items():
                if key.startswith("cvss") and isinstance(value, dict) and value.get("baseScore") is not None:
                    scores.append((float(value["baseScore"]), value.get("baseSeverity")))
    cvss, severity = max(scores) if scores else (old.cvss if old else None, old.severity if old else None)

    url = next((ref["url"] for c in cna for ref in c.get("references") or [] if DSA.search(ref.get("url") or "")),
               old.url if old else CVE_PAGE.format(id=group_id))
    published = min([iso_utc(m["datePublished"]) for m in meta if m.get("datePublished")] + ([old.published] if old else []))
    updated = max([iso_utc(m["dateUpdated"]) for m in meta if m.get("dateUpdated")] + ([old.updated] if old and old.updated else []), default=None)

    names = ", ".join(sorted(products, key=lambda p: int(p[5:]))) or "iDRAC"
    weakness = next((d.get("description") for c in cna for pt in c.get("problemTypes") or []
                     for d in pt.get("descriptions") or [] if d.get("description")), None)
    title = f"Dell {names} : {weakness}" if weakness else f"Dell {names} : vulnérabilité ({', '.join(cve_ids)})"
    fixed_text = " ; ".join(f"{p} {', '.join(v)}" for p, v in sorted(products.items(), key=lambda i: int(i[0][5:])) if v)
    description = next((d["value"] for c in cna for d in c.get("descriptions") or [] if d.get("lang", "").startswith("en")), "")
    summary = short_summary(f"Versions corrigées : {fixed_text}. {description}" if fixed_text else description)

    affected = list(old.affected) if old else []
    for versions in products.values():
        for version in versions:
            major, minor = VERSION.match(version).groups()
            branch = f"{PRODUCT}-{int(major)}.{minor}"
            if branch not in affected:
                affected.append(branch)

    return Advisory(
        id=group_id,
        source="dell",
        vendor="Dell",
        title=title[:200],
        published=published,
        updated=updated if updated and updated != published else None,
        severity=normalize_severity(severity),
        cvss=cvss,
        cves=cve_ids,
        url=url,
        summary=summary,
        affected=affected,
    )


COLLECTOR = DellAdvisories()
