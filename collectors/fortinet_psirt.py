"""Fortinet PSIRT : avis de sécurité FortiGuard.

- flux RSS https://www.fortiguard.com/rss/ir.xml (redirigé vers filestore.fortinet.com) :
  50 derniers avis, score CVSSv3 en tête de description, lien vers le document CSAF (`csaf:link`) ;
- document CSAF 2.0 de chaque avis : CVE et versions touchées. Il n'est téléchargé que pour les
  avis nouveaux ou révisés, avec un plafond par passage.

`affected` ne retient que les produits suivis par Vigie (FortiOS) et seulement les plages de
versions que l'on sait ramener sans ambiguïté à une branche (`fortios-7.4`).

Les versions corrigées (`known_not_affected` : « FortiOS-7.6.7 ») sont rendues comme des versions
de branche avec `security_fix: true`. L'état conserve celles des avis déjà traités.
"""

import logging
import re

import feedparser

from collectors._text import cves, severity_from_cvss, short_summary, strip_html, utc_from_struct
from collectors.base import Collector, Context
from vigie.models import Advisory, BranchData, CollectResult, Release, branch_id

FEED = "https://www.fortiguard.com/rss/ir.xml"
CVSS = re.compile(r"CVSSv3 Score:\s*(\d+(?:\.\d+)?)", re.I)
ADVISORY_ID = re.compile(r"FG-IR-\d+-\d+")
REVISED = re.compile(r"Revised on (\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
MAX_CSAF_PER_RUN = 60

# Nom de produit dans le CSAF -> identifiant Vigie (products.yaml).
CSAF_PRODUCTS = {"FortiOS": "fortios"}

# Partie « version » d'un product_id CSAF, une fois le nom du produit retiré. Formats observés :
#   « >=7.6.0|<=7.6.6 », « >= 8.0.0 and <= 8.0.1 », « 7.4 all versions », « 7.6.0 ».
_VERSION = r"\d+(?:\.\w+)*"
RANGE = re.compile(rf"^>=\s*({_VERSION})\s*(?:\||and)\s*<=\s*({_VERSION})$")
ALL_VERSIONS = re.compile(rf"^({_VERSION}) all versions$")
SINGLE = re.compile(rf"^({_VERSION})$")
BRANCH = re.compile(r"^(\d+\.\d+)(?:\.|$)")
FIXED_VERSION = re.compile(r"^(\d+\.\d+)\.\d+$")  # « FortiOS-7.6.7 » ; pas « FortiOS-upcoming 7.6.9 »

log = logging.getLogger(__name__)


class FortinetPsirt(Collector):
    name = "fortinet_psirt"
    label = "Fortinet PSIRT (FortiGuard)"
    kind = "advisories"
    home = "https://www.fortiguard.com/psirt"

    def collect(self, ctx: Context) -> CollectResult:
        feed = feedparser.parse(ctx.client.get(FEED).content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux RSS illisible : {feed.bozo_exception}")
        previous = {a.id: a for a in (ctx.previous.advisories if ctx.previous else [])}
        # État antérieur aux versions corrigées : relire une fois les CSAF des avis déjà connus.
        backfill = bool(ctx.previous) and not ctx.previous.branches
        advisories, fixes, budget = [], {}, MAX_CSAF_PER_RUN
        for entry in feed.entries:
            advisory = parse_entry(entry)
            if advisory is None:
                continue
            known = previous.get(advisory.id)
            csaf_link = entry.get("csaf_link")
            if known and known.updated == advisory.updated and known.cves and not backfill:
                # Avis déjà enrichi et non révisé depuis : inutile de retélécharger le CSAF.
                advisory.cves, advisory.affected = known.cves, known.affected
            elif csaf_link and budget > 0:
                budget -= 1
                self._enrich(ctx, advisory, csaf_link, fixes)
            elif known:
                advisory.cves = known.cves or advisory.cves
                advisory.affected = known.affected
            advisories.append(advisory)
        branches = [
            BranchData(product=product, branch=branch,
                       releases=[Release(version=v, security_fix=True) for v in sorted(versions)])
            for (product, branch), versions in sorted(fixes.items())
        ]
        return CollectResult(branches=branches, advisories=advisories)

    def _enrich(self, ctx: Context, advisory: Advisory, link: str, fixes: dict) -> None:
        """CVE, branches touchées et, à défaut, score CVSS ; un échec n'est pas bloquant."""
        try:
            document = ctx.client.json(link)
        except Exception as exc:
            log.warning("Fortinet : %s : CSAF indisponible (%s)", advisory.id, exc)
            return
        parsed = parse_csaf(document)
        advisory.cves = list(dict.fromkeys(parsed["cves"] + advisory.cves))
        advisory.affected = parsed["affected"]
        for product, branch, version in parsed["fixed"]:
            fixes.setdefault((product, branch), set()).add(version)
        if advisory.cvss is None and parsed["cvss"] is not None:
            advisory.cvss = parsed["cvss"]
            advisory.severity = severity_from_cvss(parsed["cvss"])


def parse_entry(entry) -> Advisory | None:
    match = ADVISORY_ID.search(entry.get("link", ""))
    published = utc_from_struct(entry.get("published_parsed"))
    if not match or not published:
        return None
    text = strip_html(entry.get("summary"))
    score = CVSS.search(text)
    cvss = float(score.group(1)) if score else None
    revised = REVISED.search(text)
    return Advisory(
        id=match.group(0),
        source="fortinet",
        vendor="Fortinet",
        title=entry.title.strip(),
        published=published,
        url=entry.link,
        updated=f"{revised.group(1)}T{revised.group(2)}Z" if revised else None,
        severity=severity_from_cvss(cvss),
        cvss=cvss,
        cves=cves(entry.title + " " + text),
        summary=short_summary(REVISED.sub("", CVSS.sub("", text))),
    )


def parse_csaf(document: dict) -> dict:
    """CVE, branches Vigie touchées et score CVSS le plus élevé d'un document CSAF Fortinet."""
    names = product_names(document.get("product_tree") or {})
    found_cves, affected, fixed, scores = [], [], [], []
    for vuln in document.get("vulnerabilities") or []:
        found_cves += cves(vuln.get("cve"))
        for product_id in (vuln.get("product_status") or {}).get("known_affected") or []:
            branch = affected_branch(product_id, names.get(product_id))
            if branch:
                affected.append(branch)
        for product_id in (vuln.get("product_status") or {}).get("known_not_affected") or []:
            if version := fixed_version(product_id):
                fixed.append(version)
        for score in vuln.get("scores") or []:
            base = (score.get("cvss_v3") or {}).get("baseScore")
            if isinstance(base, (int, float)):
                scores.append(float(base))
    return {
        "cves": list(dict.fromkeys(found_cves)),
        "affected": list(dict.fromkeys(affected)),
        "cvss": max(scores) if scores else None,
        "fixed": list(dict.fromkeys(fixed)),
    }


def product_names(tree: dict) -> dict[str, str]:
    """{product_id: nom du produit} d'après l'arbre des produits.

    Le nom ne se déduit pas du product_id seul : « FortiManager 8.0.0 » et
    « FortiManager Cloud 8.0.0 » sont deux produits distincts.
    """
    names = {}

    def walk(branches):
        for branch in branches or []:
            product = branch.get("product") or {}
            if product.get("product_id") and product.get("name"):
                names[product["product_id"]] = product["name"]
            walk(branch.get("branches"))

    walk(tree.get("branches"))
    return names


def affected_branch(product_id: str, name: str | None) -> str | None:
    """Branche Vigie (« fortios-7.4 ») d'un product_id CSAF touché, ou None si on ne sait pas."""
    product = CSAF_PRODUCTS.get(name or "")
    if product is None or not product_id.startswith(name):
        return None
    spec = product_id[len(name):].strip().lstrip("/").strip()
    if match := RANGE.match(spec):
        low, high = (BRANCH.match(v) for v in match.groups())
        if not low or not high or low.group(1) != high.group(1):
            log.info("Fortinet : plage sur plusieurs branches ignorée : %s", product_id)
            return None
        version = match.group(1)
    elif match := ALL_VERSIONS.match(spec) or SINGLE.match(spec):
        version = match.group(1)
    else:
        log.info("Fortinet : format de version inconnu : %s", product_id)
        return None
    branch = BRANCH.match(version)
    return branch_id(product, branch.group(1)) if branch else None


def fixed_version(product_id: str) -> tuple[str, str, str] | None:
    """(produit, branche, version) d'une version corrigée « FortiOS-7.6.7 », sinon None."""
    for name, product in CSAF_PRODUCTS.items():
        if product_id.startswith(f"{name}-"):
            version = product_id[len(name) + 1:]
            if match := FIXED_VERSION.match(version):
                return product, match.group(1), version
    return None


COLLECTOR = FortinetPsirt()
