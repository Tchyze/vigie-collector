"""Cisco : avis de sécurité, depuis le flux RSS officiel du Cisco PSIRT.

https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml
(l'ancienne adresse rss.x?i=44 renvoie désormais une page HTML). Chaque description se termine
par la sévérité (« Security Impact Rating ») et les CVE.

Branches IOS XE touchées : pour un avis qui cite IOS XE (titre ou description), le document CSAF
de Cisco (fournisseur CSAF de confiance) est lu. Il range chaque version touchée sous la famille
« Cisco IOS XE Software », puis sous sa branche (`product_version` « 17.9 ») : la branche
`cisco-ios-xe-17.9` se lit directement. L'index https://www.cisco.com/.well-known/csaf/changes.csv
donne le chemin du document et sa date de mise à jour (`updated`) ; un document n'est relu que s'il
a changé. Le CSAF ne donne pas les versions corrigées. Un échec du CSAF n'empêche pas de publier
l'avis, sans branches.

Conditions d'utilisation : citer Cisco comme source ; usage non commercial.
"""

import logging
import re
from urllib.parse import urlsplit

import feedparser

from collectors._text import cves, iso_utc, normalize_severity, short_summary, strip_html, utc_from_struct
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

FEED = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
CSAF_INDEX = "https://www.cisco.com/.well-known/csaf/changes.csv"
CSAF_DOCUMENT = "https://www.cisco.com/.well-known/csaf/{path}"
IOS_XE = re.compile(r"\bIOS XE\b")
IOS_XE_FAMILY = "Cisco IOS XE Software"
PRODUCT = "cisco-ios-xe"
MAX_CSAF_PER_RUN = 10  # documents de 100 à 600 Ko
log = logging.getLogger(__name__)
ATTRIBUTION = "Source : Cisco Systems, Inc. — Cisco Security Advisories (usage non commercial)"
RATING = re.compile(r"Security Impact Rating:\s*(\w+)", re.I)
TRAILER = re.compile(r"This advisory is available at the following link:|Security Impact Rating:", re.I)


class Cisco(Collector):
    name = "cisco"
    label = "Cisco Security Advisories"
    kind = "advisories"
    home = "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"
    attribution = ATTRIBUTION

    def collect(self, ctx: Context) -> CollectResult:
        feed = feedparser.parse(ctx.client.get(FEED).content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux RSS illisible : {feed.bozo_exception}")
        advisories = []
        for entry in feed.entries:
            parts = urlsplit(entry.get("link", "").strip())
            advisory_id = parts.path.rstrip("/").rsplit("/", 1)[-1]
            published = utc_from_struct(entry.get("published_parsed"))
            if not advisory_id.startswith("cisco-sa-") or not published:
                continue
            text = strip_html(entry.get("summary"))
            rating = RATING.search(text)
            advisories.append(Advisory(
                id=advisory_id,
                source="cisco",
                vendor="Cisco",
                title=entry.title.strip(),
                published=published,
                url=f"{parts.scheme}://{parts.netloc}{parts.path}",
                severity=normalize_severity(rating.group(1)) if rating else None,
                cves=cves(text),
                summary=short_summary(TRAILER.split(text, 1)[0]),
                attribution=ATTRIBUTION,
            ))
        add_ios_xe_branches(ctx, advisories)
        return CollectResult(advisories=advisories)


def add_ios_xe_branches(ctx: Context, advisories: list[Advisory]) -> None:
    """Remplit `affected` (et `updated`) des avis IOS XE à partir de leur document CSAF."""
    candidates = [a for a in advisories if IOS_XE.search(f"{a.title} {a.summary or ''}")]
    if not candidates:
        return
    previous = {a.id: a for a in (ctx.previous.advisories if ctx.previous else [])}
    try:
        index = csaf_index(ctx.client.text(CSAF_INDEX))
    except Exception as exc:  # noqa: BLE001 — l'avis reste publié, sans branches
        log.warning("Cisco : index CSAF indisponible (%s)", exc)
        index = {}
    budget = MAX_CSAF_PER_RUN
    for advisory in candidates:
        path, changed = index.get(advisory.id.lower(), (None, None))
        old = previous.get(advisory.id)
        if old and old.affected and (changed is None or old.updated == changed):
            advisory.affected, advisory.updated = old.affected, old.updated  # document inchangé
            continue
        if path is None or budget <= 0:
            continue
        budget -= 1
        try:
            advisory.affected = ios_xe_branches(ctx.client.json(CSAF_DOCUMENT.format(path=path)))
        except Exception as exc:  # noqa: BLE001
            log.warning("Cisco : CSAF de %s illisible (%s)", advisory.id, exc)
            continue
        if changed and changed > advisory.published:
            advisory.updated = changed


def csaf_index(text: str) -> dict[str, tuple[str, str]]:
    """{identifiant en minuscules : (chemin du document, date de mise à jour)}."""
    index = {}
    for line in text.splitlines():
        path, _, stamp = line.strip().strip('"').partition(",")
        path, stamp = path.strip('"'), stamp.strip().strip('"')
        if path.endswith(".json") and stamp:
            index[path.rsplit("/", 1)[-1][:-5].lower()] = (path, iso_utc(stamp))
    return index


def ios_xe_branches(document: dict) -> list[str]:
    """Branches IOS XE (« cisco-ios-xe-17.9 ») dont une version est en known_affected."""
    affected_ids = {pid for v in document.get("vulnerabilities") or []
                    for pid in (v.get("product_status") or {}).get("known_affected") or []}
    branches = set()

    def walk(node: dict, family: str | None, branch: str | None) -> None:
        for child in node.get("branches") or []:
            category, name = child.get("category"), (child.get("name") or "").strip()
            fam = name if category == "product_family" else family
            br = name if category == "product_version" and fam == IOS_XE_FAMILY else branch
            product = child.get("product")
            if product and fam == IOS_XE_FAMILY and br and product.get("product_id") in affected_ids:
                branches.add(br)
            walk(child, fam, br)

    walk(document.get("product_tree") or {}, None, None)
    key = lambda b: tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.]", b))  # noqa: E731
    return [f"{PRODUCT}-{b.lower()}" for b in sorted(branches, key=key, reverse=True)]


COLLECTOR = Cisco()
