"""Stormshield : avis de sécurité publiés par l'éditeur (advisories.stormshield.eu).

Le flux RSS (WordPress) donne l'identifiant (`2026-034`), le titre, la date et le produit en
catégorie (« Stormshield Network Security »…). Sa description est vide et le site n'a pas d'API :
CVE, score et versions touchées ne figurent que dans la page HTML de l'avis, que Vigie ne lit
pas (pas de scraping). On garde donc l'essentiel, avec le lien vers l'avis officiel ; les CVE
citées dans le titre sont reprises.

Le flux ne montre que les 10 derniers billets : l'historique se construit au fil des passages.
"""

import re

import feedparser

from collectors._text import cves, utc_from_struct
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

FEED = "https://advisories.stormshield.eu/feed/"
ADVISORY_ID = re.compile(r"advisories\.stormshield\.eu/(\d{4}-\d{3,})/?$")
CATEGORY = "Advisories"


class Stormshield(Collector):
    name = "stormshield"
    label = "Stormshield Security Advisories"
    kind = "advisories"
    home = "https://advisories.stormshield.eu/"

    def collect(self, ctx: Context) -> CollectResult:
        feed = feedparser.parse(ctx.client.get(FEED).content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux RSS illisible : {feed.bozo_exception}")
        advisories = [a for a in (parse_entry(e) for e in feed.entries) if a is not None]
        return CollectResult(advisories=advisories)


def parse_entry(entry) -> Advisory | None:
    """Avis Vigie pour un billet de la catégorie « Advisories », sinon None (actualités…)."""
    terms = [t.get("term") for t in entry.get("tags") or []]
    match = ADVISORY_ID.search(entry.get("link", ""))
    published = utc_from_struct(entry.get("published_parsed"))
    if CATEGORY not in terms or not match or not published:
        return None
    products = [t for t in terms if t and t.startswith("Stormshield")]
    return Advisory(
        id=f"STORMSHIELD-{match.group(1)}",
        source="stormshield",
        vendor="Stormshield",
        title=entry.title.strip(),
        published=published,
        url=entry.link,
        cves=cves(entry.title),
        summary=f"Produit : {', '.join(products)}." if products else None,
    )


COLLECTOR = Stormshield()
