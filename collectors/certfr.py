"""CERT-FR : avis et alertes de sécurité (ANSSI).

Source transverse : elle couvre aussi des éditeurs sans flux exploitable (Stormshield,
HPE Aruba, Microsoft…). Le domaine a migré vers cert.cyber.gouv.fr.

- flux RSS https://www.cert.cyber.gouv.fr/avis/feed/ et /alerte/feed/ : titre, date, résumé ;
- JSON de chaque document (<lien>/json/) : CVE et historique des révisions. Il n'est téléchargé
  que pour les documents nouveaux ou modifiés, avec un plafond par passage.

Les systèmes touchés sont décrits en texte libre : `affected` reste vide.
"""

import datetime as dt
import logging
import re

import feedparser

from collectors._text import cves, iso_utc, short_summary, utc_from_struct
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

FEEDS = (
    "https://www.cert.cyber.gouv.fr/avis/feed/",
    "https://www.cert.cyber.gouv.fr/alerte/feed/",
)
REFERENCE = re.compile(r"CERTFR-\d{4}-(?:AVI|ALE)-\d+")
MAX_JSON_PER_RUN = 60
log = logging.getLogger(__name__)


class CertFr(Collector):
    name = "certfr"
    label = "CERT-FR (avis et alertes)"
    kind = "advisories"
    home = "https://www.cert.cyber.gouv.fr/"

    def collect(self, ctx: Context) -> CollectResult:
        previous = {a.id: a for a in (ctx.previous.advisories if ctx.previous else [])}
        cutoff = (ctx.today - dt.timedelta(days=ctx.catalog.advisory_retention_days)).isoformat()
        advisories, budget = [], MAX_JSON_PER_RUN
        for feed_url in FEEDS:
            feed = feedparser.parse(ctx.client.get(feed_url).content)
            if feed.bozo and not feed.entries:
                raise ValueError(f"{feed_url} : flux illisible : {feed.bozo_exception}")
            for entry in feed.entries:
                link = entry.get("link", "")
                match = REFERENCE.search(link)
                published = utc_from_struct(entry.get("published_parsed"))
                if not match or not published:
                    continue
                advisory = Advisory(
                    id=match.group(0),
                    source="certfr",
                    vendor="CERT-FR",
                    title=entry.title.strip(),
                    published=published,
                    url=link,
                    summary=short_summary(entry.get("summary")),
                )
                known = previous.get(advisory.id)
                if known and known.title == advisory.title and known.cves:
                    advisory.cves, advisory.updated = known.cves, known.updated
                elif not known and published[:10] < cutoff:
                    # Alerte ancienne (le flux garde les alertes publiées il y a des années) :
                    # hors rétention, elle serait retéléchargée à chaque passage pour rien.
                    pass
                elif budget > 0:
                    budget -= 1
                    self._enrich(ctx, advisory, link)
                elif known:
                    advisory.cves, advisory.updated = known.cves, known.updated
                advisories.append(advisory)
        return CollectResult(advisories=advisories)

    def _enrich(self, ctx: Context, advisory: Advisory, link: str) -> None:
        """CVE et date de dernière révision depuis le JSON du document ; un échec n'est pas bloquant."""
        try:
            data = ctx.client.json(link.rstrip("/") + "/json/")
        except Exception as exc:
            log.warning("CERT-FR : %s : JSON indisponible (%s)", advisory.id, exc)
            return
        advisory.cves = cves(" ".join(c.get("name") or "" for c in data.get("cves") or []))
        revisions = sorted(r["revision_date"] for r in data.get("revisions") or [] if r.get("revision_date"))
        if len(revisions) > 1:
            advisory.updated = iso_utc(revisions[-1])


COLLECTOR = CertFr()
