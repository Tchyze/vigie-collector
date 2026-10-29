"""Cisco : avis de sécurité, depuis le flux RSS officiel du Cisco PSIRT.

https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml
(l'ancienne adresse rss.x?i=44 renvoie désormais une page HTML). Chaque description se termine
par la sévérité (« Security Impact Rating ») et les CVE.

Conditions d'utilisation : citer Cisco comme source ; usage non commercial.
"""

import re
from urllib.parse import urlsplit

import feedparser

from collectors._text import cves, normalize_severity, short_summary, strip_html, utc_from_struct
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

FEED = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
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
        return CollectResult(advisories=advisories)


COLLECTOR = Cisco()
