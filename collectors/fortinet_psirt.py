"""Fortinet PSIRT : avis de sécurité FortiGuard (flux RSS officiel).

https://www.fortiguard.com/rss/ir.xml (redirigé vers filestore.fortinet.com) : 50 derniers avis,
avec le score CVSSv3 en tête de description. Le flux ne donne pas les versions touchées sous
forme exploitable : `affected` reste vide (les fichiers CSAF de chaque avis le permettraient).
"""

import re

import feedparser

from collectors._text import cves, severity_from_cvss, short_summary, strip_html, utc_from_struct
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

FEED = "https://www.fortiguard.com/rss/ir.xml"
CVSS = re.compile(r"CVSSv3 Score:\s*(\d+(?:\.\d+)?)", re.I)
ADVISORY_ID = re.compile(r"FG-IR-\d+-\d+")
REVISED = re.compile(r"Revised on (\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")


class FortinetPsirt(Collector):
    name = "fortinet_psirt"
    label = "Fortinet PSIRT (FortiGuard)"
    kind = "advisories"
    home = "https://www.fortiguard.com/psirt"

    def collect(self, ctx: Context) -> CollectResult:
        feed = feedparser.parse(ctx.client.get(FEED).content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux RSS illisible : {feed.bozo_exception}")
        advisories = []
        for entry in feed.entries:
            match = ADVISORY_ID.search(entry.get("link", ""))
            published = utc_from_struct(entry.get("published_parsed"))
            if not match or not published:
                continue
            text = strip_html(entry.get("summary"))
            score = CVSS.search(text)
            cvss = float(score.group(1)) if score else None
            revised = REVISED.search(text)
            advisories.append(Advisory(
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
            ))
        return CollectResult(advisories=advisories)


COLLECTOR = FortinetPsirt()
