"""HPE : bulletins de sécurité (Security Bulletins), depuis le flux RSS officiel.

https://support.hpe.com/hpesc/public/api/document/sec_bull_rss_feed : 50 derniers bulletins de
tous les produits HPE (serveurs ProLiant et iLO `HPESBHF`, réseau `HPESBNW`, stockage `HPESBST`…).
Le titre porte l'identifiant et la révision (« HPESBHF05170 rev.1 - … ») ; le flux ne donne ni
sévérité ni CVE en dehors du titre.

Pour iLO, les générations citées dans le titre (« Integrated Lights-Out 6 (iLO 6) »,
« Integrated Lights-Out (iLO) 7 ») donnent `affected` (`hpe-ilo-6`).
"""

import re

import feedparser

from collectors._text import cves, utc_from_struct
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

FEED = "https://support.hpe.com/hpesc/public/api/document/sec_bull_rss_feed"
TITLE = re.compile(r"^(HPESB[A-Z]{2}\d+)\s+rev\.?\s*(\d+)\s*-\s*(.+)$", re.S)  # « rev.1 », « rev 2 », « rev. 1 »
ILO = (
    re.compile(r"Integrated Lights-Out\s*(?:\(iLO\)\s*)?(\d)\b"),
    re.compile(r"\biLO\s+(\d)\b"),
)


class HpeBulletins(Collector):
    name = "hpe_bulletins"
    label = "HPE Security Bulletins"
    kind = "advisories"
    home = "https://support.hpe.com/connect/s/securitybulletinlibrary"

    def collect(self, ctx: Context) -> CollectResult:
        feed = feedparser.parse(ctx.client.get(FEED).content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux RSS illisible : {feed.bozo_exception}")
        return CollectResult(advisories=[a for a in (parse_entry(e) for e in feed.entries) if a])


def parse_entry(entry) -> Advisory | None:
    match = TITLE.match((entry.get("title") or "").strip())
    published = utc_from_struct(entry.get("published_parsed"))
    if not match or not published or not entry.get("link"):
        return None
    bulletin, revision, text = match.group(1), int(match.group(2)), " ".join(match.group(3).split())
    generations = sorted({g for pattern in ILO for g in pattern.findall(text)}, reverse=True)
    return Advisory(
        id=bulletin,
        source="hpe",
        vendor="HPE",
        title=text,
        published=published,
        url=entry["link"],
        cves=cves(text),
        summary=f"Révision {revision} du bulletin." if revision > 1 else None,
        affected=[f"hpe-ilo-{g}" for g in generations],
    )


COLLECTOR = HpeBulletins()
