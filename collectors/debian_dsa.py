"""Debian : avis de sécurité DSA.

- liste officielle du security tracker (data/DSA/list) : date, paquet, CVE et suites corrigées
  (« [trixie] - paquet version »), d'où `affected` (trixie -> debian-13) ;
- flux https://www.debian.org/security/dsa-long : résumé court des derniers DSA (facultatif).

Le flux RSS seul ne donne ni CVE ni branche, d'où le recours à la liste du tracker.
"""

import datetime as dt
import logging
import re

import feedparser

from collectors._text import cves, parse_day_month_year, short_summary, strip_html
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

LIST = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list"
FEED = "https://www.debian.org/security/dsa-long"
TRACKER = "https://security-tracker.debian.org/tracker/{id}"
HEADER = re.compile(r"^\[(\d{1,2} \w{3} \d{4})\] (DSA-\d+-\d+) (\S+) - (.+)$")
SUITE = re.compile(r"^\s+\[(\w+)\] - \S+ (?!<)")  # « <not-affected> », « <no-dsa> »… : pas un correctif
CODENAMES = {
    "jessie": "8", "stretch": "9", "buster": "10", "bullseye": "11",
    "bookworm": "12", "trixie": "13", "forky": "14", "duke": "15",
}
log = logging.getLogger(__name__)


class DebianDsa(Collector):
    name = "debian_dsa"
    label = "Debian Security Advisories (DSA)"
    kind = "advisories"
    home = "https://www.debian.org/security/"

    def collect(self, ctx: Context) -> CollectResult:
        cutoff = ctx.today - dt.timedelta(days=ctx.catalog.advisory_retention_days)
        advisories = parse_list(ctx.client.text(LIST), cutoff)
        summaries = self._summaries(ctx)
        for advisory in advisories:
            advisory.summary = summaries.get(advisory.id)
        return CollectResult(advisories=advisories)

    def _summaries(self, ctx: Context) -> dict[str, str]:
        try:
            feed = feedparser.parse(ctx.client.get(FEED).content)
        except Exception as exc:  # le résumé est un complément : son absence n'est pas une erreur
            log.warning("Debian : flux dsa-long indisponible (%s)", exc)
            return {}
        summaries = {}
        for entry in feed.entries:
            advisory_id = entry.get("title", "").split(" ", 1)[0]
            text = strip_html(re.sub(r"<a [^>]*>.*?</a>", "", entry.get("summary", ""), flags=re.S))
            if advisory_id.startswith("DSA-") and text:
                summaries[advisory_id] = short_summary(text)
        return summaries


def parse_list(text: str, cutoff: dt.date) -> list[Advisory]:
    """Analyse data/DSA/list (du plus récent au plus ancien) jusqu'à la date limite."""
    advisories: list[Advisory] = []
    current = None
    for line in text.splitlines():
        header = HEADER.match(line)
        if header:
            day = parse_day_month_year(header.group(1))
            if dt.date.fromisoformat(day) < cutoff:
                break
            advisory_id, package, description = header.group(2), header.group(3), header.group(4).strip()
            current = Advisory(
                id=advisory_id,
                source="debian",
                vendor="Debian",
                title=f"{advisory_id} {package} - {description}",
                published=f"{day}T00:00:00Z",
                url=TRACKER.format(id=advisory_id),
            )
            advisories.append(current)
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("{"):
            current.cves = list(dict.fromkeys(current.cves + cves(stripped)))
            continue
        suite = SUITE.match(line)
        if suite:
            release = CODENAMES.get(suite.group(1))
            if release is None:
                log.warning("Debian : suite inconnue « %s » (%s)", suite.group(1), current.id)
            elif f"debian-{release}" not in current.affected:
                current.affected.append(f"debian-{release}")
    return advisories


COLLECTOR = DebianDsa()
