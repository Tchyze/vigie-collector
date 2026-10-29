"""Fortinet : publications de firmware FortiOS, depuis le flux officiel du portail support.

https://support.fortinet.com/rss/firmware.xml annonce chaque image publiée (tous produits).
On ne retient que les versions FortiOS standard (« FortiOS 7.4.13 ») : les variantes
FIPS-CC et les autres produits sont ignorés. Le téléchargement demande un compte, mais les
annonces sont publiques. Le flux n'indique pas les correctifs de sécurité (security_fix = null).
"""

import re

import feedparser

from collectors._text import date_from_struct
from collectors.base import Collector, Context
from vigie.models import BranchData, CollectResult, Release

FEED = "https://support.fortinet.com/rss/firmware.xml"
TITLE = re.compile(r"^FortiOS (\d+)\.(\d+)\.(\d+)$")


class FortinetFirmware(Collector):
    name = "fortinet_firmware"
    label = "Fortinet (annonces de firmware)"
    kind = "versions"
    home = "https://support.fortinet.com/"

    def collect(self, ctx: Context) -> CollectResult:
        feed = feedparser.parse(ctx.client.get(FEED).content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux RSS illisible : {feed.bozo_exception}")
        branches: dict[str, BranchData] = {}
        for entry in feed.entries:
            match = TITLE.match(entry.title.strip())
            if not match:
                continue
            name = f"{match[1]}.{match[2]}"
            branch = branches.setdefault(name, BranchData(product="fortios", branch=name))
            version = f"{name}.{match[3]}"
            if any(r.version == version for r in branch.releases):
                continue
            branch.releases.append(Release(
                version=version,
                date=date_from_struct(entry.get("published_parsed")),
                url=entry.get("link"),
            ))
        return CollectResult(branches=list(branches.values()))


COLLECTOR = FortinetFirmware()
