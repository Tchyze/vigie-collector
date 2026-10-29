"""OpenSSH (portable) : versions publiées, depuis les tags du miroir officiel openssh/openssh-portable.

https://github.com/openssh/openssh-portable/tags.atom expose les derniers tags avec leur date ;
l'historique se construit d'un build à l'autre. La présence de correctifs de sécurité n'est pas
indiquée par cette source (security_fix = null) : il faudrait analyser les notes de version.
"""

import re

import feedparser

from collectors._text import date_from_struct, tag_name
from collectors.base import Collector, Context
from vigie.models import BranchData, CollectResult, Release

TAGS = "https://github.com/openssh/openssh-portable/tags.atom"
NOTES = "https://www.openssh.org/txt/release-{version}"
TAG = re.compile(r"^V_(\d+)_(\d+)(?:_(\d+))?_P(\d+)$")


class OpenSSH(Collector):
    name = "openssh"
    label = "OpenSSH portable (tags)"
    kind = "versions"
    home = "https://www.openssh.org/"

    def collect(self, ctx: Context) -> CollectResult:
        feed = feedparser.parse(ctx.client.get(TAGS).content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux Atom illisible : {feed.bozo_exception}")
        branch = BranchData(product="openssh", branch="portable")
        for entry in feed.entries:
            match = TAG.match(tag_name(entry))
            if not match:
                continue
            base = ".".join(part for part in match.groups()[:3] if part is not None)
            branch.releases.append(Release(
                version=f"{base}p{match[4]}",
                date=date_from_struct(entry.get("updated_parsed")),
                url=NOTES.format(version=base),
            ))
        return CollectResult(branches=[branch] if branch.releases else [])


COLLECTOR = OpenSSH()
