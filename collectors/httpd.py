"""Apache HTTP Server : versions publiées (tags du dépôt officiel) et correctifs de sécurité (CHANGES_2.4).

- https://github.com/apache/httpd/tags.atom : tags récents avec leur date (hors candidats -rc) ;
- https://downloads.apache.org/httpd/CHANGES_2.4 : journal officiel, lignes « *) SECURITY: CVE-… ».

Le flux Atom n'expose que les derniers tags : l'historique se construit d'un build à l'autre.
"""

import re

import feedparser

from collectors._text import change_summary, cves, date_from_struct, tag_name
from collectors.base import Collector, Context
from vigie.models import BranchData, CollectResult, Release

TAGS = "https://github.com/apache/httpd/tags.atom"
CHANGES = "https://downloads.apache.org/httpd/CHANGES_2.4"
VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
HEADER = re.compile(r"^Changes with Apache (\d+\.\d+\.\d+)\s*$", re.M)
ITEM = re.compile(r"^\s+\*\) (SECURITY:)?", re.M)


class Httpd(Collector):
    name = "httpd"
    label = "Apache httpd (tags et CHANGES_2.4)"
    kind = "versions"
    home = "https://httpd.apache.org/"

    def collect(self, ctx: Context) -> CollectResult:
        feed = feedparser.parse(ctx.client.get(TAGS).content)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux Atom illisible : {feed.bozo_exception}")
        changes = parse_changes(ctx.client.text(CHANGES))

        branches: dict[str, BranchData] = {}
        for entry in feed.entries:
            version = tag_name(entry)
            match = VERSION.match(version)
            if not match:
                continue  # candidats « 2.4.69-rc1-candidate » et autres tags
            security_fix, summary = changes.get(version, (None, None))
            name = f"{match[1]}.{match[2]}"
            branch = branches.setdefault(name, BranchData(product="apache-httpd", branch=name))
            branch.releases.append(Release(
                version=version,
                date=date_from_struct(entry.get("updated_parsed")),
                security_fix=security_fix,
                summary=summary,
                url=CHANGES if name == "2.4" else None,
            ))
        return CollectResult(branches=list(branches.values()))


def parse_changes(text: str) -> dict[str, tuple[bool, str | None]]:
    """{version: (contient un correctif de sécurité, résumé)} pour chaque section du journal."""
    headers = list(HEADER.finditer(text))
    result = {}
    for header, following in zip(headers, headers[1:] + [None]):
        body = text[header.end(): following.start() if following else len(text)]
        items = ITEM.findall(body)
        security = sum(1 for flag in items if flag)
        security_ids = cves("".join(re.findall(r"\*\) SECURITY: (CVE-\d{4}-\d+)", body)))
        counts = {"security": security, "change": len(items) - security}
        result[header.group(1)] = (security > 0, change_summary(counts, security_ids))
    return result


COLLECTOR = Httpd()
