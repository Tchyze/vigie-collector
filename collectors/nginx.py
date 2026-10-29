"""nginx : versions, dates et correctifs de sécurité depuis les fichiers CHANGES officiels.

https://nginx.org/en/CHANGES (branche mainline) et https://nginx.org/en/CHANGES-1.<pair> (stable).
Les release notes GitHub ne mentionnent pas toujours les correctifs de sécurité, d'où ce choix.
"""

import re

from collectors._text import change_summary, cves, parse_day_month_year
from collectors.base import Collector, Context
from vigie.models import BranchData, CollectResult, Release

MAINLINE = "https://nginx.org/en/CHANGES"
STABLE = "https://nginx.org/en/CHANGES-{branch}"
HEADER = re.compile(r"^Changes with nginx (\d+\.\d+\.\d+)\s+(\d{1,2} \w{3} \d{4})\s*$", re.M)
ITEM = re.compile(r"^\s+\*\) (Security|Feature|Change|Bugfix|Workaround)\b", re.M)


class Nginx(Collector):
    name = "nginx"
    label = "nginx.org (CHANGES)"
    kind = "versions"
    home = "https://nginx.org/en/CHANGES"

    def collect(self, ctx: Context) -> CollectResult:
        releases = parse_changes(ctx.client.text(MAINLINE), MAINLINE)
        mainline = max(releases, key=lambda r: tuple(int(x) for x in r.version.split(".")))
        major, minor, _ = (int(x) for x in mainline.version.split("."))
        if minor % 2 == 1:  # mainline impaire -> stable = branche paire précédente
            url = STABLE.format(branch=f"{major}.{minor - 1}")
            releases += parse_changes(ctx.client.text(url), url)

        branches: dict[str, BranchData] = {}
        for release in releases:
            name = ".".join(release.version.split(".")[:2])
            branch = branches.setdefault(name, BranchData(product="nginx", branch=name))
            if all(r.version != release.version for r in branch.releases):
                branch.releases.append(release)
        return CollectResult(branches=list(branches.values()))


def parse_changes(text: str, url: str) -> list[Release]:
    headers = list(HEADER.finditer(text))
    releases = []
    for header, following in zip(headers, headers[1:] + [None]):
        body = text[header.end(): following.start() if following else len(text)]
        counts: dict[str, int] = {}
        for kind in ITEM.findall(body):
            key = "bugfix" if kind == "Workaround" else kind.lower()
            counts[key] = counts.get(key, 0) + 1
        security_text = "".join(
            part for part in re.split(r"(?=^\s+\*\) )", body, flags=re.M) if "*) Security:" in part
        )
        releases.append(Release(
            version=header.group(1),
            date=parse_day_month_year(header.group(2)),
            security_fix=bool(counts.get("security")),
            summary=change_summary(counts, cves(security_text)),
            url=url,
        ))
    return releases


COLLECTOR = Nginx()
