"""Palo Alto Networks : avis de sécurité, depuis l'API JSON publique du portail sécurité.

https://security.paloaltonetworks.com/json/ — plus riche que le flux RSS du même site :
sévérité, score CVSS et, pour chaque produit, les versions touchées. C'est ce qui permet de
renseigner `affected` avec les branches PAN-OS de façon fiable.
"""

import re

from collectors._text import cves, iso_utc, normalize_severity, short_summary
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

API = "https://security.paloaltonetworks.com/json/?limit=100&sort=-updated"
ADVISORY_URL = "https://security.paloaltonetworks.com/{id}"
PANOS_BRANCH = re.compile(r"^PAN-OS (\d+\.\d+)$")
NOT_AFFECTED = {"", "none", "n/a"}  # après retrait des renvois de note (« None * »)


class PaloAlto(Collector):
    name = "paloalto"
    label = "Palo Alto Networks Security Advisories"
    kind = "advisories"
    home = "https://security.paloaltonetworks.com/"

    def collect(self, ctx: Context) -> CollectResult:
        items = ctx.client.json(API)
        if not isinstance(items, list):
            raise ValueError("réponse inattendue : liste d'avis attendue")
        return CollectResult(advisories=[parse(item) for item in items])


def parse(item: dict) -> Advisory:
    problem = next((p.get("value") for p in item.get("problem") or [] if p.get("lang") == "en"), None)
    ids = [item["ID"]] if item["ID"].startswith("CVE-") else []
    score = item.get("baseScore")
    return Advisory(
        id=item["ID"],
        source="paloalto",
        vendor="Palo Alto Networks",
        title=item["title"].strip(),
        published=iso_utc(item["date"]),
        updated=iso_utc(item["updated"]) if item.get("updated") else None,
        url=ADVISORY_URL.format(id=item["ID"]),
        severity=normalize_severity(item.get("baseSeverity")),
        cvss=float(score) if isinstance(score, (int, float)) else None,
        cves=list(dict.fromkeys(ids + cves(item["title"]))),
        summary=short_summary(problem),
        affected=affected_branches(item),
    )


def affected_branches(item: dict) -> list[str]:
    """Branches PAN-OS dont la ligne « version » est marquée comme touchée.

    Les listes `version` et `affected` sont parallèles ; si elles ne le sont pas, on ne déduit rien.
    """
    versions, affected = item.get("version") or [], item.get("affected") or []
    if len(versions) != len(affected):
        return []
    branches = []
    for version, status in zip(versions, affected):
        match = PANOS_BRANCH.match(version.strip())
        if match and (status or "").split("*")[0].strip().lower() not in NOT_AFFECTED:
            branches.append(f"panos-{match.group(1)}")
    return list(dict.fromkeys(branches))


COLLECTOR = PaloAlto()
