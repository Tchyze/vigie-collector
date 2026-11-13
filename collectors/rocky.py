"""Rocky Linux : avis de sécurité RLSA critiques, depuis l'API publique Apollo.

https://apollo.build.resf.org/api/v3/advisories/ : titre (« Critical: edk2 security update »),
sévérité, CVE avec score CVSS, versions majeures touchées. Rocky publie environ 2 500 avis par an,
reprenant ceux de Red Hat : comme pour Red Hat, seuls les avis « Critical » sont retenus.

Les avis des SIG (RXSA, variante « Rocky Linux SIG Cloud »…) ne concernent pas la distribution
elle-même et sont ignorés.
"""

import datetime as dt

from collectors._text import iso_utc, short_summary
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

API = "https://apollo.build.resf.org"
FIRST_PAGE = "/api/v3/advisories/?severity=Critical&kind=Security&size=100&page=1"
ADVISORY_URL = "https://errata.rockylinux.org/{id}"
VARIANT = "Rocky Linux"
MAX_PAGES = 10


class Rocky(Collector):
    name = "rocky"
    label = "Rocky Linux Security Advisories (RLSA critiques)"
    kind = "advisories"
    home = "https://errata.rockylinux.org/"

    def collect(self, ctx: Context) -> CollectResult:
        cutoff = (ctx.today - dt.timedelta(days=ctx.catalog.advisory_retention_days)).isoformat()
        advisories, path = [], FIRST_PAGE
        for _ in range(MAX_PAGES):
            data = ctx.client.json(API + path)
            items = data.get("advisories")
            if not isinstance(items, list):
                raise ValueError("réponse inattendue : liste « advisories » attendue")
            for item in items:
                if (item.get("published_at") or "")[:10] >= cutoff and (advisory := parse(item)):
                    advisories.append(advisory)
            # Tri du plus récent au plus ancien : inutile d'aller au-delà de la rétention.
            path = (data.get("links") or {}).get("next")
            if not path or not items or items[-1].get("published_at", "")[:10] < cutoff:
                break
        return CollectResult(advisories=advisories)


def parse(item: dict) -> Advisory | None:
    majors = sorted({
        p["major_version"] for p in item.get("affected_products") or []
        if p.get("variant") == VARIANT and isinstance(p.get("major_version"), int)
    }, reverse=True)
    if not majors or not item.get("name") or not item.get("published_at"):
        return None
    scores = []
    for cve in item.get("cves") or []:
        try:
            scores.append(float(cve.get("cvss3_base_score")))
        except (TypeError, ValueError):
            pass
    return Advisory(
        id=item["name"],
        source="rocky",
        vendor="Rocky Linux",
        title=(item.get("synopsis") or item["name"]).strip(),
        published=iso_utc(item["published_at"]),
        url=ADVISORY_URL.format(id=item["name"]),
        severity="critical" if (item.get("severity") or "").lower() == "critical" else None,
        cvss=max(scores) if scores else None,
        cves=list(dict.fromkeys(c["cve"] for c in item.get("cves") or [] if c.get("cve"))),
        summary=short_summary((item.get("topic") or "").split("\nA Common Vulnerability")[0]),
        affected=[f"rocky-linux-{major}" for major in majors],
    )


COLLECTOR = Rocky()
