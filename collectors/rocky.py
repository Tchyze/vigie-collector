"""Rocky Linux : avis de sécurité RLSA critiques, depuis l'API errata publique.

https://errata.rockylinux.org/api/v2/advisories : titre (« Critical: edk2 security update »),
sévérité, CVE avec score CVSS, produits touchés (« Rocky Linux 9 »). Rocky publie environ 2 500
avis par an, reprenant ceux de Red Hat : comme pour Red Hat, seuls les avis critiques sont retenus.

L'API Apollo v3 (apollo.build.resf.org), plus riche, est trop lente depuis GitHub Actions
(délais dépassés, erreurs 500) : la v2 répond en une à deux secondes.

Les avis des SIG (RXSA, « Rocky Linux SIG Cloud »…) ne concernent pas la distribution elle-même et
sont ignorés.
"""

import datetime as dt
import re

from collectors._text import iso_utc, short_summary
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

API = "https://errata.rockylinux.org/api/v2/advisories?filters.severity=SEVERITY_CRITICAL&filters.type=TYPE_SECURITY&size=20&page={page}"
ADVISORY_URL = "https://errata.rockylinux.org/{id}"
PRODUCT = re.compile(r"^Rocky Linux (\d+)$")
MAX_PAGES = 20


class Rocky(Collector):
    name = "rocky"
    label = "Rocky Linux Security Advisories (RLSA critiques)"
    kind = "advisories"
    home = "https://errata.rockylinux.org/"

    def collect(self, ctx: Context) -> CollectResult:
        cutoff = (ctx.today - dt.timedelta(days=ctx.catalog.advisory_retention_days)).isoformat()
        advisories: dict[str, Advisory] = {}
        for page in range(MAX_PAGES):
            items = ctx.client.json(API.format(page=page)).get("advisories")
            if not isinstance(items, list):
                raise ValueError("réponse inattendue : liste « advisories » attendue")
            for item in items:
                if (item.get("publishedAt") or "")[:10] >= cutoff and (advisory := parse(item)):
                    advisories.setdefault(advisory.id, advisory)
            # Tri du plus récent au plus ancien : inutile d'aller au-delà de la rétention.
            if not items or items[-1].get("publishedAt", "")[:10] < cutoff:
                break
        return CollectResult(advisories=list(advisories.values()))


def parse(item: dict) -> Advisory | None:
    majors = sorted({
        int(m.group(1)) for product in item.get("affectedProducts") or []
        if (m := PRODUCT.match(product.strip()))
    }, reverse=True)
    if not majors or not item.get("name") or not item.get("publishedAt"):
        return None
    scores = []
    for cve in item.get("cves") or []:
        try:
            scores.append(float(cve.get("cvss3BaseScore")))
        except (TypeError, ValueError):
            pass
    return Advisory(
        id=item["name"],
        source="rocky",
        vendor="Rocky Linux",
        title=(item.get("synopsis") or item["name"]).strip(),
        published=iso_utc(item["publishedAt"]),
        url=ADVISORY_URL.format(id=item["name"]),
        severity="critical" if item.get("severity") == "SEVERITY_CRITICAL" else None,
        cvss=max(scores) if scores else None,
        cves=list(dict.fromkeys(c["name"] for c in item.get("cves") or [] if c.get("name"))),
        summary=short_summary((item.get("topic") or "").split("\nA Common Vulnerability")[0]),
        affected=[f"rocky-linux-{major}" for major in majors],
    )


COLLECTOR = Rocky()
