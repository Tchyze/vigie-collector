"""VMware (Broadcom) : avis de sécurité VMSA.

Depuis le rachat par Broadcom, la liste de vmware.com n'est plus tenue à jour. Les VMSA sont
publiés sur le portail de support Broadcom, dont la page publique (sans connexion) charge la
liste par une requête POST :

    https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList

Cette API n'est pas documentée : c'est celle de la page du portail, segment « VC » (VMware Cloud
Foundation : ESX, vCenter, NSX, Workstation…). Elle donne l'identifiant VMSA dans le titre, la
sévérité, les CVE, les produits et les dates. Les versions touchées ne figurent que dans l'avis
complet : `affected` reste vide.

Un avis révisé garde son identifiant de base (« VMSA-2026-0006.1 » → `VMSA-2026-0006`) et sa date
de mise à jour.
"""

import datetime as dt
import re

from collectors._text import cves, iso_utc, normalize_severity, parse_day_month_year, short_summary
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

API = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"
SEGMENT = "VC"
# Une seule page : environ 350 avis depuis 2012, sans tri côté serveur.
PAYLOAD = {"pageNumber": 0, "pageSize": 500, "searchVal": "", "segment": SEGMENT, "sortInfo": {"column": "", "order": ""}}
VMSA = re.compile(r"\b(VMSA-\d{4}-\d{4})(?:\.(\d+))?")


class Vmware(Collector):
    name = "vmware"
    label = "VMware Security Advisories (Broadcom)"
    kind = "advisories"
    home = "https://support.broadcom.com/web/ecx/security-advisory?segment=VC"

    def collect(self, ctx: Context) -> CollectResult:
        cutoff = (ctx.today - dt.timedelta(days=ctx.catalog.advisory_retention_days)).isoformat()
        data = ctx.client.post_json(API, PAYLOAD)
        items = (data.get("data") or {}).get("list") if isinstance(data, dict) else None
        if not data.get("success") or not isinstance(items, list):
            raise ValueError("réponse inattendue : data.list attendu")
        advisories: dict[str, Advisory] = {}
        for item in items:
            advisory = parse(item)
            if advisory is None or max(advisory.published, advisory.updated or "")[:10] < cutoff:
                continue
            current = advisories.get(advisory.id)
            if current is None or (advisory.updated or "") > (current.updated or ""):
                advisories[advisory.id] = advisory
        return CollectResult(advisories=list(advisories.values()))


def parse(item: dict) -> Advisory | None:
    title = (item.get("title") or "").strip()
    match = VMSA.search(title)
    if not match or not item.get("published") or item.get("alertType", "S") != "S":
        return None
    try:
        published = parse_day_month_year(item["published"]) + "T00:00:00Z"
    except (KeyError, ValueError):
        return None
    updated = iso_utc(item["updated"]) if item.get("updated") else None
    products = (item.get("supportProducts") or "").strip()
    return Advisory(
        id=match.group(1),
        source="vmware",
        vendor="Broadcom (VMware)",
        title=title,
        published=published,
        url=item.get("notificationUrl") or "https://support.broadcom.com/web/ecx/security-advisory?segment=VC",
        updated=updated if updated and updated[:10] > published[:10] else None,
        severity=normalize_severity(item.get("severity")),
        cves=cves(f"{item.get('affectedCve') or ''} {title}"),
        summary=short_summary(f"Produits : {products}.") if products and not products.endswith("...") else None,
    )


COLLECTOR = Vmware()
