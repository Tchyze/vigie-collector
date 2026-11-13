"""Microsoft : mises à jour de sécurité mensuelles (Patch Tuesday) pour Windows Server.

API publique CVRF du MSRC (https://api.msrc.microsoft.com/cvrf/v3.0/) :

- `updates` : un document par mois, avec ses dates de publication et de dernière révision ;
- `cvrf/<mois>` : toutes les vulnérabilités du mois (plus de 1 000, environ 18 Mo).

Un mois compte des centaines de CVE touchant Windows Server : Vigie publie **un avis par mois**
pour Windows Server, comme on applique ces correctifs (une mise à jour cumulative mensuelle).
`cves` liste les CVE critiques ou déjà exploitées ; `affected`, les versions de Windows Server
touchées ; `severity` et `cvss`, les plus élevés du mois.

Les documents sont révisés presque chaque jour : on ne retélécharge un mois que si sa date de
révision a changé, avec un plafond par passage (mois inconnus d'abord, puis les plus récents).
"""

import datetime as dt
import logging
import re

from collectors._text import iso_utc
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

API = "https://api.msrc.microsoft.com/cvrf/v3.0"
RELEASE_NOTE = "https://msrc.microsoft.com/update-guide/releaseNote/{id}"
MAX_DOCUMENTS_PER_RUN = 2
# « Windows Server 2012 R2 (Server Core installation) » -> windows-server-2012-r2
WINDOWS_SERVER = re.compile(r"^Windows Server (\d{4})( R2)?(?: \(Server Core installation\))?$")
KNOWN_AFFECTED, SEVERITY, EXPLOIT_STATUS = 3, 3, 1  # types CVRF (ProductStatuses, Threats)
SEVERITIES = {"low": "low", "moderate": "medium", "important": "high", "critical": "critical"}
ORDER = ["low", "medium", "high", "critical"]
log = logging.getLogger(__name__)


class Microsoft(Collector):
    name = "microsoft"
    label = "Microsoft Security Updates (Windows Server)"
    kind = "advisories"
    home = "https://msrc.microsoft.com/update-guide/"

    def collect(self, ctx: Context) -> CollectResult:
        cutoff = (ctx.today - dt.timedelta(days=ctx.catalog.advisory_retention_days)).isoformat()
        months = [
            m for m in ctx.client.json(f"{API}/updates", headers={"Accept": "application/json"}).get("value") or []
            if (m.get("InitialReleaseDate") or "")[:10] >= cutoff and m.get("ID") and m.get("CvrfUrl")
        ]
        previous = {a.id: a for a in (ctx.previous.advisories if ctx.previous else [])}
        # Mois jamais traités d'abord, puis du plus récent au plus ancien.
        months.sort(key=lambda m: m["InitialReleaseDate"], reverse=True)
        months.sort(key=lambda m: advisory_id(m["ID"]) in previous)  # tri stable
        advisories, budget = [], MAX_DOCUMENTS_PER_RUN
        for month in months:
            known = previous.get(advisory_id(month["ID"]))
            revised = iso_utc(month["CurrentReleaseDate"]) if month.get("CurrentReleaseDate") else None
            if known and known.updated == revised:
                advisories.append(known)
                continue
            if budget > 0:
                budget -= 1
                try:
                    document = ctx.client.json(month["CvrfUrl"], headers={"Accept": "application/json"})
                    advisory = parse(document, month)
                except Exception as exc:
                    log.warning("Microsoft : %s : document CVRF indisponible (%s)", month["ID"], exc)
                    advisory = None
                if advisory:
                    advisories.append(advisory)
                    continue
            if known:
                advisories.append(known)
        return CollectResult(advisories=advisories)


def advisory_id(month_id: str) -> str:
    return f"MSRC-{month_id}"


def parse(document: dict, month: dict) -> Advisory | None:
    """Avis mensuel Windows Server, ou None si le mois ne touche aucune version de Windows Server."""
    products = {
        p["ProductID"]: p["Value"]
        for p in (document.get("ProductTree") or {}).get("FullProductName") or []
        if (p.get("Value") or "").startswith("Windows Server")
    }
    total, critical, exploited, branches, scores, worst = 0, [], [], set(), [], None
    for vuln in document.get("Vulnerability") or []:
        affected = {
            pid for status in vuln.get("ProductStatuses") or [] if status.get("Type") == KNOWN_AFFECTED
            for pid in status.get("ProductID") or [] if pid in products
        }
        if not affected or not vuln.get("CVE"):
            continue
        total += 1
        for pid in affected:
            if match := WINDOWS_SERVER.match(products[pid]):
                branches.add(match.group(1) + ("-r2" if match.group(2) else ""))
        severity = _severity(vuln, affected)
        if severity and (worst is None or ORDER.index(severity) > ORDER.index(worst)):
            worst = severity
        if severity == "critical":
            critical.append(vuln["CVE"])
        if _exploited(vuln, affected):
            exploited.append(vuln["CVE"])
        scores += [
            float(s["BaseScore"]) for s in vuln.get("CVSSScoreSets") or []
            if isinstance(s.get("BaseScore"), (int, float)) and affected & set(s.get("ProductID") or [])
        ]
    if not total:
        return None
    published = iso_utc(month["InitialReleaseDate"])
    title = ((document.get("DocumentTitle") or {}).get("Value") or month.get("DocumentTitle") or month["ID"]).strip()
    summary = f"{total} vulnérabilités corrigées pour Windows Server, dont {len(critical)} critiques"
    summary += f" et {len(exploited)} déjà exploitées." if exploited else "."
    return Advisory(
        id=advisory_id(month["ID"]),
        source="microsoft",
        vendor="Microsoft",
        title=f"{title} — Windows Server",
        published=published,
        url=RELEASE_NOTE.format(id=month["ID"]),
        updated=iso_utc(month["CurrentReleaseDate"]) if month.get("CurrentReleaseDate") else None,
        severity=worst,
        cvss=max(scores) if scores else None,
        cves=sorted(set(critical) | set(exploited), key=_cve_key),
        summary=summary,
        affected=[f"windows-server-{b}" for b in sorted(branches, reverse=True)],
    )


def _severity(vuln: dict, affected: set[str]) -> str | None:
    found = [
        SEVERITIES.get(((t.get("Description") or {}).get("Value") or "").lower())
        for t in vuln.get("Threats") or []
        if t.get("Type") == SEVERITY and affected & set(t.get("ProductID") or [])
    ]
    found = [s for s in found if s]
    return max(found, key=ORDER.index) if found else None


def _exploited(vuln: dict, affected: set[str]) -> bool:
    return any(
        "Exploited:Yes" in ((t.get("Description") or {}).get("Value") or "")
        for t in vuln.get("Threats") or []
        if t.get("Type") == EXPLOIT_STATUS and (not t.get("ProductID") or affected & set(t["ProductID"]))
    )


def _cve_key(cve: str) -> tuple[int, int]:
    _, year, number = cve.split("-")
    return int(year), int(number)


COLLECTOR = Microsoft()
