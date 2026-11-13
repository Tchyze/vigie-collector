"""Red Hat : avis de sécurité RHSA critiques touchant Red Hat Enterprise Linux.

API publique Security Data (https://access.redhat.com/hydra/rest/securitydata/csaf.json) :
identifiant, sévérité, date, CVE et paquets publiés. Elle ne donne pas le titre ; le document
CSAF de chaque avis le donne, mais pèse plusieurs Mo. On s'en passe :

- les branches touchées viennent de la version des paquets sources
  (`kernel-0:5.14.0-570.el9_6.src` → `rhel-9`). Un avis n'est retenu que si **tous** ses paquets
  sources ont une version RHEL standard : un seul paquet d'un produit en couche (OpenShift
  `rhaos4.15.el9`, Satellite `el9sat`, JBoss `el7eap`…) l'écarte, car ces produits utilisent aussi
  l'étiquette `.el9` ;
- le titre reprend la forme de Red Hat (« <paquets> security update ») à partir des paquets
  sources.

Red Hat publie plusieurs milliers d'avis « important » par an : seuls les avis « critical » sont
retenus. Le CERT-FR reprend chaque semaine une synthèse des autres.
"""

import datetime as dt
import re

from collectors._text import iso_utc
from collectors.base import Collector, Context
from vigie.models import Advisory, CollectResult

API = "https://access.redhat.com/hydra/rest/securitydata/csaf.json?after={after}&severity=critical&per_page={size}&page={page}"
ERRATA_URL = "https://access.redhat.com/errata/{id}"
PAGE_SIZE = 1000
MAX_PAGES = 10
# Paquet source « nom-époque:version-release.src », suivi pour un module de « ::mysql:8.4 ».
SOURCE_PACKAGE = re.compile(r"^(.+)-\d+:[^-]+-([^-]+)\.src(?:::([\w.+-]+:[\w.+-]+))?$")
# Release RHEL : « 570.el9_6 », « 1.el9_6.1 », « 2.module+el9.9.0+24089+64aac046.4 »,
# « 284.202.1.rt14.487.el9_2 » (RHEL for Real Time). Pas « 16.rhaos4.15.el9 », « 4.el9sat »…
RHEL_RELEASE = re.compile(r"^[\d.]+(?:\.rt[\d.]+)?\.(?:module\+)?el(\d+)(?:_\d+)*(?:[.+][\w.+]*)?$")
TITLE_PACKAGES = 3


class RedHat(Collector):
    name = "redhat"
    label = "Red Hat Security Advisories (RHSA critiques)"
    kind = "advisories"
    home = "https://access.redhat.com/security/security-updates/"

    def collect(self, ctx: Context) -> CollectResult:
        after = (ctx.today - dt.timedelta(days=ctx.catalog.advisory_retention_days)).isoformat()
        items: list[dict] = []
        for page in range(1, MAX_PAGES + 1):
            batch = ctx.client.json(API.format(after=after, size=PAGE_SIZE, page=page))
            if not isinstance(batch, list):
                raise ValueError("réponse inattendue : liste d'avis attendue")
            items += batch
            if len(batch) < PAGE_SIZE:
                break
        advisories = [a for a in (parse(item) for item in items) if a is not None]
        return CollectResult(advisories=advisories)


def parse(item: dict) -> Advisory | None:
    """Avis Vigie pour un RHSA, ou None s'il ne touche aucune version de RHEL."""
    sources = source_packages(item.get("released_packages") or [])
    majors = [RHEL_RELEASE.match(release) for _, release, _ in sources]
    if not sources or not all(majors) or not item.get("RHSA") or not item.get("released_on"):
        return None
    branches = [f"rhel-{n}" for n in sorted({int(m.group(1)) for m in majors}, reverse=True)]
    return Advisory(
        id=item["RHSA"],
        source="redhat",
        vendor="Red Hat",
        title=title(sources),
        published=iso_utc(item["released_on"]),
        url=ERRATA_URL.format(id=item["RHSA"]),
        severity="critical" if (item.get("severity") or "").lower() == "critical" else None,
        cves=list(dict.fromkeys(item.get("CVEs") or [])),
        affected=branches,
    )


def source_packages(packages: list[str]) -> list[tuple[str, str, str | None]]:
    """(nom, release, module) des paquets sources ; les paquets binaires sont ignorés."""
    return [m.groups() for p in packages if (m := SOURCE_PACKAGE.match(p))]


def title(sources: list[tuple[str, str, str | None]]) -> str:
    """« kernel, kernel-rt security update », comme les titres Red Hat ; un module par son flux."""
    names = list(dict.fromkeys(module or name for name, _, module in sources))
    shown = ", ".join(names[:TITLE_PACKAGES]) + (", …" if len(names) > TITLE_PACKAGES else "")
    return f"{shown} security update"


COLLECTOR = RedHat()
