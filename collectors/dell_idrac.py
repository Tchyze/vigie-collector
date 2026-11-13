"""Dell iDRAC : versions de firmware publiées, depuis le catalogue public Dell (PowerEdge).

https://downloads.dell.com/catalog/Catalog.xml.gz est le catalogue qu'utilisent les outils de mise
à jour Dell (OpenManage, Lifecycle Controller). Il ne liste que les versions **courantes** de
chaque composant : l'historique se construit au fil des passages.

Dell maintient plusieurs séries de firmware iDRAC en parallèle, selon la génération du serveur
(par exemple 7.00 pour les PowerEdge 14G, 7.30 pour les 15G et 16G) : chaque série est une
branche (`7.30`), sinon la « dernière version » annoncée ne conviendrait pas à tous les serveurs.
La génération d'iDRAC vient de l'identifiant de composant (113033 : iDRAC10) ou, pour l'identifiant
commun 25227, de la version (2.x : iDRAC8 ; 3.x à 7.x : iDRAC9).

« Criticality » vaut Urgent pour les mises à jour que Dell demande d'appliquer au plus vite ; ce
n'est pas une indication de correctif de sécurité, il est repris dans le résumé.
"""

import datetime as dt
import gzip
import re
import xml.etree.ElementTree as ET

from collectors.base import Collector, Context
from vigie.models import BranchData, CollectResult, Release
from vigie.versions import sort_versions

CATALOG = "https://downloads.dell.com/catalog/Catalog.xml.gz"
DRIVER_URL = "https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid={id}"
PRODUCT = "dell-idrac"
NAME = re.compile(r"^iDRAC (\d+)\.(\d+)\.[\d.]+$")
IDRAC10 = "113033"
URGENT = "2"


class DellIdrac(Collector):
    name = "dell_idrac"
    label = "Dell iDRAC (catalogue Dell)"
    kind = "versions"
    home = "https://www.dell.com/support/kbdoc/000178115"

    def collect(self, ctx: Context) -> CollectResult:
        raw = ctx.client.get(CATALOG).content
        return CollectResult(branches=parse_catalog(gzip.decompress(raw)))


def parse_catalog(xml: bytes) -> list[BranchData]:
    root = ET.fromstring(xml)  # UTF-16, déclaré dans l'en-tête XML
    if root.tag != "Manifest":
        raise ValueError(f"catalogue inattendu : élément racine {root.tag}")
    branches: dict[str, BranchData] = {}
    for component in root.iter("SoftwareComponent"):
        kind = component.find("ComponentType")
        name = NAME.match((component.findtext("Name/Display") or "").strip())
        if kind is None or kind.get("value") != "FRMW" or not name:
            continue
        major, minor = int(name.group(1)), int(name.group(2))
        devices = {d.get("componentID") for d in component.iter("Device")}
        generation = 10 if IDRAC10 in devices else 8 if major == 2 else 9 if 3 <= major <= 7 else None
        if generation is None:
            continue
        stream = f"{major}.{minor:02d}"
        branch = branches.setdefault(stream, BranchData(
            product=PRODUCT, branch=stream, label=f"iDRAC{generation} {stream}",
        ))
        criticality = component.find("Criticality")
        branch.releases.append(Release(
            version=component.get("vendorVersion") or name.group(0)[len("iDRAC "):],
            date=_date(component.get("releaseDate")),
            summary="Mise à jour jugée urgente par Dell." if criticality is not None and criticality.get("value") == URGENT else None,
            url=DRIVER_URL.format(id=component.get("releaseID")) if component.get("releaseID") else None,
        ))
    for branch in branches.values():
        branch.releases = sort_versions(branch.releases, key=lambda r: r.version)
    return sort_versions(branches.values(), key=lambda b: b.branch)


def _date(text: str | None) -> str | None:
    """« October 26, 2026 » -> « 2026-10-26 », indépendamment de la locale."""
    try:
        month, day, year = (text or "").replace(",", "").split()
        return dt.date(int(year), MONTHS[month[:3].title()], int(day)).isoformat()
    except (ValueError, KeyError):
        return None


MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

COLLECTOR = DellIdrac()
