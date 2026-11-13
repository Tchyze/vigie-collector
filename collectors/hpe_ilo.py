"""HPE iLO : versions de firmware publiées, depuis le dépôt public HPE (Software Delivery Repository).

Chaque dépôt de firmware ProLiant publie un index JSON (`fwrepodata/fwrepo.json`) : nom du
paquet, description, version et date de chaque firmware. Les entrées iLO se reconnaissent à leur
description (« … HPE Integrated Lights-Out 6 ») ; la génération d'iLO donne la branche :

- fwpp-gen10 : iLO 4 et iLO 5 ;
- fwpp-gen11 : iLO 6 ;
- fwpp-gen12 : iLO 6 et iLO 7.

Une même version figure souvent dans plusieurs dépôts et sous deux formats (rpm et fwpkg) : elle
n'est comptée qu'une fois. HPE ne publie pas de dates de fin de support exploitables : elles
peuvent être ajoutées dans overrides.yaml.
"""

import logging
import re

from collectors.base import CollectError, Collector, Context
from vigie.models import BranchData, CollectResult, Release
from vigie.versions import sort_versions

REPOSITORIES = ("fwpp-gen10", "fwpp-gen11", "fwpp-gen12")
INDEX = "https://downloads.linux.hpe.com/SDR/repo/{repo}/current/fwrepodata/fwrepo.json"
PRODUCT = "hpe-ilo"
ILO = re.compile(r"Integrated Lights-Out (\d+)\b")
VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)*$")
DATE = re.compile(r"^(\d{4})(\d{2})(\d{2})$")
log = logging.getLogger(__name__)


class HpeIlo(Collector):
    name = "hpe_ilo"
    label = "HPE iLO (dépôt de firmware HPE)"
    kind = "versions"
    home = "https://downloads.linux.hpe.com/SDR/"

    def collect(self, ctx: Context) -> CollectResult:
        releases: dict[str, dict[str, Release]] = {}
        failures = []
        for repo in REPOSITORIES:
            try:
                index = ctx.client.json(INDEX.format(repo=repo))
            except Exception as exc:  # un dépôt en échec ne prive pas les autres
                log.warning("HPE iLO : %s : %s", repo, exc)
                failures.append(f"{repo} : {exc}")
                continue
            for generation, release in parse_index(index):
                known = releases.setdefault(generation, {}).get(release.version)
                if known is None or (release.date and (known.date is None or release.date < known.date)):
                    releases[generation][release.version] = release
        branches = [
            BranchData(product=PRODUCT, branch=generation, label=f"iLO {generation}",
                       releases=sort_versions(found.values(), key=lambda r: r.version))
            for generation, found in sorted(releases.items())
        ]
        result = CollectResult(branches=branches)
        if failures:
            if not branches:
                raise ValueError("; ".join(failures))
            raise CollectError("; ".join(failures), result)
        return result


def parse_index(index: dict) -> list[tuple[str, Release]]:
    """(génération d'iLO, version) pour chaque firmware iLO de l'index."""
    if not isinstance(index, dict):
        raise ValueError("réponse inattendue : objet JSON attendu")
    found = []
    for entry in index.values():
        match = ILO.search((entry or {}).get("description") or "")
        version = ((entry or {}).get("version") or "").strip()
        if not match or not VERSION.match(version):
            continue
        date = DATE.match((entry.get("date") or "").strip())
        found.append((match.group(1), Release(
            version=version,
            date=f"{date.group(1)}-{date.group(2)}-{date.group(3)}" if date else None,
        )))
    return found


COLLECTOR = HpeIlo()
