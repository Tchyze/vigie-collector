"""Ubuntu : avis de sécurité USN, depuis les données OSV publiées par Canonical.

OSV (https://osv.dev) republie chaque USN en JSON, un fichier par avis, dans un bucket public :

- https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/modified_id.csv : index de tous les
  avis Ubuntu (« horodatage,identifiant »), USN et fiches CVE, environ 3,6 Mo ;
- https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/USN-<n>-<m>.json : l'avis : titre
  (`summary`, « apache2 vulnerabilities »), texte (`details`), date, CVE (`upstream`) et versions
  d'Ubuntu corrigées (`affected[].package.ecosystem` : « Ubuntu:24.04:LTS », « Ubuntu:Pro:18.04:LTS »).

Cette source remplace l'API ubuntu.com/security/notices.json, limitée à 20 avis par page et
sujette aux 503 en rafale. Les USN n'ont pas de sévérité. Les avis du noyau citent des milliers
de CVE : `cves` en garde au plus 100.

Collecte progressive : seuls les USN encore inconnus sont téléchargés, du plus récent au plus
ancien (l'ordre des numéros suit celui des publications), dans un plafond par passage. Le premier
avis antérieur à la date limite arrête la descente ; quand l'état couvre déjà toute la période,
les numéros inférieurs au plus ancien avis connu sont ignorés. Un avis déjà connu n'est pas relu :
OSV retouche des centaines d'USN anciens chaque mois sans changement de fond.

Limite connue : un USN « -2 » publié bien après le « -1 » d'un numéro antérieur à la période
n'est pas repris (il est couvert par le CERT-FR s'il est important).
"""

import datetime as dt
import logging
import re

from collectors._text import cves, iso_utc, short_summary
from collectors.base import CollectError, Collector, Context
from vigie.models import Advisory, CollectResult

INDEX = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/modified_id.csv"
ADVISORY = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/{id}.json"
NOTICE_URL = "https://ubuntu.com/security/notices/{id}"
MAX_CVES = 100  # un avis du noyau en cite plusieurs milliers ; l'avis complet reste en lien
MAX_FETCH_PER_RUN = 120  # une requête par seconde : deux minutes au plus par passage
COMPLETE_MARGIN_DAYS = 7  # l'état « couvre la période » si son plus ancien avis est à moins de 7 jours de la limite
USN = re.compile(r"^USN-(\d+)-(\d+)$")
RELEASE = re.compile(r"\b(\d{2}\.\d{2})\b")
log = logging.getLogger(__name__)


class Ubuntu(Collector):
    name = "ubuntu"
    label = "Ubuntu Security Notices (USN, via OSV)"
    kind = "advisories"
    home = "https://ubuntu.com/security/notices"

    def collect(self, ctx: Context) -> CollectResult:
        today = ctx.today
        cutoff = (today - dt.timedelta(days=ctx.catalog.advisory_retention_days)).isoformat()
        previous = {a.id: a for a in (ctx.previous.advisories if ctx.previous else [])}

        floor = None
        if previous:
            oldest = min(a.published for a in previous.values())[:10]
            limit = (dt.date.fromisoformat(cutoff) + dt.timedelta(days=COMPLETE_MARGIN_DAYS)).isoformat()
            if oldest <= limit:  # l'historique est complet : ne pas redescendre sous le plus ancien connu
                floor = min(number(i)[0] for i in previous if USN.match(i))

        todo = sorted(
            (i for i in usn_ids(ctx.client.text(INDEX)) if i not in previous and (floor is None or number(i)[0] >= floor)),
            key=number,
            reverse=True,
        )
        found: dict[str, Advisory] = {}
        try:
            for advisory_id in todo[:MAX_FETCH_PER_RUN]:
                if floor is not None and number(advisory_id)[0] < floor:
                    continue
                advisory = parse(ctx.client.json(ADVISORY.format(id=advisory_id)))
                if advisory is None:
                    continue
                if advisory.published[:10] < cutoff:
                    floor = number(advisory_id)[0] + 1  # plus ancien que la période : on arrête de descendre
                    continue
                found[advisory.id] = advisory
        except Exception as exc:
            if not found:
                raise
            log.warning("Ubuntu : collecte interrompue après %d avis (%s)", len(found), exc)
            raise CollectError(f"collecte interrompue : {exc}", result(previous, found)) from exc
        if len(todo) > MAX_FETCH_PER_RUN:
            log.info("Ubuntu : %d avis restent à lire aux prochains passages", len(todo) - MAX_FETCH_PER_RUN)
        return result(previous, found)


def result(previous: dict[str, Advisory], found: dict[str, Advisory]) -> CollectResult:
    """Avis connus et nouveaux : une source sans nouveauté ne doit pas paraître vide."""
    return CollectResult(advisories=list({**previous, **found}.values()))


def usn_ids(index: str) -> list[str]:
    ids = []
    for line in index.splitlines():
        _, _, advisory_id = line.partition(",")
        advisory_id = advisory_id.strip()
        if USN.match(advisory_id):
            ids.append(advisory_id)
    return list(dict.fromkeys(ids))


def number(advisory_id: str) -> tuple[int, int]:
    match = USN.match(advisory_id)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def parse(data: dict) -> Advisory | None:
    advisory_id = data.get("id") or ""
    if not USN.match(advisory_id) or not data.get("published") or data.get("withdrawn"):
        return None
    releases = []
    for affected in data.get("affected") or []:
        ecosystem = (affected.get("package") or {}).get("ecosystem") or ""
        if (match := RELEASE.search(ecosystem)) and ecosystem.startswith("Ubuntu:"):
            releases.append(match.group(1))
    return Advisory(
        id=advisory_id,
        source="ubuntu",
        vendor="Canonical",
        title=(data.get("summary") or advisory_id).strip(),
        published=iso_utc(data["published"]),
        url=NOTICE_URL.format(id=advisory_id),
        cves=cves(" ".join(u for u in data.get("upstream") or [] if u.startswith("CVE-")))[:MAX_CVES],
        summary=short_summary(data.get("details")),
        affected=[f"ubuntu-{v}" for v in sorted(set(releases), key=lambda v: tuple(map(int, v.split("."))))],
    )


COLLECTOR = Ubuntu()
