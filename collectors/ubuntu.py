"""Ubuntu : avis de sécurité USN, depuis l'API publique de ubuntu.com.

https://ubuntu.com/security/notices.json : identifiant, titre, résumé court, CVE et versions
d'Ubuntu corrigées (`releases` : « 24.04 » → `ubuntu-24.04`). Les USN n'ont pas de sévérité.
Les avis du noyau citent des milliers de CVE : `cves` en garde au plus 100.

L'API renvoie 20 avis par page, du plus récent au plus ancien, soit environ 80 pages pour un an,
et les pages profondes répondent lentement. La collecte est donc progressive :

1. les nouveautés, depuis la première page jusqu'à une page entièrement connue ;
2. puis le rattrapage de l'historique, repris là où l'état s'arrête (son nombre d'avis donne
   l'offset, avec une page de recouvrement), jusqu'à la date limite ;

le tout dans un plafond de pages par passage. Une erreur en cours de route rend ce qui a déjà été
lu (`CollectError`) : l'état garde le reste.
"""

import datetime as dt
import logging

from collectors._text import cves, iso_utc, short_summary
from collectors.base import CollectError, Collector, Context
from vigie.models import Advisory, CollectResult

API = "https://ubuntu.com/security/notices.json?limit={limit}&offset={offset}"
NOTICE_URL = "https://ubuntu.com/security/notices/{id}"
PAGE_SIZE = 20  # maximum accepté par l'API
MAX_CVES = 100  # un avis du noyau en cite plusieurs milliers ; l'avis complet reste en lien
MAX_PAGES_PER_RUN = 6  # l'API limite les rafales (503, connexions coupées)
log = logging.getLogger(__name__)


class Ubuntu(Collector):
    name = "ubuntu"
    label = "Ubuntu Security Notices (USN)"
    kind = "advisories"
    home = "https://ubuntu.com/security/notices"

    def collect(self, ctx: Context) -> CollectResult:
        cutoff = (ctx.today - dt.timedelta(days=ctx.catalog.advisory_retention_days)).isoformat()
        previous = ctx.previous.advisories if ctx.previous else []
        known = {a.id for a in previous}
        found: dict[str, Advisory] = {}
        budget = MAX_PAGES_PER_RUN

        def read(offset: int) -> list[dict]:
            nonlocal budget
            budget -= 1
            notices = ctx.client.json(API.format(limit=PAGE_SIZE, offset=offset)).get("notices")
            if not isinstance(notices, list):
                raise ValueError("réponse inattendue : liste « notices » attendue")
            for notice in notices:
                if (notice.get("published") or "")[:10] >= cutoff and (advisory := parse(notice)):
                    found.setdefault(advisory.id, advisory)
            return notices

        try:
            # 1. nouveautés
            offset = 0
            while budget > 0:
                notices = read(offset)
                offset += PAGE_SIZE
                if not notices or notices[-1].get("published", "")[:10] < cutoff:
                    return CollectResult(advisories=list(found.values()))  # année complète
                if all(n.get("id") in known for n in notices):
                    break
            # 2. rattrapage de l'historique, si l'état ne remonte pas encore à la date limite
            oldest = min((a.published for a in previous), default="")
            if previous and oldest[:10] > cutoff:
                offset = max(offset, len(known | set(found)) - PAGE_SIZE)
                while budget > 0:
                    notices = read(offset)
                    offset += PAGE_SIZE
                    if not notices or notices[-1].get("published", "")[:10] < cutoff:
                        break
        except Exception as exc:
            if not found:
                raise
            log.warning("Ubuntu : collecte interrompue après %d avis (%s)", len(found), exc)
            raise CollectError(f"collecte interrompue : {exc}", CollectResult(advisories=list(found.values()))) from exc
        return CollectResult(advisories=list(found.values()))


def parse(notice: dict) -> Advisory | None:
    if notice.get("is_hidden") or not notice.get("id") or not notice.get("published"):
        return None
    versions = [r["version"] for r in notice.get("releases") or [] if r.get("version")]
    return Advisory(
        id=notice["id"],
        source="ubuntu",
        vendor="Canonical",
        title=(notice.get("title") or notice["id"]).strip(),
        published=iso_utc(notice["published"]),
        url=NOTICE_URL.format(id=notice["id"]),
        cves=cves(" ".join(notice.get("cves_ids") or []))[:MAX_CVES],
        summary=short_summary(notice.get("summary")),
        affected=list(dict.fromkeys(f"ubuntu-{v}" for v in versions)),
    )


COLLECTOR = Ubuntu()
