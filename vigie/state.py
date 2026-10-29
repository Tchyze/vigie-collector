"""État par source, conservé d'un build à l'autre (output/state/<source>.json).

Il sert à deux choses : garder les dernières données valides d'une source en échec, et
construire un historique pour les flux qui n'exposent que leurs dernières entrées.
"""

import datetime as dt
import json
from pathlib import Path

from vigie.models import CollectResult


def load(path: Path) -> CollectResult | None:
    if not path.exists():
        return None
    return CollectResult.from_dict(json.loads(path.read_text(encoding="utf-8"))["result"])


def save(path: Path, source: str, result: CollectResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"source": source, "result": result.to_dict()}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def accumulate(previous: CollectResult | None, current: CollectResult) -> CollectResult:
    """Ajoute au résultat courant ce que l'état précédent connaissait et que la source ne montre plus.

    Le résultat courant l'emporte toujours pour une même branche, version ou avis.
    """
    if previous is None:
        return current
    branches = {b.id: b for b in current.branches}
    for old in previous.branches:
        new = branches.get(old.id)
        if new is None:
            branches[old.id] = old
            continue
        known = {r.version for r in new.releases}
        new.releases.extend(r for r in old.releases if r.version not in known)
    advisories = {a.id: a for a in current.advisories}
    for old in previous.advisories:
        advisories.setdefault(old.id, old)
    return CollectResult(branches=list(branches.values()), advisories=list(advisories.values()))


def prune_advisories(result: CollectResult, today: dt.date, retention_days: int) -> CollectResult:
    """Retire les avis dont la dernière activité (publication ou mise à jour) dépasse la rétention."""
    cutoff = (today - dt.timedelta(days=retention_days)).isoformat()
    kept = [a for a in result.advisories if max(a.published, a.updated or "")[:10] >= cutoff]
    return CollectResult(branches=result.branches, advisories=kept)
