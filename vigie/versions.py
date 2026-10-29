"""Comparaison de numéros de version hétérogènes (7.4.13, 12.2.4-h1, 10.6p1, 23h2-ac…)."""

import re

from packaging.version import InvalidVersion, Version

_TOKEN = re.compile(r"\d+|[a-z]+")


def token_key(version: str) -> tuple:
    """Clé de tri par segments : les nombres se comparent numériquement, et une version
    prolongée (12.2.4-h1) passe après sa base (12.2.4)."""
    return tuple((1, int(t), "") if t.isdigit() else (0, 0, t) for t in _TOKEN.findall(version.lower()))


def sort_versions(versions, *, key=lambda v: v, reverse: bool = True) -> list:
    """Trie avec packaging quand toutes les versions sont conformes PEP 440, par segments sinon."""
    items = list(versions)
    try:
        parsed = {id(item): Version(key(item)) for item in items}
        return sorted(items, key=lambda item: parsed[id(item)], reverse=reverse)
    except InvalidVersion:
        return sorted(items, key=lambda item: token_key(key(item)), reverse=reverse)
