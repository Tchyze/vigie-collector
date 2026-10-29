"""Registre des collecteurs : chaque module expose un objet `COLLECTOR` (voir base.Collector)."""

from collectors import endoflife

ALL = [
    endoflife.COLLECTOR,
]
