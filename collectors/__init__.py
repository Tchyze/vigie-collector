"""Registre des collecteurs : chaque module expose un objet `COLLECTOR` (voir base.Collector)."""

from collectors import endoflife, nginx

ALL = [
    endoflife.COLLECTOR,
    nginx.COLLECTOR,
]
