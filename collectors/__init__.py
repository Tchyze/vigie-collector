"""Registre des collecteurs : chaque module expose un objet `COLLECTOR` (voir base.Collector)."""

from collectors import endoflife, httpd, nginx, openssh

ALL = [
    endoflife.COLLECTOR,
    nginx.COLLECTOR,
    httpd.COLLECTOR,
    openssh.COLLECTOR,
]
