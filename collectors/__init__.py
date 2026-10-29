"""Registre des collecteurs : chaque module expose un objet `COLLECTOR` (voir base.Collector)."""

from collectors import cisco, endoflife, fortinet_firmware, fortinet_psirt, httpd, nginx, openssh, paloalto

ALL = [
    endoflife.COLLECTOR,
    nginx.COLLECTOR,
    httpd.COLLECTOR,
    openssh.COLLECTOR,
    fortinet_firmware.COLLECTOR,
    fortinet_psirt.COLLECTOR,
    paloalto.COLLECTOR,
    cisco.COLLECTOR,
]
