"""Registre des collecteurs : chaque module expose un objet `COLLECTOR` (voir base.Collector)."""

from collectors import (
    certfr,
    cisco,
    debian_dsa,
    endoflife,
    fortinet_firmware,
    fortinet_psirt,
    httpd,
    nginx,
    openssh,
    paloalto,
)

ALL = [
    # versions et fins de support
    endoflife.COLLECTOR,
    nginx.COLLECTOR,
    httpd.COLLECTOR,
    openssh.COLLECTOR,
    fortinet_firmware.COLLECTOR,
    # avis de sécurité
    fortinet_psirt.COLLECTOR,
    paloalto.COLLECTOR,
    cisco.COLLECTOR,
    certfr.COLLECTOR,
    debian_dsa.COLLECTOR,
]
