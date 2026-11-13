"""Registre des collecteurs : chaque module expose un objet `COLLECTOR` (voir base.Collector)."""

from collectors import (
    certfr,
    cisco,
    debian_dsa,
    endoflife,
    fortinet_firmware,
    fortinet_psirt,
    httpd,
    microsoft,
    nginx,
    openssh,
    paloalto,
    redhat,
    rocky,
    stormshield,
    ubuntu,
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
    redhat.COLLECTOR,
    rocky.COLLECTOR,
    microsoft.COLLECTOR,
    stormshield.COLLECTOR,
    ubuntu.COLLECTOR,
]
