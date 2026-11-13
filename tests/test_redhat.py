import pytest

from collectors import redhat


def test_advisories(ctx):
    advisories = {a.id: a for a in redhat.COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 25  # 80 RHSA critiques enregistrés, dont 25 pour RHEL

    cockpit = advisories["RHSA-2026:99115"]
    assert cockpit.title == "cockpit-image-builder security update"
    assert cockpit.published == "2026-11-11T19:58:38Z"
    assert cockpit.url == "https://access.redhat.com/errata/RHSA-2026:99115"
    assert cockpit.severity == "critical"
    assert cockpit.cves == ["CVE-2026-102276", "CVE-2026-102278"]
    assert cockpit.affected == ["rhel-10"]

    # produits en couche : Satellite, OpenStack, Red Hat SSO
    for layered in ("RHSA-2026:99950", "RHSA-2026:99947", "RHSA-2026:99764"):
        assert layered not in advisories


def item(*packages, rhsa="RHSA-2026:1"):
    return {"RHSA": rhsa, "severity": "critical", "released_on": "2026-11-01T10:00:00Z",
            "CVEs": ["CVE-2026-1"], "released_packages": list(packages)}


@pytest.mark.parametrize(("packages", "branches", "title"), [
    (["kernel-0:5.14.0-570.el9_6.src", "kernel-0:5.14.0-570.el9_6.x86_64"], ["rhel-9"], "kernel security update"),
    (["kernel-rt-0:5.14.0-284.202.1.rt14.487.el9_2.src"], ["rhel-9"], "kernel-rt security update"),
    (["mysql-0:8.4.13-1.module+el9.9.0+25300+c0fc77bc.src::mysql:8.4",
      "mecab-0:0.996-3.module+el9.9.0+24089+64aac046.4.src::mysql:8.4"], ["rhel-9"], "mysql:8.4 security update"),
    (["openssl-1:3.2.2-6.el10_0.src", "openssl-1:3.0.7-29.el9_6.src"], ["rhel-10", "rhel-9"], "openssl security update"),
    (["a-0:1-1.el9.src", "b-0:1-1.el9.src", "c-0:1-1.el9.src", "d-0:1-1.el9.src"], ["rhel-9"],
     "a, b, c, … security update"),
])
def test_rhel(packages, branches, title):
    advisory = redhat.parse(item(*packages))
    assert (advisory.affected, advisory.title) == (branches, title)


@pytest.mark.parametrize("packages", [
    # OpenShift : un paquet en .el9 ordinaire ne suffit pas
    ["conmon-3:2.1.7-16.rhaos4.15.el9.src", "cri-tools-0:1.28.0-11.el9.src"],
    ["satellite-0:6.18.11-1.el9sat.src"],
    ["389-ds-base-0:2.6.1-9.module+el8dsrv+24847+c94540a6.src::redhat-ds:12"],
    ["eap7-undertow-0:2.2.37-18.SP16_redhat_00001.1.ep7.el7.src"],
    ["kernel-0:6.12.0-231.20.el10nv.src"],
    ["rhel-9-image-0:9.6-1.noarch"],  # aucun paquet source
])
def test_not_rhel(packages):
    assert redhat.parse(item(*packages)) is None
