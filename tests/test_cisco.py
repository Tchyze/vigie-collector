from collectors.cisco import ATTRIBUTION, COLLECTOR


def test_advisories(ctx):
    advisories = {a.id: a for a in COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 50

    sdwan = advisories["cisco-sa-sdwan-rpa-EHchtZk"]
    # lien sans les paramètres de suivi du flux
    assert sdwan.url == ("https://sec.cloudapps.cisco.com/security/center/content/"
                         "CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk")
    assert sdwan.severity == "critical"
    assert sdwan.cves == ["CVE-2026-20127"]
    assert sdwan.published == "2026-10-28T21:54:35Z"
    assert "advisory is available" not in sdwan.summary
    assert "Security Impact Rating" not in sdwan.summary
    assert all(a.attribution == ATTRIBUTION for a in advisories.values())
    assert all(len(a.summary or "") <= 300 for a in advisories.values())
