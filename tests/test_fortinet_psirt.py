from collectors.fortinet_psirt import COLLECTOR


def test_advisories(ctx):
    advisories = {a.id: a for a in COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 50

    php = advisories["FG-IR-26-186"]
    assert php.url == "https://fortiguard.fortinet.com/psirt/FG-IR-26-186"
    assert php.published == "2026-10-21T07:00:00Z"
    assert (php.cvss, php.severity) == (9.8, "critical")
    assert php.cves == ["CVE-2026-109618", "CVE-2026-109619"]
    assert php.affected == []

    fortisiem = advisories["FG-IR-26-180"]
    assert fortisiem.updated == "2026-10-13T00:00:00Z"
    assert "Revised on" not in fortisiem.summary
    assert "CVSSv3" not in fortisiem.summary
    assert all(len(a.summary or "") <= 300 for a in advisories.values())
