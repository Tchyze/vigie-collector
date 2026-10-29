from collectors.paloalto import COLLECTOR, affected_branches


def test_advisories(ctx):
    advisories = {a.id: a for a in COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 30

    brotli = advisories["CVE-2026-111497"]
    assert brotli.url == "https://security.paloaltonetworks.com/CVE-2026-111497"
    assert (brotli.severity, brotli.cvss) == ("critical", 9.2)
    assert brotli.published == "2026-10-26T18:30:00Z"
    assert brotli.updated == "2026-10-29T05:30:00Z"
    assert brotli.cves == ["CVE-2026-111497"]
    # PAN-OS 11.1 et 10.2 sont marqués « None » : non touchés
    assert brotli.affected == ["panos-12.2", "panos-12.1", "panos-11.2"]

    bulletin = advisories["PAN-SA-2026-0006"]
    assert (bulletin.severity, bulletin.affected, bulletin.cves) == ("info", [], [])

    # GlobalProtect n'est pas une branche PAN-OS
    assert advisories["CVE-2026-0307"].affected == []


def test_affected_requires_parallel_lists():
    item = {"version": ["PAN-OS 11.2", "PAN-OS 11.1"], "affected": ["< 11.2.4"]}
    assert affected_branches(item) == []


def test_footnote_marks_are_not_affected():
    item = {"version": ["PAN-OS 12.1", "PAN-OS 11.2"], "affected": ["None *", "All"]}
    assert affected_branches(item) == ["panos-11.2"]
