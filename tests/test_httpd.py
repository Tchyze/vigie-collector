from collectors.httpd import COLLECTOR, parse_changes


def test_versions_from_tags_with_security_from_changes(ctx):
    [branch] = COLLECTOR.collect(ctx).branches
    assert branch.id == "apache-httpd-2.4"
    releases = {r.version: r for r in branch.releases}
    assert "2.4.69-rc1-candidate" not in releases
    latest = releases["2.4.69"]
    assert latest.date == "2026-10-01"
    assert latest.security_fix is True
    assert latest.summary.startswith("20 correctif(s) de sécurité (CVE-2026-93546")
    assert len(latest.summary) <= 300


def test_version_missing_from_changes_is_unknown(ctx):
    changes = parse_changes("Changes with Apache 2.4.70\n\n  *) mod_ssl: fix.\n")
    assert changes == {"2.4.70": (False, "1 changement(s)")}
