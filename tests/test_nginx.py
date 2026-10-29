from collectors.nginx import COLLECTOR, parse_changes


def test_mainline_and_stable_branches(ctx):
    branches = {b.id: b for b in COLLECTOR.collect(ctx).branches}
    assert {"nginx-1.31", "nginx-1.30"} <= set(branches)

    mainline = {r.version: r for r in branches["nginx-1.31"].releases}
    assert mainline["1.31.8"].date == "2026-10-21"
    assert mainline["1.31.8"].security_fix is False
    assert mainline["1.31.8"].url == "https://nginx.org/en/CHANGES"
    assert mainline["1.31.7"].security_fix is True
    assert "CVE-2026-15176" in mainline["1.31.7"].summary

    stable = {r.version: r for r in branches["nginx-1.30"].releases}
    assert stable["1.30.6"].security_fix is True
    assert stable["1.30.6"].url == "https://nginx.org/en/CHANGES-1.30"
    assert all(len(r.summary or "") <= 300 for r in stable.values())


def test_parse_changes_counts_entries():
    text = """
Changes with nginx 1.2.3                                         01 Feb 2026

    *) Security: something (CVE-2026-0001).

    *) Feature: a thing.

    *) Workaround: a hack.

Changes with nginx 1.2.2                                         15 Jan 2026

    *) Bugfix: a fix.
"""
    new, old = parse_changes(text, "https://nginx.org/en/CHANGES")
    assert (new.version, new.date, new.security_fix) == ("1.2.3", "2026-02-01", True)
    assert new.summary == "1 correctif(s) de sécurité (CVE-2026-0001), 1 nouveauté(s), 1 correction(s)"
    assert (old.security_fix, old.summary) == (False, "1 correction(s)")
