from collectors.openssh import COLLECTOR


def test_portable_tags(ctx):
    [branch] = COLLECTOR.collect(ctx).branches
    assert branch.id == "openssh-portable"
    latest = branch.releases[0]
    assert (latest.version, latest.date) == ("10.6p1", "2026-10-06")
    assert latest.url == "https://www.openssh.org/txt/release-10.6"
    assert latest.security_fix is None
    versions = [r.version for r in branch.releases]
    assert "10.0p2" in versions and "9.9p1" in versions
