from collectors.fortinet_firmware import COLLECTOR


def test_fortios_releases_only(ctx):
    branches = {b.id: b for b in COLLECTOR.collect(ctx).branches}
    assert set(branches) == {"fortios-7.2", "fortios-7.4", "fortios-7.6", "fortios-8.0"}
    versions = {r.version for b in branches.values() for r in b.releases}
    assert versions == {"7.2.14", "7.4.13", "7.6.8", "8.0.2", "8.0.1"}  # sans les variantes FIPS-CC
    release = branches["fortios-7.4"].releases[0]
    assert release.date is not None and release.security_fix is None
    assert release.url.startswith("https://support.fortinet.com/")
