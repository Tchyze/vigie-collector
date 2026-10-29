import datetime as dt

from collectors.debian_dsa import COLLECTOR, parse_list


def test_advisories(ctx):
    advisories = {a.id: a for a in COLLECTOR.collect(ctx).advisories}
    chromium = advisories["DSA-6592-1"]
    assert chromium.title == "DSA-6592-1 chromium - security update"
    assert chromium.published == "2026-10-28T00:00:00Z"
    assert chromium.url == "https://security-tracker.debian.org/tracker/DSA-6592-1"
    assert chromium.affected == ["debian-13"]
    assert chromium.cves[0] == "CVE-2026-118304"
    assert chromium.summary.startswith("Security issues were discovered in Chromium")
    # le flux dsa-long ne couvre que les 30 derniers : les autres restent sans résumé
    assert sum(1 for a in advisories.values() if a.summary) == 30


SAMPLE = """\
[20 Oct 2026] DSA-7000-1 openssl - security update
	{CVE-2026-0001 CVE-2026-0002}
	[trixie] - openssl 3.5.1-1+deb13u1
	[bookworm] - openssl <not-affected> (vulnerable code not present)
	NOTE: a note
[02 Jan 2026] DSA-6000-1 bind9 - security update
	{CVE-2025-0001}
	[bookworm] - bind9 1:9.18.33-1~deb12u2
	[trixie] - bind9 1:9.20.9-1+deb13u1
[01 Jan 2025] DSA-5000-1 old - security update
	[bookworm] - old 1.0
"""


def test_parse_list_suites_and_cutoff():
    recent, older = parse_list(SAMPLE, cutoff=dt.date(2025, 10, 29))
    assert recent.id == "DSA-7000-1"
    assert recent.cves == ["CVE-2026-0001", "CVE-2026-0002"]
    assert recent.affected == ["debian-13"]  # « <not-affected> » n'est pas un correctif
    assert older.affected == ["debian-12", "debian-13"]
