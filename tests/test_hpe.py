import httpx
import pytest

from collectors import hpe_bulletins, hpe_ilo
from collectors.base import CollectError, Context
from tests.conftest import TODAY, fixture_client


def test_ilo_versions(ctx):
    branches = {b.branch: b for b in hpe_ilo.COLLECTOR.collect(ctx).branches}
    assert set(branches) == {"4", "5", "6", "7"}
    assert {b.product for b in branches.values()} == {"hpe-ilo"}
    assert branches["6"].label == "iLO 6"

    ilo6 = {r.version: r for r in branches["6"].releases}
    assert ilo6["1.10"].date == "2022-11-28"
    # même version dans deux dépôts (gen11 et gen12, rpm et fwpkg) : une seule entrée
    assert len(branches["6"].releases) == len(ilo6)
    assert branches["6"].releases[0].version == max(ilo6, key=lambda v: tuple(map(int, v.split("."))))
    assert all(r.security_fix is None for b in branches.values() for r in b.releases)


def test_ilo_failed_repository_keeps_the_others(catalog):
    broken = {hpe_ilo.INDEX.format(repo="fwpp-gen12"): httpx.Response(503)}
    client = fixture_client(broken)
    with pytest.raises(CollectError) as error:
        hpe_ilo.COLLECTOR.collect(Context(client=client, catalog=catalog, today=TODAY))
    assert "fwpp-gen12" in str(error.value)
    assert {b.branch for b in error.value.partial.branches} >= {"4", "5", "6"}


def test_bulletins(ctx):
    advisories = {a.id: a for a in hpe_bulletins.COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 50

    ilo = advisories["HPESBHF05170"]
    assert ilo.title.startswith("HPE Integrated Lights-Out 7 (iLO 7), Integrated Lights-Out 6 (iLO 6)")
    assert ilo.url == "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbhf05170en_us&docLocale=en_US"
    assert ilo.affected == ["hpe-ilo-7", "hpe-ilo-6", "hpe-ilo-5"]
    assert ilo.summary is None

    assert advisories["HPESBHF05163"].affected == ["hpe-ilo-7"]  # « Integrated Lights-Out (iLO) 7 »
    assert advisories["HPESBNW05171"].summary == "Révision 3 du bulletin."
    assert "HPESBNW05156" in advisories  # « rev 2 », sans point


@pytest.mark.parametrize(("title", "affected"), [
    ("HPESBHF00001 rev.1 - HPE iLO 5 and iLO 6, Remote Code Execution", ["hpe-ilo-6", "hpe-ilo-5"]),
    ("HPESBHF00002 rev.1 - HPE ProLiant Gen11 Servers, BIOS Vulnerability", []),
])
def test_bulletin_ilo_generations(title, affected):
    entry = {"title": title, "link": "https://support.hpe.com/x", "published_parsed": (2026, 11, 1, 0, 0, 0, 6, 305, 0)}
    assert hpe_bulletins.parse_entry(entry).affected == affected
