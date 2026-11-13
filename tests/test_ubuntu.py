import httpx
import pytest

from collectors import ubuntu
from collectors.base import CollectError, Context
from tests.conftest import TODAY, fixture_client
from vigie.models import Advisory, CollectResult

RECENT = ["USN-9090-1", "USN-9089-1", "USN-9088-1", "USN-9087-1", "USN-9086-1"]
IN_PERIOD = "USN-7894-1"   # publié le 2025-11-26 : dans l'année qui précède TODAY (2026-10-29)
TOO_OLD = "USN-7786-1"     # publié le 2025-09-30 : avant la date limite


def url(advisory_id: str) -> str:
    return ubuntu.ADVISORY.format(id=advisory_id)


def collect(catalog, previous=None, overrides=None):
    client = fixture_client(overrides)
    result = ubuntu.COLLECTOR.collect(Context(client=client, catalog=catalog, today=TODAY, previous=previous))
    return client._client._transport.requested, {a.id: a for a in result.advisories}


def known(*advisory_ids, published="2026-11-01T00:00:00Z") -> CollectResult:
    return CollectResult(advisories=[
        Advisory(id=i, source="ubuntu", vendor="Canonical", title=i, published=published, url="https://x/")
        for i in advisory_ids
    ])


def test_first_run_reads_newest_first_and_stops_before_the_cutoff(catalog):
    requested, advisories = collect(catalog)
    assert requested == [ubuntu.INDEX] + [url(i) for i in RECENT + [IN_PERIOD, TOO_OLD]]
    assert set(advisories) == set(RECENT) | {IN_PERIOD}

    apache = advisories["USN-9090-1"]
    assert apache.title == "apache2 vulnerabilities"
    assert apache.vendor == "Canonical"
    assert apache.source == "ubuntu"
    assert apache.url == "https://ubuntu.com/security/notices/USN-9090-1"
    assert apache.published == "2026-11-12T21:25:57Z"
    assert apache.severity is None
    assert apache.cves == sorted(apache.cves) and len(apache.cves) == 5
    assert all(c.startswith("CVE-") for c in apache.cves)
    # versions standard et Ubuntu Pro (ESM), triées
    assert apache.affected == ["ubuntu-14.04", "ubuntu-16.04", "ubuntu-18.04", "ubuntu-20.04",
                               "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04", "ubuntu-26.10"]
    assert apache.summary and len(apache.summary) <= 300
    assert advisories["USN-9088-1"].affected == ["ubuntu-18.04"]   # seulement Ubuntu Pro 18.04
    assert all(len(a.cves) <= ubuntu.MAX_CVES for a in advisories.values())


def test_known_advisories_are_not_read_again(catalog):
    previous = known("USN-9090-1", "USN-9089-1", "USN-9088-1")
    requested, advisories = collect(catalog, previous)
    assert requested == [ubuntu.INDEX, url("USN-9087-1"), url("USN-9086-1"), url(IN_PERIOD), url(TOO_OLD)]
    assert set(advisories) == set(RECENT) | {IN_PERIOD}   # connus + nouveaux


def test_complete_history_is_not_read_below_the_oldest_known(catalog):
    # l'état remonte à la date limite : rien sous le plus ancien numéro connu
    previous = known("USN-9087-1", published="2025-11-01T00:00:00Z")
    requested, advisories = collect(catalog, previous)
    assert requested == [ubuntu.INDEX, url("USN-9090-1"), url("USN-9089-1"), url("USN-9088-1")]
    assert set(advisories) == {"USN-9090-1", "USN-9089-1", "USN-9088-1", "USN-9087-1"}


def test_nothing_new_still_returns_the_known_advisories(catalog):
    previous = known(*RECENT, IN_PERIOD, TOO_OLD, published="2025-10-30T00:00:00Z")
    requested, advisories = collect(catalog, previous)
    assert requested == [ubuntu.INDEX]
    assert len(advisories) == 7   # pas de « 0 résultat » : build.py le prendrait pour une panne


def test_budget_per_run(catalog, monkeypatch):
    monkeypatch.setattr(ubuntu, "MAX_FETCH_PER_RUN", 2)
    requested, advisories = collect(catalog)
    assert requested == [ubuntu.INDEX, url("USN-9090-1"), url("USN-9089-1")]
    assert set(advisories) == {"USN-9090-1", "USN-9089-1"}


def test_interrupted_run_returns_what_was_read(catalog):
    overrides = {url("USN-9088-1"): httpx.Response(503, text="Service Unavailable")}
    with pytest.raises(CollectError) as error:
        collect(catalog, previous=known("USN-1000-1"), overrides=overrides)
    assert {a.id for a in error.value.partial.advisories} == {"USN-9090-1", "USN-9089-1", "USN-1000-1"}


def test_unreachable_index_is_an_error(catalog):
    with pytest.raises(Exception):
        collect(catalog, overrides={ubuntu.INDEX: httpx.Response(503, text="Service Unavailable")})


def test_index_keeps_only_usn_once():
    index = "2026-11-13T00:00:00Z,UBUNTU-CVE-2026-1234\n2026-11-13T00:00:00Z,USN-9000-1\n" \
            "2026-11-12T00:00:00Z,LSN-0100-1\n2026-11-11T00:00:00Z,USN-9000-1\n\n"
    assert ubuntu.usn_ids(index) == ["USN-9000-1"]


def test_withdrawn_or_foreign_entries_are_ignored():
    assert ubuntu.parse({"id": "USN-1-1", "published": "2026-01-01T00:00:00Z", "withdrawn": "2026-02-01T00:00:00Z"}) is None
    assert ubuntu.parse({"id": "UBUNTU-CVE-2026-1", "published": "2026-01-01T00:00:00Z"}) is None
    assert ubuntu.parse({"id": "USN-1-1"}) is None
