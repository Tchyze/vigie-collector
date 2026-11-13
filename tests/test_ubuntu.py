import json

import httpx
import pytest

from collectors import ubuntu
from collectors.base import CollectError, Context
from tests.conftest import FIXTURES, TODAY, fixture_client
from vigie.models import Advisory, CollectResult


def page(offset: int) -> str:
    return ubuntu.API.format(limit=ubuntu.PAGE_SIZE, offset=offset)


def ids(offset: int) -> list[str]:
    data = json.loads((FIXTURES / "ubuntu" / f"notices-{offset}.json").read_text(encoding="utf-8"))
    return [n["id"] for n in data["notices"]]


def collect(catalog, previous=None, overrides=None):
    client = fixture_client(overrides)
    result = ubuntu.COLLECTOR.collect(Context(client=client, catalog=catalog, today=TODAY, previous=previous))
    return client._client._transport.requested, {a.id: a for a in result.advisories}


def known(*advisory_ids, published="2026-11-01T00:00:00Z") -> CollectResult:
    return CollectResult(advisories=[
        Advisory(id=i, source="ubuntu", vendor="Canonical", title=i, published=published, url="https://x/")
        for i in advisory_ids
    ])


def test_first_run_reads_up_to_the_budget(catalog):
    requested, advisories = collect(catalog)
    assert requested == [page(0), page(20), page(40), page(60)]
    assert len(advisories) == 80

    apache = advisories["USN-9090-1"]
    assert apache.title == "Apache HTTP Server vulnerabilities"
    assert apache.vendor == "Canonical"
    assert apache.url == "https://ubuntu.com/security/notices/USN-9090-1"
    assert apache.summary == "Several security issues were fixed in Apache HTTP Server."
    assert apache.published.startswith("2026-11-12T")
    assert "ubuntu-24.04" in apache.affected and "ubuntu-26.04" in apache.affected
    assert len(apache.cves) == 5
    assert all(len(a.cves) <= ubuntu.MAX_CVES for a in advisories.values())


def test_incremental_run_then_backfill(catalog):
    # tout le début est connu : une page de nouveautés, puis rattrapage repris après l'état
    previous = known(*ids(0), *ids(20))
    requested, advisories = collect(catalog, previous)
    assert requested == [page(0), page(20), page(40), page(60)]
    assert set(ids(60)) <= set(advisories)


def test_complete_history_is_not_backfilled(catalog):
    previous = known(*ids(0), published="2025-06-01T00:00:00Z")  # l'état remonte à la date limite
    requested, _ = collect(catalog, previous)
    assert requested == [page(0)]


def test_interrupted_run_returns_what_was_read(catalog):
    overrides = {page(20): httpx.Response(503, text="Service Unavailable")}
    with pytest.raises(CollectError) as error:
        collect(catalog, overrides=overrides)
    assert {a.id for a in error.value.partial.advisories} == set(ids(0))


def test_hidden_notice_is_ignored():
    assert ubuntu.parse({"id": "USN-1-1", "published": "2026-01-01T00:00:00", "is_hidden": True}) is None
