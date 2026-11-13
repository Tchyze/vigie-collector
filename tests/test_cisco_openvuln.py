import httpx
import pytest

from collectors import cisco_openvuln
from collectors.base import CollectError, Context
from tests.conftest import TODAY, fixture_client
from vigie.versions import sort_versions

TOKEN = cisco_openvuln.TOKEN_URL


def run(catalog, overrides=None):
    client = fixture_client(overrides)
    ctx = Context(client=client, catalog=catalog, today=TODAY)
    return client._client._transport, ctx


def collect(catalog, overrides=None):
    transport, ctx = run(catalog, overrides)
    result = cisco_openvuln.COLLECTOR.collect(ctx)
    return transport.requested, {b.branch: b for b in result.branches}


def releases(branch):
    return {r.version: r.security_fix for r in branch.releases}


def test_versions_by_branch(catalog):
    _, branches = collect(catalog)
    assert {"26.2", "26.1", "17.18", "17.15", "17.12", "17.9", "16.12"} <= set(branches)
    assert "3.11" not in branches                       # ancien format 3.11.15E
    assert set(releases(branches["26.1"])) == {"26.1.3", "26.1.2", "26.1.1a", "26.1.1"}   # sans 26.1.2s1
    assert "17.18.5x" not in releases(branches["17.18"])
    latest = sort_versions(branches["17.9"].releases, key=lambda r: r.version)[0]
    assert latest.version == "17.9.10"
    assert sort_versions(branches["17.12"].releases, key=lambda r: r.version)[0].version == "17.12.8"


def test_security_fixes_from_first_fixed(catalog):
    _, branches = collect(catalog)
    fixes = {v for v, fix in releases(branches["17.12"]).items() if fix}
    assert fixes == {"17.12.8", "17.12.7", "17.12.6", "17.12.5b", "17.12.1a", "17.12.2a",
                     "17.12.3a", "17.12.4a", "17.12.5a"}
    assert releases(branches["17.12"])["17.12.5"] is None   # inconnu, pas « faux »
    assert releases(branches["26.1"])["26.1.2"] is True
    assert not any(releases(branches["17.15"]).values())    # 17.15.3 cité par un avis 17.12 : ignoré ici


def test_one_query_per_branch_from_17(catalog):
    requested, _ = collect(catalog)
    assert requested[0] == TOKEN
    queried = [u.rsplit("=", 1)[1] for u in requested if "OSType/iosxe" in u]
    assert sorted(queried) == sorted(["26.2.1", "26.1.1", "17.18.1", "17.15.1", "17.12.1", "17.9.1"])


def test_token_sent_and_secrets_kept_out_of_urls(catalog):
    transport, ctx = run(catalog)
    seen = []
    original = transport.handle_request

    def spy(request):
        seen.append(request)
        return original(request)

    transport.handle_request = spy
    cisco_openvuln.COLLECTOR.collect(ctx)
    assert b"client_secret=secret-de-test" in seen[0].read()
    assert all("secret-de-test" not in str(r.url) for r in seen)
    assert all(r.headers["Authorization"] == "Bearer jeton-de-test" for r in seen[1:])


def test_missing_credentials(catalog, monkeypatch):
    monkeypatch.delenv("CISCO_CLIENT_SECRET")
    transport, ctx = run(catalog)
    with pytest.raises(RuntimeError, match="identifiants absents"):
        cisco_openvuln.COLLECTOR.collect(ctx)
    assert transport.requested == []


def test_refused_token(catalog):
    with pytest.raises(httpx.HTTPStatusError) as exc:
        collect(catalog, {TOKEN: httpx.Response(401, json={"error": "invalid_client"})})
    assert "secret-de-test" not in str(exc.value)


def test_failed_branch_query_keeps_versions(catalog):
    url = cisco_openvuln.BY_VERSION.format(version="17.12.1")
    transport, ctx = run(catalog, {url: httpx.Response(503)})
    with pytest.raises(CollectError) as exc:
        cisco_openvuln.COLLECTOR.collect(ctx)
    branches = {b.branch: b for b in exc.value.partial.branches}
    assert "17.12.8" in releases(branches["17.12"])
    assert not any(releases(branches["17.12"]).values())
    assert releases(branches["26.1"])["26.1.2"] is True
