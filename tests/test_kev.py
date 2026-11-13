import json

import httpx

import collectors
from tests.conftest import fixture_client
from tests.test_build import read, run_build
from vigie import kev


def test_fetch_reads_the_catalogue():
    catalog = kev.fetch(fixture_client())
    assert catalog["CVE-2026-0322"] == "2026-10-14"
    assert all(c.startswith("CVE-") for c in catalog)


def test_exploited_flag():
    catalog = {"CVE-2026-0322": "2026-10-14"}
    assert kev.exploited(["CVE-2026-1", "CVE-2026-0322"], catalog) is True
    assert kev.exploited(["CVE-2026-1"], catalog) is False
    assert kev.exploited([], catalog) is None        # avis sans CVE : on ne sait pas
    assert kev.exploited(["CVE-2026-0322"], None) is None   # catalogue jamais lu


def by_id(path):
    return {a["id"]: a for a in read(path)["advisories"]}


def test_build_marks_exploited_advisories(tmp_path):
    assert run_build(tmp_path) == 0
    advisories = by_id(tmp_path / "out" / "advisories.json")
    assert advisories["CVE-2026-0322"]["exploited"] is True           # Palo Alto, au catalogue KEV
    assert advisories["VMSA-2026-0008"]["exploited"] is True          # CVE-2026-111497
    assert advisories["DSA-6592-1"]["exploited"] is False
    source = next(s for s in read(tmp_path / "out" / "index.json")["sources"] if s["name"] == "cisa_kev")
    assert (source["kind"], source["status"], source["count"]) == ("enrichment", "ok", 7)


def test_unreachable_catalogue_keeps_the_previous_one(tmp_path):
    assert run_build(tmp_path, out="first") == 0
    broken = fixture_client({kev.URL: httpx.Response(503)})
    assert run_build(tmp_path, out="second", previous="first", client=broken) == 0
    assert by_id(tmp_path / "second" / "advisories.json")["CVE-2026-0322"]["exploited"] is True
    source = next(s for s in read(tmp_path / "second" / "index.json")["sources"] if s["name"] == "cisa_kev")
    assert source["status"] == "error" and source["last_success"] == "2026-10-29T12:00:00Z"


def test_never_read_catalogue_gives_null(tmp_path):
    broken = fixture_client({kev.URL: httpx.Response(503)})
    assert run_build(tmp_path, client=broken, sources=[c for c in collectors.ALL if c.name == "paloalto"]) == 0
    assert by_id(tmp_path / "out" / "advisories.json")["CVE-2026-0322"]["exploited"] is None
