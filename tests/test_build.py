import datetime as dt
import json

import httpx

import collectors
import build
from tests.conftest import ROOT, fixture_client
from vigie import validate
from vigie.catalog import load_catalog, load_overrides

NOW = dt.datetime(2026, 10, 29, 12, 0, tzinfo=dt.timezone.utc)


def run_build(tmp_path, *, out="out", previous="none", client=None, sources=None):
    catalog = load_catalog(ROOT / "products.yaml")
    return build.run(
        catalog=catalog,
        overrides=load_overrides(ROOT / "overrides.yaml", catalog),
        sources=sources or collectors.ALL,
        client=client or fixture_client(),
        output=tmp_path / out,
        previous=tmp_path / previous,
        now=NOW,
    )


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_full_build_from_fixtures(tmp_path):
    assert run_build(tmp_path) == 0
    out = tmp_path / "out"
    index = read(out / "index.json")
    assert validate.errors("index", index) == []
    assert all(s["status"] == "ok" for s in index["sources"]), index["sources"]
    assert all(s["count"] > 0 for s in index["sources"])
    for entry in index["products"]:
        assert validate.errors("product", read(out / entry["file"])) == []
        assert entry["branch_count"] > 0, entry["id"]
    assert validate.errors("advisories", read(out / "advisories.json")) == []
    assert (out / "schema" / "product.schema.json").exists()

    debian = {b["id"]: b for b in read(out / "products/debian.json")["branches"]}
    assert debian["debian-13"]["status"] == "active"
    assert debian["debian-11"]["status"] == "eol"  # LTS terminé le 2026-08-31
    assert debian["debian-10"]["status"] == "eol"


def test_failing_source_keeps_previous_data(tmp_path):
    assert run_build(tmp_path, out="first") == 0
    broken = {url: httpx.Response(503) for url in ("https://endoflife.date/api/v1/products/debian",)}
    assert run_build(tmp_path, out="second", previous="first", client=fixture_client(broken)) == 0

    index = read(tmp_path / "second" / "index.json")
    eol_source = next(s for s in index["sources"] if s["name"] == "endoflife")
    assert eol_source["status"] == "error"
    assert "debian" in eol_source["error"]
    assert eol_source["last_success"] == "2026-10-29T12:00:00Z"
    first = read(tmp_path / "first" / "products/debian.json")["branches"]
    second = read(tmp_path / "second" / "products/debian.json")["branches"]
    assert second == first


def test_zero_results_after_non_zero_fails(tmp_path):
    assert run_build(tmp_path, out="first") == 0
    catalog = load_catalog(ROOT / "products.yaml")
    empty = {f"https://endoflife.date/api/v1/products/{p.endoflife}": httpx.Response(200, json={"result": {"releases": []}})
             for p in catalog.products.values() if p.endoflife}
    sources = [c for c in collectors.ALL if c.name == "endoflife"]
    code = run_build(tmp_path, out="second", previous="first", client=fixture_client(empty), sources=sources)
    assert code == 1
    index = read(tmp_path / "second" / "index.json")
    assert "0 résultat" in index["sources"][0]["error"]
    assert read(tmp_path / "second" / "products/debian.json")["branches"]
