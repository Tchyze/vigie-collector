from collectors.endoflife import COLLECTOR


def by_id(result):
    return {b.id: b for b in result.branches}


def test_debian_branches(ctx):
    branches = by_id(COLLECTOR.collect(ctx))
    assert {"debian-13", "debian-12", "debian-11", "debian-1.1"} <= set(branches)

    trixie = branches["debian-13"]
    assert trixie.label == "13 (Trixie)"
    assert trixie.release_date == "2025-08-09"
    assert trixie.eol_dates == {
        "end_of_security_support": "2028-08-09",
        "end_of_life": "2030-06-30",
        "end_of_extended_support": "2035-06-30",
    }
    assert trixie.eol_labels["end_of_life"] == "Debian LTS"
    assert trixie.eol_source_url == "https://endoflife.date/debian"
    assert trixie.declared_eol is False
    [latest] = trixie.releases
    assert (latest.version, latest.date) == ("13.7", "2026-09-12")
    assert latest.url == "https://www.debian.org/News/2026/20260912"
    assert latest.security_fix is None


def test_product_failure_keeps_other_products(ctx, catalog):
    from vigie.catalog import Product
    from collectors.base import CollectError
    import pytest

    catalog.products["absent"] = Product(id="absent", label="Absent", vendor="X", category="os", endoflife="absent")
    with pytest.raises(CollectError) as info:
        COLLECTOR.collect(ctx)
    assert "absent" in str(info.value)
    assert "debian-13" in by_id(info.value.partial)
