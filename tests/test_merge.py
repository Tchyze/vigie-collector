import datetime as dt

from vigie.catalog import Catalog, Product
from vigie.merge import Contribution, merge_branches
from vigie.models import BranchData, Release

TODAY = dt.date(2026, 10, 29)


def catalog():
    return Catalog(products={
        "fortios": Product(id="fortios", label="FortiOS", vendor="Fortinet", category="firewall", endoflife="fortios"),
        "openssh": Product(id="openssh", label="OpenSSH", vendor="OpenBSD", category="service", single_branch="portable"),
    })


def reference(**kw):
    return Contribution("endoflife", "reference", BranchData(product="fortios", branch="7.4", **kw))


def vendor(**kw):
    return Contribution("fortinet_firmware", "vendor", BranchData(product="fortios", branch="7.4", **kw))


def test_priority_overrides_vendor_reference():
    contributions = [
        reference(label="7.4", eol_dates={"end_of_life": "2027-11-14", "end_of_active_support": "2026-05-14"},
                  eol_labels={"end_of_life": "End of Support"},
                  releases=[Release("7.4.11", "2026-01-10", url="https://ref/7.4.11")]),
        vendor(releases=[Release("7.4.11", "2026-01-09", security_fix=True), Release("7.4.13", "2026-10-20")]),
    ]
    overrides = {("fortios", "7.4"): {"eol": {"end_of_life": "2028-01-01"}, "releases": [
        {"version": "7.4.13", "summary": "Corrections de sécurité"}]}}
    [branch] = merge_branches(catalog(), contributions, overrides, TODAY)["fortios"]

    assert branch["eol"]["end_of_life"] == "2028-01-01"
    assert branch["eol"]["end_of_active_support"] == "2026-05-14"
    assert branch["eol"]["trigger_date"] == "2028-01-01"
    assert branch["eol"]["labels"] == {"end_of_life": "End of Support"}
    assert branch["status"] == "active"
    assert branch["latest_version"] == "7.4.13"
    assert branch["latest_release_date"] == "2026-10-20"
    assert branch["sources"] == ["overrides", "fortinet_firmware", "endoflife"]
    r13, r11 = branch["releases"]
    assert r13 == {"version": "7.4.13", "date": "2026-10-20", "security_fix": None,
                   "summary": "Corrections de sécurité", "url": None}
    # version connue des deux sources : champ par champ, l'éditeur d'abord
    assert r11 == {"version": "7.4.11", "date": "2026-01-09", "security_fix": True,
                   "summary": None, "url": "https://ref/7.4.11"}


def test_override_latest_version():
    overrides = {("fortios", "7.4"): {"latest_version": "7.4.12", "latest_release_date": "2026-09-01"}}
    [branch] = merge_branches(catalog(), [reference(releases=[Release("7.4.13")])], overrides, TODAY)["fortios"]
    assert (branch["latest_version"], branch["latest_release_date"]) == ("7.4.12", "2026-09-01")


def test_vendor_only_branch_dropped_when_product_has_reference():
    contribs = [Contribution("nginx", "vendor", BranchData(product="fortios", branch="5.0", releases=[Release("5.0.1")]))]
    assert merge_branches(catalog(), contribs, {}, TODAY)["fortios"] == []


def test_product_without_reference_and_eol_soon():
    contribs = [Contribution("openssh", "vendor", BranchData(product="openssh", branch="portable",
                                                             releases=[Release("10.6p1", "2026-10-06")]))]
    overrides = {("openssh", "portable"): {"eol": {"end_of_life": "2027-01-01"}}}
    [branch] = merge_branches(catalog(), contribs, overrides, TODAY)["openssh"]
    assert branch["id"] == "openssh-portable"
    assert branch["status"] == "eol_soon"
    assert branch["eol"]["source_url"] is None


def test_declared_eol_without_date():
    [branch] = merge_branches(catalog(), [reference(declared_eol=True)], {}, TODAY)["fortios"]
    assert branch["status"] == "eol"
    assert branch["eol"]["trigger_date"] is None
