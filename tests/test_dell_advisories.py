import httpx
import pytest

from collectors import dell_advisories as dell
from collectors.base import CollectError, Context
from tests.conftest import TODAY, fixture_client
from vigie.models import Advisory, CollectResult

RECORD = dell.CVE_RECORD.format


def collect(catalog, previous=None, overrides=None):
    client = fixture_client(overrides)
    result = dell.COLLECTOR.collect(Context(client=client, catalog=catalog, today=TODAY, previous=previous))
    return client._client._transport.requested, {a.id: a for a in result.advisories}


def test_discovery_keeps_dell_idrac_cves_only(catalog):
    requested, advisories = collect(catalog)
    # iSM, iDRAC Tools, modules Ansible (Dell) et OpenStack Ironic (MITRE) sont écartés dès NVD
    assert requested == [dell.NVD] + [RECORD(id=c) for c in (
        "CVE-2026-23855", "CVE-2026-79940", "CVE-2026-70412", "CVE-2026-35155")]
    assert set(advisories) == {"DSA-2026-392", "DSA-2026-374", "DSA-2026-348", "DSA-2026-187"}


def test_advisory_fields(catalog):
    _, advisories = collect(catalog)
    dsa = advisories["DSA-2026-392"]
    assert dsa.source == "dell" and dsa.vendor == "Dell"
    assert dsa.cves == ["CVE-2026-23855"]
    assert dsa.url.startswith("https://www.dell.com/support/kbdoc/") and "dsa-2026-392" in dsa.url
    assert dsa.title.startswith("Dell iDRAC9, iDRAC10 : CWE-78")
    assert (dsa.severity, dsa.cvss) == ("high", 7.2)
    assert dsa.published == "2026-09-09T16:02:57Z"
    assert dsa.summary.startswith("Versions corrigées : iDRAC9 7.30.10.50, 7.00.00.184 ; iDRAC10 1.30.30.50.")
    assert len(dsa.summary) <= 300
    # une branche par version corrigée (build.py ne garde que les branches publiées)
    assert dsa.affected == ["dell-idrac-7.30", "dell-idrac-7.00", "dell-idrac-1.30"]
    assert advisories["DSA-2026-348"].severity == "low"


def test_known_cves_are_not_read_again(catalog):
    previous = CollectResult(advisories=[Advisory(
        id="DSA-2026-392", source="dell", vendor="Dell", title="x", published="2026-09-09T16:02:57Z",
        url="https://x/", cves=["CVE-2026-23855"])])
    requested, advisories = collect(catalog, previous)
    assert RECORD(id="CVE-2026-23855") not in requested
    assert advisories["DSA-2026-392"].title == "x"   # l'avis connu est rendu tel quel
    assert len(advisories) == 4


def test_cutoff_and_budget(catalog, monkeypatch):
    monkeypatch.setattr(dell, "MAX_RECORDS_PER_RUN", 1)
    requested, advisories = collect(catalog)
    assert requested == [dell.NVD, RECORD(id="CVE-2026-23855")]
    assert set(advisories) == {"DSA-2026-392"}


def test_nvd_failure_is_an_error(catalog):
    with pytest.raises(Exception):
        collect(catalog, overrides={dell.NVD: httpx.Response(503, text="unavailable")})


def test_interrupted_run_returns_what_was_read(catalog):
    overrides = {RECORD(id="CVE-2026-70412"): httpx.Response(503, text="unavailable")}
    with pytest.raises(CollectError) as error:
        collect(catalog, overrides=overrides)
    assert {a.id for a in error.value.partial.advisories} == {"DSA-2026-392", "DSA-2026-374"}


def record(cve_id, dsa=None, product="iDRAC9", fixed="7.30.10.50 or later", score=5.0):
    refs = [{"url": f"https://www.dell.com/support/kbdoc/en-us/1/dsa-{dsa}-security-update"}] if dsa else []
    return {
        "cveMetadata": {"cveId": cve_id, "datePublished": "2026-10-01T00:00:00.000Z"},
        "containers": {"cna": {
            "affected": [{"vendor": "Dell", "product": product, "versions": [{"version": "0", "lessThan": fixed, "status": "affected"}]}],
            "references": refs,
            "metrics": [{"cvssV3_1": {"baseScore": score, "baseSeverity": "MEDIUM"}}],
            "descriptions": [{"lang": "en", "value": f"{product} issue"}],
        }},
    }


def test_cves_of_one_dsa_form_one_advisory():
    result = dell.merge({}, [record("CVE-2026-1001", "2026-500", score=4.0),
                             record("CVE-2026-1002", "2026-500", "iDRAC10", "1.30.30.50 or later", 8.1)])
    [advisory] = result.advisories
    assert advisory.id == "DSA-2026-500"
    assert advisory.cves == ["CVE-2026-1001", "CVE-2026-1002"]
    assert advisory.cvss == 8.1
    assert set(advisory.affected) == {"dell-idrac-7.30", "dell-idrac-1.30"}


def test_without_dsa_link_the_cve_is_the_advisory():
    [advisory] = dell.merge({}, [record("CVE-2026-1003")]).advisories
    assert advisory.id == "CVE-2026-1003"
    assert advisory.url == "https://www.cve.org/CVERecord?id=CVE-2026-1003"


def test_other_dell_products_are_not_idrac():
    assert dell.idrac_products(record("CVE-1", product="iDRAC Service Module")) == []
    assert dell.idrac_products(record("CVE-1", product="iDRAC Tools")) == []
    assert dell.idrac_products(record("CVE-1", product="iDRAC10", fixed="1.30.30.50 or later")) == [("iDRAC10", ["1.30.30.50"])]
