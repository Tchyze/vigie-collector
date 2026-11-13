from collectors.cisco import ATTRIBUTION, COLLECTOR


def test_advisories(ctx, monkeypatch):
    monkeypatch.delenv("CISCO_CLIENT_ID")   # flux RSS seul
    advisories = {a.id: a for a in COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 50

    sdwan = advisories["cisco-sa-sdwan-rpa-EHchtZk"]
    # lien sans les paramètres de suivi du flux
    assert sdwan.url == ("https://sec.cloudapps.cisco.com/security/center/content/"
                         "CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk")
    assert sdwan.severity == "critical"
    assert sdwan.cves == ["CVE-2026-20127"]
    assert sdwan.published == "2026-10-28T21:54:35Z"   # date de mise à jour, faute de mieux
    assert sdwan.cvss is None
    assert "advisory is available" not in sdwan.summary
    assert "Security Impact Rating" not in sdwan.summary
    assert all(a.attribution == ATTRIBUTION for a in advisories.values())
    assert all(len(a.summary or "") <= 300 for a in advisories.values())


# --- Branches IOS XE depuis le CSAF -------------------------------------------------------------
import httpx  # noqa: E402
import pytest  # noqa: E402

from collectors import cisco  # noqa: E402
from collectors.base import Context  # noqa: E402
from tests.conftest import TODAY, fixture_client  # noqa: E402
from vigie.models import Advisory, CollectResult  # noqa: E402

HARDENING = "cisco-sa-hardening-iosxe-V8NMuMZJ"
CSAF = cisco.CSAF_DOCUMENT.format(path="2026/cisco-sa-hardening-iosxe-v8nmumzj.json")


@pytest.fixture
def no_openvuln(monkeypatch):
    monkeypatch.delenv("CISCO_CLIENT_ID")


def run(catalog, previous=None, overrides=None):
    client = fixture_client(overrides)
    result = cisco.COLLECTOR.collect(Context(client=client, catalog=catalog, today=TODAY, previous=previous))
    return client._client._transport.requested, {a.id: a for a in result.advisories}


def test_ios_xe_branches_from_csaf(catalog, no_openvuln):
    requested, advisories = run(catalog)
    assert requested[1:] == [cisco.CSAF_INDEX, CSAF]   # un seul avis IOS XE dans le flux
    advisory = advisories[HARDENING]
    assert {"cisco-ios-xe-17.9", "cisco-ios-xe-17.12", "cisco-ios-xe-17.15", "cisco-ios-xe-26.1"} <= set(advisory.affected)
    assert advisory.updated == "2026-10-21T22:02:05Z"   # date du document CSAF
    assert all(a.affected == [] for i, a in advisories.items() if i != HARDENING)


def test_unchanged_csaf_is_not_read_again(catalog, no_openvuln):
    old = Advisory(id=HARDENING, source="cisco", vendor="Cisco", title="t", published="2026-10-02T19:21:28Z",
                   url="https://x/", updated="2026-10-21T22:02:05Z", affected=["cisco-ios-xe-17.9"])
    requested, advisories = run(catalog, CollectResult(advisories=[old]))
    assert CSAF not in requested
    assert advisories[HARDENING].affected == ["cisco-ios-xe-17.9"]


def test_csaf_failure_keeps_the_advisory(catalog, no_openvuln):
    _, advisories = run(catalog, overrides={CSAF: httpx.Response(503)})
    assert advisories[HARDENING].affected == [] and len(advisories) == 50
    _, advisories = run(catalog, overrides={cisco.CSAF_INDEX: httpx.Response(503)})
    assert advisories[HARDENING].affected == [] and len(advisories) == 50


def test_only_the_ios_xe_family_counts():
    document = {
        "product_tree": {"branches": [{"category": "vendor", "name": "Cisco", "branches": [
            {"category": "product_family", "name": "Cisco IOS XE Software", "branches": [
                {"category": "product_version", "name": "17.9", "branches": [
                    {"category": "service_pack", "name": "17.9.4a", "product": {"product_id": "A"}}]},
                {"category": "product_version", "name": "17.12", "branches": [
                    {"category": "service_pack", "name": "17.12.1", "product": {"product_id": "B"}}]}]},
            {"category": "product_family", "name": "Cisco IOS Software", "branches": [
                {"category": "product_version", "name": "15.9", "branches": [
                    {"category": "service_pack", "name": "15.9.3M", "product": {"product_id": "C"}}]}]}]}]},
        "vulnerabilities": [{"product_status": {"known_affected": ["A", "C"]}}],
    }
    assert cisco.ios_xe_branches(document) == ["cisco-ios-xe-17.9"]


# --- Détails depuis openVuln ---------------------------------------------------------------------
from collectors._cisco_api import TOKEN_URL  # noqa: E402

SDWAN = "cisco-sa-sdwan-rpa-EHchtZk"


def test_openvuln_details(catalog):
    requested, advisories = run(catalog)
    assert requested[1:] == [TOKEN_URL, cisco.OPENVULN_LATEST]   # ni index ni document CSAF
    sdwan = advisories[SDWAN]
    assert sdwan.cvss == 10.0
    assert sdwan.published == "2026-02-25T16:00:00Z"            # première publication
    assert sdwan.updated == "2026-10-28T21:54:35Z"              # la date du flux
    assert sdwan.affected == []
    hardening = advisories[HARDENING]
    assert hardening.affected == ["cisco-ios-xe-26.1", "cisco-ios-xe-17.15", "cisco-ios-xe-17.12",
                                  "cisco-ios-xe-17.9", "cisco-ios-xe-16.12", "cisco-ios-xe-3.2"]
    assert hardening.cvss == 9.8 and hardening.published == "2026-08-05T16:00:00Z"
    emudhra = advisories["cisco-sa-emudhra-info-ScS22A1r"]
    assert emudhra.cvss is None                                  # « NA »
    tunnel = advisories["cisco-sa-asaftd-tunnel-dos-s6mgkb75"]
    assert tunnel.updated is None                                # jamais mis à jour
    assert len(advisories) == 50


def test_openvuln_failure_falls_back_to_csaf(catalog):
    requested, advisories = run(catalog, overrides={cisco.OPENVULN_LATEST: httpx.Response(503)})
    assert CSAF in requested
    assert "cisco-ios-xe-17.12" in advisories[HARDENING].affected
    assert advisories[SDWAN].cvss is None and advisories[SDWAN].published == "2026-10-28T21:54:35Z"


def test_refused_token_falls_back_to_csaf(catalog):
    requested, advisories = run(catalog, overrides={TOKEN_URL: httpx.Response(401)})
    assert cisco.OPENVULN_LATEST not in requested and CSAF in requested
    assert len(advisories) == 50


def test_ios_xe_branches_from_names():
    names = ["Cisco IOS XE Software 17.9.4a", "Cisco IOS XE Software 17.12.1z5", "Cisco IOS XE Software 17.9.1",
             "Cisco IOS XE Catalyst SD-WAN 17.9.1", "Cisco IOS Software 15.9(3)M", "NA"]
    assert cisco.ios_xe_branches_from_names(names) == ["cisco-ios-xe-17.12", "cisco-ios-xe-17.9"]
