from collectors.cisco import ATTRIBUTION, COLLECTOR


def test_advisories(ctx):
    advisories = {a.id: a for a in COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 50

    sdwan = advisories["cisco-sa-sdwan-rpa-EHchtZk"]
    # lien sans les paramètres de suivi du flux
    assert sdwan.url == ("https://sec.cloudapps.cisco.com/security/center/content/"
                         "CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk")
    assert sdwan.severity == "critical"
    assert sdwan.cves == ["CVE-2026-20127"]
    assert sdwan.published == "2026-10-28T21:54:35Z"
    assert "advisory is available" not in sdwan.summary
    assert "Security Impact Rating" not in sdwan.summary
    assert all(a.attribution == ATTRIBUTION for a in advisories.values())
    assert all(len(a.summary or "") <= 300 for a in advisories.values())


# --- Branches IOS XE depuis le CSAF -------------------------------------------------------------
import httpx  # noqa: E402

from collectors import cisco  # noqa: E402
from collectors.base import Context  # noqa: E402
from tests.conftest import TODAY, fixture_client  # noqa: E402
from vigie.models import Advisory, CollectResult  # noqa: E402

HARDENING = "cisco-sa-hardening-iosxe-V8NMuMZJ"
CSAF = cisco.CSAF_DOCUMENT.format(path="2026/cisco-sa-hardening-iosxe-v8nmumzj.json")


def run(catalog, previous=None, overrides=None):
    client = fixture_client(overrides)
    result = cisco.COLLECTOR.collect(Context(client=client, catalog=catalog, today=TODAY, previous=previous))
    return client._client._transport.requested, {a.id: a for a in result.advisories}


def test_ios_xe_branches_from_csaf(catalog):
    requested, advisories = run(catalog)
    assert requested[1:] == [cisco.CSAF_INDEX, CSAF]   # un seul avis IOS XE dans le flux
    advisory = advisories[HARDENING]
    assert {"cisco-ios-xe-17.9", "cisco-ios-xe-17.12", "cisco-ios-xe-17.15", "cisco-ios-xe-26.1"} <= set(advisory.affected)
    assert advisory.updated == "2026-10-21T22:02:05Z"   # date du document CSAF
    assert all(a.affected == [] for i, a in advisories.items() if i != HARDENING)


def test_unchanged_csaf_is_not_read_again(catalog):
    old = Advisory(id=HARDENING, source="cisco", vendor="Cisco", title="t", published="2026-10-02T19:21:28Z",
                   url="https://x/", updated="2026-10-21T22:02:05Z", affected=["cisco-ios-xe-17.9"])
    requested, advisories = run(catalog, CollectResult(advisories=[old]))
    assert CSAF not in requested
    assert advisories[HARDENING].affected == ["cisco-ios-xe-17.9"]


def test_csaf_failure_keeps_the_advisory(catalog):
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
