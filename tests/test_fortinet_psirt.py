import json

import pytest

import collectors.fortinet_psirt as fortinet
from collectors.base import Context
from tests.conftest import FIXTURES, TODAY, fixture_client
from vigie.models import Advisory, CollectResult

CSAF_267 = ("https://filestore.fortinet.com/fortiguard/psirt/"
            "csaf_authentication-bypass-by-primary-weakness_fg-ir-26-267.json")


def csaf(advisory_id: str) -> dict:
    return json.loads((FIXTURES / "fortinet" / "csaf" / f"{advisory_id}.json").read_text(encoding="utf-8"))


def test_advisories(ctx):
    advisories = {a.id: a for a in fortinet.COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 50

    fortios = advisories["FG-IR-26-267"]
    assert fortios.url == "https://fortiguard.fortinet.com/psirt/FG-IR-26-267"
    assert fortios.published == "2026-11-10T08:00:00Z"
    assert (fortios.cvss, fortios.severity) == (9.3, "critical")
    assert fortios.cves == ["CVE-2026-126253"]  # absente du flux RSS, prise dans le CSAF
    assert fortios.affected == ["fortios-8.0", "fortios-7.6", "fortios-7.4", "fortios-7.2"]
    assert "CVSSv3" not in fortios.summary and "Revised on" not in fortios.summary

    # produit non suivi par Vigie : CVE renseignée, aucune branche
    assert advisories["FG-IR-26-258"].cves == ["CVE-2026-126244"]
    assert advisories["FG-IR-26-258"].affected == []

    # CSAF indisponible : l'avis est gardé tel que le donne le flux
    assert advisories["FG-IR-26-190"].cves == []
    assert advisories["FG-IR-26-190"].cvss == 7.3
    assert all(len(a.summary or "") <= 300 for a in advisories.values())


def test_csaf_only_affected_branches_are_kept():
    # 8.0, 7.4 et 7.2 sont en « known_not_affected » (« FortiOS/ 7.4 all versions ») : à ignorer
    parsed = fortinet.parse_csaf(csaf("FG-IR-26-195"))
    assert parsed == {"cves": ["CVE-2026-121530"], "affected": ["fortios-7.6"], "cvss": 5.9}


def test_csaf_several_products():
    # FortiOS, FortiPAM, FortiSASE… : seules les branches FortiOS sont retenues
    parsed = fortinet.parse_csaf(csaf("FG-IR-26-269"))
    assert parsed["affected"] == ["fortios-8.0", "fortios-7.6", "fortios-7.4", "fortios-7.2"]
    assert parsed["cves"] == ["CVE-2026-126255"]


def test_csaf_alternative_range_syntax():
    # FortiMail « >= 8.0.0 and <= 8.0.1 » : format reconnu, produit non suivi
    parsed = fortinet.parse_csaf(csaf("FG-IR-26-212"))
    assert parsed == {"cves": ["CVE-2026-126160"], "affected": [], "cvss": 8.2}


@pytest.mark.parametrize(("product_id", "name", "expected"), [
    ("FortiOS >=7.6.0|<=7.6.6", "FortiOS", "fortios-7.6"),
    ("FortiOS >= 7.4.0 and <= 7.4.8", "FortiOS", "fortios-7.4"),
    ("FortiOS/ 7.2 all versions", "FortiOS", "fortios-7.2"),
    ("FortiOS 7.0 all versions", "FortiOS", "fortios-7.0"),
    ("FortiOS 7.6.0", "FortiOS", "fortios-7.6"),
    ("FortiOS >=7.0.0|<=7.4.3", "FortiOS", None),        # plusieurs branches : ambigu
    ("FortiOS 7 all versions", "FortiOS", None),          # pas de branche majeure.mineure
    ("FortiOS-upcoming 7.6.9", "FortiOS", None),          # format inconnu
    ("FortiManager Cloud 7.6.0", "FortiManager Cloud", None),
    ("FortiOS 7.6.0", None, None),                        # absent de l'arbre des produits
])
def test_affected_branch(product_id, name, expected):
    assert fortinet.affected_branch(product_id, name) == expected


def previous_267(**changes) -> CollectResult:
    fields = dict(
        id="FG-IR-26-267", source="fortinet", vendor="Fortinet", title="Authentication bypass",
        published="2026-11-10T08:00:00Z", updated="2026-11-10T00:00:00Z", url="https://x/",
        cves=["CVE-2026-000001"], affected=["fortios-7.4"],
    )
    fields.update(changes)
    return CollectResult(advisories=[Advisory(**fields)])


def collect(previous):
    client = fixture_client()
    result = fortinet.COLLECTOR.collect(Context(client=client, catalog=None, today=TODAY, previous=previous))
    return client._client._transport.requested, next(a for a in result.advisories if a.id == "FG-IR-26-267")


def test_known_advisory_is_not_downloaded_again():
    requested, advisory = collect(previous_267())
    assert CSAF_267 not in requested
    assert (advisory.cves, advisory.affected) == (["CVE-2026-000001"], ["fortios-7.4"])


def test_revised_advisory_is_downloaded_again():
    requested, advisory = collect(previous_267(updated="2026-10-01T00:00:00Z"))
    assert CSAF_267 in requested
    assert advisory.cves == ["CVE-2026-126253"]


def test_advisory_without_cve_is_enriched():
    # état enregistré avant l'ajout du CSAF : aucune CVE
    requested, advisory = collect(previous_267(cves=[], affected=[]))
    assert CSAF_267 in requested
    assert advisory.affected == ["fortios-8.0", "fortios-7.6", "fortios-7.4", "fortios-7.2"]


def test_budget_keeps_previous_data(monkeypatch):
    monkeypatch.setattr(fortinet, "MAX_CSAF_PER_RUN", 0)
    requested, advisory = collect(previous_267(cves=[], affected=["fortios-7.4"]))
    assert not any("/psirt/csaf_" in url for url in requested)
    assert advisory.affected == ["fortios-7.4"]
