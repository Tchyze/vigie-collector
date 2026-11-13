import json

from collectors import microsoft
from collectors.base import Context
from tests.conftest import FIXTURES, TODAY, fixture_client
from vigie.models import Advisory, CollectResult

NOV = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Nov"
OCT = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct"
SEP = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep"
NOV_REVISED = "2026-11-13T01:44:39Z"


def collect(catalog, previous=None):
    client = fixture_client()
    result = microsoft.COLLECTOR.collect(Context(client=client, catalog=catalog, today=TODAY, previous=previous))
    return client._client._transport.requested, {a.id: a for a in result.advisories}


def test_monthly_advisory(catalog):
    requested, advisories = collect(catalog)
    # deux documents au plus par passage, les plus récents d'abord ; octobre est absent (404)
    assert [u for u in requested if "/cvrf/20" in u] == [NOV, OCT]
    assert list(advisories) == ["MSRC-2026-Nov"]

    nov = advisories["MSRC-2026-Nov"]
    assert nov.title == "November 2026 Security Updates — Windows Server"
    assert nov.url == "https://msrc.microsoft.com/update-guide/releaseNote/2026-Nov"
    assert (nov.published, nov.updated) == ("2026-11-10T08:00:00Z", NOV_REVISED)
    assert (nov.severity, nov.cvss) == ("critical", 8.1)
    assert nov.cves == ["CVE-2026-109459", "CVE-2026-113749", "CVE-2026-113752", "CVE-2026-113825"]
    assert nov.affected == ["windows-server-2025", "windows-server-2022", "windows-server-2019", "windows-server-2016"]
    assert nov.summary == "8 vulnérabilités corrigées pour Windows Server, dont 4 critiques."


def known(month: str, updated: str) -> Advisory:
    return Advisory(id=f"MSRC-{month}", source="microsoft", vendor="Microsoft", title=month,
                    published="2026-01-01T00:00:00Z", url="https://x/", updated=updated, summary="déjà vu")


def test_unchanged_month_is_not_downloaded_again(catalog):
    previous = CollectResult(advisories=[known("2026-Nov", NOV_REVISED)])
    requested, advisories = collect(catalog, previous)
    assert NOV not in requested
    assert advisories["MSRC-2026-Nov"].summary == "déjà vu"
    # le budget va aux mois inconnus, du plus récent au plus ancien
    assert [u for u in requested if "/cvrf/20" in u] == [OCT, SEP]


def test_failed_download_keeps_previous_data(catalog):
    previous = CollectResult(advisories=[known("2026-Oct", "2026-01-01T00:00:00Z")])
    _, advisories = collect(catalog, previous)
    assert advisories["MSRC-2026-Oct"].summary == "déjà vu"


def test_parse_exploited_and_branch_names():
    document = json.loads((FIXTURES / "microsoft" / "2026-Nov.json").read_text(encoding="utf-8"))
    products = {p["Value"]: p["ProductID"] for p in document["ProductTree"]["FullProductName"]}
    exploited = {
        "CVE": "CVE-2026-1",
        "ProductStatuses": [{"Type": 3, "ProductID": [products["Windows Server 2012 R2 (Server Core installation)"]]}],
        "Threats": [
            {"Type": 3, "Description": {"Value": "Important"}, "ProductID": [products["Windows Server 2012 R2 (Server Core installation)"]]},
            {"Type": 1, "Description": {"Value": "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"}},
        ],
        "CVSSScoreSets": [],
    }
    document["Vulnerability"] = [exploited]
    month = {"ID": "2026-Nov", "InitialReleaseDate": "2026-11-10T08:00:00Z", "CurrentReleaseDate": NOV_REVISED}
    advisory = microsoft.parse(document, month)
    assert advisory.affected == ["windows-server-2012-r2"]
    assert (advisory.severity, advisory.cves) == ("high", ["CVE-2026-1"])
    assert advisory.summary == "1 vulnérabilités corrigées pour Windows Server, dont 0 critiques et 1 déjà exploitées."

    document["Vulnerability"] = []
    assert microsoft.parse(document, month) is None
