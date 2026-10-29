import collectors.certfr as certfr
from collectors.base import Context
from tests.conftest import TODAY, fixture_client
from vigie.models import Advisory, CollectResult

JSON_1381 = "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1381/json/"


def test_avis_and_alertes(ctx):
    advisories = {a.id: a for a in certfr.COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 80

    tenable = advisories["CERTFR-2026-AVI-1381"]
    assert tenable.url == "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1381/"
    assert tenable.published == "2026-10-26T00:00:00Z"
    assert tenable.vendor == "CERT-FR"
    assert set(tenable.cves) == {"CVE-2026-109618", "CVE-2026-109619"}
    assert tenable.updated is None  # une seule révision
    assert tenable.affected == []

    # alerte de 2024, hors rétention : gardée dans le résultat, mais son JSON n'est pas demandé
    assert advisories["CERTFR-2024-ALE-004"].cves == []

    # JSON absent : l'avis est gardé, sans CVE
    assert advisories["CERTFR-2026-AVI-1383"].cves == []


def test_known_advisory_is_not_downloaded_again(catalog):
    client = fixture_client()
    previous = CollectResult(advisories=[Advisory(
        id="CERTFR-2026-AVI-1381", source="certfr", vendor="CERT-FR",
        title="Multiples vulnérabilités dans les produits Tenable (26 octobre 2026)",
        published="2026-10-26T00:00:00Z", url="https://x/", cves=["CVE-2026-109618"],
    )])
    result = certfr.COLLECTOR.collect(Context(client=client, catalog=catalog, today=TODAY, previous=previous))
    assert JSON_1381 not in client._client._transport.requested
    tenable = next(a for a in result.advisories if a.id == "CERTFR-2026-AVI-1381")
    assert tenable.cves == ["CVE-2026-109618"]


def test_json_budget_per_run(ctx, monkeypatch):
    monkeypatch.setattr(certfr, "MAX_JSON_PER_RUN", 2)
    certfr.COLLECTOR.collect(ctx)
    requested = [u for u in ctx.client._client._transport.requested if u.endswith("/json/")]
    assert len(requested) == 2


def test_revision_date_from_json(ctx, monkeypatch):
    monkeypatch.setattr(ctx.catalog, "advisory_retention_days", 365 * 5)
    fortios = next(a for a in certfr.COLLECTOR.collect(ctx).advisories if a.id == "CERTFR-2024-ALE-004")
    assert fortios.cves == ["CVE-2024-21762"]
    assert fortios.updated == "2024-07-01T00:00:00Z"  # dernière révision
