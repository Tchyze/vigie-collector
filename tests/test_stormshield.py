from collectors import stormshield


def test_advisories(ctx):
    advisories = {a.id: a for a in stormshield.COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 10

    smc = advisories["STORMSHIELD-2026-034"]
    assert smc.title == "Potential RCE in SMC Web Administration Portal"
    assert smc.url == "https://advisories.stormshield.eu/2026-034"
    assert smc.published == "2026-10-30T11:40:15Z"
    assert smc.summary == "Produit : Stormshield Management Center."
    assert (smc.cves, smc.affected, smc.severity) == ([], [], None)

    php = advisories["STORMSHIELD-2026-033"]
    assert php.cves == ["CVE-2026-109618", "CVE-2026-109619"]

    assert advisories["STORMSHIELD-2026-032"].summary == "Produit : Stormshield Network Security."


def test_news_is_ignored():
    entry = {"title": "Nouvelle version du site", "link": "https://advisories.stormshield.eu/2026-099",
             "published_parsed": None, "tags": [{"term": "News"}]}
    assert stormshield.parse_entry(entry) is None
