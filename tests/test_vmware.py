from collectors import vmware


def test_advisories(ctx):
    advisories = {a.id: a for a in vmware.COLLECTOR.collect(ctx).advisories}
    # VMSA publiés ou révisés dans l'année précédant le 2026-10-29
    assert set(advisories) >= {"VMSA-2026-0008", "VMSA-2026-0007", "VMSA-2026-0006", "VMSA-2026-0001"}
    assert all(a.id.startswith("VMSA-") for a in advisories.values())

    node = advisories["VMSA-2026-0008"]
    assert node.title.startswith("VMSA-2026-0008: Node.js Brotli decoder")
    assert node.published == "2026-10-28T00:00:00Z"
    assert node.severity == "critical"
    assert node.cves == ["CVE-2026-111497"]
    assert node.url.startswith("https://support.broadcom.com/web/ecx/support-content-notification/")
    assert node.summary == "Produits : VMware Cloud Foundation."
    assert node.affected == []

    # avis révisé : identifiant de base, date de mise à jour
    esx = advisories["VMSA-2026-0006"]
    assert esx.title.startswith("VMSA-2026-0006.1: VMware ESX, vCenter")
    assert esx.updated == "2026-08-19T09:26:23Z"
    assert esx.summary is None  # liste de produits tronquée par le portail


def item(**changes):
    data = {"title": "VMSA-2026-0010: ESX update (CVE-2026-10001)", "published": "02 November 2026",
            "updated": "2026-11-02T10:00:00.123", "severity": "HIGH", "alertType": "S",
            "affectedCve": "CVE-2026-10001, CVE-2026-10002", "supportProducts": "VMware ESX",
            "notificationUrl": "https://support.broadcom.com/x"}
    data.update(changes)
    return data


def test_parse():
    advisory = vmware.parse(item())
    assert (advisory.id, advisory.severity, advisory.cves) == ("VMSA-2026-0010", "high", ["CVE-2026-10001", "CVE-2026-10002"])
    assert advisory.updated is None  # mise à jour le jour même de la publication


def test_not_a_vmsa():
    assert vmware.parse(item(title="Notice about support portal")) is None
    assert vmware.parse(item(alertType="N")) is None
