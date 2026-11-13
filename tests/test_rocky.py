from collectors import rocky


def test_advisories(ctx):
    advisories = {a.id: a for a in rocky.COLLECTOR.collect(ctx).advisories}
    assert len(advisories) == 25

    edk2 = advisories["RLSA-2026:96240"]
    assert edk2.title == "Critical: edk2 security update"
    assert edk2.published == "2026-11-10T12:09:45Z"
    assert edk2.url == "https://errata.rockylinux.org/RLSA-2026:96240"
    assert (edk2.severity, edk2.cvss) == ("critical", 8.8)
    assert edk2.cves == ["CVE-2026-97631"]
    assert edk2.affected == ["rocky-linux-10"]
    assert edk2.summary == "An update is available for edk2. This update affects Rocky Linux 10."
    assert all(a.affected for a in advisories.values())


def item(**changes):
    data = {
        "name": "RLSA-2026:1", "synopsis": "Critical: kernel security update", "severity": "Critical",
        "published_at": "2026-11-01T10:00:00.123456Z", "topic": "An update is available for kernel.",
        "affected_products": [
            {"variant": "Rocky Linux", "major_version": 9, "name": "Rocky Linux 9 x86_64"},
            {"variant": "Rocky Linux", "major_version": 9, "name": "Rocky Linux 9 aarch64"},
            {"variant": "Rocky Linux", "major_version": 8, "name": "Rocky Linux 8 x86_64"},
        ],
        "cves": [{"cve": "CVE-2026-1", "cvss3_base_score": "9.8"}, {"cve": "CVE-2026-2", "cvss3_base_score": ""}],
    }
    data.update(changes)
    return data


def test_parse():
    advisory = rocky.parse(item())
    assert advisory.affected == ["rocky-linux-9", "rocky-linux-8"]
    assert advisory.published == "2026-11-01T10:00:00Z"
    assert (advisory.cvss, advisory.cves) == (9.8, ["CVE-2026-1", "CVE-2026-2"])


def test_sig_advisory_is_ignored():
    sig = item(name="RXSA-2026:1", affected_products=[{"variant": "Rocky Linux SIG Cloud", "major_version": 8}])
    assert rocky.parse(sig) is None
