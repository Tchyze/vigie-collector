import pytest

from vigie import validate


@pytest.mark.parametrize("kind", sorted(validate.SCHEMAS))
def test_schemas_are_valid(kind):
    validate.validator(kind)


def make_branch(**changes):
    branch = {
        "id": "debian-12",
        "product": "debian",
        "vendor": "Debian",
        "category": "os",
        "branch": "12",
        "label": "12 (Bookworm)",
        "lts": False,
        "release_date": "2023-06-10",
        "status": "active",
        "latest_version": "12.15",
        "latest_release_date": "2026-07-11",
        "eol": {
            "end_of_active_support": None,
            "end_of_security_support": "2026-07-11",
            "end_of_life": "2028-06-30",
            "end_of_extended_support": "2033-06-30",
            "trigger": "end_of_life",
            "trigger_date": "2028-06-30",
            "declared_eol": False,
            "labels": {"end_of_life": "Debian LTS"},
            "source_url": "https://endoflife.date/debian",
        },
        "releases": [
            {"version": "12.15", "date": "2026-07-11", "security_fix": None, "summary": None,
             "url": "https://www.debian.org/News/2026/2026051602"},
        ],
        "sources": ["endoflife"],
    }
    branch.update(changes)
    return branch


def product_doc(branch):
    return {
        "schema_version": 1,
        "generated_at": "2026-10-29T12:00:00Z",
        "product": "debian",
        "label": "Debian",
        "vendor": "Debian",
        "category": "os",
        "branches": [branch],
    }


def test_valid_product_document():
    assert validate.errors("product", product_doc(make_branch())) == []


@pytest.mark.parametrize("changes", [
    {"status": "unknown"},
    {"category": "router"},
    {"release_date": "10/06/2023"},
    {"id": "Debian 12"},
])
def test_invalid_branch_is_rejected(changes):
    assert validate.errors("product", product_doc(make_branch(**changes)))


def test_summary_length_is_bounded():
    branch = make_branch()
    branch["releases"][0]["summary"] = "x" * 301
    assert validate.errors("product", product_doc(branch))


def test_wrong_schema_version_is_rejected():
    doc = product_doc(make_branch())
    doc["schema_version"] = 2
    assert validate.errors("product", doc)


def test_advisory_document():
    doc = {
        "schema_version": 1,
        "generated_at": "2026-10-29T12:00:00Z",
        "retention_days": 365,
        "advisories": [{
            "id": "DSA-6592-1", "source": "debian", "vendor": "Debian",
            "title": "DSA-6592-1 chromium - security update",
            "published": "2026-10-28T00:00:00Z", "updated": None, "severity": None, "cvss": None,
            "cves": ["CVE-2026-118304"], "url": "https://security-tracker.debian.org/tracker/DSA-6592-1",
            "summary": None, "affected": ["debian-13"], "attribution": None,
        }],
    }
    assert validate.errors("advisories", doc) == []
    doc["advisories"][0]["cves"] = ["2026-118304"]
    assert validate.errors("advisories", doc)
