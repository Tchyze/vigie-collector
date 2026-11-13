import gzip

import httpx
import pytest

from collectors import dell_idrac
from collectors.base import Context
from tests.conftest import TODAY, fixture_client


def test_idrac_streams(ctx):
    branches = {b.branch: b for b in dell_idrac.COLLECTOR.collect(ctx).branches}
    assert list(branches) == ["7.30", "7.00", "2.86", "1.30"]
    assert {b.product for b in branches.values()} == {"dell-idrac"}
    assert {s: b.label for s, b in branches.items()} == {
        "7.30": "iDRAC9 7.30", "7.00": "iDRAC9 7.00", "2.86": "iDRAC8 2.86", "1.30": "iDRAC10 1.30",
    }

    latest = branches["7.30"].releases[0]
    assert (latest.version, latest.date) == ("7.30.65.51", "2026-10-26")
    assert latest.url == "https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=77JC4"
    assert latest.summary is None and latest.security_fix is None

    urgent = branches["7.30"].releases[1]
    assert (urgent.version, urgent.summary) == ("7.30.30.54", "Mise à jour jugée urgente par Dell.")


def make_catalog(*components: str) -> bytes:
    xml = '<?xml version="1.0" encoding="utf-16"?><Manifest>' + "".join(components) + "</Manifest>"
    return gzip.compress(xml.encode("utf-16"))


def component(name, version, device="25227", kind="FRMW"):
    return (f'<SoftwareComponent vendorVersion="{version}" releaseDate="January 05, 2026" releaseID="ABC12">'
            f'<Name><Display>{name}</Display></Name><ComponentType value="{kind}"/>'
            f'<SupportedDevices><Device componentID="{device}"/></SupportedDevices></SoftwareComponent>')


def collect(catalog_bytes, catalog_):
    client = fixture_client({dell_idrac.CATALOG: httpx.Response(200, content=catalog_bytes)})
    return dell_idrac.COLLECTOR.collect(Context(client=client, catalog=catalog_, today=TODAY)).branches


def test_generation_from_component_id(catalog):
    branches = collect(make_catalog(
        component("iDRAC 2.10.10.10", "2.10.10.10", device="113033"),  # iDRAC10 en 2.x
        component("iDRAC 6.10.80.00", "6.10.80.00"),
        component("iDRAC Service Module 5.4", "5.4.2.0", kind="APAC"),
        component("BIOS 2.3.4", "2.3.4"),
    ), catalog)
    assert {b.branch: b.label for b in branches} == {"6.10": "iDRAC9 6.10", "2.10": "iDRAC10 2.10"}
    assert branches[0].releases[0].date == "2026-01-05"


def test_unexpected_document(catalog):
    with pytest.raises(ValueError, match="catalogue inattendu"):
        collect(gzip.compress('<?xml version="1.0"?><html/>'.encode()), catalog)
