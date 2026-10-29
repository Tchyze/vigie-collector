import datetime as dt

import pytest

from vigie.status import add_months, compute_status
from vigie.versions import sort_versions

TODAY = dt.date(2026, 10, 29)


@pytest.mark.parametrize("trigger, declared, expected", [
    ("2026-10-29", False, "eol"),
    ("2020-01-01", False, "eol"),
    ("2026-10-30", False, "eol_soon"),
    ("2027-04-29", False, "eol_soon"),
    ("2027-04-30", False, "active"),
    (None, False, "active"),
    (None, True, "eol"),
    ("2030-01-01", True, "active"),  # une date future l'emporte sur l'indicateur
])
def test_status(trigger, declared, expected):
    assert compute_status(trigger, declared, TODAY, 6) == expected


def test_threshold_is_configurable():
    assert compute_status("2027-01-15", False, TODAY, 1) == "active"
    assert compute_status("2027-01-15", False, TODAY, 3) == "eol_soon"


def test_add_months_clamps_day():
    assert add_months(dt.date(2026, 8, 31), 6) == dt.date(2027, 2, 28)


@pytest.mark.parametrize("versions, expected", [
    (["7.4.9", "7.4.13", "7.4.10"], ["7.4.13", "7.4.10", "7.4.9"]),
    (["12.2.4", "12.2.4-h1", "12.2.3-h9"], ["12.2.4-h1", "12.2.4", "12.2.3-h9"]),
    (["9.9p2", "10.0p1", "10.10p1"], ["10.10p1", "10.0p1", "9.9p2"]),
    (["2016", "2025", "2012-r2", "2012"], ["2025", "2016", "2012-r2", "2012"]),
])
def test_sort_versions(versions, expected):
    assert sort_versions(versions) == expected
