import datetime as dt
from pathlib import Path

import httpx
import pytest
import yaml

from collectors.base import Context
from vigie.catalog import load_catalog
from vigie.http import HttpClient

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
TODAY = dt.date(2026, 10, 29)


class FixtureTransport(httpx.BaseTransport):
    """Rejoue les réponses enregistrées ; toute autre URL répond 404."""

    def __init__(self, overrides: dict[str, httpx.Response] | None = None):
        manifest = yaml.safe_load((FIXTURES / "manifest.yaml").read_text(encoding="utf-8"))
        self.files = {entry["url"]: FIXTURES / entry["file"] for entry in manifest}
        self.overrides = overrides or {}
        self.requested: list[str] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requested.append(url)
        if url in self.overrides:
            return self.overrides[url]
        if url in self.files:
            return httpx.Response(200, content=self.files[url].read_bytes())
        return httpx.Response(404, content=b"absent des fixtures")


def fixture_client(overrides=None) -> HttpClient:
    return HttpClient(min_interval=0, retries=0, github_token="", transport=FixtureTransport(overrides))


@pytest.fixture
def client():
    return fixture_client()


@pytest.fixture
def catalog():
    return load_catalog(ROOT / "products.yaml")


@pytest.fixture
def ctx(client, catalog):
    return Context(client=client, catalog=catalog, today=TODAY)
