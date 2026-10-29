"""Client HTTP poli : User-Agent explicite, timeouts, pause entre deux requêtes vers un même hôte."""

import logging
import os
import time
from urllib.parse import urlsplit

import httpx

from vigie import __version__

USER_AGENT = f"Vigie-collector/{__version__} (+https://github.com/Tchyze/vigie-collector)"
log = logging.getLogger(__name__)


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 30.0,
        min_interval: float = 1.0,
        retries: int = 1,
        retry_delay: float = 5.0,
        github_token: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        self._client = httpx.Client(
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            follow_redirects=True,
            transport=transport,
        )
        self.min_interval = min_interval
        self.retries = retries
        self.retry_delay = retry_delay
        self.github_token = github_token if github_token is not None else os.environ.get("GITHUB_TOKEN")
        self._last_request: dict[str, float] = {}

    def get(self, url: str, *, headers: dict | None = None) -> httpx.Response:
        host = urlsplit(url).hostname or ""
        headers = dict(headers or {})
        if host == "api.github.com" and self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        for attempt in range(self.retries + 1):
            self._wait(host)
            try:
                response = self._client.get(url, headers=headers)
                if response.status_code < 500 or attempt == self.retries:
                    response.raise_for_status()
                    return response
                log.warning("%s : HTTP %s, nouvel essai", url, response.status_code)
            except httpx.TransportError as exc:
                if attempt == self.retries:
                    raise
                log.warning("%s : %s, nouvel essai", url, exc)
            time.sleep(self.retry_delay)
        raise AssertionError("inaccessible")

    def text(self, url: str, **kwargs) -> str:
        return self.get(url, **kwargs).text

    def json(self, url: str, **kwargs):
        return self.get(url, **kwargs).json()

    def _wait(self, host: str) -> None:
        last = self._last_request.get(host)
        if last is not None:
            delay = self.min_interval - (time.monotonic() - last)
            if delay > 0:
                time.sleep(delay)
        self._last_request[host] = time.monotonic()

    def close(self) -> None:
        self._client.close()
