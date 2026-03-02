"""HTTP session helpers, rate-limiting, and retry logic."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT: int = 10  # seconds
DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (compatible; osint-tool/1.0; +https://github.com/UKT-glitch/osint-tool)"
)


def build_session(
    retries: int = 3,
    backoff_factor: float = 0.5,
    status_forcelist: tuple[int, ...] = (429, 500, 502, 503, 504),
    headers: dict[str, str] | None = None,
) -> requests.Session:
    """Return a :class:`requests.Session` pre-configured with retry logic."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    default_headers: dict[str, str] = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        default_headers.update(headers)
    session.headers.update(default_headers)
    return session


class RateLimiter:
    """Simple token-bucket rate-limiter (calls per second)."""

    def __init__(self, calls_per_second: float = 5.0) -> None:
        self._min_interval = 1.0 / calls_per_second
        self._last_call: float = 0.0

    def wait(self) -> None:
        """Block until the next call is permitted."""
        elapsed = time.monotonic() - self._last_call
        wait_time = self._min_interval - elapsed
        if wait_time > 0:
            time.sleep(wait_time)
        self._last_call = time.monotonic()


def safe_get(
    session: requests.Session,
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    **kwargs: Any,
) -> requests.Response | None:
    """Perform a GET request and return the response, or *None* on error."""
    try:
        response = session.get(url, timeout=timeout, **kwargs)
        return response
    except requests.RequestException as exc:
        logger.debug("GET %s failed: %s", url, exc)
        return None
