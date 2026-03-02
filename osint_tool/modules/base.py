"""Base class for all OSINT modules."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import requests

from osint_tool.models import OsintResult
from osint_tool.utils.http import RateLimiter, build_session

logger = logging.getLogger(__name__)


class BaseModule(ABC):
    """Abstract base for every OSINT module.

    Subclasses must implement :meth:`run` and set a unique :attr:`name`.
    """

    name: str = ""
    description: str = ""
    supported_target_types: list[str] = []

    def __init__(
        self,
        rate_limit: float = 5.0,
        timeout: int = 10,
        proxies: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.session: requests.Session = build_session()
        if proxies:
            self.session.proxies.update(proxies)
        self._rate_limiter = RateLimiter(calls_per_second=rate_limit)

    @abstractmethod
    def run(self, target: str) -> OsintResult:
        """Execute intelligence gathering for *target*.

        Returns an :class:`~osint_tool.models.OsintResult` with all
        discovered findings.
        """

    def _new_result(self, target: str) -> OsintResult:
        return OsintResult(target=target, module=self.name)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
