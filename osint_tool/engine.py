"""Core OSINT engine – orchestrates module execution."""

from __future__ import annotations

import logging
from typing import Any

from osint_tool.models import OsintResult
from osint_tool.modules import MODULE_REGISTRY, BaseModule
from osint_tool.utils.validators import detect_target_type

logger = logging.getLogger(__name__)


class OsintEngine:
    """High-level facade for running OSINT investigations.

    Example::

        engine = OsintEngine()
        results = engine.run(targets=["johndoe@example.com"])
    """

    def __init__(
        self,
        module_kwargs: dict[str, dict[str, Any]] | None = None,
        proxies: dict[str, str] | None = None,
        timeout: int = 10,
    ) -> None:
        """
        Args:
            module_kwargs: Per-module keyword arguments passed to each module
                           constructor, e.g. ``{"email": {"hibp_api_key": "abc"}}``.
            proxies:       Proxy dict forwarded to all HTTP sessions
                           (e.g. ``{"https": "socks5://127.0.0.1:9050"}``).
            timeout:       Default HTTP timeout in seconds.
        """
        self._module_kwargs = module_kwargs or {}
        self._proxies = proxies
        self._timeout = timeout

    # ------------------------------------------------------------------

    def run(
        self,
        targets: list[str],
        modules: list[str] | None = None,
    ) -> list[OsintResult]:
        """Run OSINT investigation against each target.

        Args:
            targets: List of targets (usernames, emails, IPs, domains, phones).
            modules: Module names to execute; *None* means auto-detect.

        Returns:
            List of :class:`~osint_tool.models.OsintResult` objects.
        """
        results: list[OsintResult] = []

        for target in targets:
            target_type = detect_target_type(target)
            active_modules = self._select_modules(target_type, modules)

            if not active_modules:
                logger.warning("No applicable modules for target '%s' (type: %s)", target, target_type)
                continue

            for module_name in active_modules:
                module = self._build_module(module_name)
                if module is None:
                    continue
                logger.info("Running module '%s' on target '%s'", module_name, target)
                try:
                    result = module.run(target)
                except Exception as exc:  # noqa: BLE001
                    logger.error("Module '%s' raised an exception for '%s': %s", module_name, target, exc)
                    result = OsintResult(target=target, module=module_name)
                    result.errors.append(str(exc))
                results.append(result)

        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _select_modules(self, target_type: str, requested: list[str] | None) -> list[str]:
        if requested:
            return [m for m in requested if m in MODULE_REGISTRY]

        # Auto-select based on target type
        return [
            name
            for name, cls in MODULE_REGISTRY.items()
            if target_type in cls.supported_target_types
        ]

    def _build_module(self, name: str) -> BaseModule | None:
        cls = MODULE_REGISTRY.get(name)
        if cls is None:
            logger.error("Unknown module: '%s'", name)
            return None
        kwargs: dict[str, Any] = {"timeout": self._timeout}
        if self._proxies:
            kwargs["proxies"] = self._proxies
        kwargs.update(self._module_kwargs.get(name, {}))
        return cls(**kwargs)  # type: ignore[arg-type]
