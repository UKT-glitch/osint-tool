"""Shared data models used across all modules."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FindingLevel(str, Enum):
    """Severity / confidence level for a single finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single piece of intelligence discovered about a target."""

    module: str
    title: str
    description: str
    level: FindingLevel = FindingLevel.INFO
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "title": self.title,
            "description": self.description,
            "level": self.level.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class OsintResult:
    """Aggregated result for a single target."""

    target: str
    module: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def add_finding(
        self,
        title: str,
        description: str,
        level: FindingLevel = FindingLevel.INFO,
        data: dict[str, Any] | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                module=self.module,
                title=title,
                description=description,
                level=level,
                data=data or {},
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "raw": self.raw,
        }
