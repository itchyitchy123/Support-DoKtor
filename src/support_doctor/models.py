from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterable


class Severity(str, Enum):
    OK = "OK"
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Mode(str, Enum):
    INSPECT = "inspect"
    PLAN = "plan"
    EXECUTE = "execute"


@dataclass
class Evidence:
    source: str
    detail: str
    severity: Severity = Severity.INFO
    timestamp: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TimelineEvent:
    timestamp: datetime
    title: str
    detail: str
    source: str
    severity: Severity = Severity.INFO


@dataclass
class Recommendation:
    action: str
    reason: str
    risk: Severity = Severity.INFO


@dataclass
class RecoveryPlan:
    risk: Severity
    proposed_actions: list[str]
    rollback: list[str]
    execute_supported: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class Incident:
    key: str
    title: str
    severity: Severity
    probable_cause: str
    affected_domain: str | None = None
    primary_endpoint: str | None = None
    first_seen: datetime | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    plan: RecoveryPlan | None = None

    def sanitized_json(self, platform: dict[str, str]) -> dict[str, Any]:
        return {
            "incident": self.key,
            "severity": self.severity.value.lower(),
            "platform": platform.get("panel") or platform.get("os") or "unknown",
            "web_stack": platform.get("web_stack", "unknown"),
            "php": platform.get("php", "unknown"),
            "database": platform.get("database", "unknown"),
            "cause": self.probable_cause,
            # Domains are useful in the terminal report but are hostnames in
            # practice. Keep them out of fleet analytics by design.
            "domain_scoped": self.affected_domain is not None,
            "primary_endpoint": self.primary_endpoint,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "metrics": self.metrics,
            "recommendations": [r.action for r in self.recommendations],
        }


@dataclass
class HealthCheck:
    name: str
    status: Severity
    detail: str


@dataclass
class Report:
    platform: dict[str, str]
    health: list[HealthCheck]
    incidents: list[Incident]
    generated_at: datetime
    mode: Mode = Mode.INSPECT
    collection: dict[str, Any] = field(default_factory=dict)

    def strongest_status(self, names: Iterable[str]) -> Severity:
        rank = {
            Severity.UNKNOWN: 0,
            Severity.OK: 1,
            Severity.INFO: 2,
            Severity.WARNING: 3,
            Severity.CRITICAL: 4,
        }
        result = Severity.UNKNOWN
        wanted = set(names)
        for check in self.health:
            if check.name in wanted and rank[check.status] > rank[result]:
                result = check.status
        return result
