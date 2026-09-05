from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from support_doctor.context import InvestigationContext
from support_doctor.logs import bucket_counts, common_access_logs, summarize_access
from support_doctor.models import Evidence, Incident, Recommendation, RecoveryPlan, Severity, TimelineEvent
from support_doctor.util import command_output, parse_log_timestamp, safe_read_lines

from .base import DiagnosticModule

MAX_CHILDREN_RE = re.compile(r"server reached pm\.max_children setting \((\d+)\)", re.I)
POOL_RE = re.compile(r"\[pool ([^\]]+)\]")
FpmHit = tuple[Path, str, datetime | None, int, str | None]


class PhpFpmModule(DiagnosticModule):
    name = "php-fpm"

    def inspect(self, context: InvestigationContext) -> list[Incident]:
        log_paths = _php_fpm_logs(context.root)
        hits: list[FpmHit] = []
        for path, line in safe_read_lines(
            log_paths, limit=None if context.center_time else 20000, root=context.root, budget=context.scan_budget
        ):
            ts = parse_log_timestamp(line, year=context.center_time.year if context.center_time else None)
            if not context.in_window(ts):
                continue
            match = MAX_CHILDREN_RE.search(line)
            if not match:
                continue
            pool_match = POOL_RE.search(line)
            hits.append((path, line, ts, int(match.group(1)), pool_match.group(1) if pool_match else None))

        if not hits:
            return []

        first_seen = min((hit[2] for hit in hits if hit[2] is not None), default=None)
        first = next((hit for hit in hits if hit[2] == first_seen), hits[0])
        max_children = max(hit[3] for hit in hits)
        pool_name = first[4] or context.domain
        access_logs = common_access_logs(context.root)
        apache = summarize_access(access_logs["apache"], context)
        nginx = summarize_access(access_logs["nginx"], context)
        access = nginx if nginx.requests >= apache.requests else apache
        endpoint, endpoint_count = access.endpoints.most_common(1)[0] if access.endpoints else ("unknown", 0)
        client_count = len(access.clients)
        memory = _php_memory_estimate(context.root)
        safe_max = _safe_max_children(memory["available_mb"], memory["worker_mb"], memory["worker_count"])
        recommendation = _capacity_recommendation(max_children, safe_max)
        metrics: dict[str, Any] = {
            "configured_max_children": max_children,
            "capacity_events": len(hits),
            "current_max_children": max_children,
            "requests": access.requests,
            "primary_endpoint_requests": endpoint_count,
            "unique_clients": client_count,
            "reverse_proxy_detected": nginx.requests > 0 and apache.requests > 0,
        }
        if memory["worker_mb"]:
            metrics["observed_peak_php_memory_mb"] = memory["worker_mb"]
            metrics["observed_php_processes"] = memory["worker_count"]
        if memory["available_mb"]:
            metrics["available_php_budget_mb"] = memory["available_mb"]
        if safe_max is not None:
            metrics["calculated_safe_max_children"] = safe_max
            metrics["capacity_estimate"] = "heuristic_peak_rss"

        timeline = [
            TimelineEvent(
                timestamp=hit[2],
                title="PHP-FPM max_children reached",
                detail=f"Pool {hit[4] or 'unknown'} reached {hit[3]} workers",
                source=str(hit[0]),
                severity=Severity.CRITICAL,
            )
            for hit in hits
            if hit[2]
        ]
        for ts, count in bucket_counts([Path(path) for path in access.source_paths], context).items():
            timeline.append(
                TimelineEvent(
                    timestamp=ts,
                    title="Web request volume",
                    detail=f"{count} request(s) in minute bucket",
                    source="access logs",
                    severity=Severity.INFO,
                )
            )
        timeline.sort(key=lambda item: item.timestamp)

        incident = Incident(
            key="php_fpm_capacity",
            title="PHP-FPM pool reached pm.max_children",
            severity=Severity.CRITICAL,
            probable_cause="application_concurrency",
            affected_domain=context.domain or pool_name,
            primary_endpoint=endpoint,
            first_seen=first[2],
            metrics=metrics,
            evidence=[
                Evidence(str(path), line, Severity.CRITICAL, ts, {"pool": hit_pool, "max_children": size})
                for path, line, ts, size, hit_pool in hits[:20]
            ],
            timeline=timeline,
            recommendations=[
                Recommendation(
                    "Analyze PHP worker memory", "Worker sizing determines whether capacity can be increased safely."
                ),
                Recommendation(recommendation, memory["reason"], Severity.WARNING),
                Recommendation(
                    f"Inspect {endpoint} execution time", "Primary endpoint dominates correlated request volume."
                ),
                Recommendation(
                    "Check database query latency", "PHP worker exhaustion can be caused by slow downstream queries."
                ),
                Recommendation(
                    "Check for abusive clients", "High request concurrency may be concentrated in a small client set."
                ),
            ],
        )
        return [incident]

    def plan(self, context: InvestigationContext) -> list[Incident]:
        incidents = self.inspect(context)
        for incident in incidents:
            incident.plan = RecoveryPlan(
                risk=Severity.WARNING,
                proposed_actions=[
                    "Preserve PHP-FPM pool configuration",
                    "Capture per-process PHP memory during a recurrence",
                    "Estimate pm.max_children from observed peak worker RSS and memory budget",
                    "Profile the dominant endpoint before increasing concurrency",
                ],
                rollback=[
                    "Restore preserved pool configuration if any manual tuning is attempted",
                    "Restart PHP-FPM only after configuration validation",
                ],
                execute_supported=False,
                notes=["No configuration changes performed by plan mode."],
            )
        return incidents


def _php_fpm_logs(root: Path) -> list[Path]:
    candidates = [
        root / "var/log/php-fpm/error.log",
        root / "var/log/php-fpm/www-error.log",
        root / "opt/cpanel/ea-php84/root/usr/var/log/php-fpm/error.log",
        root / "opt/cpanel/ea-php83/root/usr/var/log/php-fpm/error.log",
        root / "opt/cpanel/ea-php82/root/usr/var/log/php-fpm/error.log",
        root / "usr/local/cpanel/logs/php-fpm/error.log",
    ]
    candidates.extend(root.glob("opt/cpanel/*/root/usr/var/log/php-fpm/error.log*"))
    candidates.extend(root.glob("var/log/php-fpm/error.log*"))
    return list(dict.fromkeys(candidates))


def _php_memory_estimate(root: Path) -> dict[str, Any]:
    if root.resolve() != Path("/"):
        return {
            "worker_mb": 0,
            "worker_count": 0,
            "available_mb": 0,
            "reason": "Live PHP worker memory is unavailable for an offline root; capture it on the source host before tuning capacity.",
        }
    out = command_output(["ps", "-eo", "comm=,rss="])
    rss = []
    for line in out.splitlines():
        name, _, value = line.strip().partition(" ")
        if "php-fpm" in name.lower() and value.strip().isdigit():
            rss.append(int(value.strip()) // 1024)
    worker_mb = max(rss) if rss else 0
    worker_count = len(rss)
    mem = command_output(["awk", "/MemAvailable/ {print int($2/1024)}", "/proc/meminfo"])
    try:
        available_mb = int(mem)
    except ValueError:
        available_mb = 0
    if available_mb <= 0:
        return {
            "worker_mb": worker_mb,
            "worker_count": worker_count,
            "available_mb": 0,
            "reason": "PHP worker RSS and memory budget were unavailable; do not tune capacity from this report.",
        }
    budget = int(available_mb * 0.65)
    if worker_mb <= 0:
        return {
            "worker_mb": 0,
            "worker_count": 0,
            "available_mb": budget,
            "reason": "No live PHP-FPM worker RSS sample was available; capture worker memory before tuning capacity.",
        }
    return {
        "worker_mb": worker_mb,
        "worker_count": worker_count,
        "available_mb": budget,
        "reason": "Heuristic based on peak observed PHP process RSS plus 65% of currently available memory as headroom; validate against service and database usage.",
    }


def _safe_max_children(available_mb: int, worker_mb: int, worker_count: int = 0) -> Optional[int]:
    if worker_mb <= 0:
        return None
    return max(worker_count + int(available_mb / worker_mb), 1)


def _capacity_recommendation(current: int, safe: Optional[int]) -> str:
    if safe is None:
        return "Do not change max_children until worker memory is measured"
    if safe <= current:
        return "DO NOT increase max_children"
    return f"Consider raising max_children only after validating application latency; heuristic estimate is {safe}"
