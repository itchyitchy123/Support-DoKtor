from __future__ import annotations

import os
from pathlib import Path

from support_doctor.context import InvestigationContext
from support_doctor.logs import common_access_logs, summarize_access
from support_doctor.models import Evidence, Incident, Recommendation, Severity

from .base import DiagnosticModule

MAX_WORDPRESS_DIRECTORIES = 10_000
MAX_WORDPRESS_ROOTS = 100


class WordpressModule(DiagnosticModule):
    name = "wordpress"

    def inspect(self, context: InvestigationContext) -> list[Incident]:
        logs = common_access_logs(context.root)
        summary = summarize_access([*logs["apache"], *logs["nginx"]], context)
        wp_hits: dict[str, int] = {
            endpoint: count
            for endpoint, count in summary.endpoints.items()
            if "wp-admin/admin-ajax.php" in endpoint or "xmlrpc.php" in endpoint or "wp-cron.php" in endpoint
        }
        roots = _wordpress_roots(context.root)
        if not wp_hits and not roots:
            return []
        severity = Severity.WARNING if wp_hits else Severity.INFO
        return [
            Incident(
                key="wordpress_activity",
                title="WordPress activity profile",
                severity=severity,
                probable_cause="wordpress_hot_endpoint" if wp_hits else "wordpress_detected",
                affected_domain=context.domain,
                primary_endpoint=max(wp_hits, key=lambda endpoint: wp_hits[endpoint]) if wp_hits else None,
                # Reports may be shipped to fleet analytics. Counts preserve
                # diagnostic value without exposing customer filesystem paths.
                metrics={"wordpress_root_count": len(roots), "hot_endpoints": wp_hits},
                evidence=[Evidence("filesystem", f"Detected {len(roots)} WordPress root(s)", Severity.INFO)],
                recommendations=[
                    Recommendation(
                        "Profile hot WordPress endpoints",
                        "admin-ajax, xmlrpc, and wp-cron often explain PHP concurrency incidents.",
                    ),
                    Recommendation(
                        "Review plugin/theme errors and slow queries",
                        "Application code is often the bottleneck behind worker exhaustion.",
                    ),
                ],
            )
        ]


def _wordpress_roots(root: Path) -> list[Path]:
    bases = [root / "home", root / "var/www", root / "usr/local/apache/htdocs"]
    results: list[Path] = []
    visited = 0
    for base in bases:
        for current, directories, files in os.walk(base, topdown=True, onerror=lambda _error: None, followlinks=False):
            visited += 1
            directories.sort()
            if visited >= MAX_WORDPRESS_DIRECTORIES:
                directories.clear()
            if "wp-config.php" in files:
                results.append(Path(current))
                if len(results) >= MAX_WORDPRESS_ROOTS:
                    return results
            if visited >= MAX_WORDPRESS_DIRECTORIES:
                return results
    return results
