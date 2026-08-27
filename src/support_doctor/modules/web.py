from __future__ import annotations

from support_doctor.context import InvestigationContext
from support_doctor.logs import common_access_logs, summarize_access
from support_doctor.models import Evidence, Incident, Recommendation, Severity

from .base import DiagnosticModule


class WebModule(DiagnosticModule):
    name = "web"

    def inspect(self, context: InvestigationContext) -> list[Incident]:
        logs = common_access_logs(context.root)
        incidents = []
        for server, paths in logs.items():
            summary = summarize_access(paths, context)
            if summary.requests == 0:
                continue
            endpoint, count = summary.endpoints.most_common(1)[0]
            incidents.append(
                Incident(
                    key=f"{server}_traffic_profile",
                    title=f"{server.title()} request profile",
                    severity=Severity.INFO,
                    probable_cause="traffic_profile",
                    affected_domain=context.domain,
                    primary_endpoint=endpoint,
                    first_seen=summary.first_seen,
                    metrics={
                        "requests": summary.requests,
                        "primary_endpoint_requests": count,
                        "unique_clients": len(summary.clients),
                        "top_client_request_counts": [count for _client, count in summary.clients.most_common(5)],
                    },
                    evidence=[
                        Evidence(
                            server,
                            f"Analyzed {summary.requests} request(s) from {len(summary.source_paths)} log path(s)",
                        )
                    ],
                    recommendations=[
                        Recommendation(
                            "Review top endpoints and client concentration",
                            "Traffic shape can reveal abusive clients or slow application paths.",
                        )
                    ],
                )
            )
        return incidents
