from __future__ import annotations

from support_doctor.context import InvestigationContext
from support_doctor.models import Evidence, Incident, Recommendation, Severity
from support_doctor.util import parse_log_timestamp, safe_read_lines

from .base import DiagnosticModule


class MailModule(DiagnosticModule):
    name = "mail"

    def inspect(self, context: InvestigationContext) -> list[Incident]:
        counters = {"auth_failures": 0, "spam_rejections": 0, "queue_warnings": 0}
        evidence: list[Evidence] = []
        for path in [
            context.root / "var/log/exim_mainlog",
            context.root / "var/log/maillog",
            context.root / "var/log/mail.log",
        ]:
            for source, line in safe_read_lines([path], limit=None if context.center_time else 20000):
                ts = parse_log_timestamp(line, year=context.center_time.year if context.center_time else None)
                if not context.in_window(ts):
                    continue
                lower = line.lower()
                key = None
                if "authentication failed" in lower or "auth failed" in lower:
                    key = "auth_failures"
                elif "spam" in lower or "blacklist" in lower:
                    key = "spam_rejections"
                elif "queue" in lower and ("frozen" in lower or "retry" in lower):
                    key = "queue_warnings"
                if key:
                    counters[key] += 1
                    if len(evidence) < 30:
                        evidence.append(Evidence(str(source), line, Severity.WARNING, ts, {"category": key}))
        if not any(counters.values()):
            return []
        return [
            Incident(
                key="mail_delivery_degradation",
                title="Mail delivery or authentication issue",
                severity=Severity.WARNING,
                probable_cause="mail_log_anomalies",
                metrics=counters,
                evidence=evidence,
                recommendations=[
                    Recommendation("Inspect mail queue", "Queue growth can confirm delivery impact."),
                    Recommendation(
                        "Check authentication source IPs",
                        "Repeated failures may indicate compromised credentials or brute force.",
                    ),
                    Recommendation(
                        "Review DNSBL and SPF/DKIM/DMARC status", "Rejections may be reputation or DNS related."
                    ),
                ],
            )
        ]
