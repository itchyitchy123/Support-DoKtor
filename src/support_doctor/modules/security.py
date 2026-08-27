from __future__ import annotations

from support_doctor.context import InvestigationContext
from support_doctor.models import Evidence, Incident, Recommendation, Severity
from support_doctor.util import parse_log_timestamp, safe_read_lines

from .base import DiagnosticModule


class SecurityModule(DiagnosticModule):
    name = "security"

    def inspect(self, context: InvestigationContext) -> list[Incident]:
        evidence = []
        for path in [
            context.root / "var/log/secure",
            context.root / "var/log/messages",
            context.root / "var/log/lfd.log",
            context.root / "var/log/fail2ban.log",
        ]:
            for source, line in safe_read_lines([path], limit=None if context.center_time else 20000):
                ts = parse_log_timestamp(line, year=context.center_time.year if context.center_time else None)
                if not context.in_window(ts):
                    continue
                lower = line.lower()
                if any(term in lower for term in ("failed password", "mod_security", "blocked", "ban ", "suspicious")):
                    if len(evidence) < 40:
                        evidence.append(Evidence(str(source), line, Severity.WARNING, ts))
        if not evidence:
            return []
        return [
            Incident(
                key="security_activity",
                title="Security controls observed activity",
                severity=Severity.WARNING,
                probable_cause="security_log_anomalies",
                evidence=evidence,
                recommendations=[
                    Recommendation("Group events by source IP", "Concentration can distinguish attack traffic from normal user errors."),
                    Recommendation("Check ModSecurity and firewall rule IDs", "False positives require rule-specific evidence."),
                ],
            )
        ]
