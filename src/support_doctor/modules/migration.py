from __future__ import annotations

from support_doctor.context import InvestigationContext
from support_doctor.models import Evidence, Incident, Recommendation, RecoveryPlan, Severity

from .base import DiagnosticModule


class MigrationModule(DiagnosticModule):
    name = "migration"

    def inspect(self, context: InvestigationContext) -> list[Incident]:
        paths = {
            "home": context.root / "home",
            "mysql": context.root / "var/lib/mysql",
            "apache_conf": context.root / "etc/httpd/conf",
            "nginx_conf": context.root / "etc/nginx",
            "mail": context.root / "var/mail",
        }
        present = {name: path.exists() for name, path in paths.items()}
        return [
            Incident(
                key="migration_readiness",
                title="Migration readiness snapshot",
                severity=Severity.INFO,
                probable_cause="operator_requested_assessment",
                metrics=present,
                evidence=[
                    Evidence("filesystem", f"{name}: {'present' if ok else 'missing'}") for name, ok in present.items()
                ],
                recommendations=[
                    Recommendation(
                        "Inventory domains, databases, mailboxes, DNS, and SSL material",
                        "Migration failures usually come from missing service inventory.",
                    ),
                    Recommendation(
                        "Validate source backups before cutover", "Rollback quality depends on backup completeness."
                    ),
                ],
            )
        ]

    def plan(self, context: InvestigationContext) -> list[Incident]:
        incidents = self.inspect(context)
        for incident in incidents:
            incident.plan = RecoveryPlan(
                risk=Severity.WARNING,
                proposed_actions=[
                    "Freeze content or schedule delta sync window",
                    "Back up home directories, databases, mail stores, DNS zones, and SSL certificates",
                    "Restore to target and validate service versions",
                    "Lower DNS TTL before final cutover",
                    "Run post-migration web, mail, DNS, and SSL checks",
                ],
                rollback=[
                    "Keep source server unchanged until validation completes",
                    "Restore DNS to source addresses if target validation fails",
                ],
                execute_supported=False,
            )
        return incidents
