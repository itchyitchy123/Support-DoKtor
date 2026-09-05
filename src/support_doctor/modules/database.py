from __future__ import annotations

from pathlib import Path

from support_doctor.context import InvestigationContext
from support_doctor.models import Evidence, Incident, Recommendation, RecoveryPlan, Severity
from support_doctor.util import parse_log_timestamp, safe_read_lines

from .base import DiagnosticModule

ERROR_PATTERNS = {
    "database_crash": ("crash", "segfault", "signal", "aborting"),
    "innodb_corruption": ("innodb: corruption", "page corruption", "innodb_force_recovery"),
    "database_performance": ("too many connections", "lock wait timeout", "slow query"),
}


class MysqlModule(DiagnosticModule):
    name = "mysql"

    def inspect(self, context: InvestigationContext) -> list[Incident]:
        evidence_by_key: dict[str, list[Evidence]] = {}
        for path, line in safe_read_lines(
            _mysql_logs(context.root),
            limit=None if context.center_time else 20000,
            root=context.root,
            budget=context.scan_budget,
        ):
            ts = parse_log_timestamp(line, year=context.center_time.year if context.center_time else None)
            if not context.in_window(ts):
                continue
            lower = line.lower()
            for key, needles in ERROR_PATTERNS.items():
                if any(needle in lower for needle in needles):
                    evidence_by_key.setdefault(key, []).append(Evidence(str(path), line, Severity.WARNING, ts))

        incidents = []
        for key, evidence in evidence_by_key.items():
            severity = Severity.CRITICAL if key in {"database_crash", "innodb_corruption"} else Severity.WARNING
            incidents.append(
                Incident(
                    key=key,
                    title=key.replace("_", " ").title(),
                    severity=severity,
                    probable_cause=key,
                    first_seen=min((item.timestamp for item in evidence if item.timestamp), default=None),
                    evidence=evidence[:25],
                    recommendations=[
                        Recommendation(
                            "Preserve database logs and configuration",
                            "Recovery decisions need the original failure evidence.",
                        ),
                        Recommendation(
                            "Check backups before repair attempts",
                            "Physical and logical backup state controls recovery risk.",
                        ),
                    ],
                )
            )
        return incidents

    def plan(self, context: InvestigationContext) -> list[Incident]:
        incidents = self.inspect(context)
        if not incidents:
            incidents = [
                Incident(
                    key="mysql_recovery_plan",
                    title="MySQL/MariaDB recovery plan",
                    severity=Severity.INFO,
                    probable_cause="operator_requested_plan",
                )
            ]
        for incident in incidents:
            incident.plan = RecoveryPlan(
                risk=Severity.CRITICAL,
                proposed_actions=[
                    "Stop MariaDB only during an approved maintenance window",
                    "Preserve current configuration and error logs",
                    "Create a physical backup of the datadir before recovery attempts",
                    "Enable innodb_force_recovery=1 only if corruption prevents startup",
                    "Attempt logical extraction into a clean instance",
                ],
                rollback=[
                    "Remove temporary recovery configuration",
                    "Restore original configuration",
                    "Restart MariaDB and validate application connectivity",
                ],
                execute_supported=False,
                notes=["Database execute mode is intentionally disabled in this version."],
            )
        return incidents


def _mysql_logs(root: Path) -> list[Path]:
    paths = [
        root / "var/log/mysqld.log",
        root / "var/log/mysql/error.log",
        root / "var/log/mariadb/mariadb.log",
    ]
    paths.extend(root.glob("var/lib/mysql/*.err*"))
    return list(dict.fromkeys(paths))
