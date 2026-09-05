from __future__ import annotations

from datetime import datetime, timezone

from .context import InvestigationContext
from .health import collect_health
from .models import Evidence, Incident, Mode, Recommendation, Report, Severity
from .modules import (
    MailModule,
    MigrationModule,
    MysqlModule,
    PhpFpmModule,
    SecurityModule,
    SslModule,
    WebModule,
    WordpressModule,
)
from .modules.base import DiagnosticModule
from .platform import detect_platform

MODULES: dict[str, DiagnosticModule] = {
    "web": WebModule(),
    "apache": WebModule("apache"),
    "nginx": WebModule("nginx"),
    "php-fpm": PhpFpmModule(),
    "mysql": MysqlModule(),
    "mariadb": MysqlModule(),
    "mail": MailModule(),
    "wordpress": WordpressModule(),
    "security": SecurityModule(),
    "ssl": SslModule(),
    "migration": MigrationModule(),
}


DEFAULT_INVESTIGATION_MODULES = ["php-fpm", "web", "mysql", "mail", "wordpress", "security"]


def run_investigation(context: InvestigationContext, module_names: list[str] | None = None) -> Report:
    platform = detect_platform(context.root)
    health = collect_health(context.root)
    incidents = []
    for module_name in module_names or DEFAULT_INVESTIGATION_MODULES:
        module = MODULES[module_name]
        incidents.extend(_run_module(module, context))
    incidents.sort(key=lambda item: _severity_rank(item.severity), reverse=True)
    return Report(
        platform=platform,
        health=health,
        incidents=incidents,
        generated_at=datetime.now(timezone.utc),
        mode=context.mode,
        collection=context.collection_summary(),
    )


def run_single_module(module_name: str, context: InvestigationContext) -> Report:
    platform = detect_platform(context.root)
    health = collect_health(context.root)
    module = MODULES[module_name]
    incidents = _run_module(module, context)
    incidents.sort(key=lambda item: _severity_rank(item.severity), reverse=True)
    return Report(
        platform=platform,
        health=health,
        incidents=incidents,
        generated_at=datetime.now(timezone.utc),
        mode=context.mode,
        collection=context.collection_summary(),
    )


def _run_module(module: DiagnosticModule, context: InvestigationContext) -> list[Incident]:
    try:
        if context.mode == Mode.PLAN:
            return module.plan(context)
        if context.mode == Mode.EXECUTE:
            return module.execute(context)
        return module.inspect(context)
    except Exception as exc:  # A diagnostic must report partial failure, not abort the run.
        return [
            Incident(
                key=f"{module.name.replace('-', '_')}_diagnostic_failure",
                title=f"{module.name} diagnostic failed",
                severity=Severity.WARNING,
                probable_cause="diagnostic_collection_failure",
                metrics={"error_type": type(exc).__name__},
                evidence=[Evidence(module.name, f"{type(exc).__name__}: {exc}", Severity.WARNING)],
                recommendations=[
                    Recommendation("Retry with narrower scope", "The module could not collect complete evidence.")
                ],
            )
        ]


def _severity_rank(value: Severity) -> int:
    return {"CRITICAL": 4, "WARNING": 3, "INFO": 2, "OK": 1, "UNKNOWN": 0}.get(value.value, 0)
