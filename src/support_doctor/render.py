from __future__ import annotations

import json
import re
from datetime import datetime

from .models import Incident, Report


def render_text(report: Report) -> str:
    lines = ["HOSTING INCIDENT REPORT", "========================================", ""]
    lines.extend(_platform(report))
    lines.append("")
    lines.extend(_health(report))
    lines.append("")
    if report.incidents:
        for index, incident in enumerate(report.incidents):
            if index:
                lines.append("")
            lines.extend(_incident(incident))
    else:
        lines.extend(["Detected incident:", "", "  No incidents detected from available evidence."])
    lines.append("")
    if report.mode.value != "execute":
        lines.append("No configuration changes performed.")
    elif not any(incident.plan and incident.plan.execute_supported for incident in report.incidents):
        lines.append("No supported configuration changes performed.")
    return "\n".join(lines)


def render_case_summary(report: Report) -> str:
    if not report.incidents:
        return "No incident evidence was detected from the available logs and system state."
    incident = report.incidents[0]
    bits = []
    if incident.title:
        bits.append(f"Investigation found {incident.title.lower()}")
    if incident.first_seen:
        bits.append(f"at approximately {_fmt_time(incident.first_seen)}")
    sentence = " ".join(bits).strip() + "."
    details = []
    if "configured_max_children" in incident.metrics:
        details.append(
            f"The pool reported reaching its configured ceiling of {incident.metrics['configured_max_children']} workers"
        )
    if incident.primary_endpoint:
        if details:
            details[-1] = f"{details[-1]} during increased requests to {incident.primary_endpoint}"
        else:
            details.append(f"Increased requests to {incident.primary_endpoint} were observed")
    if "calculated_safe_max_children" in incident.metrics:
        safe = incident.metrics["calculated_safe_max_children"]
        current = incident.metrics.get("current_max_children")
        if current and safe <= current:
            details.append(
                "Increasing PHP-FPM capacity is not currently recommended based on the calculated memory budget"
            )
    if details:
        sentence += " " + ". ".join(details) + "."
    if incident.recommendations:
        sentence += (
            " Further investigation should focus on "
            + ", ".join(r.action.lower() for r in incident.recommendations[:3])
            + "."
        )
    return sentence


def render_json(report: Report) -> str:
    platform = {key: value for key, value in report.platform.items() if key != "host"}
    payload = {
        "generated_at": report.generated_at.isoformat(),
        "mode": report.mode.value,
        "platform": platform,
        "health": [{"name": h.name, "status": h.status.value, "detail": h.detail} for h in report.health],
        "incidents": [incident.sanitized_json(report.platform) for incident in report.incidents],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _platform(report: Report) -> list[str]:
    p = report.platform
    return [
        "Platform:",
        f"  OS:          {_display(p.get('os', 'unknown'))}",
        f"  Panel:       {_display(p.get('panel', 'unknown'))}",
        f"  Web:         {_display(p.get('web_stack', 'unknown'))}",
        f"  Database:    {_display(p.get('database', 'unknown'))}",
        f"  PHP:         {_display(p.get('php', 'unknown'))}",
    ]


def _health(report: Report) -> list[str]:
    lines = ["Health:"]
    for item in report.health:
        lines.append(f"  {item.name + ':':<12}{item.status.value:<9} {_display(item.detail)}")
    return lines


def _incident(incident: Incident) -> list[str]:
    lines = ["Detected incident:", "", f"  {_display(incident.title)}", ""]
    if incident.affected_domain:
        lines.append(f"Domain: {_display(incident.affected_domain)}")
    if incident.primary_endpoint:
        lines.extend(["", "Primary endpoint:", f"  {_display(incident.primary_endpoint)}"])
    if incident.first_seen:
        lines.append(f"First occurrence: {_fmt_time(incident.first_seen)}")
    lines.append("")
    lines.append("Metrics:")
    for key, value in incident.metrics.items():
        lines.append(f"  {key.replace('_', ' ').title() + ':':<34}{_display(value)}")
    if incident.timeline:
        lines.append("")
        lines.append("Incident timeline:")
        for event in incident.timeline[:20]:
            lines.append(f"  {_fmt_time(event.timestamp)}  {_display(event.title)}: {_display(event.detail)}")
    if incident.evidence:
        lines.append("")
        lines.append("Evidence:")
        for item in incident.evidence[:8]:
            prefix = _fmt_time(item.timestamp) + " " if item.timestamp else ""
            lines.append(f"  {prefix}{_display(item.source)}: {_display(item.detail[:180])}")
    lines.append("")
    lines.append("Probable cause:")
    lines.append(f"  {_display(incident.probable_cause.replace('_', ' '))}")
    if incident.recommendations:
        lines.append("")
        lines.append("Recommended next steps:")
        for index, rec in enumerate(incident.recommendations, 1):
            lines.append(f"  {index}. {_display(rec.action)}")
    if incident.plan:
        lines.append("")
        lines.append(f"Recovery plan risk: {incident.plan.risk.value}")
        lines.append("")
        lines.append("Proposed actions:")
        for action in incident.plan.proposed_actions:
            lines.append(f"  - {action}")
        lines.append("")
        lines.append("Rollback:")
        for action in incident.plan.rollback:
            lines.append(f"  - {action}")
        if incident.plan.notes:
            lines.append("")
            lines.append("Notes:")
            for note in incident.plan.notes:
                lines.append(f"  - {note}")
    return lines


def _fmt_time(value: datetime | None) -> str:
    if not value:
        return "unknown"
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _display(value: object) -> str:
    """Prevent log content from emitting terminal control sequences."""
    text = str(value)
    return re.sub(r"[\x00-\x1f\x7f]", lambda match: f"\\x{ord(match.group(0)):02x}", text)
