from __future__ import annotations

import os
from pathlib import Path

from .models import HealthCheck, Severity
from .util import command_output


def collect_health(root: Path = Path("/")) -> list[HealthCheck]:
    live = root.resolve() == Path("/")
    return [
        _load() if live else HealthCheck("Load", Severity.UNKNOWN, "live load unavailable for offline root"),
        _memory(root),
        _disk(root),
        _service("MariaDB", ["systemctl", "is-active", "mariadb"]) if live else _offline_service("MariaDB"),
        _service("Apache", ["systemctl", "is-active", "httpd"]) if live else _offline_service("Apache"),
        _service("Nginx", ["systemctl", "is-active", "nginx"]) if live else _offline_service("Nginx"),
        _service("PHP-FPM", ["systemctl", "is-active", "php-fpm"]) if live else _offline_service("PHP-FPM"),
    ]


def _load() -> HealthCheck:
    try:
        one, _five, _fifteen = os.getloadavg()
        cpus = os.cpu_count() or 1
    except OSError:
        return HealthCheck("Load", Severity.UNKNOWN, "load average unavailable")
    ratio = one / cpus
    if ratio >= 2:
        status = Severity.CRITICAL
    elif ratio >= 1:
        status = Severity.WARNING
    else:
        status = Severity.OK
    return HealthCheck("Load", status, f"{one:.2f} on {cpus} CPU(s)")


def _memory(root: Path) -> HealthCheck:
    path = root / "proc/meminfo"
    try:
        fields = {}
        for line in path.read_text().splitlines():
            key, value = line.split(":", 1)
            fields[key] = int(value.strip().split()[0])
        total = fields["MemTotal"]
        available = fields.get("MemAvailable", fields.get("MemFree", 0))
    except (OSError, ValueError, KeyError):
        return HealthCheck("Memory", Severity.UNKNOWN, "memory information unavailable")
    pct = available / total if total else 0
    if pct < 0.08:
        status = Severity.CRITICAL
    elif pct < 0.18:
        status = Severity.WARNING
    else:
        status = Severity.OK
    return HealthCheck("Memory", status, f"{available // 1024} MB available of {total // 1024} MB")


def _disk(root: Path) -> HealthCheck:
    out = command_output(["df", "-P", str(root)])
    lines = out.splitlines()
    if len(lines) < 2:
        return HealthCheck("Disk", Severity.UNKNOWN, "disk usage unavailable")
    parts = lines[-1].split()
    used = parts[4] if len(parts) > 4 else "unknown"
    try:
        pct = int(used.rstrip("%"))
    except ValueError:
        return HealthCheck("Disk", Severity.UNKNOWN, f"disk usage {used}")
    if pct >= 95:
        status = Severity.CRITICAL
    elif pct >= 85:
        status = Severity.WARNING
    else:
        status = Severity.OK
    return HealthCheck("Disk", status, f"{used} used on {parts[-1]}")


def _service(name: str, args: list[str]) -> HealthCheck:
    out = command_output(args)
    if out == "active":
        return HealthCheck(name, Severity.OK, "systemd service active")
    if out in {"inactive", "failed"}:
        return HealthCheck(name, Severity.CRITICAL, f"systemd service {out}")
    return HealthCheck(name, Severity.UNKNOWN, "service status unavailable")


def _offline_service(name: str) -> HealthCheck:
    return HealthCheck(name, Severity.UNKNOWN, "live service status unavailable for offline root")
