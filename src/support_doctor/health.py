from __future__ import annotations

import os
import re
from pathlib import Path

from .models import HealthCheck, Severity
from .util import command_output

SERVICE_UNITS = {
    "Database": {"mariadb.service", "mysql.service", "mysqld.service"},
    "Apache": {"apache2.service", "httpd.service"},
    "Nginx": {"nginx.service"},
}
SERVICE_PROCESSES = {
    "Database": re.compile(r"^(?:mariadbd|mysqld)$"),
    "Apache": re.compile(r"^(?:apache2|httpd)$"),
    "Nginx": re.compile(r"^nginx$"),
    "PHP-FPM": re.compile(r"^php-fpm(?:\d+(?:\.\d+)?)?$"),
}
PHP_FPM_UNIT_RE = re.compile(r"(?:ea-php\d+-php-fpm|php(?:\d+(?:\.\d+)?)?-fpm)\.service$")
LIVE_DISK_PATHS = (Path("/"), Path("/var"), Path("/home"), Path("/tmp"))  # noqa: S108 -- monitored mount


def collect_health(root: Path = Path("/")) -> list[HealthCheck]:
    live = root.resolve() == Path("/")
    checks = [
        _privileges(root, live),
        _load() if live else HealthCheck("Load", Severity.UNKNOWN, "live load unavailable for offline root"),
        _memory(root),
        _swap(root),
    ]
    checks.extend(_filesystem_checks(root, live))
    if not live:
        checks.extend(_offline_service(name) for name in (*SERVICE_UNITS, "PHP-FPM"))
        return checks

    installed = _systemd_units()
    processes = _process_names()
    for name, candidates in SERVICE_UNITS.items():
        checks.append(_service_health(name, candidates, installed, processes))
    php_units = {unit for unit in installed if PHP_FPM_UNIT_RE.fullmatch(unit)}
    checks.append(_service_health("PHP-FPM", php_units, installed, processes))
    return checks


def _privileges(root: Path, live: bool) -> HealthCheck:
    if live:
        if os.geteuid() == 0:
            return HealthCheck("Privileges", Severity.OK, "running as root; privileged logs should be readable")
        return HealthCheck(
            "Privileges",
            Severity.WARNING,
            "running without root privileges; protected logs and service details may be missing",
        )
    if os.access(root, os.R_OK | os.X_OK):
        return HealthCheck("Privileges", Severity.OK, "offline root is readable and searchable")
    return HealthCheck("Privileges", Severity.WARNING, "offline root is not fully accessible")


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


def _meminfo(root: Path) -> dict[str, int]:
    fields: dict[str, int] = {}
    for line in (root / "proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        fields[key] = int(value.strip().split()[0])
    return fields


def _memory(root: Path) -> HealthCheck:
    try:
        fields = _meminfo(root)
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


def _swap(root: Path) -> HealthCheck:
    try:
        fields = _meminfo(root)
        total = fields["SwapTotal"]
        free = fields["SwapFree"]
    except (OSError, ValueError, KeyError):
        return HealthCheck("Swap", Severity.UNKNOWN, "swap information unavailable")
    if total == 0:
        return HealthCheck("Swap", Severity.INFO, "swap is not configured")
    used = max(total - free, 0)
    pct = used / total
    if pct >= 0.8:
        status = Severity.CRITICAL
    elif pct >= 0.5:
        status = Severity.WARNING
    else:
        status = Severity.OK
    return HealthCheck("Swap", status, f"{used // 1024} MB used of {total // 1024} MB ({pct:.0%})")


def _filesystem_checks(root: Path, live: bool) -> list[HealthCheck]:
    paths = [path for path in LIVE_DISK_PATHS if path.exists()] if live else [root]
    checks = _df_checks(paths, inode=False)
    checks.extend(_df_checks(paths, inode=True))
    return checks or [HealthCheck("Disk", Severity.UNKNOWN, "filesystem usage unavailable")]


def _df_checks(paths: list[Path], inode: bool) -> list[HealthCheck]:
    args = ["df", "-Pi" if inode else "-P", *[str(path) for path in paths]]
    lines = command_output(args, timeout=5).splitlines()
    if len(lines) < 2:
        return []
    checks: list[HealthCheck] = []
    seen_mounts: set[str] = set()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        mount = parts[-1]
        if mount in seen_mounts:
            continue
        seen_mounts.add(mount)
        checks.append(_usage_check("Inodes" if inode else "Disk", mount, parts[-2]))
    return checks


def _usage_check(kind: str, mount: str, used: str) -> HealthCheck:
    try:
        pct = int(used.rstrip("%"))
    except ValueError:
        return HealthCheck(f"{kind} {mount}", Severity.UNKNOWN, f"usage {used}")
    if pct >= 95:
        status = Severity.CRITICAL
    elif pct >= 85:
        status = Severity.WARNING
    else:
        status = Severity.OK
    return HealthCheck(f"{kind} {mount}", status, f"{used} used")


def _disk(root: Path) -> HealthCheck:
    """Compatibility wrapper for a single filesystem capacity check."""
    checks = _df_checks([root], inode=False)
    return checks[0] if checks else HealthCheck("Disk", Severity.UNKNOWN, "disk usage unavailable")


def _systemd_units() -> set[str]:
    out = command_output(
        ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"],
        timeout=5,
    )
    return {line.split()[0] for line in out.splitlines() if line.split() and line.split()[0].endswith(".service")}


def _process_names() -> set[str]:
    names: set[str] = set()
    try:
        processes = Path("/proc").iterdir()
        for process in processes:
            if not process.name.isdigit():
                continue
            try:
                name = (process / "comm").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if name:
                names.add(name)
    except OSError:
        pass
    return names


def _service_health(name: str, candidates: set[str], installed: set[str], processes: set[str]) -> HealthCheck:
    systemd = _service(name, candidates, installed)
    if systemd.status != Severity.UNKNOWN:
        return systemd
    pattern = SERVICE_PROCESSES[name]
    running = sorted(process for process in processes if pattern.fullmatch(process))
    if running:
        return HealthCheck(name, Severity.OK, f"running process(es): {', '.join(running)}")
    return HealthCheck(name, Severity.UNKNOWN, "not detected via systemd or process table")


def _service(name: str, candidates: set[str] | list[str], installed: set[str] | None = None) -> HealthCheck:
    normalized = {unit if unit.endswith(".service") else f"{unit}.service" for unit in candidates}
    targets = sorted(normalized & installed) if installed is not None else sorted(normalized)
    if not targets:
        return HealthCheck(name, Severity.UNKNOWN, "no matching systemd unit installed")

    states = {unit: command_output(["systemctl", "is-active", unit]) for unit in targets}
    active = [unit.removesuffix(".service") for unit, state in states.items() if state == "active"]
    if active:
        return HealthCheck(name, Severity.OK, f"active unit(s): {', '.join(active)}")
    failed = [unit.removesuffix(".service") for unit, state in states.items() if state == "failed"]
    if failed:
        return HealthCheck(name, Severity.CRITICAL, f"failed unit(s): {', '.join(failed)}")
    inactive = [unit.removesuffix(".service") for unit, state in states.items() if state == "inactive"]
    if inactive:
        return HealthCheck(name, Severity.CRITICAL, f"inactive unit(s): {', '.join(inactive)}")
    return HealthCheck(name, Severity.UNKNOWN, "service state unavailable")


def _offline_service(name: str) -> HealthCheck:
    return HealthCheck(name, Severity.UNKNOWN, "live service status unavailable for offline root")
