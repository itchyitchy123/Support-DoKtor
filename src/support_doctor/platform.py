from __future__ import annotations

import re
from pathlib import Path
from typing import Dict

from .util import command_output


def detect_platform(root: Path = Path("/")) -> Dict[str, str]:
    data: Dict[str, str] = {
        "host": command_output(["hostname"]) or "unknown",
        "os": _os_release(root),
        "panel": _panel(root),
        "web_stack": _web_stack(root),
        "database": _database_version() if root.resolve() == Path("/") else "unknown (offline root)",
        "php": _php_version() if root.resolve() == Path("/") else "unknown (offline root)",
    }
    return data


def _os_release(root: Path) -> str:
    path = root / "etc/os-release"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return command_output(["uname", "-sr"]) or "unknown"
    fields = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value.strip('"')
    return fields.get("PRETTY_NAME") or fields.get("NAME") or "unknown"


def _panel(root: Path) -> str:
    if (root / "usr/local/cpanel").exists():
        version_file = root / "usr/local/cpanel/version"
        try:
            return f"cPanel {version_file.read_text().strip()}"
        except OSError:
            return "cPanel"
    if (root / "usr/local/cwpsrv").exists() or (root / "usr/local/cwp").exists():
        return "CWP"
    return "VPS/unknown panel"


def _web_stack(root: Path) -> str:
    apache = (root / "usr/sbin/httpd").exists() or (root / "usr/sbin/apache2").exists()
    nginx = (root / "usr/sbin/nginx").exists() or (root / "etc/nginx").exists()
    if apache and nginx:
        return "Apache + Nginx reverse proxy"
    if apache:
        return "Apache"
    if nginx:
        return "Nginx"
    return "unknown"


def _database_version() -> str:
    out = command_output(["mysql", "--version"]) or command_output(["mariadb", "--version"])
    if not out:
        return "unknown"
    match = re.search(r"(MariaDB|MySQL).*?(\d+\.\d+(?:\.\d+)?)", out, re.I)
    if match:
        return f"{match.group(1)} {match.group(2)}"
    return out[:80]


def _php_version() -> str:
    out = command_output(["php", "-r", "echo PHP_VERSION;"])
    if out:
        return out
    out = command_output(["php", "-v"])
    return out.splitlines()[0] if out else "unknown"
