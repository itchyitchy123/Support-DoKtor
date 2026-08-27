from __future__ import annotations

import re
from pathlib import Path

from .util import command_output


def detect_platform(root: Path = Path("/")) -> dict[str, str]:
    live = root.resolve() == Path("/")
    data: dict[str, str] = {
        "host": (command_output(["hostname"]) or "unknown") if live else "offline snapshot",
        "os": _os_release(root),
        "panel": _panel(root),
        "web_stack": _web_stack(root),
        "database": _database_version() if live else "unknown (offline root)",
        "php": _php_version() if live else "unknown (offline root)",
    }
    return data


def _os_release(root: Path) -> str:
    path = root / "etc/os-release"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        if root.resolve() != Path("/"):
            return "unknown (offline root)"
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
    mariadb = re.search(r"(\d+\.\d+(?:\.\d+)?)[-_]MariaDB\b", out, re.I)
    if mariadb:
        return f"MariaDB {mariadb.group(1)}"
    mysql = re.search(r"\bDistrib\s+(\d+\.\d+(?:\.\d+)?)", out, re.I)
    if not mysql and "mysql" in out.lower():
        mysql = re.search(r"\bVer\s+(\d+\.\d+(?:\.\d+)?)", out, re.I)
    if mysql:
        return f"MySQL {mysql.group(1)}"
    return out[:80]


def _php_version() -> str:
    out = command_output(["php", "-r", "echo PHP_VERSION;"])
    if out:
        return out
    out = command_output(["php", "-v"])
    return out.splitlines()[0] if out else "unknown"
