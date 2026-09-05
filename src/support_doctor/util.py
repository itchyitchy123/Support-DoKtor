from __future__ import annotations

import bz2
import gzip
import lzma
import os
import re
import socket
import subprocess
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional, TextIO

MAX_DIRECTORY_LOG_FILES = 512
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_INVESTIGATION_LOG_BYTES = 512 * 1024 * 1024
MAX_INVESTIGATION_LOG_FILES = 4096
MAX_INVESTIGATION_DIRECTORIES = 10_000
TRUSTED_COMMAND_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


COMMON_TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
)


class ScanBudget:
    """Shared per-command limits for filesystem and log collection."""

    def __init__(
        self,
        max_bytes: int = MAX_INVESTIGATION_LOG_BYTES,
        max_files: int = MAX_INVESTIGATION_LOG_FILES,
        max_directories: int = MAX_INVESTIGATION_DIRECTORIES,
    ):
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.max_directories = max_directories
        self.bytes_read = 0
        self.files_read = 0
        self.directories_visited = 0
        self.limit_reached = False

    def start_file(self) -> bool:
        if self.files_read >= self.max_files:
            self.limit_reached = True
            return False
        self.files_read += 1
        return True

    def allow_bytes(self, amount: int) -> bool:
        if self.bytes_read + amount > self.max_bytes:
            self.limit_reached = True
            return False
        self.bytes_read += amount
        return True

    def visit_directory(self) -> bool:
        if self.directories_visited >= self.max_directories:
            self.limit_reached = True
            return False
        self.directories_visited += 1
        return True


def safe_read_lines(
    paths: Iterable[Path],
    limit: Optional[int] = 20000,
    root: Optional[Path] = None,
    budget: Optional[ScanBudget] = None,
) -> Iterator[tuple[Path, str]]:
    boundary = root.resolve() if root is not None else None
    for path in paths:
        try:
            is_directory = path.is_dir()
            if is_directory and budget is not None and not budget.visit_directory():
                continue
            candidates = sorted(path.iterdir())[:MAX_DIRECTORY_LOG_FILES] if is_directory else [path]
            for candidate in candidates:
                try:
                    if not candidate.is_file() or not _within_root(candidate, boundary):
                        continue
                    if budget is not None and not budget.start_file():
                        continue
                    with _open_log(candidate) as handle:
                        consumed = 0
                        if limit is None:
                            for line in handle:
                                size = len(line.encode("utf-8", errors="replace"))
                                consumed += size
                                if consumed > MAX_LOG_BYTES or budget is not None and not budget.allow_bytes(size):
                                    break
                                yield candidate, line.rstrip("\n")
                        else:
                            lines = deque(_bounded_lines(handle, budget), maxlen=limit)
                            for line in lines:
                                yield candidate, line.rstrip("\n")
                except (OSError, UnicodeError):
                    continue
        except (OSError, UnicodeError):
            continue


def _within_root(path: Path, boundary: Optional[Path]) -> bool:
    if boundary is None:
        return True
    try:
        path.resolve().relative_to(boundary)
    except ValueError:
        return False
    return True


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    for fmt in (
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return _as_utc_naive(datetime.strptime(value, fmt))
        except ValueError:
            pass
    raise ValueError(f"Unsupported time format: {value}")


def parse_log_timestamp(line: str, year: Optional[int] = None) -> Optional[datetime]:
    php_fpm = re.search(r"\[(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2})\]", line)
    if php_fpm:
        return _try_parse(php_fpm.group(1), "%d-%b-%Y %H:%M:%S")

    bracket = re.search(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})(?:\s+([+-]\d{4}))?", line)
    if bracket:
        value = bracket.group(1)
        if bracket.group(2):
            return _try_parse(value + bracket.group(2), "%d/%b/%Y:%H:%M:%S%z")
        return _try_parse(value, "%d/%b/%Y:%H:%M:%S")

    iso = re.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(Z|[+-]\d{2}:?\d{2})?", line)
    if iso:
        value = iso.group(1).replace("T", " ")
        if iso.group(2):
            offset = "+00:00" if iso.group(2) == "Z" else iso.group(2)
            return _try_parse(value + offset, "%Y-%m-%d %H:%M:%S%z")
        return _try_parse(value, "%Y-%m-%d %H:%M:%S")

    syslog = re.match(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if syslog:
        dt = _try_parse(syslog.group(1), "%b %d %H:%M:%S")
        return dt.replace(year=year or datetime.now().year) if dt else None
    return None


def _try_parse(value: str, fmt: str) -> Optional[datetime]:
    try:
        return _as_utc_naive(datetime.strptime(value, fmt))
    except ValueError:
        return None


def _as_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _open_log(path: Path) -> TextIO:
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.name.endswith(".bz2"):
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if path.name.endswith(".xz"):
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _bounded_lines(handle: Iterable[str], budget: Optional[ScanBudget] = None) -> Iterator[str]:
    consumed = 0
    for line in handle:
        size = len(line.encode("utf-8", errors="replace"))
        consumed += size
        if consumed > MAX_LOG_BYTES or budget is not None and not budget.allow_bytes(size):
            return
        yield line


def command_output(args: list[str], timeout: int = 2) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 -- argv execution only; shell is never enabled
            args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            env={"PATH": TRUSTED_COMMAND_PATH, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.strip()


def detect_existing(paths: Iterable[str]) -> list[Path]:
    return [Path(path) for path in paths if Path(path).exists()]


def hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return os.environ.get("HOSTNAME", "unknown")
