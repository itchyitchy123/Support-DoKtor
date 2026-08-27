from __future__ import annotations

import bz2
import gzip
import lzma
import os
import re
import socket
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Optional, TextIO

MAX_DIRECTORY_LOG_FILES = 512
MAX_LOG_BYTES = 64 * 1024 * 1024


COMMON_TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
)


def safe_read_lines(paths: Iterable[Path], limit: Optional[int] = 20000) -> Iterator[tuple[Path, str]]:
    for path in paths:
        try:
            candidates = sorted(path.iterdir())[:MAX_DIRECTORY_LOG_FILES] if path.is_dir() else [path]
            for candidate in candidates:
                try:
                    if not candidate.is_file():
                        continue
                    with _open_log(candidate) as handle:
                        consumed = 0
                        if limit is None:
                            for line in handle:
                                consumed += len(line.encode("utf-8", errors="replace"))
                                if consumed > MAX_LOG_BYTES:
                                    break
                                yield candidate, line.rstrip("\n")
                        else:
                            lines = deque(_bounded_lines(handle), maxlen=limit)
                            for line in lines:
                                yield candidate, line.rstrip("\n")
                except OSError:
                    continue
        except OSError:
            continue


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    raise ValueError(f"Unsupported time format: {value}")


def parse_log_timestamp(line: str, year: Optional[int] = None) -> Optional[datetime]:
    php_fpm = re.search(r"\[(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2})\]", line)
    if php_fpm:
        return _try_parse(php_fpm.group(1), "%d-%b-%Y %H:%M:%S")

    bracket = re.search(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})", line)
    if bracket:
        return _try_parse(bracket.group(1), "%d/%b/%Y:%H:%M:%S")

    iso = re.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", line)
    if iso:
        return _try_parse(iso.group(1).replace("T", " "), "%Y-%m-%d %H:%M:%S")

    syslog = re.match(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if syslog:
        dt = _try_parse(syslog.group(1), "%b %d %H:%M:%S")
        return dt.replace(year=year or datetime.now().year) if dt else None
    return None


def _try_parse(value: str, fmt: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value, fmt)
    except ValueError:
        return None


def _open_log(path: Path) -> TextIO:
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.name.endswith(".bz2"):
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if path.name.endswith(".xz"):
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _bounded_lines(handle: Iterable[str]) -> Iterator[str]:
    consumed = 0
    for line in handle:
        consumed += len(line.encode("utf-8", errors="replace"))
        if consumed > MAX_LOG_BYTES:
            return
        yield line


def command_output(args: list[str], timeout: int = 2) -> str:
    import subprocess

    try:
        completed = subprocess.run(
            args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
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
