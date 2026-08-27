from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from .context import InvestigationContext
from .util import parse_log_timestamp, safe_read_lines

ACCESS_RE = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^ ?"]+)')
IP_RE = re.compile(r"^(\S+)")


@dataclass
class AccessSummary:
    requests: int
    endpoints: Counter
    clients: Counter
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    source_paths: list[str]


def summarize_access(paths: Iterable[Path], context: InvestigationContext) -> AccessSummary:
    endpoints: Counter = Counter()
    clients: Counter = Counter()
    first_seen = None
    last_seen = None
    source_paths = set()
    requests = 0
    for path, line in safe_read_lines(paths, limit=None if context.center_time else 20000):
        ts = parse_log_timestamp(line, year=context.center_time.year if context.center_time else None)
        if not context.in_window(ts):
            continue
        if context.domain and context.domain not in line:
            continue
        endpoint = ACCESS_RE.search(line)
        client = IP_RE.search(line)
        if not endpoint:
            continue
        requests += 1
        endpoints[endpoint.group(1)] += 1
        if client:
            clients[client.group(1)] += 1
        source_paths.add(str(path))
        if ts and (first_seen is None or ts < first_seen):
            first_seen = ts
        if ts and (last_seen is None or ts > last_seen):
            last_seen = ts
    return AccessSummary(requests, endpoints, clients, first_seen, last_seen, sorted(source_paths))


def common_access_logs(root: Path) -> dict[str, list[Path]]:
    return {
        "apache": [
            root / "var/log/httpd/access_log",
            root / "var/log/apache2/access.log",
            root / "usr/local/apache/logs/access_log",
            root / "etc/apache2/logs/domlogs",
        ],
        "nginx": [
            root / "var/log/nginx/access.log",
            root / "usr/local/nginx/logs/access.log",
            root / "usr/local/cpanel/logs/nginx/access.log",
        ],
    }


def bucket_counts(paths: Iterable[Path], context: InvestigationContext) -> dict[datetime, int]:
    buckets: dict[datetime, int] = defaultdict(int)
    for _path, line in safe_read_lines(paths, limit=None if context.center_time else 20000):
        ts = parse_log_timestamp(line, year=context.center_time.year if context.center_time else None)
        if not ts or not context.in_window(ts):
            continue
        if context.domain and context.domain not in line:
            continue
        bucket = ts.replace(second=0, microsecond=0)
        buckets[bucket] += 1
    return dict(sorted(buckets.items()))
