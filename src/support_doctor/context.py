from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .models import Mode
from .util import ScanBudget


@dataclass
class InvestigationContext:
    domain: Optional[str] = None
    center_time: Optional[datetime] = None
    window_minutes: int = 10
    mode: Mode = Mode.INSPECT
    root: Path = Path("/")
    scan_budget: ScanBudget = field(default_factory=ScanBudget)

    def __post_init__(self) -> None:
        if self.window_minutes < 0:
            raise ValueError("--window must be zero or greater")
        if not self.root.is_absolute():
            self.root = self.root.absolute()
        if not self.root.is_dir():
            raise ValueError(f"--root must be an existing directory: {self.root}")

    @property
    def live_root(self) -> bool:
        return self.root.resolve() == Path("/")

    @property
    def start_time(self) -> Optional[datetime]:
        if not self.center_time:
            return None
        return self.center_time - timedelta(minutes=self.window_minutes)

    @property
    def end_time(self) -> Optional[datetime]:
        if not self.center_time:
            return None
        return self.center_time + timedelta(minutes=self.window_minutes)

    def in_window(self, timestamp: Optional[datetime]) -> bool:
        if not timestamp or not self.start_time or not self.end_time:
            return True
        return self.start_time <= timestamp <= self.end_time

    def collection_summary(self) -> dict[str, int | bool]:
        return {
            "directories_visited": self.scan_budget.directories_visited,
            "log_files_read": self.scan_budget.files_read,
            "log_bytes_read": self.scan_budget.bytes_read,
            "scan_limit_reached": self.scan_budget.limit_reached,
        }
