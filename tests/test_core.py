from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from support_doctor.context import InvestigationContext
from support_doctor.engine import _run_module
from support_doctor.health import _disk, _load, _memory, _service
from support_doctor.models import HealthCheck, Incident, Mode, Report, Severity
from support_doctor.modules.base import DiagnosticModule
from support_doctor.modules.migration import MigrationModule
from support_doctor.modules.ssl import _fetch_public_certificate
from support_doctor.platform import detect_platform
from support_doctor.render import render_json, render_text
from support_doctor.util import parse_log_timestamp, parse_time


class CoreTests(unittest.TestCase):
    def test_context_window_and_validation(self):
        center = datetime(2026, 8, 26, 3, 17)
        context = InvestigationContext(center_time=center, window_minutes=5)

        self.assertEqual(context.start_time, datetime(2026, 8, 26, 3, 12))
        self.assertEqual(context.end_time, datetime(2026, 8, 26, 3, 22))
        self.assertTrue(context.in_window(center))
        self.assertFalse(context.in_window(datetime(2026, 8, 26, 3, 30)))
        with self.assertRaises(ValueError):
            InvestigationContext(window_minutes=-1)
        with self.assertRaises(ValueError):
            InvestigationContext(root=Path("/definitely/not/a/support-doctor-root"))

    def test_time_parsers_cover_supported_log_formats(self):
        self.assertEqual(parse_time("2026-08-26T03:17:00"), datetime(2026, 8, 26, 3, 17))
        self.assertEqual(parse_log_timestamp("[26-Aug-2026 03:17:00] warning"), datetime(2026, 8, 26, 3, 17))
        self.assertEqual(
            parse_log_timestamp("host [26/Aug/2026:03:17:00 +0000] request"),
            datetime(2026, 8, 26, 3, 17),
        )
        self.assertEqual(parse_log_timestamp("Aug 26 03:17:00 host service", year=2025), datetime(2025, 8, 26, 3, 17))
        self.assertIsNone(parse_log_timestamp("not a timestamp"))
        with self.assertRaises(ValueError):
            parse_time("next Tuesday")

    @patch("support_doctor.health.os.cpu_count", return_value=2)
    @patch("support_doctor.health.os.getloadavg", return_value=(4.0, 2.0, 1.0))
    def test_load_health_thresholds(self, _getloadavg, _cpu_count):
        check = _load()
        self.assertEqual(check.status, Severity.CRITICAL)
        self.assertIn("4.00", check.detail)

    def test_memory_health_thresholds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = root / "proc"
            proc.mkdir()
            (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 50 kB\n", encoding="utf-8")
            check = _memory(root)

        self.assertEqual(check.status, Severity.CRITICAL)

    @patch(
        "support_doctor.health.command_output",
        return_value="Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 1 1 1 96% /data",
    )
    def test_disk_health_thresholds(self, _command_output):
        self.assertEqual(_disk(Path("/")).status, Severity.CRITICAL)

    @patch("support_doctor.health.command_output", return_value="failed")
    def test_service_health_failure(self, _command_output):
        self.assertEqual(_service("MariaDB", ["systemctl"]).status, Severity.CRITICAL)

    def test_offline_platform_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "etc/os-release", 'PRETTY_NAME="AlmaLinux 9"\n')
            _write(root / "usr/local/cpanel/version", "11.120\n")
            _write(root / "usr/sbin/httpd", "")
            (root / "etc/nginx").mkdir(parents=True)
            platform = detect_platform(root)

        self.assertEqual(platform["os"], "AlmaLinux 9")
        self.assertEqual(platform["panel"], "cPanel 11.120")
        self.assertEqual(platform["web_stack"], "Apache + Nginx reverse proxy")
        self.assertEqual(platform["php"], "unknown (offline root)")

    def test_report_rendering_escapes_controls_and_sanitizes_host(self):
        report = Report(
            platform={"host": "private-host", "os": "Linux", "panel": "none"},
            health=[HealthCheck("Disk", Severity.WARNING, "nearly full")],
            incidents=[
                Incident(
                    key="example",
                    title="Example\x1b[31m",
                    severity=Severity.WARNING,
                    probable_cause="test_case",
                    metrics={"count": 1},
                )
            ],
            generated_at=datetime.now(timezone.utc),
        )

        self.assertIn(r"Example\x1b[31m", render_text(report))
        self.assertNotIn("private-host", render_json(report))
        self.assertEqual(report.strongest_status(["Disk"]), Severity.WARNING)

    def test_module_failure_becomes_incident(self):
        class BrokenModule(DiagnosticModule):
            name = "broken"

            def inspect(self, context: InvestigationContext) -> list[Incident]:
                raise RuntimeError("synthetic failure")

        incidents = _run_module(BrokenModule(), InvestigationContext())
        self.assertEqual(incidents[0].key, "broken_diagnostic_failure")
        self.assertIn("RuntimeError", incidents[0].evidence[0].detail)

    def test_migration_plan_is_non_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            incidents = MigrationModule().plan(InvestigationContext(root=Path(tmp), mode=Mode.PLAN))

        self.assertEqual(incidents[0].plan.risk, Severity.WARNING)
        self.assertFalse(incidents[0].plan.execute_supported)

    def test_ssl_rejects_malformed_hostname(self):
        with self.assertRaises(ValueError):
            _fetch_public_certificate("bad_host.example")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
