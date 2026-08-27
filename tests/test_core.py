from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from support_doctor.context import InvestigationContext
from support_doctor.engine import _run_module
from support_doctor.health import _df_checks, _disk, _load, _memory, _privileges, _service, _service_health, _swap
from support_doctor.models import HealthCheck, Incident, Mode, Report, Severity
from support_doctor.modules.base import DiagnosticModule
from support_doctor.modules.mail import MailModule
from support_doctor.modules.migration import MigrationModule
from support_doctor.modules.php_fpm import _safe_max_children
from support_doctor.modules.security import SecurityModule
from support_doctor.modules.ssl import _fetch_public_certificate
from support_doctor.platform import _database_version, detect_platform
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

    def test_swap_health_detects_pressure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = root / "proc"
            proc.mkdir()
            (proc / "meminfo").write_text("SwapTotal: 1000 kB\nSwapFree: 100 kB\n", encoding="utf-8")
            check = _swap(root)

        self.assertEqual(check.status, Severity.CRITICAL)
        self.assertIn("90%", check.detail)

    @patch(
        "support_doctor.health.command_output",
        return_value="Filesystem 1024-blocks Used Available Capacity Mounted on\nfs 1 1 1 96% /data",
    )
    def test_disk_health_thresholds(self, _command_output):
        self.assertEqual(_disk(Path("/")).status, Severity.CRITICAL)

    @patch(
        "support_doctor.health.command_output",
        return_value=(
            "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/vda1 100 90 10 90% /\n/dev/vda1 100 90 10 90% /"
        ),
    )
    def test_inode_checks_deduplicate_mounts(self, _command_output):
        checks = _df_checks([Path("/"), Path("/var")], inode=True)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].name, "Inodes /")
        self.assertEqual(checks[0].status, Severity.WARNING)

    @patch("support_doctor.health.command_output", return_value="failed")
    def test_service_health_failure(self, _command_output):
        self.assertEqual(_service("MariaDB", ["systemctl"]).status, Severity.CRITICAL)

    @patch("support_doctor.health.command_output")
    def test_service_health_supports_distro_unit_aliases(self, command_output):
        command_output.side_effect = lambda args: "active" if args[-1] == "apache2.service" else "inactive"
        check = _service(
            "Apache",
            {"apache2.service", "httpd.service"},
            {"apache2.service", "httpd.service"},
        )

        self.assertEqual(check.status, Severity.OK)
        self.assertIn("apache2", check.detail)

    def test_service_health_falls_back_to_process_table(self):
        check = _service_health("Database", set(), set(), {"mariadbd"})
        self.assertEqual(check.status, Severity.OK)
        self.assertIn("mariadbd", check.detail)

    @patch("support_doctor.health.os.geteuid", return_value=1000)
    def test_non_root_live_run_warns_about_incomplete_evidence(self, _geteuid):
        self.assertEqual(_privileges(Path("/"), live=True).status, Severity.WARNING)

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

    @patch("support_doctor.platform.command_output")
    def test_offline_platform_does_not_fall_back_to_live_host(self, command_output):
        with tempfile.TemporaryDirectory() as tmp:
            platform = detect_platform(Path(tmp))

        self.assertEqual(platform["host"], "offline snapshot")
        self.assertEqual(platform["os"], "unknown (offline root)")
        command_output.assert_not_called()

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

    def test_php_capacity_ceiling_includes_existing_processes(self):
        self.assertEqual(_safe_max_children(available_mb=1000, worker_mb=100, worker_count=5), 15)

    def test_mail_ignores_normal_spamassassin_daemon_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "var/log/maillog",
                "Aug 26 03:17:00 host spamd[10]: connection from localhost [127.0.0.1]\n",
            )
            incidents = MailModule().inspect(InvestigationContext(root=root))

        self.assertEqual(incidents, [])

    def test_mail_detects_actual_spam_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "var/log/maillog", "Aug 26 03:17:00 host mta: message rejected as spam\n")
            incidents = MailModule().inspect(InvestigationContext(root=root))

        self.assertEqual(incidents[0].metrics["spam_rejections"], 1)

    def test_mail_classifies_dnsbl_lookup_pressure_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "var/log/maillog",
                "Aug 26 03:17:00 host spamd: dns_block_rule URIBL_BLOCKED hit; DNSBL blocked due to queries\n",
            )
            incidents = MailModule().inspect(InvestigationContext(root=root))

        self.assertEqual(incidents[0].metrics["dnsbl_warnings"], 1)
        self.assertEqual(incidents[0].metrics["spam_rejections"], 0)

    def test_security_ignores_fail2ban_service_name_but_detects_ban(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(
                root / "var/log/messages",
                "Aug 26 03:17:00 host systemd: Started Fail2Ban Service\n"
                "Aug 26 03:17:01 host lfd: ModSecurity IP D/B Tracking\n",
            )
            _write(
                root / "var/log/fail2ban.log",
                "2026-08-26 03:17:01 fail2ban.jail: WARNING ban time increment unavailable\n",
            )
            self.assertEqual(SecurityModule().inspect(InvestigationContext(root=root)), [])
            _write(root / "var/log/fail2ban.log", "2026-08-26 03:17:01 fail2ban.actions: NOTICE Ban 203.0.113.4\n")
            incidents = SecurityModule().inspect(InvestigationContext(root=root))

        self.assertEqual(len(incidents), 1)

    @patch(
        "support_doctor.platform.command_output",
        return_value="mysql  Ver 15.1 Distrib 10.11.14-MariaDB, for Linux (x86_64)",
    )
    def test_database_version_reports_server_distribution(self, _command_output):
        self.assertEqual(_database_version(), "MariaDB 10.11.14")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
