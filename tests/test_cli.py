from __future__ import annotations

import gzip
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from support_doctor.cli import main
from support_doctor.modules.php_fpm import _php_memory_estimate
from support_doctor.modules.ssl import _fetch_public_certificate


class CliTests(unittest.TestCase):
    def test_investigate_detects_php_fpm_incident(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_fixture(root)
            code, out = _run(
                [
                    "investigate",
                    "--root",
                    str(root),
                    "--domain",
                    "practice.example.com",
                    "--time",
                    "2026-08-26 06:40",
                ]
            )

        self.assertEqual(code, 0)
        self.assertIn("PHP-FPM pool reached pm.max_children", out)
        self.assertIn("/ajax.php", out)
        self.assertIn("Do not change max_children until worker memory is measured", out)
        self.assertIn("No configuration changes performed.", out)

    def test_json_is_sanitized_and_structured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_fixture(root)
            code, out = _run(["php-fpm", "--root", str(root), "--domain", "practice.example.com", "--json"])

        payload = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(payload["incidents"][0]["incident"], "php_fpm_capacity")
        self.assertEqual(payload["incidents"][0]["cause"], "application_concurrency")
        self.assertEqual(payload["incidents"][0]["primary_endpoint"], "/ajax.php")

    def test_mysql_plan_is_non_executing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "var/log/mariadb/mariadb.log", "2026-08-26 03:17:00 InnoDB: page corruption detected\n")
            code, out = _run(["mysql", "--root", str(root), "--plan"])

        self.assertEqual(code, 0)
        self.assertIn("Recovery plan risk: CRITICAL", out)
        self.assertIn("Create a physical backup", out)

    def test_historical_scan_reads_beyond_tail_and_ignores_bad_timestamps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lines = ["[not-a-date] unrelated line\n"] * 20001
            lines[0] = "[26-Aug-2026 03:17:00] WARNING: [pool site] server reached pm.max_children setting (12)\n"
            _write(root / "var/log/php-fpm/error.log", "".join(lines))
            code, out = _run(["php-fpm", "--root", str(root), "--time", "2026-08-26 03:17"])

        self.assertEqual(code, 0)
        self.assertIn("pm.max_children", out)

    def test_case_summary_uses_configured_ceiling_language(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_fixture(root)
            code, out = _run(["case-summary", "--root", str(root), "--domain", "practice.example.com"])

        self.assertEqual(code, 0)
        self.assertIn("configured ceiling of 65 workers", out)

    def test_compressed_rotated_logs_and_syslog_year_are_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rotated = root / "var/log/php-fpm/error.log.1.gz"
            rotated.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(rotated, "wt", encoding="utf-8") as handle:
                handle.write(
                    "[26-Aug-2025 03:17:00] WARNING: [pool site] server reached pm.max_children setting (12)\n"
                )
            _write(root / "var/log/maillog", "Aug 26 03:17:00 host dovecot: authentication failed\n")
            code, out = _run(["php-fpm", "--root", str(root), "--time", "2025-08-26 03:17"])
            mail_code, mail_out = _run(["mail", "--root", str(root), "--time", "2025-08-26 03:17"])

        self.assertEqual(code, 0)
        self.assertIn("pm.max_children", out)
        self.assertEqual(mail_code, 0)
        self.assertIn("Mail delivery or authentication issue", mail_out)

    def test_json_does_not_expose_host_or_client_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_fixture(root)
            code, out = _run(["web", "--root", str(root), "--domain", "practice.example.com", "--json"])

        self.assertEqual(code, 0)
        self.assertNotIn("203.0.113.10", out)
        self.assertNotIn('"host"', out)

    def test_json_timestamp_is_utc(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = _run(["web", "--root", tmp, "--json"])

        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["generated_at"].endswith("+00:00"))

    def test_execute_fails_closed_when_no_action_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = _run(["web", "--root", tmp, "--execute"])

        self.assertEqual(code, 2)
        self.assertIn("No supported configuration changes performed.", out)

    def test_offline_root_does_not_use_live_php_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            estimate = _php_memory_estimate(Path(tmp))

        self.assertEqual(estimate["worker_mb"], 0)
        self.assertEqual(estimate["available_mb"], 0)
        self.assertIn("offline root", estimate["reason"])

    def test_wordpress_json_does_not_expose_customer_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            customer_root = root / "home/customer/public_html"
            _write(customer_root / "wp-config.php", "<?php\n")
            code, out = _run(["wordpress", "--root", str(root), "--json"])

        self.assertEqual(code, 0)
        self.assertNotIn("customer", out)
        self.assertEqual(json.loads(out)["incidents"][0]["metrics"]["wordpress_root_count"], 1)

    def test_ssl_rejects_private_targets_before_connecting(self):
        with self.assertRaises(ValueError):
            _fetch_public_certificate("127.0.0.1")


def _run(args: list[str]) -> tuple[int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(args)
    return code, buffer.getvalue()


def _write_fixture(root: Path) -> None:
    _write(
        root / "var/log/php-fpm/error.log",
        "\n".join(
            [
                "[26-Aug-2026 06:40:20] WARNING: [pool practice.example.com] server reached pm.max_children setting (65), consider raising it",
                "[26-Aug-2026 06:40:45] WARNING: [pool practice.example.com] server reached pm.max_children setting (65), consider raising it",
            ]
        )
        + "\n",
    )
    access_line = '203.0.113.10 - - [26/Aug/2026:06:40:21 -0500] "GET /ajax.php HTTP/1.1" 200 123 "https://practice.example.com" "curl"\n'
    _write(root / "var/log/nginx/access.log", access_line * 278)
    _write(root / "etc/os-release", 'PRETTY_NAME="AlmaLinux 9.7"\n')


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
