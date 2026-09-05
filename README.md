# Support DoKtor

[![CI](https://github.com/itchyitchy123/Support-DoKtor/actions/workflows/ci.yml/badge.svg)](https://github.com/itchyitchy123/Support-DoKtor/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Support DoKtor is a read-first Linux hosting diagnostic and recovery-planning CLI for cPanel, CWP, and unmanaged VPS environments. It correlates system state and logs into an evidence-based incident report before an engineer changes anything.

> [!IMPORTANT]
> This project is alpha software. Treat its output as decision support, not as authorization to alter a production host. Review evidence, backups, blast radius, and rollback steps before remediation.

## Capabilities

- Detects Linux distribution, hosting panel, web stack, PHP, and database versions.
- Checks privileges, load, memory, swap, disk capacity, inode capacity, and common service state.
- Correlates PHP-FPM saturation with Apache or Nginx request traffic.
- Identifies database, mail, WordPress, and security log anomalies.
- Reads current and compressed rotated logs with bounded memory and I/O.
- Produces terminal-safe human reports and reduced, host-free JSON for analytics.
- Inspects mounted snapshots through `--root` without mixing in live-host memory or service data.

## Support matrix

| Environment | Status | Notes |
| --- | --- | --- |
| Linux live host | Supported | Root is recommended for complete evidence |
| cPanel | Supported | Includes common EA-PHP and Apache/Nginx paths |
| Control Web Panel (CWP) | Supported | Common CWP filesystem and service layouts |
| Unmanaged VPS | Supported | Best-effort service and log discovery |
| Mounted filesystem snapshot | Supported | Read-only analysis; live state is intentionally unavailable |

Support is path- and distribution-aware but intentionally best-effort. A missing log, service, or package is reported as unknown or incomplete rather than inferred from the analyst host.

## Install

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
support-doctor --help
```

For local development, install the quality and build tools with `python -m pip install -e '.[dev]'`.

## Usage

```bash
# Broad, read-only investigation of the current host
sudo support-doctor investigate

# Reconstruct a ten-minute window around an event
sudo support-doctor investigate --domain example.com --time "2026-08-26 03:17"

# Analyze a mounted filesystem snapshot
support-doctor php-fpm --root /mnt/incident-snapshot --inspect

# Generate actions and rollback notes without applying them
sudo support-doctor mysql --plan

# Emit reduced structured output for downstream processing
sudo support-doctor investigate --json > report.json

# Let monitoring fail when warning-or-higher findings are present
sudo support-doctor investigate --json --fail-on warning > report.json
```

Commands include `investigate`, `case-summary`, `php-fpm`, `web`, `apache`, `nginx`, `mysql`, `mariadb`, `mail`, `wordpress`, `security`, `ssl`, and `migration`.

## Documentation

The [documentation wiki](docs/README.md) contains detailed guides for installation, operating modes, architecture, command behavior, incident runbooks, privacy, troubleshooting, and development.

## Example sanitized report

Structured output is deliberately reduced for analytics and ticketing systems. It keeps stable categories and counts while removing hostnames, addresses, customer paths, and raw log evidence:

```json
{
  "schema_version": 1,
  "mode": "inspect",
  "platform": {
    "database": "MariaDB 10.11.14",
    "os": "AlmaLinux 9.7",
    "panel": "cPanel 11.120",
    "php": "8.2.21",
    "web_stack": "Apache + Nginx reverse proxy"
  },
  "health": [
    {"name": "Memory", "status": "OK", "detail": "4096 MB available of 8192 MB"},
    {"name": "Disk <path>", "status": "WARNING", "detail": "87% used"}
  ],
  "collection": {
    "directories_visited": 4,
    "log_bytes_read": 18342,
    "log_files_read": 6,
    "scan_limit_reached": false
  },
  "incidents": [
    {
      "incident": "php_fpm_capacity",
      "severity": "critical",
      "cause": "application_concurrency",
      "domain_scoped": true,
      "primary_endpoint": "/wp-admin/admin-ajax.php",
      "metrics": {
        "capacity_events": 12,
        "configured_max_children": 65,
        "unique_clients": 4
      },
      "recommendations": ["Measure worker memory before changing pool capacity"]
    }
  ]
}
```

Use normal terminal output when an engineer needs the bounded evidence and log source context. Treat that output as sensitive incident data.

## Safety model

The default mode is `--inspect` and does not mutate system configuration. `--plan` adds proposed actions and rollback guidance without making changes. `--execute` is fail-closed: modules must explicitly implement and opt in to an action, otherwise the command returns exit code `2`. No module in v0.1.0 performs remediation.

By default, a completed diagnostic exits `0` even when it finds an incident. Automation can opt into policy enforcement with `--fail-on warning` or `--fail-on critical`: exit code `1` means the configured severity was reached, while `2` means execution was unsupported or command usage was invalid.

The JSON report is schema-versioned and intentionally excludes raw evidence, hostnames, client IP addresses, and customer filesystem paths. Human-readable reports can contain log evidence and should be handled as sensitive incident data.

Remote SSL inspection only connects to globally routable addresses. Diagnostic collection is bounded to 64 MiB per log, 512 files per scanned log directory, and 10,000 directories per discovery scan.

Each command also has a shared 512 MiB / 4,096-file log budget across all modules. Reports include collection counts and indicate when a scan ceiling was reached. Snapshot analysis does not follow paths that resolve outside `--root`. Explicit log timezone offsets are normalized to UTC; offset-free formats retain their source wall-clock time because those formats do not carry enough information to infer a timezone.

The SSL module validates the certificate chain and hostname using the system trust store after restricting DNS results to globally routable addresses. PHP-FPM capacity guidance is explicitly heuristic and uses peak observed process RSS; it is not a substitute for service-wide capacity modelling.

For live-host investigations, run as root so protected logs and complete service state are available. Non-root execution remains read-only but emits a warning that evidence may be incomplete. Service discovery recognizes common Debian/Ubuntu, RHEL-family, cPanel EA-PHP, MariaDB, and MySQL systemd unit names. Filesystem checks deduplicate the mounts backing `/`, `/var`, `/home`, and `/tmp`.

## Development

```bash
make setup
make check
make build
```

CI tests every supported Python minor version and separately enforces formatting, linting, typing, coverage, and package-build checks. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

MIT. See [LICENSE](LICENSE).
