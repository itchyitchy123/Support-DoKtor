# Support DoKtor

[![CI](https://github.com/itchyitchy123/Support-DoKtor/actions/workflows/ci.yml/badge.svg)](https://github.com/itchyitchy123/Support-DoKtor/actions/workflows/ci.yml)

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

## Safety model

The default mode is `--inspect` and does not mutate system configuration. `--plan` adds proposed actions and rollback guidance without making changes. `--execute` is fail-closed: modules must explicitly implement and opt in to an action, otherwise the command returns exit code `2`. No module in v0.1.0 performs remediation.

By default, a completed diagnostic exits `0` even when it finds an incident. Automation can opt into policy enforcement with `--fail-on warning` or `--fail-on critical`: exit code `1` means the configured severity was reached, while `2` means execution was unsupported or command usage was invalid.

The JSON report intentionally excludes raw evidence, hostnames, client IP addresses, and customer filesystem paths. Human-readable reports can contain log evidence and should be handled as sensitive incident data.

Remote SSL inspection only connects to globally routable addresses. Diagnostic collection is bounded to 64 MiB per log, 512 files per scanned log directory, and 10,000 directories per WordPress discovery scan.

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
