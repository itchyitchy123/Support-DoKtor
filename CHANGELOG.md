# Changelog

All notable changes will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CI, developer tooling, contribution guidance, and security policy.
- Root-privilege visibility for potentially incomplete investigations.
- Swap, inode, and operational filesystem health checks.
- Cross-distribution systemd unit discovery for web, database, and PHP-FPM services.
- Read-only process-table fallback when systemd state is unavailable.
- Optional severity-based CLI exit policy for monitoring and automation.
- Built-wheel installation smoke test and dependency consistency check in CI.

### Changed

- Offline snapshot analysis no longer samples live-host PHP memory.
- Offline platform detection no longer falls back to the analyst host.
- Execute mode now fails closed when no supported action is available.
- JSON WordPress metrics no longer contain customer filesystem paths.
- WordPress discovery is bounded and does not follow directory symlinks.
- Report generation timestamps are emitted in UTC.
- PHP-FPM capacity estimates now include existing PHP processes plus calculated memory headroom.
- Mail and security log matching now avoids normal SpamAssassin, ModSecurity tracking, and Fail2Ban service activity.
- DNSBL lookup-pressure warnings are separated from confirmed spam rejections.
- Database detection reports the MariaDB distribution version instead of the MySQL client protocol version.

### Security

- SSL diagnostics now accept only globally routable resolved addresses.
- Ruff security rules now run as part of the standard lint gate.

## [0.1.0] - 2026-08-26

### Added

- Initial read-first hosting diagnostic and recovery-planning engine.
