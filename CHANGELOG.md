# Changelog

All notable changes will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CI, developer tooling, contribution guidance, and security policy.
- Public-facing package metadata, repository links, badges, and a sanitized report example.
- Schema versioning for structured JSON output.
- Root-privilege visibility for potentially incomplete investigations.
- Swap, inode, and operational filesystem health checks.
- Cross-distribution systemd unit discovery for web, database, and PHP-FPM services.
- Read-only process-table fallback when systemd state is unavailable.
- Optional severity-based CLI exit policy for monitoring and automation.
- Built-wheel installation smoke test and dependency consistency check in CI.
- Shared collection budgets, completeness metadata, and snapshot path-boundary enforcement.
- Versioned operator wiki covering architecture, commands, runbooks, privacy, troubleshooting, and releases.

### Changed

- Structured JSON now redacts filesystem paths and client addresses from health details and represents domain scope without emitting hostnames.
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
- Apache and Nginx module aliases now inspect only their selected log family.
- Historical timestamps with explicit offsets are normalized to UTC.
- PHP-FPM capacity estimates use peak observed RSS and are labeled heuristic.

### Security

- SSL diagnostics now accept only globally routable resolved addresses.
- SSL diagnostics validate certificate trust and hostname instead of merely retrieving a peer certificate.
- Ruff security rules now run as part of the standard lint gate.

## [0.1.0] - 2026-08-26

### Added

- Initial read-first hosting diagnostic and recovery-planning engine.
