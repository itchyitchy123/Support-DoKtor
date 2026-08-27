# Changelog

All notable changes will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CI, developer tooling, contribution guidance, and security policy.

### Changed

- Offline snapshot analysis no longer samples live-host PHP memory.
- Execute mode now fails closed when no supported action is available.
- JSON WordPress metrics no longer contain customer filesystem paths.
- WordPress discovery is bounded and does not follow directory symlinks.
- Report generation timestamps are emitted in UTC.

### Security

- SSL diagnostics now accept only globally routable resolved addresses.

## [0.1.0] - 2026-08-26

### Added

- Initial read-first hosting diagnostic and recovery-planning engine.
