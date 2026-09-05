# Contributing

## Local workflow

1. Use Python 3.10 or newer and create an isolated virtual environment.
2. Run `make setup` to install the package and development tools.
3. Add tests for behavior changes, especially safety boundaries and log parsing.
4. Run `make check` before opening a pull request.

Documentation changes belong in the same pull request as the behavior they describe. Start with [docs/README.md](docs/README.md) when adding an operator-facing guide or runbook.

Keep pull requests focused and explain operational impact, failure modes, and rollback considerations. Never commit production logs, customer domains, IP addresses, credentials, certificates, or filesystem snapshots.

## Design expectations

- Inspection must remain non-mutating.
- Execution must fail closed and require explicit module support.
- Offline-root analysis must not mix in live-host state.
- External connections must reject non-public targets before connecting.
- Log readers must remain bounded and tolerate permission, encoding, rotation, and malformed-record failures.
- JSON intended for aggregation must not expose raw evidence or host/customer identifiers.
- Collection limits, incomplete evidence, and operator recovery steps must be documented when behavior changes.

Commit messages should be imperative and describe the outcome, for example `Harden offline snapshot isolation`.
