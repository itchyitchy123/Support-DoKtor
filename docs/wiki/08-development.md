# Development and release process

## Local setup

```bash
python3 -m venv .venv
. .venv/bin/activate
make setup
```

## Quality gates

```bash
make format
make check
```

`make check` runs formatting validation, Ruff linting, dependency checks, mypy, unit tests with coverage, and an isolated package build.

## Testing expectations

Behavior changes should include tests for:

- normal and malformed log records
- compressed and rotated logs
- permission failures
- offline/live separation
- snapshot boundary and symlink behavior
- structured-output privacy
- exit-code and fail-closed behavior
- network validation and timeout behavior

Never use production logs, real domains, customer paths, credentials, certificates, or snapshots in fixtures.

## Code review checklist

- Does the change mutate anything in inspect or plan mode?
- Does execution remain explicitly opt-in and fail closed?
- Is live-host state kept separate from offline-root state?
- Are external connections bounded and restricted?
- Are reads bounded by file, byte, directory, and time limits?
- Does human output remain terminal-safe?
- Does JSON avoid identifiers and raw evidence?
- Are operator-visible failure modes documented?
- Is rollback guidance present for proposed changes?

## Release checklist

1. Update the changelog.
2. Run `make check` on supported Python versions where practical.
3. Inspect the sdist and wheel contents.
4. Smoke-test the installed wheel in a clean environment.
5. Review README examples for privacy and correctness.
6. Tag only after CI passes on the intended commit.

## Commit style

Use imperative, outcome-oriented commit messages, for example:

```text
Harden offline snapshot isolation
Document PHP-FPM incident runbook
Add sanitized report schema metadata
```
