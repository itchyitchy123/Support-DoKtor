# Getting started

Support DoKtor is a Linux hosting diagnostic and recovery-planning CLI. It is designed to collect evidence first, make proposed changes explicit, and keep remediation disabled until a module has an intentionally implemented action.

## Install

Runtime requirements:

- Linux or a Linux filesystem snapshot
- Python 3.10 or newer
- Root access for complete live-host evidence

For an isolated installation:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install support-doctor
support-doctor --help
```

For a source checkout:

```bash
python -m pip install -e .
python -m pip install -e '.[dev]'
```

## First live investigation

Start with a read-only report:

```bash
sudo support-doctor investigate
```

Focus correlation on one site and one event window:

```bash
sudo support-doctor investigate \
  --domain example.com \
  --time '2026-08-26 03:17' \
  --window 10
```

The time window is inclusive and extends on both sides of the supplied center time. Explicit timezone offsets are normalized to UTC. Log formats without timezone information retain their source wall-clock time.

## Snapshot investigation

Mount or provide an authorized filesystem snapshot and point the tool at its root:

```bash
support-doctor investigate --root /mnt/incident-snapshot
```

Offline mode deliberately does not use live-host memory, services, process tables, hostnames, or package versions. Paths resolving outside the supplied root are skipped, including external symlinks.

## What to save

For an engineer-facing case, save the terminal report only in an access-controlled incident directory. For automation or ticketing, prefer sanitized JSON:

```bash
sudo support-doctor investigate --json > report.json
```

Human output may include bounded raw log evidence. JSON contains stable categories, counts, recommendations, and collection metadata, but omits raw evidence and host/customer identifiers.

## Before acting on a finding

1. Confirm the host, snapshot, domain, and time window.
2. Check the `Privileges` and `Collection` sections for incomplete evidence.
3. Read the evidence and recommendations together.
4. Confirm backups, rollback, and blast radius with the service owner.
5. Use `--plan` to record proposed actions without changing the host.

No v0.1.0 module performs remediation in `--execute` mode.
