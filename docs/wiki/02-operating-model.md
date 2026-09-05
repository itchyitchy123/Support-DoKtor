# Operating model and safety

## Three modes

```text
--inspect  -> evidence collection only
--plan     -> evidence + proposed actions + rollback guidance
--execute  -> fail closed unless a module explicitly supports execution
```

### Inspect

Inspect mode reads system state and logs. It may perform the explicitly requested public TLS inspection for the `ssl` command, but it does not change service configuration, restart services, modify files, or alter firewall state.

### Plan

Plan mode attaches a `RecoveryPlan` to findings. A plan is not an approval and does not run its proposed actions. Operators must review backups, risk, maintenance windows, and rollback independently.

### Execute

Execute mode is intentionally conservative. If a module has no explicitly supported action, the command returns exit code `2` and reports that no supported configuration change was performed. An empty report also fails closed.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Collection completed; findings may still be present |
| `1` | `--fail-on warning` or `--fail-on critical` threshold was reached |
| `2` | Invalid usage, unsupported execution, or fail-closed execution result |

This lets monitoring choose its own policy without making every diagnostic finding a command failure.

## Blast radius

Live inspection can read privileged logs and process/service state. Human reports may contain sensitive evidence. The tool does not send reports anywhere, write a report file automatically, or mutate the target host.

The `ssl` command is the exception to purely local collection: it resolves the requested domain, rejects non-global addresses, applies bounded DNS and connection timeouts, and validates the certificate chain and hostname using the system trust store.

## Collection limits

There are several independent safety limits:

- 64 MiB decompressed input per log file.
- 512 files when a log directory is scanned.
- 512 MiB and 4,096 files across one command.
- 10,000 directories across one command.
- 100 WordPress roots returned by discovery.

Reports expose whether the shared collection limit was reached. A limited scan is incomplete evidence and should be treated accordingly.

## Snapshot boundaries

Every snapshot-derived log path is checked after symlink resolution against the canonical `--root`. WordPress discovery does the same and does not follow nested directory symlinks. This protects both privacy and the operator’s intended scope.
