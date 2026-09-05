# Privacy and security

## Data classes

| Output | Sensitivity | Intended use |
| --- | --- | --- |
| Human terminal report | High | Authorized engineers and incident records |
| Sanitized JSON | Reduced, not public by default | Fleet analytics, monitoring, ticket metadata |
| Snapshot filesystem | High | Authorized forensic or operations workflow |

## Human output

Human output may contain:

- log excerpts
- source paths
- domains supplied by the operator
- endpoint names
- service and process details

Protect it as incident data. Use a restrictive `umask`, controlled storage, approved transfer channels, and explicit retention/deletion procedures.

## Structured output

JSON has `schema_version: 1` and intentionally excludes:

- hostnames and requested domains
- client IPv4 and IPv6 addresses
- customer filesystem paths
- raw log evidence

It retains counts, categories, relative request endpoints, severity, recommendations, platform categories, and collection completeness. Downstream systems must still apply their own access controls and retention policies.

## Network behavior

Only the `ssl` command performs an external network probe. It requires a domain, validates hostname syntax, resolves in a bounded daemon thread, filters out non-global addresses, connects to vetted numeric addresses, uses a total connection deadline, and validates the certificate using the system trust store.

No shell is used for local command probes. Local subprocesses receive a minimal trusted environment with a fixed command path.

## Snapshot threat model

Snapshots may be incomplete, malformed, or intentionally hostile. Readers:

- bound files, bytes, and directories
- tolerate permission and decoding failures
- reject paths resolving outside the selected root
- avoid following directory symlinks during WordPress discovery
- do not execute files from the snapshot

The snapshot must still be mounted and handled by an authorized operator. Filesystem bugs in the underlying OS or mount layer are outside the application’s control.
