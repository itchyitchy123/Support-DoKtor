# Troubleshooting and failure modes

## “Evidence may be incomplete”

Run as root for a live host when authorized. Without root, protected logs, service state, and process details may be unavailable. For snapshots, verify read and search permissions on the mount.

## “No incidents detected”

This means no supported pattern was found in the available evidence. It does not prove the service is healthy. Check:

- log paths for the distribution or panel
- event time and timezone
- collection limits
- rotation and compression formats
- access permissions
- whether the issue is represented in the supported module patterns

## Collection limit reached

The command stopped collecting after the shared byte, file, or directory budget. Narrow the scope with a module, `--domain`, and `--time`, or provide a smaller snapshot. Treat the report as incomplete.

## Offline root reports unknown service state

This is expected. Offline mode does not run the snapshot’s systemd or process table and does not substitute the analyst host’s state.

## SSL validation fails

Check DNS, public reachability, certificate chain, hostname coverage, system CA certificates, and egress policy. A private, loopback, link-local, documentation, or otherwise non-global address is rejected by design.

## JSON contains fewer details than terminal output

This is intentional. Use terminal output for authorized engineering investigation and JSON for reduced analytics or ticket metadata.

## Execute mode returns `2`

No current v0.1.0 module supports remediation. This is the expected fail-closed result, not a partial change.

## Diagnostic module failure

The report contains a warning incident with an `error_type`. Retry with a narrower scope, confirm filesystem readability, and check the human report for the module name. Do not assume an absent incident means collection succeeded.
