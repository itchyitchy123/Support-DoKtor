# Incident-response runbooks

These runbooks describe a safe investigation sequence. They do not authorize production changes.

## PHP-FPM saturation

1. Capture an inspect report around the event:

   ```bash
   sudo support-doctor php-fpm --domain example.com --time '2026-08-26 03:17' --window 10
   ```

2. Confirm `configured_max_children`, capacity event count, request volume, and primary endpoint.
3. Check whether the report has live worker memory. Offline snapshots cannot provide it.
4. Do not increase `pm.max_children` from the report alone.
5. Review database latency, endpoint execution time, and client concentration.
6. Use `--plan` to record proposed next steps if a change review is required.

## Disk or inode pressure

1. Run `support-doctor investigate --json` and inspect Disk and Inodes health checks.
2. Confirm the affected mount in human output.
3. Check deleted-open files, logs, backups, cache directories, and inode-heavy mail or session trees with the host’s standard tools.
4. Preserve evidence before deleting anything.
5. Define a rollback or recovery path for every cleanup action outside Support DoKtor.

## Database errors

1. Run `support-doctor mysql --inspect` or `mariadb --inspect`.
2. If corruption or storage errors appear, stop before repair commands.
3. Confirm backup integrity and recovery objectives.
4. Use `--plan` for a written recovery sequence.
5. Involve the database owner before restarting or repairing the service.

## Mail delivery degradation

1. Run `support-doctor mail --time 'YYYY-MM-DD HH:MM'` for a bounded event window.
2. Separate authentication failures, queue warnings, spam rejection, and DNSBL pressure.
3. Check queue depth, DNS, SPF/DKIM/DMARC, reputation, and credential abuse with the mail operator.
4. Avoid treating normal SpamAssassin daemon activity as proof of spam rejection.

## Security activity

1. Run `support-doctor security --time 'YYYY-MM-DD HH:MM'`.
2. Treat findings as activity requiring validation, not as proof of compromise.
3. Correlate timestamps and sources with firewall, authentication, WAF, and hosting-panel data.
4. Preserve logs before rotation or containment changes.

## Snapshot reconstruction

1. Mount the snapshot read-only where possible.
2. Confirm the mount and permissions.
3. Run with `--root /mnt/snapshot`.
4. Review the `Privileges`, `Collection`, and offline-platform indicators.
5. Remember that live load, service status, process memory, and network checks are unavailable or intentionally separated.
