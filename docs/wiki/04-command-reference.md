# Command reference

All commands accept the common options below.

| Option | Purpose |
| --- | --- |
| `--root PATH` | Analyze the live root or an alternate mounted snapshot |
| `--domain NAME` | Focus log correlation on one domain |
| `--time TIME` | Center a historical window; supports `YYYY-MM-DD HH:MM`, seconds, ISO, and explicit offsets |
| `--window MINUTES` | Minutes before and after `--time`; default `10` |
| `--inspect` | Evidence-only mode; default |
| `--plan` | Add proposed actions and rollback notes |
| `--execute` | Attempt explicitly implemented actions; otherwise fail closed |
| `--json` | Emit privacy-reduced structured output |
| `--fail-on warning\|critical` | Return `1` at the selected severity threshold |

## Commands

### `investigate`

Runs the broad default investigation: PHP-FPM, web traffic, database, mail, WordPress, and security logs, plus platform and health checks.

```bash
sudo support-doctor investigate
```

### `case-summary`

Produces a short engineer-ready summary based on the strongest incident from the broad investigation.

```bash
sudo support-doctor case-summary --domain example.com --time '2026-08-26 03:17'
```

### `web`

Summarizes Apache and Nginx access traffic, top endpoints, request counts, and client concentration.

### `apache` / `nginx`

Run the same traffic analysis scoped to only the selected web-server log family.

### `php-fpm`

Detects `pm.max_children` saturation, correlates request volume, and estimates capacity from observed peak process RSS when live process data is available. The result is a heuristic, not a tuning authorization.

### `mysql` / `mariadb`

Scans common MySQL/MariaDB error logs for corruption, connection, and resource anomalies. The aliases share diagnostic behavior.

### `mail`

Checks common Exim, syslog, and mail.log locations for authentication failures, spam rejections, DNSBL pressure, and queue warnings.

### `wordpress`

Detects WordPress roots and hot `admin-ajax.php`, `xmlrpc.php`, and `wp-cron.php` endpoints. Discovery is bounded and does not expose root paths in JSON.

### `security`

Checks common security logs for failed authentication, ModSecurity events, bans, suspicious activity, and related anomalies.

### `ssl`

Requires `--domain`. Resolves only globally routable addresses, applies DNS and connection timeouts, and validates the certificate chain and hostname.

```bash
support-doctor ssl --domain example.com
```

### `migration`

Reports a read-only migration readiness snapshot and, in plan mode, proposes inventory, backup, cutover, and rollback steps. It does not migrate anything.
