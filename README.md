# Support DoKtor

Support DoKtor is a read-first Linux hosting diagnostic and recovery planning
engine for cPanel, CWP, and VPS environments.

It is designed to build an evidence-based incident report before an engineer
changes anything.

```bash
support-doctor investigate
support-doctor investigate --domain example.com --time "2026-08-26 03:17"
support-doctor php-fpm --inspect
support-doctor mysql --plan
support-doctor case-summary
```

The default mode is non-mutating. Remediation workflows are split into:

- `--inspect`: collect evidence only
- `--plan`: produce proposed actions and rollback notes
- `--execute`: reserved for approved, module-specific actions

This initial implementation focuses on safe diagnostics, report generation,
timeline reconstruction, and sanitized JSON suitable for later fleet analytics.
