# Security policy

## Supported versions

Until the first stable release, security fixes are applied to the latest revision of the default branch only.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's **Security** tab and select **Report a vulnerability** to submit a private advisory to the maintainers. Include affected versions, reproduction steps, impact, and any suggested mitigation. Avoid attaching real customer logs or credentials; use minimal synthetic fixtures.

Expect an acknowledgement within five business days. Disclosure timelines will be coordinated after impact and remediation are understood.

## Operational scope

Support DoKtor reads privileged host data and its human-readable output can contain sensitive log material. Run only on systems you are authorized to inspect, restrict report access, and remove reports according to your incident-data retention policy.

For live investigations, use a restrictive `umask` before redirecting human-readable output, store reports in an access-controlled incident directory, transfer them only through approved channels, and delete temporary copies after the incident. Prefer `--json` for automation and ticketing because it omits raw evidence and host/customer identifiers; still review downstream systems' retention and access controls.
