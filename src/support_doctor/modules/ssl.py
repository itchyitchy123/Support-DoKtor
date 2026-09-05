from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import threading
import time
from queue import Queue

from support_doctor.context import InvestigationContext
from support_doctor.models import Evidence, Incident, Recommendation, Severity

from .base import DiagnosticModule


class SslModule(DiagnosticModule):
    name = "ssl"

    def inspect(self, context: InvestigationContext) -> list[Incident]:
        if not context.domain:
            return [
                Incident(
                    key="ssl_domain_required",
                    title="SSL inspection requires --domain",
                    severity=Severity.INFO,
                    probable_cause="missing_domain",
                    recommendations=[
                        Recommendation(
                            "Run with --domain example.com", "Remote certificate inspection needs a hostname."
                        )
                    ],
                )
            ]
        try:
            decoded = _fetch_public_certificate(context.domain)
        except (OSError, ssl.SSLError, ValueError) as exc:
            return [
                Incident(
                    key="ssl_connection_failed",
                    title="SSL connection failed",
                    severity=Severity.WARNING,
                    probable_cause="tls_handshake_or_network_failure",
                    metrics={"validation_performed": True},
                    affected_domain=context.domain,
                    evidence=[Evidence(context.domain, str(exc), Severity.WARNING)],
                    recommendations=[
                        Recommendation(
                            "Validate DNS and web server TLS configuration", "The certificate could not be retrieved."
                        )
                    ],
                )
            ]
        size = len(decoded)
        return [
            Incident(
                key="ssl_certificate_present",
                title="SSL certificate retrieved and validated",
                severity=Severity.OK,
                probable_cause="no_incident_detected",
                affected_domain=context.domain,
                metrics={"certificate_der_bytes": size, "validation_performed": True},
                evidence=[Evidence(context.domain, "TLS certificate chain and hostname were validated", Severity.OK)],
            )
        ]


def _fetch_public_certificate(domain: str) -> bytes:
    if len(domain) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", domain) or ".." in domain:
        raise ValueError("invalid TLS hostname")
    if domain.endswith("."):
        domain = domain[:-1]
    labels = domain.split(".")
    if not domain or any(
        len(label) > 63 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) for label in labels
    ):
        raise ValueError("invalid TLS hostname")

    addresses = _resolve_addresses(domain)
    public_addresses: list[tuple[str, int]] = []
    for _family, _socktype, _proto, _canonname, sockaddr in addresses:
        address = ipaddress.ip_address(str(sockaddr[0]))
        if not address.is_global:
            continue
        # Connect to the vetted numeric address, not the hostname, so a second
        # DNS lookup cannot redirect the connection to a private target.
        target = (str(address), 443)
        if target not in public_addresses:
            public_addresses.append(target)
    if not public_addresses:
        raise ValueError("hostname resolves only to non-public addresses")

    tls = ssl.create_default_context()
    last_error: OSError | None = None
    deadline = time.monotonic() + 10
    for sockaddr in public_addresses:
        try:
            remaining = max(deadline - time.monotonic(), 0.1)
            with socket.create_connection(sockaddr, timeout=min(4, remaining)) as raw:
                with tls.wrap_socket(raw, server_hostname=domain) as connection:
                    certificate = connection.getpeercert(binary_form=True)
                    if certificate is None:
                        raise OSError("TLS peer did not provide a certificate")
                    return certificate
        except OSError as exc:
            last_error = exc
    raise OSError(f"could not connect to any public address: {last_error}")


def _resolve_addresses(domain: str) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    """Resolve without allowing a stuck system resolver to hang the CLI."""
    result: Queue[tuple[str, object]] = Queue(maxsize=1)

    def resolve() -> None:
        try:
            result.put(("ok", socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)))
        except OSError as exc:
            result.put(("error", exc))

    worker = threading.Thread(target=resolve, name="support-doctor-dns", daemon=True)
    worker.start()
    worker.join(timeout=4)
    if worker.is_alive():
        raise TimeoutError("DNS resolution timed out")
    status, value = result.get()
    if status == "error":
        if isinstance(value, OSError):
            raise value
        raise OSError("DNS resolution failed")
    if isinstance(value, list):
        return value
    raise OSError("DNS resolution returned no addresses")
