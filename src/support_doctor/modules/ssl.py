from __future__ import annotations

import ssl
import socket
import ipaddress
import re
from datetime import datetime

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
                    recommendations=[Recommendation("Run with --domain example.com", "Remote certificate inspection needs a hostname.")],
                )
            ]
        try:
            decoded = _fetch_public_certificate(context.domain)
        except Exception as exc:
            return [
                Incident(
                    key="ssl_connection_failed",
                    title="SSL connection failed",
                    severity=Severity.WARNING,
                    probable_cause="tls_handshake_or_network_failure",
                    affected_domain=context.domain,
                    evidence=[Evidence(context.domain, str(exc), Severity.WARNING)],
                    recommendations=[Recommendation("Validate DNS and web server TLS configuration", "The certificate could not be retrieved.")],
                )
            ]
        size = len(decoded)
        return [
            Incident(
                key="ssl_certificate_present",
                title="SSL certificate retrieved",
                severity=Severity.OK,
                probable_cause="no_incident_detected",
                affected_domain=context.domain,
                first_seen=datetime.now(),
                metrics={"certificate_der_bytes": size},
                evidence=[Evidence(context.domain, "TLS certificate was retrievable", Severity.OK)],
            )
        ]


def _fetch_public_certificate(domain: str) -> bytes:
    if len(domain) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", domain) or ".." in domain:
        raise ValueError("invalid TLS hostname")
    if domain.endswith("."):
        domain = domain[:-1]
    labels = domain.split(".")
    if not domain or any(
        len(label) > 63 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("invalid TLS hostname")

    addresses = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    public_addresses = []
    for _family, _socktype, _proto, _canonname, sockaddr in addresses:
        address = ipaddress.ip_address(sockaddr[0])
        if any((address.is_private, address.is_loopback, address.is_link_local, address.is_reserved, address.is_multicast)):
            continue
        public_addresses.append(sockaddr)
    if not public_addresses:
        raise ValueError("hostname resolves only to non-public addresses")

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    last_error = None
    for sockaddr in public_addresses:
        try:
            with socket.create_connection(sockaddr, timeout=4) as raw:
                with tls.wrap_socket(raw, server_hostname=domain) as connection:
                    return connection.getpeercert(binary_form=True)
        except OSError as exc:
            last_error = exc
    raise OSError(f"could not connect to any public address: {last_error}")
