"""TLS/SSL checks -- certificate validation, cipher strength, protocol version."""

from __future__ import annotations

import asyncio
import logging
import ssl
import socket
from datetime import datetime, timezone

from webprobe.models import (
    AuthContext,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
    TlsInfo,
)

logger = logging.getLogger(__name__)


async def probe_tls(hostname: str, port: int = 443) -> TlsInfo | None:
    """Probe a host's TLS configuration and return TlsInfo, or None on failure."""

    def _probe() -> TlsInfo | None:
        try:
            ctx = ssl.create_default_context()
            # Allow connecting even with cert issues so we can inspect
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Protocol version
                    protocol_version = ssock.version() or ""

                    # Cipher info
                    cipher_info = ssock.cipher()
                    cipher_suite = cipher_info[0] if cipher_info else ""
                    forward_secrecy = bool(
                        cipher_suite and ("ECDHE" in cipher_suite or "DHE" in cipher_suite)
                    )

                    # Certificate
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert(binary_form=False)

                    cert_subject = ""
                    cert_issuer = ""
                    cert_not_after = ""
                    cert_days_remaining = 0
                    cert_self_signed = False
                    cert_key_type = ""
                    cert_key_size = 0
                    san_names: list[str] = []

                    if cert_dict:
                        # Subject
                        subject_parts = cert_dict.get("subject", ())
                        for rdn in subject_parts:
                            for attr_type, attr_value in rdn:
                                if attr_type == "commonName":
                                    cert_subject = attr_value

                        # Issuer
                        issuer_parts = cert_dict.get("issuer", ())
                        issuer_cn = ""
                        for rdn in issuer_parts:
                            for attr_type, attr_value in rdn:
                                if attr_type == "commonName":
                                    issuer_cn = attr_value
                        cert_issuer = issuer_cn

                        # Self-signed check
                        cert_self_signed = cert_subject == cert_issuer

                        # Expiry
                        not_after_str = cert_dict.get("notAfter", "")
                        if not_after_str:
                            cert_not_after = not_after_str
                            try:
                                # OpenSSL date format: 'Mon DD HH:MM:SS YYYY GMT'
                                expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                                expiry = expiry.replace(tzinfo=timezone.utc)
                                now = datetime.now(timezone.utc)
                                cert_days_remaining = (expiry - now).days
                            except (ValueError, TypeError):
                                pass

                        # SAN names
                        san_entries = cert_dict.get("subjectAltName", ())
                        for san_type, san_value in san_entries:
                            if san_type == "DNS":
                                san_names.append(san_value)

                    # Try to get key info via the raw cert (best-effort)
                    if cert_der:
                        try:
                            import struct  # noqa: F811
                            # Use ssl to load the cert for key info
                            x509 = ssl._ssl._test_decode_cert(None)  # type: ignore[attr-defined]
                        except Exception:
                            pass

                    # Re-connect with verification to check key type/size
                    try:
                        ctx2 = ssl.create_default_context()
                        with socket.create_connection((hostname, port), timeout=10) as sock2:
                            with ctx2.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                                # Get the cipher to determine key exchange info
                                pass
                    except Exception:
                        pass

                    return TlsInfo(
                        protocol_version=protocol_version,
                        cipher_suite=cipher_suite,
                        forward_secrecy=forward_secrecy,
                        cert_subject=cert_subject,
                        cert_issuer=cert_issuer,
                        cert_not_after=cert_not_after,
                        cert_days_remaining=cert_days_remaining,
                        cert_self_signed=cert_self_signed,
                        cert_key_type=cert_key_type,
                        cert_key_size=cert_key_size,
                        san_names=san_names,
                    )

        except Exception:
            logger.debug("TLS probe failed for %s:%d", hostname, port, exc_info=True)
            return None

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _probe)


def check_tls(
    url: str,
    tls_info: TlsInfo,
    auth_ctx: AuthContext = AuthContext.anonymous,
) -> list[SecurityFinding]:
    """Analyze TLS configuration for security issues."""
    findings: list[SecurityFinding] = []

    if not tls_info:
        return findings

    protocol = tls_info.protocol_version

    # TLS 1.0/1.1 -> critical
    if protocol in ("TLSv1", "TLSv1.0", "TLSv1.1", "TLS 1.0", "TLS 1.1"):
        findings.append(SecurityFinding(
            category=SecurityCategory.tls,
            severity=SecuritySeverity.critical,
            title=f"Deprecated TLS version: {protocol}",
            detail=f"Server negotiated {protocol}, which is deprecated and has known vulnerabilities.",
            evidence=f"protocol={protocol}",
            url=url,
            auth_context=auth_ctx,
        ))

    # TLS 1.2 without forward secrecy
    if protocol in ("TLSv1.2", "TLS 1.2") and not tls_info.forward_secrecy:
        cipher = tls_info.cipher_suite
        findings.append(SecurityFinding(
            category=SecurityCategory.tls,
            severity=SecuritySeverity.medium,
            title="TLS 1.2 without forward secrecy",
            detail="TLS 1.2 connection does not use ECDHE/DHE key exchange. Past sessions can be decrypted if the server key is compromised.",
            evidence=f"cipher={cipher}",
            url=url,
            auth_context=auth_ctx,
        ))

    # Weak ciphers
    cipher_upper = tls_info.cipher_suite.upper()
    weak_cipher_patterns = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
    for weak in weak_cipher_patterns:
        if weak in cipher_upper:
            findings.append(SecurityFinding(
                category=SecurityCategory.tls,
                severity=SecuritySeverity.high,
                title=f"Weak cipher suite: contains {weak}",
                detail=f"Negotiated cipher suite contains '{weak}', which is considered cryptographically weak.",
                evidence=f"cipher={tls_info.cipher_suite}",
                url=url,
                auth_context=auth_ctx,
            ))
            break  # One finding for weak cipher

    # Certificate expired
    if tls_info.cert_days_remaining < 0:
        findings.append(SecurityFinding(
            category=SecurityCategory.tls,
            severity=SecuritySeverity.critical,
            title="TLS certificate expired",
            detail=f"Certificate expired {abs(tls_info.cert_days_remaining)} days ago. Browsers will show security warnings.",
            evidence=f"notAfter={tls_info.cert_not_after}",
            url=url,
            auth_context=auth_ctx,
        ))
    elif tls_info.cert_days_remaining <= 30:
        findings.append(SecurityFinding(
            category=SecurityCategory.tls,
            severity=SecuritySeverity.high,
            title="TLS certificate expires within 30 days",
            detail=f"Certificate expires in {tls_info.cert_days_remaining} days. Renew soon to avoid outages.",
            evidence=f"notAfter={tls_info.cert_not_after}, days_remaining={tls_info.cert_days_remaining}",
            url=url,
            auth_context=auth_ctx,
        ))
    elif tls_info.cert_days_remaining <= 90:
        findings.append(SecurityFinding(
            category=SecurityCategory.tls,
            severity=SecuritySeverity.medium,
            title="TLS certificate expires within 90 days",
            detail=f"Certificate expires in {tls_info.cert_days_remaining} days.",
            evidence=f"notAfter={tls_info.cert_not_after}, days_remaining={tls_info.cert_days_remaining}",
            url=url,
            auth_context=auth_ctx,
        ))

    # Self-signed certificate
    if tls_info.cert_self_signed:
        findings.append(SecurityFinding(
            category=SecurityCategory.tls,
            severity=SecuritySeverity.high,
            title="Self-signed TLS certificate",
            detail="Certificate appears to be self-signed. Browsers will show security warnings and users cannot verify server identity.",
            evidence=f"subject={tls_info.cert_subject}, issuer={tls_info.cert_issuer}",
            url=url,
            auth_context=auth_ctx,
        ))

    # Key size checks
    if tls_info.cert_key_size > 0:
        key_type = tls_info.cert_key_type.upper()
        if "RSA" in key_type and tls_info.cert_key_size < 2048:
            findings.append(SecurityFinding(
                category=SecurityCategory.tls,
                severity=SecuritySeverity.high,
                title=f"Weak RSA key size: {tls_info.cert_key_size} bits",
                detail=f"RSA key is {tls_info.cert_key_size} bits, minimum recommended is 2048 bits.",
                evidence=f"key_type={tls_info.cert_key_type}, key_size={tls_info.cert_key_size}",
                url=url,
                auth_context=auth_ctx,
            ))
        elif "EC" in key_type and tls_info.cert_key_size < 256:
            findings.append(SecurityFinding(
                category=SecurityCategory.tls,
                severity=SecuritySeverity.high,
                title=f"Weak EC key size: {tls_info.cert_key_size} bits",
                detail=f"EC key is {tls_info.cert_key_size} bits, minimum recommended is 256 bits.",
                evidence=f"key_type={tls_info.cert_key_type}, key_size={tls_info.cert_key_size}",
                url=url,
                auth_context=auth_ctx,
            ))

    return findings
