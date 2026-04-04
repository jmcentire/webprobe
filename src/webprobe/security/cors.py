"""CORS misconfiguration checks."""

from __future__ import annotations

from webprobe.models import (
    AuthContext,
    ResponseHeaders,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)


def check_cors(url: str, headers: ResponseHeaders, auth_ctx: AuthContext) -> list[SecurityFinding]:
    """Check for CORS misconfigurations."""
    findings: list[SecurityFinding] = []
    h = {k.lower(): v for k, v in headers.raw.items()}

    acao = h.get("access-control-allow-origin", "")
    if acao == "*":
        acac = h.get("access-control-allow-credentials", "")
        if acac.lower() == "true":
            findings.append(SecurityFinding(
                category=SecurityCategory.cors,
                severity=SecuritySeverity.critical,
                title="CORS allows any origin with credentials",
                detail="Access-Control-Allow-Origin: * with Allow-Credentials: true. Any site can make authenticated requests.",
                evidence=f"ACAO={acao}, ACAC={acac}",
                url=url,
                auth_context=auth_ctx,
            ))
        else:
            findings.append(SecurityFinding(
                category=SecurityCategory.cors,
                severity=SecuritySeverity.low,
                title="CORS allows any origin",
                detail="Access-Control-Allow-Origin: * -- any site can read responses (without credentials).",
                evidence=f"ACAO={acao}",
                url=url,
                auth_context=auth_ctx,
            ))

    return findings
