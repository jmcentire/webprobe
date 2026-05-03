"""Agentic Commerce dimension analyzer (Dimension 6).

v1 informational checks (5, all mechanical). Per the AUDIT_DIMENSIONS plan,
agentic-commerce protocols are early-stage; absence is informational
(severity=info), presence is recognized.

  agentic_commerce.x402_payment_required        — endpoints respond 402 with payment requirements
  agentic_commerce.x402_bazaar_discovery        — Bazaar discovery resources reachable
  agentic_commerce.mpp_openapi_extensions       — OpenAPI has x-payment-info on payable ops
  agentic_commerce.ucp_profile                  — /.well-known/ucp profile present
  agentic_commerce.acp_discovery                — /.well-known/acp.json valid
"""

from __future__ import annotations

import json
import time
from urllib.parse import urljoin, urlparse

from webprobe.artifact_store import ArtifactStore
from webprobe.models import (
    Artifact,
    ArtifactRef,
    ArtifactType,
    CaptureStatus,
    CheckMode,
    CheckResult,
    CheckSeverity,
    CheckStatus,
    DimensionId,
    Fix,
    FixActionType,
    HttpExchange,
    Reference,
)


DIMENSION = DimensionId.agentic_commerce
_V1_WEIGHT = 1.0 / 5  # 5 checks


def _origin(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return url.rstrip("/")
    return f"{p.scheme}://{p.netloc}"


def _decode(art: Artifact) -> object | None:
    body = ""
    if art.raw_bytes is not None:
        try:
            body = art.raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            body = ""
    body = body or (art.payload or {}).get("body", "")
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def check_x402_payment_required(store: ArtifactStore, base_url: str) -> CheckResult:
    """Look for any captured http_response artifact returning 402 with a payment body."""
    candidates = store.find_by_type(ArtifactType.http_response)
    origin = _origin(base_url)
    for art in candidates:
        if not art.source_url.startswith(origin):
            continue
        status = (art.payload or {}).get("status")
        if status == 402:
            return CheckResult(
                dimension=DIMENSION,
                check_id="agentic_commerce.x402_payment_required",
                title="x402 payment-required endpoint",
                goal="At least one endpoint returns HTTP 402 with payment requirements",
                status=CheckStatus.pass_,
                severity=CheckSeverity.info,
                mode=CheckMode.mechanical,
                weight=_V1_WEIGHT,
                evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=f"402 at {art.source_url}"),
            )
    return CheckResult(
        dimension=DIMENSION,
        check_id="agentic_commerce.x402_payment_required",
        title="x402 payment-required endpoint",
        goal="At least one endpoint returns HTTP 402 with payment requirements",
        status=CheckStatus.not_detected,
        severity=CheckSeverity.info,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=HttpExchange(method="GET", url=base_url, status=None),
        reason="artifact_unavailable:http_response:no_402_observed",
    )


def check_x402_bazaar_discovery(store: ArtifactStore, base_url: str) -> CheckResult:
    target = urljoin(_origin(base_url) + "/", "platform/v2/x402/discovery/resources")
    art = store.find(ArtifactType.well_known, target) or store.find(ArtifactType.http_response, target)
    if art is None:
        return CheckResult(
            dimension=DIMENSION,
            check_id="agentic_commerce.x402_bazaar_discovery",
            title="x402 Bazaar discovery resources",
            goal="Bazaar discovery endpoint is reachable",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=HttpExchange(method="GET", url=target, status=None),
            reason="artifact_unavailable:bazaar_discovery:not_captured",
        )
    if art.capture_status == CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id="agentic_commerce.x402_bazaar_discovery",
            title="x402 Bazaar discovery resources",
            goal="Bazaar discovery endpoint is reachable",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt="reachable"),
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="agentic_commerce.x402_bazaar_discovery",
        title="x402 Bazaar discovery resources",
        goal="Bazaar discovery endpoint is reachable",
        status=CheckStatus.not_detected,
        severity=CheckSeverity.info,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error),
        reason=f"artifact_unavailable:bazaar_discovery:{art.capture_error}",
    )


def check_mpp_openapi_extensions(store: ArtifactStore, base_url: str) -> CheckResult:
    """Look at OpenAPI artifact for x-payment-info extensions on operations."""
    openapis = store.find_by_type(ArtifactType.openapi)
    origin = _origin(base_url)
    relevant = [a for a in openapis if a.source_url.startswith(origin)]
    if not relevant:
        return CheckResult(
            dimension=DIMENSION,
            check_id="agentic_commerce.mpp_openapi_extensions",
            title="MPP x-payment-info extensions",
            goal="OpenAPI declares x-payment-info on payable operations",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=HttpExchange(method="GET", url=base_url, status=None),
            reason="artifact_unavailable:openapi:not_captured",
        )

    art = relevant[0]
    if art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id="agentic_commerce.mpp_openapi_extensions",
            title="MPP x-payment-info extensions",
            goal="OpenAPI declares x-payment-info on payable operations",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error),
            reason=f"artifact_unavailable:openapi:{art.capture_error}",
        )

    # The openapi parser puts operations in payload.operations; raw_bytes has the doc.
    raw = art.raw_bytes.decode("utf-8", errors="replace") if art.raw_bytes else ""
    has_payment = "x-payment-info" in raw
    if has_payment:
        return CheckResult(
            dimension=DIMENSION,
            check_id="agentic_commerce.mpp_openapi_extensions",
            title="MPP x-payment-info extensions",
            goal="OpenAPI declares x-payment-info on payable operations",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt="x-payment-info found"),
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="agentic_commerce.mpp_openapi_extensions",
        title="MPP x-payment-info extensions",
        goal="OpenAPI declares x-payment-info on payable operations",
        status=CheckStatus.not_detected,
        severity=CheckSeverity.info,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt="no x-payment-info"),
        reason="artifact_unavailable:mpp_extensions:not_present",
    )


def _well_known_check(
    store: ArtifactStore,
    base_url: str,
    *,
    check_id: str,
    title: str,
    goal: str,
    path: str,
    required_fields: list[str],
    references: list[Reference],
) -> CheckResult:
    target = urljoin(_origin(base_url) + "/", path)
    art = store.find(ArtifactType.well_known, target)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id=check_id,
            title=title,
            goal=goal,
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error) if art is not None else HttpExchange(method="GET", url=target, status=None),
            reason=f"artifact_unavailable:{path}:not_captured",
        )
    parsed = _decode(art)
    if isinstance(parsed, dict) and all(f in parsed for f in required_fields):
        return CheckResult(
            dimension=DIMENSION,
            check_id=check_id,
            title=title,
            goal=goal,
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=f"keys={sorted(parsed.keys())}"),
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id=check_id,
        title=title,
        goal=goal,
        status=CheckStatus.fail,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=f"missing fields or bad shape"),
        fix=Fix(
            action_type=FixActionType.add_well_known_resource,
            target=target,
            payload={"required_fields": required_fields},
            summary=f"Make {path} return JSON with {required_fields}",
            references=references,
        ),
    )


def check_ucp_profile(store: ArtifactStore, base_url: str) -> CheckResult:
    return _well_known_check(
        store, base_url,
        check_id="agentic_commerce.ucp_profile",
        title="UCP profile",
        goal="/.well-known/ucp declares protocol + services",
        path=".well-known/ucp",
        required_fields=["version"],
        references=[Reference(label="ucp.dev", url="https://ucp.dev/")],
    )


def check_acp_discovery(store: ArtifactStore, base_url: str) -> CheckResult:
    target = urljoin(_origin(base_url) + "/", ".well-known/acp.json")
    art = store.find(ArtifactType.well_known, target)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id="agentic_commerce.acp_discovery",
            title="ACP discovery",
            goal="/.well-known/acp.json valid with protocol.name=acp",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error) if art is not None else HttpExchange(method="GET", url=target, status=None),
            reason="artifact_unavailable:acp_discovery:not_captured",
        )
    parsed = _decode(art)
    if isinstance(parsed, dict):
        protocol = parsed.get("protocol") or {}
        if isinstance(protocol, dict) and protocol.get("name") == "acp" and parsed.get("api_base_url"):
            return CheckResult(
                dimension=DIMENSION,
                check_id="agentic_commerce.acp_discovery",
                title="ACP discovery",
                goal="/.well-known/acp.json valid with protocol.name=acp",
                status=CheckStatus.pass_,
                severity=CheckSeverity.info,
                mode=CheckMode.mechanical,
                weight=_V1_WEIGHT,
                evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=f"protocol.name={protocol.get('name')}"),
            )
    return CheckResult(
        dimension=DIMENSION,
        check_id="agentic_commerce.acp_discovery",
        title="ACP discovery",
        goal="/.well-known/acp.json valid with protocol.name=acp",
        status=CheckStatus.fail,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt="invalid ACP shape"),
        fix=Fix(
            action_type=FixActionType.add_well_known_resource,
            target=target,
            payload={"protocol": {"name": "acp"}, "api_base_url": "..."},
            summary="Publish /.well-known/acp.json with protocol.name='acp' and api_base_url",
            references=[Reference(label="agenticcommerce.dev", url="https://agenticcommerce.dev/")],
        ),
    )


class AgenticCommerceAnalyzer:
    name: str = DIMENSION.value
    mode_class: CheckMode = CheckMode.mechanical
    depends_on_analyzers: tuple[str, ...] = ()

    async def run(
        self,
        store: ArtifactStore,
        *,
        mode: str = "full",
        prior_results: list[CheckResult] | None = None,
        config: dict | None = None,
    ) -> list[CheckResult]:
        config = config or {}
        url = config.get("base_url") or ""
        t0 = time.perf_counter()
        results = [
            check_x402_payment_required(store, url),
            check_x402_bazaar_discovery(store, url),
            check_mpp_openapi_extensions(store, url),
            check_ucp_profile(store, url),
            check_acp_discovery(store, url),
        ]
        elapsed = (time.perf_counter() - t0) * 1000.0
        for r in results:
            r.elapsed_ms = max(r.elapsed_ms, elapsed / len(results))
        return results


__all__ = ["DIMENSION", "AgenticCommerceAnalyzer"]
