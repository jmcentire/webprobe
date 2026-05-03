"""Agent Surface dimension analyzer (Dimension 3).

v1 checks:
  agent_surface.api_catalog                   (RFC 9727, mechanical)
  agent_surface.openid_configuration          (mechanical)
  agent_surface.oauth_authorization_server    (mechanical)
  agent_surface.oauth_protected_resource      (RFC 9728, mechanical)
  agent_surface.mcp_server_card               (SEP-2127, mechanical; tries 3 paths)
  agent_surface.agent_skills_index            (mechanical)
  agent_surface.webmcp_runtime                (runtime)

Reads well_known artifacts from the canonical store. Each check is small —
fetch + JSON-parse + shape-validate.
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
    RuntimeProbe,
)

DIMENSION = DimensionId.agent_surface
_V1_WEIGHT = 1.0 / 7  # 7 checks


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


def _check_well_known_json(
    *,
    store: ArtifactStore,
    base_url: str,
    path: str,
    check_id: str,
    title: str,
    goal: str,
    required_fields: list[str],
    severity: CheckSeverity = CheckSeverity.suggestion,
    references: list[Reference] | None = None,
    fix_action: FixActionType = FixActionType.add_well_known_resource,
    candidate_paths: list[str] | None = None,
) -> CheckResult:
    """Generic shape: fetch /.well-known/<path>, expect JSON with required_fields."""
    paths = candidate_paths or [path]
    art: Artifact | None = None
    target = ""
    for p in paths:
        target = urljoin(_origin(base_url) + "/", p)
        candidate = store.find(ArtifactType.well_known, target)
        if candidate is not None:
            art = candidate
            break

    if art is None:
        # Absent — informational NOT_DETECTED, no fix (CA004).
        return CheckResult(
            dimension=DIMENSION,
            check_id=check_id,
            title=title,
            goal=goal,
            status=CheckStatus.not_detected,
            severity=severity,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=HttpExchange(method="GET", url=target, status=None),
            reason=f"artifact_unavailable:well_known:{path}",
        )

    if art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id=check_id,
            title=title,
            goal=goal,
            status=CheckStatus.not_detected,
            severity=severity,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error),
            reason=f"artifact_unavailable:well_known:{art.capture_error}",
        )

    parsed = _decode(art)
    if not isinstance(parsed, dict):
        return CheckResult(
            dimension=DIMENSION,
            check_id=check_id,
            title=title,
            goal=goal,
            status=CheckStatus.fail,
            severity=severity,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt="not JSON or not an object"),
            fix=Fix(
                action_type=fix_action,
                target=target,
                payload={"required_fields": required_fields, "format": "JSON object"},
                summary=f"Make {path} return a valid JSON object with {required_fields}",
                references=references or [],
            ),
        )

    missing = [f for f in required_fields if f not in parsed]
    if not missing:
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
        severity=severity,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=f"missing fields: {missing}"),
        fix=Fix(
            action_type=fix_action,
            target=target,
            payload={"missing_fields": missing, "required_fields": required_fields},
            summary=f"Add missing fields to {path}: {missing}",
            references=references or [],
        ),
    )


def check_api_catalog(store: ArtifactStore, base_url: str) -> CheckResult:
    return _check_well_known_json(
        store=store,
        base_url=base_url,
        path=".well-known/api-catalog",
        check_id="agent_surface.api_catalog",
        title="API Catalog (RFC 9727)",
        goal="/.well-known/api-catalog returns linkset+json",
        required_fields=["linkset"],
        severity=CheckSeverity.suggestion,
        references=[Reference(label="RFC 9727", rfc="9727")],
    )


def check_openid_configuration(store: ArtifactStore, base_url: str) -> CheckResult:
    return _check_well_known_json(
        store=store,
        base_url=base_url,
        path=".well-known/openid-configuration",
        check_id="agent_surface.openid_configuration",
        title="OpenID Connect discovery",
        goal="/.well-known/openid-configuration returns issuer + endpoints",
        required_fields=["issuer", "authorization_endpoint", "token_endpoint"],
        severity=CheckSeverity.suggestion,
        references=[Reference(label="OpenID Connect Discovery", url="https://openid.net/specs/openid-connect-discovery-1_0.html")],
    )


def check_oauth_authorization_server(store: ArtifactStore, base_url: str) -> CheckResult:
    return _check_well_known_json(
        store=store,
        base_url=base_url,
        path=".well-known/oauth-authorization-server",
        check_id="agent_surface.oauth_authorization_server",
        title="OAuth 2.0 authorization server metadata",
        goal="/.well-known/oauth-authorization-server returns issuer + endpoints (RFC 8414)",
        required_fields=["issuer", "authorization_endpoint"],
        severity=CheckSeverity.suggestion,
        references=[Reference(label="RFC 8414", rfc="8414")],
    )


def check_oauth_protected_resource(store: ArtifactStore, base_url: str) -> CheckResult:
    return _check_well_known_json(
        store=store,
        base_url=base_url,
        path=".well-known/oauth-protected-resource",
        check_id="agent_surface.oauth_protected_resource",
        title="OAuth Protected Resource Metadata (RFC 9728)",
        goal="/.well-known/oauth-protected-resource declares authorization_servers",
        required_fields=["resource", "authorization_servers"],
        severity=CheckSeverity.suggestion,
        references=[Reference(label="RFC 9728", rfc="9728")],
    )


def check_mcp_server_card(store: ArtifactStore, base_url: str) -> CheckResult:
    return _check_well_known_json(
        store=store,
        base_url=base_url,
        path=".well-known/mcp/server-card.json",
        candidate_paths=[
            ".well-known/mcp/server-card.json",
            ".well-known/mcp/server-cards.json",
            ".well-known/mcp.json",
        ],
        check_id="agent_surface.mcp_server_card",
        title="MCP Server Card",
        goal="/.well-known/mcp/server-card.json (or fallback) returns serverInfo + transport",
        required_fields=["serverInfo"],
        severity=CheckSeverity.suggestion,
        references=[Reference(label="SEP-2127", url="https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2127")],
    )


def check_agent_skills_index(store: ArtifactStore, base_url: str) -> CheckResult:
    return _check_well_known_json(
        store=store,
        base_url=base_url,
        path=".well-known/agent-skills/index.json",
        candidate_paths=[
            ".well-known/agent-skills/index.json",
            ".well-known/skills/index.json",
        ],
        check_id="agent_surface.agent_skills_index",
        title="Agent Skills index",
        goal="/.well-known/agent-skills/index.json declares skills array",
        required_fields=["skills"],
        severity=CheckSeverity.suggestion,
        references=[Reference(label="agentskills.io", url="https://agentskills.io/")],
    )


def check_webmcp_runtime(store: ArtifactStore, base_url: str) -> CheckResult:
    """Runtime check: did the page register tools via navigator.modelContext?"""
    # The capturer/runtime layer should write a `well_known`-typed artifact at
    # source_url=base_url+"#webmcp" (synthetic) when a WebMCP runtime probe
    # was performed. If absent, NOT_DETECTED.
    target = base_url + "#webmcp_runtime"
    art = store.find(ArtifactType.well_known, target)
    if art is None:
        return CheckResult(
            dimension=DIMENSION,
            check_id="agent_surface.webmcp_runtime",
            title="WebMCP runtime detection",
            goal="navigator.modelContext.provideContext() registers tools",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.runtime,
            weight=_V1_WEIGHT,
            evidence=RuntimeProbe(url=base_url, action="check_navigator.modelContext", observation={}),
            reason="artifact_unavailable:webmcp_runtime:not_probed",
        )

    payload = art.payload or {}
    has_tools = bool(payload.get("tools"))
    if has_tools:
        return CheckResult(
            dimension=DIMENSION,
            check_id="agent_surface.webmcp_runtime",
            title="WebMCP runtime detection",
            goal="navigator.modelContext.provideContext() registers tools",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.runtime,
            weight=_V1_WEIGHT,
            evidence=RuntimeProbe(url=base_url, action="check_navigator.modelContext", observation={"tools": payload.get("tools")}),
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="agent_surface.webmcp_runtime",
        title="WebMCP runtime detection",
        goal="navigator.modelContext.provideContext() registers tools",
        status=CheckStatus.fail,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.runtime,
        weight=_V1_WEIGHT,
        evidence=RuntimeProbe(url=base_url, action="check_navigator.modelContext", observation={"tools": []}),
        fix=Fix(
            action_type=FixActionType.other,
            target=base_url,
            payload={"api": "navigator.modelContext.provideContext", "shape": {"name": "...", "description": "...", "inputSchema": {}, "execute": "callback"}},
            summary="Call navigator.modelContext.provideContext() with tool definitions on page load",
            references=[Reference(label="WebMCP", url="https://webmachinelearning.github.io/")],
        ),
    )


class AgentSurfaceAnalyzer:
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
            check_api_catalog(store, url),
            check_openid_configuration(store, url),
            check_oauth_authorization_server(store, url),
            check_oauth_protected_resource(store, url),
            check_mcp_server_card(store, url),
            check_agent_skills_index(store, url),
            check_webmcp_runtime(store, url),
        ]
        elapsed = (time.perf_counter() - t0) * 1000.0
        for r in results:
            r.elapsed_ms = max(r.elapsed_ms, elapsed / len(results))
        return results


__all__ = ["DIMENSION", "AgentSurfaceAnalyzer"]
