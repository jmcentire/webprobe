"""Bot Access & Identity dimension analyzer (Dimension 2).

v1 checks (both mechanical):
  1. bot_access.ai_bot_matrix — evaluate the configurable AI user-agent matrix
     (CA016) against the captured robots.txt; produces one summary CheckResult.
  2. bot_access.web_bot_auth_directory — fetch
     /.well-known/http-message-signatures-directory; valid JWKS structure.

Reads from the canonical ArtifactStore. Weights sum to 1.0 (CA010).
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
from webprobe.parsers import robots_txt as robots_parser


DIMENSION = DimensionId.bot_access

# Equal-weight v1 distribution: 2 checks → weight 0.5 each.
_V1_WEIGHT = 0.5


def _origin(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return url.rstrip("/")
    return f"{p.scheme}://{p.netloc}"


def check_ai_bot_matrix(store: ArtifactStore, base_url: str, config: dict) -> CheckResult:
    """1. Evaluate AI user-agent matrix against robots.txt (CA016).

    Operators may extend the matrix via config["ai_user_agent_matrix"] —
    a tuple/list of UA tokens. Default is robots_parser.DEFAULT_AI_USER_AGENT_MATRIX.

    Status policy:
      - PASS: every UA in the matrix has decision="allow" (sitewide).
      - FAIL: at least one UA is disallowed at "/".
      - NOT_DETECTED if robots.txt artifact is missing/failed.
    """
    robots_url = urljoin(_origin(base_url) + "/", "robots.txt")
    art = store.find(ArtifactType.robots_txt, robots_url)

    matrix = tuple(config.get("ai_user_agent_matrix") or robots_parser.DEFAULT_AI_USER_AGENT_MATRIX)

    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id="bot_access.ai_bot_matrix",
            title="AI bot allow/deny matrix",
            goal=f"All {len(matrix)} AI/search bots can access the site (sitewide)",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.warning,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(
                artifact_id=art.artifact_id if art is not None else "",
                excerpt=(art.capture_error if art is not None else "robots.txt not captured"),
            ),
            reason=(
                f"artifact_unavailable:robots_txt:{art.capture_error}"
                if art is not None and art.capture_error
                else "artifact_unavailable:robots_txt:not_captured"
            ),
        )

    decisions = robots_parser.evaluate_matrix(art.payload or {}, user_agents=matrix, target_path="/")
    disallowed = sorted([ua for ua, d in decisions.items() if d.get("decision") == "disallow"])
    allowed = sorted([ua for ua, d in decisions.items() if d.get("decision") == "allow"])
    no_rule = sorted([ua for ua, d in decisions.items() if d.get("decision") == "no_rule"])

    excerpt_parts: list[str] = [f"matrix_size={len(matrix)}"]
    if disallowed:
        excerpt_parts.append(f"disallowed={disallowed}")
    if no_rule:
        excerpt_parts.append(f"no_rule={no_rule}")
    if allowed:
        excerpt_parts.append(f"allowed={len(allowed)}")
    excerpt = "; ".join(excerpt_parts)

    if not disallowed:
        return CheckResult(
            dimension=DIMENSION,
            check_id="bot_access.ai_bot_matrix",
            title="AI bot allow/deny matrix",
            goal=f"All {len(matrix)} AI/search bots can access the site (sitewide)",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=excerpt),
        )

    return CheckResult(
        dimension=DIMENSION,
        check_id="bot_access.ai_bot_matrix",
        title="AI bot allow/deny matrix",
        goal=f"All {len(matrix)} AI/search bots can access the site (sitewide)",
        status=CheckStatus.fail,
        severity=CheckSeverity.warning,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=excerpt),
        fix=Fix(
            action_type=FixActionType.modify_robots_rule,
            target=robots_url,
            payload={
                "disallowed_user_agents": disallowed,
                "recommended": "Add 'User-agent: <bot>' + 'Allow: /' for each disallowed bot, OR adjust the sitewide rule.",
            },
            summary=f"Allow AI bots {disallowed} in /robots.txt (currently disallowed)",
            references=[
                Reference(label="RFC 9309", rfc="9309"),
                Reference(label="Cloudflare AI bot docs", url="https://developers.cloudflare.com/bots/concepts/bot/#ai-bots"),
            ],
        ),
    )


def check_web_bot_auth_directory(store: ArtifactStore, base_url: str) -> CheckResult:
    """2. /.well-known/http-message-signatures-directory returns valid JWKS."""
    target = urljoin(_origin(base_url) + "/", ".well-known/http-message-signatures-directory")
    art = store.find(ArtifactType.well_known, target)
    if art is None:
        # Informational-only check: absence is a soft 'not detected' rather than fail.
        return CheckResult(
            dimension=DIMENSION,
            check_id="bot_access.web_bot_auth_directory",
            title="Web Bot Auth directory",
            goal="Site identifies itself as a bot via Web Bot Auth (publishes JWKS at /.well-known/http-message-signatures-directory)",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=HttpExchange(method="GET", url=target, status=None),
            reason="artifact_unavailable:well_known_http_message_signatures_directory:not_captured",
        )

    if art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id="bot_access.web_bot_auth_directory",
            title="Web Bot Auth directory",
            goal="Site publishes valid JWKS at /.well-known/http-message-signatures-directory",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error),
            reason=f"artifact_unavailable:well_known_http_message_signatures_directory:{art.capture_error}",
        )

    # Validate JWKS shape (informational; absence is OK, malformed JWKS is FAIL).
    body = ""
    if art.raw_bytes is not None:
        try:
            body = art.raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            body = ""
    body = body or (art.payload or {}).get("body", "")

    try:
        parsed = json.loads(body) if body else None
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict) and isinstance(parsed.get("keys"), list) and parsed["keys"]:
        return CheckResult(
            dimension=DIMENSION,
            check_id="bot_access.web_bot_auth_directory",
            title="Web Bot Auth directory",
            goal="Site publishes valid JWKS at /.well-known/http-message-signatures-directory",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=f"JWKS with {len(parsed['keys'])} key(s)"),
        )

    return CheckResult(
        dimension=DIMENSION,
        check_id="bot_access.web_bot_auth_directory",
        title="Web Bot Auth directory",
        goal="Site publishes valid JWKS at /.well-known/http-message-signatures-directory",
        status=CheckStatus.fail,
        severity=CheckSeverity.warning,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=body[:200] if body else "empty body"),
        fix=Fix(
            action_type=FixActionType.add_well_known_resource,
            target=target,
            payload={"format": "JWKS", "shape": '{"keys": [...]}'},
            summary="Publish a valid JWKS at /.well-known/http-message-signatures-directory",
            references=[Reference(label="Cloudflare Web Bot Auth", url="https://blog.cloudflare.com/web-bot-auth/")],
        ),
    )


class BotAccessAnalyzer:
    """Bot Access dimension; matches the scheduler's Analyzer protocol."""

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
        base_url = config.get("base_url") or ""
        t0 = time.perf_counter()
        results = [
            check_ai_bot_matrix(store, base_url, config),
            check_web_bot_auth_directory(store, base_url),
        ]
        elapsed = (time.perf_counter() - t0) * 1000.0
        for r in results:
            r.elapsed_ms = max(r.elapsed_ms, elapsed / len(results))
        return results


__all__ = [
    "DIMENSION",
    "BotAccessAnalyzer",
    "check_ai_bot_matrix",
    "check_web_bot_auth_directory",
]
