"""Discoverability dimension analyzer (Dimension 1).

v1 checks (all mechanical except markdown_negotiation which is runtime):
  1. discoverability.robots_txt_present
  2. discoverability.robots_txt_user_agent_directive
  3. discoverability.sitemap_referenced
  4. discoverability.sitemap_valid
  5. discoverability.link_headers_present
  6. discoverability.llms_txt_present
  7. discoverability.llms_txt_structured
  8. discoverability.content_signals_directives
  9. discoverability.markdown_negotiation

Reads artifacts from the canonical ArtifactStore (CA003); writes none.
Weights sum to 1.0 per CA010. Missing artifacts produce NOT_DETECTED with
``reason="artifact_unavailable:..."`` per CA004.
"""

from __future__ import annotations

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
    Reference,
)


DIMENSION = DimensionId.discoverability


# Equal-weight v1 distribution: 9 checks → weight 1/9 each.
_V1_WEIGHT = 1.0 / 9


def _origin(url: str) -> str:
    """Return scheme://host (no path) for a URL."""
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return url.rstrip("/")
    return f"{p.scheme}://{p.netloc}"


def _evidence_from_artifact(art: Artifact, excerpt: str = "") -> ArtifactRef:
    return ArtifactRef(artifact_id=art.artifact_id, excerpt=excerpt)


def _not_detected(
    *,
    check_id: str,
    title: str,
    goal: str,
    severity: CheckSeverity,
    weight: float,
    reason: str,
    artifact: Artifact | None = None,
    mode: CheckMode = CheckMode.mechanical,
) -> CheckResult:
    """Helper: build a NOT_DETECTED result with upstream artifact reason (CA004)."""
    if artifact is not None:
        evidence = ArtifactRef(artifact_id=artifact.artifact_id, excerpt=artifact.capture_error)
    else:
        # No Artifact captured at all — synthesize a minimal HttpExchange-like
        # ArtifactRef pointing at the missing source. We use ArtifactRef with
        # an empty artifact_id when nothing exists; this is honest evidence.
        from webprobe.models import HttpExchange  # local import to keep top tight
        return CheckResult(
            dimension=DIMENSION,
            check_id=check_id,
            title=title,
            goal=goal,
            status=CheckStatus.not_detected,
            severity=severity,
            mode=mode,
            weight=weight,
            evidence=HttpExchange(method="GET", url="", status=None),
            reason=reason,
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id=check_id,
        title=title,
        goal=goal,
        status=CheckStatus.not_detected,
        severity=severity,
        mode=mode,
        weight=weight,
        evidence=evidence,
        reason=reason,
    )


# ============================================================================
# Individual check functions
# ============================================================================


def check_robots_txt_present(store: ArtifactStore, base_url: str) -> CheckResult:
    """1. robots.txt is present and valid."""
    robots_url = urljoin(_origin(base_url) + "/", "robots.txt")
    art = store.find(ArtifactType.robots_txt, robots_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected(
            check_id="discoverability.robots_txt_present",
            title="robots.txt present",
            goal="/robots.txt returns 200 with a valid robots.txt format",
            severity=CheckSeverity.warning,
            weight=_V1_WEIGHT,
            reason=(
                f"artifact_unavailable:robots_txt:{art.capture_error}"
                if art is not None and art.capture_error
                else "artifact_unavailable:robots_txt:not_captured"
            ),
            artifact=art,
        )

    # OK status. Check that it had at least the parser shape we expect.
    payload = art.payload or {}
    if not isinstance(payload, dict) or ("groups" not in payload):
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.robots_txt_present",
            title="robots.txt present",
            goal="/robots.txt returns 200 with a valid robots.txt format",
            status=CheckStatus.fail,
            severity=CheckSeverity.warning,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, "no parsed groups"),
            fix=Fix(
                action_type=FixActionType.modify_robots_rule,
                target=robots_url,
                payload={"reason": "robots.txt fetched but did not parse to expected shape"},
                summary="Make /robots.txt parseable (User-agent + Allow/Disallow rules)",
                references=[Reference(label="RFC 9309", rfc="9309")],
            ),
        )

    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.robots_txt_present",
        title="robots.txt present",
        goal="/robots.txt returns 200 with a valid robots.txt format",
        status=CheckStatus.pass_,
        severity=CheckSeverity.info,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, f"{len(payload.get('groups', []))} groups"),
    )


def check_robots_user_agent_directive(store: ArtifactStore, base_url: str) -> CheckResult:
    """2. robots.txt has at least one User-agent directive."""
    robots_url = urljoin(_origin(base_url) + "/", "robots.txt")
    art = store.find(ArtifactType.robots_txt, robots_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected(
            check_id="discoverability.robots_txt_user_agent_directive",
            title="robots.txt has User-agent rules",
            goal="robots.txt declares at least one User-agent group",
            severity=CheckSeverity.warning,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:robots_txt:not_captured",
            artifact=art,
        )

    groups = (art.payload or {}).get("groups", [])
    if groups:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.robots_txt_user_agent_directive",
            title="robots.txt has User-agent rules",
            goal="robots.txt declares at least one User-agent group",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, f"{len(groups)} group(s)"),
        )

    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.robots_txt_user_agent_directive",
        title="robots.txt has User-agent rules",
        goal="robots.txt declares at least one User-agent group",
        status=CheckStatus.fail,
        severity=CheckSeverity.warning,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, "no User-agent groups"),
        fix=Fix(
            action_type=FixActionType.add_robots_directive,
            target=robots_url,
            payload={"directive": "User-agent: *", "rules": ["Allow: /"]},
            summary="Add a User-agent group to /robots.txt (e.g. 'User-agent: *' + 'Allow: /')",
            references=[Reference(label="RFC 9309", rfc="9309")],
        ),
    )


def check_sitemap_referenced(store: ArtifactStore, base_url: str) -> CheckResult:
    """3. robots.txt references a Sitemap."""
    robots_url = urljoin(_origin(base_url) + "/", "robots.txt")
    art = store.find(ArtifactType.robots_txt, robots_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected(
            check_id="discoverability.sitemap_referenced",
            title="Sitemap referenced from robots.txt",
            goal="robots.txt includes a Sitemap directive",
            severity=CheckSeverity.warning,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:robots_txt:not_captured",
            artifact=art,
        )
    sitemaps = (art.payload or {}).get("sitemaps", [])
    if sitemaps:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.sitemap_referenced",
            title="Sitemap referenced from robots.txt",
            goal="robots.txt includes a Sitemap directive",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, f"{len(sitemaps)} Sitemap directive(s)"),
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.sitemap_referenced",
        title="Sitemap referenced from robots.txt",
        goal="robots.txt includes a Sitemap directive",
        status=CheckStatus.fail,
        severity=CheckSeverity.warning,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, "no Sitemap directive"),
        fix=Fix(
            action_type=FixActionType.add_robots_directive,
            target=robots_url,
            payload={"directive": "Sitemap", "value": urljoin(_origin(base_url) + "/", "sitemap.xml")},
            summary="Add 'Sitemap: <url-to-sitemap.xml>' to /robots.txt",
            references=[Reference(label="sitemaps.org", url="https://www.sitemaps.org/protocol.html")],
        ),
    )


def check_sitemap_valid(store: ArtifactStore, base_url: str) -> CheckResult:
    """4. The referenced sitemap fetches and parses to a valid urlset/sitemapindex."""
    # Look for ANY sitemap artifact under the origin (the URL was discovered from robots.txt).
    sitemaps = store.find_by_type(ArtifactType.sitemap)
    origin = _origin(base_url)
    relevant = [a for a in sitemaps if a.source_url.startswith(origin)]
    if not relevant:
        return _not_detected(
            check_id="discoverability.sitemap_valid",
            title="Sitemap is valid XML",
            goal="The referenced sitemap returns valid sitemap XML (urlset or sitemapindex)",
            severity=CheckSeverity.warning,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:sitemap:not_captured",
            artifact=None,
        )

    # If any sitemap parsed successfully, pass.
    ok_arts = [a for a in relevant if a.capture_status == CaptureStatus.ok and (a.payload or {}).get("kind") in ("urlset", "sitemapindex")]
    if ok_arts:
        a = ok_arts[0]
        kind = a.payload.get("kind")
        url_count = len(a.payload.get("urls", [])) if kind == "urlset" else len(a.payload.get("sitemaps", []))
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.sitemap_valid",
            title="Sitemap is valid XML",
            goal="The referenced sitemap returns valid sitemap XML",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(a, f"{kind}: {url_count} entries"),
        )

    a = relevant[0]
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.sitemap_valid",
        title="Sitemap is valid XML",
        goal="The referenced sitemap returns valid sitemap XML",
        status=CheckStatus.fail,
        severity=CheckSeverity.warning,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(a, a.capture_error or "invalid sitemap"),
        fix=Fix(
            action_type=FixActionType.other,
            target=a.source_url,
            payload={"reason": a.capture_error or "sitemap did not parse"},
            summary="Make the sitemap a valid <urlset> or <sitemapindex> per sitemaps.org",
            references=[Reference(label="sitemaps.org", url="https://www.sitemaps.org/protocol.html")],
        ),
    )


def check_link_headers_present(store: ArtifactStore, base_url: str) -> CheckResult:
    """5. Homepage exposes RFC 8288 Link headers (or via meta_tags artifact)."""
    home = base_url
    art = store.find(ArtifactType.meta_tags, home)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected(
            check_id="discoverability.link_headers_present",
            title="Link headers on homepage",
            goal="Homepage advertises agent resources via Link response headers (RFC 8288)",
            severity=CheckSeverity.suggestion,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:meta_tags:homepage_not_captured",
            artifact=art,
        )
    link_headers = (art.payload or {}).get("link_headers", [])
    if link_headers:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.link_headers_present",
            title="Link headers on homepage",
            goal="Homepage advertises agent resources via Link response headers (RFC 8288)",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, f"{len(link_headers)} Link header value(s)"),
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.link_headers_present",
        title="Link headers on homepage",
        goal="Homepage advertises agent resources via Link response headers (RFC 8288)",
        status=CheckStatus.fail,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, "no Link headers found"),
        fix=Fix(
            action_type=FixActionType.add_link_header,
            target=home,
            payload={
                "examples": [
                    '</.well-known/api-catalog>; rel="api-catalog"',
                    '</docs/api>; rel="service-doc"',
                ],
            },
            summary="Add Link response headers advertising agent resources",
            references=[Reference(label="RFC 8288", rfc="8288")],
        ),
    )


def check_llms_txt_present(store: ArtifactStore, base_url: str) -> CheckResult:
    """6. /llms.txt is reachable."""
    llms_url = urljoin(_origin(base_url) + "/", "llms.txt")
    art = store.find(ArtifactType.well_known, llms_url)
    if art is None:
        # Fallback: an http_response artifact for the URL is also acceptable signal.
        art = store.find(ArtifactType.http_response, llms_url)
    if art is None:
        return _not_detected(
            check_id="discoverability.llms_txt_present",
            title="llms.txt present",
            goal="/llms.txt provides a structured AI-agent summary of the site",
            severity=CheckSeverity.suggestion,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:llms_txt:not_captured",
            artifact=None,
        )
    if art.capture_status == CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.llms_txt_present",
            title="llms.txt present",
            goal="/llms.txt provides a structured AI-agent summary of the site",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, "200 OK"),
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.llms_txt_present",
        title="llms.txt present",
        goal="/llms.txt provides a structured AI-agent summary of the site",
        status=CheckStatus.fail,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, art.capture_error or ""),
        fix=Fix(
            action_type=FixActionType.add_well_known_resource,
            target=llms_url,
            payload={"format": "markdown", "purpose": "AI-agent summary of the site"},
            summary="Publish /llms.txt with a structured markdown summary of the site",
            references=[Reference(label="llms.txt spec", url="https://llmstxt.org/")],
        ),
    )


def check_llms_txt_structured(store: ArtifactStore, base_url: str) -> CheckResult:
    """7. /llms.txt has markdown structure (headings + sections)."""
    llms_url = urljoin(_origin(base_url) + "/", "llms.txt")
    art = store.find(ArtifactType.well_known, llms_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected(
            check_id="discoverability.llms_txt_structured",
            title="llms.txt is structured markdown",
            goal="/llms.txt has at least one heading and at least one section body",
            severity=CheckSeverity.suggestion,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:llms_txt:not_captured",
            artifact=art,
        )

    body = ""
    if art.raw_bytes is not None:
        try:
            body = art.raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            body = ""
    body = body or (art.payload or {}).get("body", "")

    has_heading = any(line.lstrip().startswith("#") for line in body.splitlines())
    has_section = sum(1 for line in body.splitlines() if line.strip()) >= 3

    if has_heading and has_section:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.llms_txt_structured",
            title="llms.txt is structured markdown",
            goal="/llms.txt has at least one heading and section body",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, "structured markdown"),
        )

    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.llms_txt_structured",
        title="llms.txt is structured markdown",
        goal="/llms.txt has at least one heading and section body",
        status=CheckStatus.fail,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, "no headings or empty body"),
        fix=Fix(
            action_type=FixActionType.add_well_known_resource,
            target=llms_url,
            payload={"format": "markdown_with_headings"},
            summary="Add markdown headings (# Title, ## Section) and section bodies to /llms.txt",
            references=[Reference(label="llms.txt spec", url="https://llmstxt.org/")],
        ),
    )


def check_content_signals_directives(store: ArtifactStore, base_url: str) -> CheckResult:
    """8. robots.txt declares Content-Signal directives."""
    robots_url = urljoin(_origin(base_url) + "/", "robots.txt")
    art = store.find(ArtifactType.robots_txt, robots_url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected(
            check_id="discoverability.content_signals_directives",
            title="Content-Signal directives in robots.txt",
            goal="robots.txt declares ai-train / search / ai-input preferences",
            severity=CheckSeverity.suggestion,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:robots_txt:not_captured",
            artifact=art,
        )
    signals = (art.payload or {}).get("content_signals", [])
    if signals:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.content_signals_directives",
            title="Content-Signal directives in robots.txt",
            goal="robots.txt declares ai-train / search / ai-input preferences",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, f"{len(signals)} Content-Signal directive(s)"),
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.content_signals_directives",
        title="Content-Signal directives in robots.txt",
        goal="robots.txt declares ai-train / search / ai-input preferences",
        status=CheckStatus.fail,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, "no Content-Signal directives"),
        fix=Fix(
            action_type=FixActionType.add_robots_directive,
            target=robots_url,
            payload={"directive": "Content-Signal", "value": "ai-train=yes, search=yes, ai-input=yes"},
            summary="Add 'Content-Signal: ai-train=..., search=..., ai-input=...' to /robots.txt",
            references=[Reference(label="contentsignals.org", url="https://contentsignals.org/")],
        ),
    )


def check_markdown_negotiation(store: ArtifactStore, base_url: str) -> CheckResult:
    """9. Homepage supports Accept: text/markdown content negotiation (runtime)."""
    # Look for an http_response artifact with content-type=text/markdown for the base URL.
    art = store.find(ArtifactType.http_response, base_url)
    if art is None:
        return _not_detected(
            check_id="discoverability.markdown_negotiation",
            title="Markdown content negotiation",
            goal="GET / with Accept: text/markdown returns Content-Type: text/markdown",
            severity=CheckSeverity.suggestion,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:http_response:homepage_not_captured",
            artifact=None,
            mode=CheckMode.runtime,
        )
    headers = (art.payload or {}).get("headers", {}) or {}
    content_type = headers.get("content-type", "") or headers.get("Content-Type", "")
    is_markdown = "text/markdown" in content_type.lower()
    if is_markdown:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.markdown_negotiation",
            title="Markdown content negotiation",
            goal="GET / with Accept: text/markdown returns Content-Type: text/markdown",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.runtime,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, content_type),
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.markdown_negotiation",
        title="Markdown content negotiation",
        goal="GET / with Accept: text/markdown returns Content-Type: text/markdown",
        status=CheckStatus.fail,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.runtime,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, content_type or "no content-type"),
        fix=Fix(
            action_type=FixActionType.add_response_header,
            target=base_url,
            payload={"accept": "text/markdown", "expected_content_type": "text/markdown"},
            summary="Negotiate text/markdown when Accept: text/markdown is requested",
            references=[Reference(label="Cloudflare Markdown for Agents", url="https://blog.cloudflare.com/")],
        ),
    )


# ============================================================================
# Analyzer
# ============================================================================


class DiscoverabilityAnalyzer:
    """Discoverability dimension; matches the scheduler's Analyzer protocol."""

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
            check_robots_txt_present(store, base_url),
            check_robots_user_agent_directive(store, base_url),
            check_sitemap_referenced(store, base_url),
            check_sitemap_valid(store, base_url),
            check_link_headers_present(store, base_url),
            check_llms_txt_present(store, base_url),
            check_llms_txt_structured(store, base_url),
            check_content_signals_directives(store, base_url),
            check_markdown_negotiation(store, base_url),
        ]
        elapsed = (time.perf_counter() - t0) * 1000.0
        for r in results:
            r.elapsed_ms = max(r.elapsed_ms, elapsed / len(results))
        return results


__all__ = [
    "DIMENSION",
    "DiscoverabilityAnalyzer",
    "check_robots_txt_present",
    "check_robots_user_agent_directive",
    "check_sitemap_referenced",
    "check_sitemap_valid",
    "check_link_headers_present",
    "check_llms_txt_present",
    "check_llms_txt_structured",
    "check_content_signals_directives",
    "check_markdown_negotiation",
]
