"""Discoverability dimension analyzer (Dimension 1).

Google Search generative AI features are grounded in normal Search indexing and
quality systems, not special AI-only files. This dimension therefore scores
Search fundamentals first and treats direct agent affordances as optional.

v1 checks (all mechanical except markdown_negotiation which is runtime):
  1. discoverability.robots_txt_present
  2. discoverability.robots_txt_user_agent_directive
  3. discoverability.sitemap_referenced
  4. discoverability.sitemap_valid
  5. discoverability.google_search_snippet_eligible
  6. discoverability.content_structure_signals
  7. discoverability.image_alt_text_signals
  8. discoverability.llms_txt_present
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
    HttpExchange,
    Reference,
)


DIMENSION = DimensionId.discoverability


# Equal-weight v1 distribution: 9 checks → weight 1/9 each.
_V1_WEIGHT = 1.0 / 9

_GOOGLE_AI_SEARCH_REF = Reference(
    label="Google Search Central: Optimizing for generative AI search",
    url="https://developers.google.com/search/docs/fundamentals/ai-optimization-guide",
)


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


def _homepage_meta_artifact(store: ArtifactStore, base_url: str) -> Artifact | None:
    return store.find(ArtifactType.meta_tags, base_url)


def _robots_meta_tokens(value: str) -> set[str]:
    tokens: set[str] = set()
    for part in value.lower().replace(";", ",").split(","):
        token = part.strip().replace(" ", "")
        if token:
            tokens.add(token)
    return tokens


def check_google_search_snippet_eligible(store: ArtifactStore, base_url: str) -> CheckResult:
    """5. Homepage does not opt out of Google indexing/snippets."""
    home = base_url
    art = _homepage_meta_artifact(store, home)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected(
            check_id="discoverability.google_search_snippet_eligible",
            title="Google Search snippet eligible",
            goal="Homepage is indexable and eligible to show a snippet in Google Search",
            severity=CheckSeverity.warning,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:meta_tags:homepage_not_captured",
            artifact=art,
        )
    robots_meta = ((art.payload or {}).get("robots_meta") or "").strip()
    tokens = _robots_meta_tokens(robots_meta)
    blocking = sorted(
        t for t in tokens
        if t in {"none", "noindex", "nosnippet"} or t.startswith("max-snippet:0")
    )
    if not blocking:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.google_search_snippet_eligible",
            title="Google Search snippet eligible",
            goal="Homepage is indexable and eligible to show a snippet in Google Search",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, robots_meta or "no restrictive robots meta"),
            references=[_GOOGLE_AI_SEARCH_REF],
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.google_search_snippet_eligible",
        title="Google Search snippet eligible",
        goal="Homepage is indexable and eligible to show a snippet in Google Search",
        status=CheckStatus.fail,
        severity=CheckSeverity.warning,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, f"restrictive robots meta: {blocking}"),
        fix=Fix(
            action_type=FixActionType.other,
            target=home,
            payload={"remove_robots_meta_tokens": blocking},
            summary="Remove robots meta directives that prevent Google indexing or snippets",
            references=[
                _GOOGLE_AI_SEARCH_REF,
                Reference(
                    label="Google robots meta tag",
                    url="https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag",
                ),
            ],
        ),
    )


def check_content_structure_signals(store: ArtifactStore, base_url: str) -> CheckResult:
    """6. Homepage has basic human-readable title and heading structure."""
    home = base_url
    art = _homepage_meta_artifact(store, home)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected(
            check_id="discoverability.content_structure_signals",
            title="Content structure signals",
            goal="Homepage has a title and heading structure that helps people navigate the content",
            severity=CheckSeverity.warning,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:meta_tags:homepage_not_captured",
            artifact=art,
        )
    payload = art.payload or {}
    title = (payload.get("title") or "").strip()
    headings = payload.get("headings") or {}
    h1s = headings.get("h1") or []
    if title and h1s:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.content_structure_signals",
            title="Content structure signals",
            goal="Homepage has a title and heading structure that helps people navigate the content",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, f"title={len(title)} chars; h1={len(h1s)}"),
            references=[_GOOGLE_AI_SEARCH_REF],
        )
    missing = []
    if not title:
        missing.append("title")
    if not h1s:
        missing.append("h1")
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.content_structure_signals",
        title="Content structure signals",
        goal="Homepage has a title and heading structure that helps people navigate the content",
        status=CheckStatus.fail,
        severity=CheckSeverity.warning,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, f"missing={missing}"),
        fix=Fix(
            action_type=FixActionType.other,
            target=home,
            payload={"missing": missing},
            summary="Add a clear page title and one primary H1 heading",
            references=[_GOOGLE_AI_SEARCH_REF],
        ),
    )


def check_image_alt_text_signals(store: ArtifactStore, base_url: str) -> CheckResult:
    """7. Images have meaningful alt text when images are present."""
    home = base_url
    art = _homepage_meta_artifact(store, home)
    if art is None or art.capture_status != CaptureStatus.ok:
        return _not_detected(
            check_id="discoverability.image_alt_text_signals",
            title="Image alt text signals",
            goal="Homepage images include meaningful alt text where images are present",
            severity=CheckSeverity.warning,
            weight=_V1_WEIGHT,
            reason="artifact_unavailable:meta_tags:homepage_not_captured",
            artifact=art,
        )
    payload = art.payload or {}
    total = int(payload.get("images_total") or 0)
    coverage = payload.get("alt_text_coverage")
    if total == 0:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.image_alt_text_signals",
            title="Image alt text signals",
            goal="Homepage images include meaningful alt text where images are present",
            status=CheckStatus.skipped,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, "no images present"),
            reason="not_applicable:no_images",
            references=[_GOOGLE_AI_SEARCH_REF],
        )
    if coverage is not None and float(coverage) >= 0.8:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.image_alt_text_signals",
            title="Image alt text signals",
            goal="Homepage images include meaningful alt text where images are present",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, f"{coverage:.0%} alt text coverage across {total} image(s)"),
            references=[_GOOGLE_AI_SEARCH_REF],
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.image_alt_text_signals",
        title="Image alt text signals",
        goal="Homepage images include meaningful alt text where images are present",
        status=CheckStatus.fail,
        severity=CheckSeverity.warning,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, f"{coverage or 0:.0%} alt text coverage across {total} image(s)"),
        fix=Fix(
            action_type=FixActionType.other,
            target=home,
            payload={"minimum_alt_text_coverage": 0.8},
            summary="Add meaningful alt text to important images",
            references=[_GOOGLE_AI_SEARCH_REF],
        ),
    )


def check_llms_txt_present(store: ArtifactStore, base_url: str) -> CheckResult:
    """8. /llms.txt is reachable as an optional non-Google agent affordance."""
    llms_url = urljoin(_origin(base_url) + "/", "llms.txt")
    art = store.find(ArtifactType.well_known, llms_url)
    if art is None:
        # Fallback: an http_response artifact for the URL is also acceptable signal.
        art = store.find(ArtifactType.http_response, llms_url)
    if art is None:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.llms_txt_present",
            title="llms.txt present (optional)",
            goal="/llms.txt may provide a structured summary for non-Google AI agents",
            status=CheckStatus.skipped,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=HttpExchange(method="GET", url=llms_url, status=None),
            reason="optional_agent_affordance_not_present:llms_txt",
            references=[_GOOGLE_AI_SEARCH_REF],
        )
    if art.capture_status == CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.llms_txt_present",
            title="llms.txt present (optional)",
            goal="/llms.txt may provide a structured summary for non-Google AI agents",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, "200 OK"),
            references=[
                _GOOGLE_AI_SEARCH_REF,
                Reference(label="llms.txt spec", url="https://llmstxt.org/"),
            ],
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.llms_txt_present",
        title="llms.txt present (optional)",
        goal="/llms.txt may provide a structured summary for non-Google AI agents",
        status=CheckStatus.fail,
        severity=CheckSeverity.suggestion,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, art.capture_error or ""),
        fix=Fix(
            action_type=FixActionType.add_well_known_resource,
            target=llms_url,
            payload={"format": "markdown", "purpose": "optional non-Google AI-agent summary"},
            summary="Publish /llms.txt only if direct AI-agent summaries are part of the site's agent strategy",
            references=[
                _GOOGLE_AI_SEARCH_REF,
                Reference(label="llms.txt spec", url="https://llmstxt.org/"),
            ],
        ),
    )


def check_markdown_negotiation(store: ArtifactStore, base_url: str) -> CheckResult:
    """9. Homepage optionally supports Accept: text/markdown content negotiation."""
    # Look for an http_response artifact with content-type=text/markdown for the base URL.
    art = store.find(ArtifactType.http_response, base_url)
    if art is None:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.markdown_negotiation",
            title="Markdown content negotiation (optional)",
            goal="GET / with Accept: text/markdown may return text/markdown for non-Google agents",
            status=CheckStatus.skipped,
            severity=CheckSeverity.info,
            mode=CheckMode.runtime,
            weight=_V1_WEIGHT,
            evidence=HttpExchange(method="GET", url=base_url, status=None),
            reason="optional_agent_affordance_not_probed:markdown_negotiation",
            references=[_GOOGLE_AI_SEARCH_REF],
        )
    headers = (art.payload or {}).get("headers", {}) or {}
    content_type = headers.get("content-type", "") or headers.get("Content-Type", "")
    is_markdown = "text/markdown" in content_type.lower()
    if is_markdown:
        return CheckResult(
            dimension=DIMENSION,
            check_id="discoverability.markdown_negotiation",
            title="Markdown content negotiation (optional)",
            goal="GET / with Accept: text/markdown may return text/markdown for non-Google agents",
            status=CheckStatus.pass_,
            severity=CheckSeverity.info,
            mode=CheckMode.runtime,
            weight=_V1_WEIGHT,
            evidence=_evidence_from_artifact(art, content_type),
            references=[_GOOGLE_AI_SEARCH_REF],
        )
    return CheckResult(
        dimension=DIMENSION,
        check_id="discoverability.markdown_negotiation",
        title="Markdown content negotiation (optional)",
        goal="GET / with Accept: text/markdown may return text/markdown for non-Google agents",
        status=CheckStatus.skipped,
        severity=CheckSeverity.info,
        mode=CheckMode.runtime,
        weight=_V1_WEIGHT,
        evidence=_evidence_from_artifact(art, content_type or "no content-type"),
        reason="optional_agent_affordance_not_present:markdown_negotiation",
        references=[_GOOGLE_AI_SEARCH_REF],
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
            check_google_search_snippet_eligible(store, base_url),
            check_content_structure_signals(store, base_url),
            check_image_alt_text_signals(store, base_url),
            check_llms_txt_present(store, base_url),
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
    "check_google_search_snippet_eligible",
    "check_content_structure_signals",
    "check_image_alt_text_signals",
    "check_llms_txt_present",
    "check_markdown_negotiation",
]
