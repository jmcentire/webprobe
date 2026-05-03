"""Public-Facing Signals dimension analyzer (Dimension 7).

v1 checks: 16 mechanical (SEO + OG/Twitter + structure + trust pages) +
6 LLM judgments (SKIPPED in mechanical_only AND in v1 until LLM impl).

Mechanical (16):
  public_facing_signals.title_length
  public_facing_signals.meta_description_present
  public_facing_signals.canonical_url_present
  public_facing_signals.og_title_present
  public_facing_signals.og_description_present
  public_facing_signals.og_image_present
  public_facing_signals.og_image_dimensions
  public_facing_signals.twitter_card_present
  public_facing_signals.twitter_title_present
  public_facing_signals.twitter_image_present
  public_facing_signals.heading_hierarchy
  public_facing_signals.alt_text_coverage
  public_facing_signals.hreflang_consistency
  public_facing_signals.contact_page_reachable
  public_facing_signals.privacy_policy_reachable
  public_facing_signals.terms_reachable

LLM sub-pass (6, mode=llm; consensus-of-N gating per CA024):
  public_facing_signals.title_describes_page
  public_facing_signals.meta_description_compels_click
  public_facing_signals.hero_value_prop_legible
  public_facing_signals.cta_specificity
  public_facing_signals.social_proof_present
  public_facing_signals.pricing_transparency
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


DIMENSION = DimensionId.public_facing_signals
_NUM_CHECKS = 22
_W = 1.0 / _NUM_CHECKS


def _origin(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return url.rstrip("/")
    return f"{p.scheme}://{p.netloc}"


def _ref(art: Artifact, excerpt: str = "") -> ArtifactRef:
    return ArtifactRef(artifact_id=art.artifact_id, excerpt=excerpt)


def _meta(store: ArtifactStore, url: str) -> Artifact | None:
    art = store.find(ArtifactType.meta_tags, url)
    return art


def _meta_or_not_detected(check_id: str, title: str, goal: str, severity: CheckSeverity, store: ArtifactStore, url: str) -> tuple[Artifact, dict] | CheckResult:
    art = _meta(store, url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
            status=CheckStatus.not_detected, severity=severity, mode=CheckMode.mechanical, weight=_W,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error) if art is not None else HttpExchange(method="GET", url=url, status=None),
            reason=f"artifact_unavailable:meta_tags:{art.capture_error if art is not None else 'not_captured'}",
        )
    return art, art.payload or {}


def _pass(check_id: str, title: str, goal: str, art: Artifact, excerpt: str, severity: CheckSeverity = CheckSeverity.info) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
        status=CheckStatus.pass_, severity=severity, mode=CheckMode.mechanical, weight=_W,
        evidence=_ref(art, excerpt),
    )


def _fail(check_id: str, title: str, goal: str, art: Artifact, excerpt: str, fix: Fix, severity: CheckSeverity = CheckSeverity.suggestion) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
        status=CheckStatus.fail, severity=severity, mode=CheckMode.mechanical, weight=_W,
        evidence=_ref(art, excerpt), fix=fix,
    )


# ============================================================================
# Mechanical sub-pass
# ============================================================================


def check_title_length(store: ArtifactStore, url: str) -> CheckResult:
    r = _meta_or_not_detected("public_facing_signals.title_length", "Page <title> 30–60 chars",
                               "title length 30-60", CheckSeverity.suggestion, store, url)
    if isinstance(r, CheckResult):
        return r
    art, p = r
    n = p.get("title_length", 0)
    if 30 <= n <= 60:
        return _pass("public_facing_signals.title_length", "Page <title> 30–60 chars",
                     "title length 30-60", art, f"{n} chars")
    return _fail("public_facing_signals.title_length", "Page <title> 30–60 chars",
                 "title length 30-60", art, f"{n} chars",
                 Fix(action_type=FixActionType.add_meta_tag, target=url,
                     payload={"target": [30, 60]}, summary="Adjust <title> to 30–60 chars"))


def check_meta_description_present(store: ArtifactStore, url: str) -> CheckResult:
    r = _meta_or_not_detected("public_facing_signals.meta_description_present", "Meta description present",
                               "meta description 50–160 chars", CheckSeverity.suggestion, store, url)
    if isinstance(r, CheckResult):
        return r
    art, p = r
    desc_len = p.get("description_length", 0)
    if 50 <= desc_len <= 160:
        return _pass("public_facing_signals.meta_description_present", "Meta description present",
                     "meta description 50–160 chars", art, f"{desc_len} chars")
    return _fail("public_facing_signals.meta_description_present", "Meta description present",
                 "meta description 50–160 chars", art, f"{desc_len} chars",
                 Fix(action_type=FixActionType.add_meta_tag, target=url,
                     payload={"name": "description", "content_length_range": [50, 160]},
                     summary="Add or adjust <meta name=description> to 50–160 chars"))


def check_canonical_url_present(store: ArtifactStore, url: str) -> CheckResult:
    r = _meta_or_not_detected("public_facing_signals.canonical_url_present", "Canonical URL present",
                               "<link rel=canonical> declared", CheckSeverity.suggestion, store, url)
    if isinstance(r, CheckResult):
        return r
    art, p = r
    canonical = p.get("canonical", "")
    if canonical:
        return _pass("public_facing_signals.canonical_url_present", "Canonical URL present",
                     "<link rel=canonical>", art, canonical)
    return _fail("public_facing_signals.canonical_url_present", "Canonical URL present",
                 "<link rel=canonical>", art, "missing",
                 Fix(action_type=FixActionType.add_meta_tag, target=url,
                     payload={"rel": "canonical", "href": url},
                     summary="Add <link rel='canonical' href='...'> to <head>"))


def _og_field_check(field: str, store: ArtifactStore, url: str) -> CheckResult:
    cid = f"public_facing_signals.og_{field}_present"
    title = f"OpenGraph og:{field} present"
    goal = f"<meta property=og:{field}>"
    r = _meta_or_not_detected(cid, title, goal, CheckSeverity.suggestion, store, url)
    if isinstance(r, CheckResult):
        return r
    art, p = r
    val = (p.get("og") or {}).get(field, "")
    if val:
        return _pass(cid, title, goal, art, val[:100])
    return _fail(cid, title, goal, art, "missing",
                 Fix(action_type=FixActionType.add_meta_tag, target=url,
                     payload={"property": f"og:{field}"},
                     summary=f"Add <meta property='og:{field}' content='...'>"))


def check_og_title_present(store: ArtifactStore, url: str) -> CheckResult:
    return _og_field_check("title", store, url)


def check_og_description_present(store: ArtifactStore, url: str) -> CheckResult:
    return _og_field_check("description", store, url)


def check_og_image_present(store: ArtifactStore, url: str) -> CheckResult:
    return _og_field_check("image", store, url)


def check_og_image_dimensions(store: ArtifactStore, url: str) -> CheckResult:
    """Informational: og:image:width and og:image:height declared."""
    r = _meta_or_not_detected("public_facing_signals.og_image_dimensions", "OpenGraph og:image dimensions",
                               "og:image:width + og:image:height", CheckSeverity.info, store, url)
    if isinstance(r, CheckResult):
        return r
    art, p = r
    og = p.get("og") or {}
    if og.get("image:width") and og.get("image:height"):
        return _pass("public_facing_signals.og_image_dimensions", "OpenGraph og:image dimensions",
                     "og:image:width + og:image:height", art, f"{og.get('image:width')}x{og.get('image:height')}")
    return CheckResult(
        dimension=DIMENSION, check_id="public_facing_signals.og_image_dimensions",
        title="OpenGraph og:image dimensions", goal="og:image:width + og:image:height",
        status=CheckStatus.not_detected, severity=CheckSeverity.info, mode=CheckMode.mechanical, weight=_W,
        evidence=_ref(art, "missing dimensions"),
        reason="artifact_unavailable:og_image_dimensions:not_declared",
    )


def _twitter_field_check(field: str, store: ArtifactStore, url: str) -> CheckResult:
    cid = f"public_facing_signals.twitter_{field}_present"
    title = f"Twitter twitter:{field} present"
    goal = f"<meta name=twitter:{field}>"
    r = _meta_or_not_detected(cid, title, goal, CheckSeverity.suggestion, store, url)
    if isinstance(r, CheckResult):
        return r
    art, p = r
    val = (p.get("twitter") or {}).get(field, "")
    if val:
        return _pass(cid, title, goal, art, val[:100])
    return _fail(cid, title, goal, art, "missing",
                 Fix(action_type=FixActionType.add_meta_tag, target=url,
                     payload={"name": f"twitter:{field}"},
                     summary=f"Add <meta name='twitter:{field}' content='...'>"))


def check_twitter_card_present(store: ArtifactStore, url: str) -> CheckResult:
    return _twitter_field_check("card", store, url)


def check_twitter_title_present(store: ArtifactStore, url: str) -> CheckResult:
    return _twitter_field_check("title", store, url)


def check_twitter_image_present(store: ArtifactStore, url: str) -> CheckResult:
    return _twitter_field_check("image", store, url)


def check_heading_hierarchy(store: ArtifactStore, url: str) -> CheckResult:
    r = _meta_or_not_detected("public_facing_signals.heading_hierarchy", "Heading hierarchy",
                               "exactly one h1; no skipped levels", CheckSeverity.suggestion, store, url)
    if isinstance(r, CheckResult):
        return r
    art, p = r
    headings = p.get("headings") or {}
    h1_count = len(headings.get("h1") or [])
    # Detect skipped levels: e.g. h2 used but h1 missing, h4 without h3, etc.
    levels_present = [int(k[1]) for k in ("h1", "h2", "h3", "h4", "h5", "h6") if headings.get(k)]
    skipped = False
    for i in range(len(levels_present) - 1):
        if levels_present[i + 1] - levels_present[i] > 1:
            skipped = True
            break
    if h1_count == 1 and not skipped:
        return _pass("public_facing_signals.heading_hierarchy", "Heading hierarchy",
                     "1 h1 + no skipped levels", art, f"levels={levels_present}")
    issues = []
    if h1_count != 1:
        issues.append(f"{h1_count} h1 elements")
    if skipped:
        issues.append("skipped heading level")
    return _fail("public_facing_signals.heading_hierarchy", "Heading hierarchy",
                 "1 h1 + no skipped levels", art, "; ".join(issues),
                 Fix(action_type=FixActionType.other, target=url,
                     payload={"h1_count": h1_count, "skipped_levels": skipped, "levels_present": levels_present},
                     summary="Use exactly one <h1> per page; don't skip heading levels"))


def check_alt_text_coverage(store: ArtifactStore, url: str) -> CheckResult:
    r = _meta_or_not_detected("public_facing_signals.alt_text_coverage", "Image alt text coverage",
                               "≥80% of images have meaningful alt", CheckSeverity.suggestion, store, url)
    if isinstance(r, CheckResult):
        return r
    art, p = r
    coverage = p.get("alt_text_coverage")
    if coverage is None:
        return CheckResult(
            dimension=DIMENSION, check_id="public_facing_signals.alt_text_coverage",
            title="Image alt text coverage", goal="≥80% of images have meaningful alt",
            status=CheckStatus.not_detected, severity=CheckSeverity.info, mode=CheckMode.mechanical, weight=_W,
            evidence=_ref(art, "no images on page"),
            reason="precondition_failed:no_images",
        )
    if coverage >= 0.8:
        return _pass("public_facing_signals.alt_text_coverage", "Image alt text coverage",
                     "≥80% of images have meaningful alt", art, f"coverage={coverage:.0%}")
    return _fail("public_facing_signals.alt_text_coverage", "Image alt text coverage",
                 "≥80% of images have meaningful alt", art, f"only {coverage:.0%}",
                 Fix(action_type=FixActionType.other, target=url,
                     payload={"current_coverage": coverage, "target": 0.8},
                     summary="Add meaningful alt text to images"))


def check_hreflang_consistency(store: ArtifactStore, url: str) -> CheckResult:
    """If hreflang declarations are present, they should pair: each language listed multiple times shouldn't be inconsistent."""
    r = _meta_or_not_detected("public_facing_signals.hreflang_consistency", "Hreflang consistency",
                               "if hreflang present, declarations are consistent", CheckSeverity.info, store, url)
    if isinstance(r, CheckResult):
        return r
    art, p = r
    alts = p.get("alternates") or []
    hreflangs = [a for a in alts if a.get("hreflang")]
    if not hreflangs:
        return CheckResult(
            dimension=DIMENSION, check_id="public_facing_signals.hreflang_consistency",
            title="Hreflang consistency", goal="if hreflang present, declarations are consistent",
            status=CheckStatus.not_detected, severity=CheckSeverity.info, mode=CheckMode.mechanical, weight=_W,
            evidence=_ref(art, "no hreflang declared"),
            reason="precondition_failed:no_hreflang",
        )
    langs = [a["hreflang"] for a in hreflangs]
    if len(langs) == len(set(langs)):
        return _pass("public_facing_signals.hreflang_consistency", "Hreflang consistency",
                     "no duplicate hreflang values", art, f"{len(langs)} declarations")
    dupes = [l for l in set(langs) if langs.count(l) > 1]
    return _fail("public_facing_signals.hreflang_consistency", "Hreflang consistency",
                 "no duplicate hreflang values", art, f"duplicates: {dupes}",
                 Fix(action_type=FixActionType.other, target=url,
                     payload={"duplicate_hreflangs": dupes},
                     summary="Each hreflang value should appear once across <link rel=alternate>"))


def _trust_page_check(slug: str, paths: list[str], store: ArtifactStore, base_url: str, severity: CheckSeverity = CheckSeverity.suggestion) -> CheckResult:
    """At least one of the given paths returns 200 (an http_response artifact with capture_status=ok and a 2xx)."""
    cid = f"public_facing_signals.{slug}_reachable"
    title = f"{slug.replace('_', ' ').title()} page reachable"
    goal = f"At least one of {paths} returns 2xx"
    origin = _origin(base_url)
    for p in paths:
        target = urljoin(origin + "/", p)
        art = store.find(ArtifactType.http_response, target)
        if art is None:
            continue
        if art.capture_status == CaptureStatus.ok:
            status = (art.payload or {}).get("status", 0)
            if status and 200 <= int(status) < 400:
                return _pass(cid, title, goal, art, f"{p} → {status}")
    # None reachable
    return CheckResult(
        dimension=DIMENSION, check_id=cid, title=title, goal=goal,
        status=CheckStatus.not_detected, severity=severity, mode=CheckMode.mechanical, weight=_W,
        evidence=HttpExchange(method="GET", url=urljoin(origin + "/", paths[0]), status=None),
        reason=f"artifact_unavailable:{slug}:none_of_{len(paths)}_candidates_reachable",
    )


def check_contact_page_reachable(store: ArtifactStore, url: str) -> CheckResult:
    return _trust_page_check("contact", ["contact", "contact-us", "support", "about", "about-us"], store, url)


def check_privacy_policy_reachable(store: ArtifactStore, url: str) -> CheckResult:
    return _trust_page_check("privacy_policy", ["privacy", "privacy-policy", "legal/privacy"], store, url)


def check_terms_reachable(store: ArtifactStore, url: str) -> CheckResult:
    return _trust_page_check("terms", ["terms", "terms-of-service", "tos", "legal/terms"], store, url)


# ============================================================================
# LLM sub-pass — SKIPPED in v1
# ============================================================================


def _llm_skip(check_id: str, title: str, goal: str, mode: str) -> CheckResult:
    if mode == "mechanical_only":
        reason = "mechanical_only_mode_skips_llm_subpass"
    else:
        reason = "llm_judgment_implementation_pending_in_v1"
    return CheckResult(
        dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
        status=CheckStatus.skipped, severity=CheckSeverity.suggestion,
        mode=CheckMode.llm, weight=_W,
        evidence=HttpExchange(method="GET", url="", status=None),
        reason=reason,
    )


def check_title_describes_page(store: ArtifactStore, url: str, mode: str) -> CheckResult:
    return _llm_skip("public_facing_signals.title_describes_page", "Title describes the page (LLM)",
                     "title is descriptive, not generic", mode)


def check_meta_description_compels_click(store: ArtifactStore, url: str, mode: str) -> CheckResult:
    return _llm_skip("public_facing_signals.meta_description_compels_click", "Meta description compels click (LLM)",
                     "meta description is informative + actionable", mode)


def check_hero_value_prop_legible(store: ArtifactStore, url: str, mode: str) -> CheckResult:
    return _llm_skip("public_facing_signals.hero_value_prop_legible", "Hero value prop legible (LLM)",
                     "homepage hero states value prop in one sentence", mode)


def check_cta_specificity(store: ArtifactStore, url: str, mode: str) -> CheckResult:
    return _llm_skip("public_facing_signals.cta_specificity", "CTA specificity (LLM)",
                     "primary CTAs are specific, not generic", mode)


def check_social_proof_present(store: ArtifactStore, url: str, mode: str) -> CheckResult:
    return _llm_skip("public_facing_signals.social_proof_present", "Social proof present (LLM)",
                     "logos/testimonials/case studies/ratings present", mode)


def check_pricing_transparency(store: ArtifactStore, url: str, mode: str) -> CheckResult:
    return _llm_skip("public_facing_signals.pricing_transparency", "Pricing transparency (LLM, hybrid)",
                     "pricing-related route reachable + transparent", mode)


# ============================================================================
# Analyzer
# ============================================================================


class PublicFacingSignalsAnalyzer:
    name: str = DIMENSION.value
    mode_class: CheckMode = CheckMode.hybrid  # mechanical + LLM sub-passes
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
            check_title_length(store, url),
            check_meta_description_present(store, url),
            check_canonical_url_present(store, url),
            check_og_title_present(store, url),
            check_og_description_present(store, url),
            check_og_image_present(store, url),
            check_og_image_dimensions(store, url),
            check_twitter_card_present(store, url),
            check_twitter_title_present(store, url),
            check_twitter_image_present(store, url),
            check_heading_hierarchy(store, url),
            check_alt_text_coverage(store, url),
            check_hreflang_consistency(store, url),
            check_contact_page_reachable(store, url),
            check_privacy_policy_reachable(store, url),
            check_terms_reachable(store, url),
            check_title_describes_page(store, url, mode),
            check_meta_description_compels_click(store, url, mode),
            check_hero_value_prop_legible(store, url, mode),
            check_cta_specificity(store, url, mode),
            check_social_proof_present(store, url, mode),
            check_pricing_transparency(store, url, mode),
        ]
        elapsed = (time.perf_counter() - t0) * 1000.0
        for r in results:
            r.elapsed_ms = max(r.elapsed_ms, elapsed / len(results))
        return results


__all__ = ["DIMENSION", "PublicFacingSignalsAnalyzer"]
