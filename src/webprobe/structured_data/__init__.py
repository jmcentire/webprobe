"""Structured Data dimension analyzer (Dimension 5).

Generalizes the Shopify product check beyond products. v1 checks (15, all
mechanical):

  Product family (5):
    structured_data.product_name_present
    structured_data.product_description_present
    structured_data.product_image_present
    structured_data.product_offer_price_present
    structured_data.product_availability
    structured_data.product_aggregate_rating
    structured_data.product_variants

  Article family (3):
    structured_data.article_headline
    structured_data.article_author
    structured_data.article_datePublished

  Other types (4):
    structured_data.organization_name
    structured_data.faqpage_questions
    structured_data.recipe_basics

  Page-level (2):
    structured_data.page_title_length
    structured_data.json_ld_validity

Conditional checks (Product / Article / FAQPage / Recipe) return SKIPPED with
reason="schema_type_not_present" when the page has no node of that type —
this excludes them from the dimension's denominator (CA007 semantics).
"""

from __future__ import annotations

import time

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
from webprobe.parsers import json_ld as jl

DIMENSION = DimensionId.structured_data
_V1_WEIGHT = 1.0 / 15  # 15 checks, equal slice


def _ref_or_synthetic(art: Artifact | None, *, url: str = "") -> ArtifactRef | HttpExchange:
    if art is not None:
        return ArtifactRef(artifact_id=art.artifact_id, excerpt="")
    return HttpExchange(method="GET", url=url, status=None)


def _skip_no_schema(check_id: str, title: str, goal: str, severity: CheckSeverity, schema_name: str, artifact: Artifact | None) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION,
        check_id=check_id,
        title=title,
        goal=goal,
        status=CheckStatus.skipped,
        severity=severity,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_ref_or_synthetic(artifact),
        reason=f"schema_type_not_present:{schema_name}",
    )


def _not_detected_no_jsonld(check_id: str, title: str, goal: str, severity: CheckSeverity, artifact: Artifact | None) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION,
        check_id=check_id,
        title=title,
        goal=goal,
        status=CheckStatus.not_detected,
        severity=severity,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=_ref_or_synthetic(artifact),
        reason="artifact_unavailable:json_ld:not_captured" if artifact is None else f"artifact_unavailable:json_ld:{artifact.capture_error}",
    )


def _pass(check_id: str, title: str, goal: str, evidence_excerpt: str, art: Artifact, severity: CheckSeverity = CheckSeverity.info) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION,
        check_id=check_id,
        title=title,
        goal=goal,
        status=CheckStatus.pass_,
        severity=severity,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=evidence_excerpt),
    )


def _fail(check_id: str, title: str, goal: str, evidence_excerpt: str, art: Artifact, fix: Fix, severity: CheckSeverity = CheckSeverity.warning) -> CheckResult:
    return CheckResult(
        dimension=DIMENSION,
        check_id=check_id,
        title=title,
        goal=goal,
        status=CheckStatus.fail,
        severity=severity,
        mode=CheckMode.mechanical,
        weight=_V1_WEIGHT,
        evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=evidence_excerpt),
        fix=fix,
    )


_SCHEMA_REF = Reference(label="schema.org", url="https://schema.org/")


def _jsonld_artifact(store: ArtifactStore, url: str) -> Artifact | None:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return None
    return art


# ============================================================================
# Product family
# ============================================================================


def _product_node(art: Artifact | None) -> dict | None:
    if art is None or art.capture_status != CaptureStatus.ok:
        return None
    types = (art.payload or {}).get("types") or {}
    products = types.get("Product") or []
    return products[0] if products else None


def check_product_name_present(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.product_name_present", "Product.name present", "Product.name <150 chars", CheckSeverity.warning, art)
    p = _product_node(art)
    if p is None:
        return _skip_no_schema("structured_data.product_name_present", "Product.name present", "Product.name <150 chars", CheckSeverity.warning, "Product", art)
    name = jl.field_value(p, "name")
    if name and len(name) <= 150:
        return _pass("structured_data.product_name_present", "Product.name present", "Product.name <150 chars", f"name={name[:80]!r}", art)
    return _fail(
        "structured_data.product_name_present",
        "Product.name present",
        "Product.name present, ≤150 chars",
        evidence_excerpt=("missing" if not name else f"too long ({len(name)} chars)"),
        art=art,
        fix=Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "Product.name"}, summary="Add or shorten Product.name (≤150 chars)", references=[_SCHEMA_REF]),
    )


def check_product_description_present(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.product_description_present", "Product.description present", "≥20 words", CheckSeverity.warning, art)
    p = _product_node(art)
    if p is None:
        return _skip_no_schema("structured_data.product_description_present", "Product.description present", "≥20 words", CheckSeverity.warning, "Product", art)
    desc = jl.field_value(p, "description") or ""
    word_count = len(desc.split())
    if word_count >= 20:
        return _pass("structured_data.product_description_present", "Product.description present", "≥20 words", f"{word_count} words", art)
    return _fail(
        "structured_data.product_description_present",
        "Product.description present",
        "≥20 words",
        f"{word_count} words" if desc else "missing",
        art,
        Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "Product.description"}, summary="Add Product.description with ≥20 words", references=[_SCHEMA_REF]),
    )


def check_product_image_present(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.product_image_present", "Product.image present", "schema.org Product.image", CheckSeverity.warning, art)
    p = _product_node(art)
    if p is None:
        return _skip_no_schema("structured_data.product_image_present", "Product.image present", "schema.org Product.image", CheckSeverity.warning, "Product", art)
    image = p.get("image")
    if image:
        return _pass("structured_data.product_image_present", "Product.image present", "schema.org Product.image", "image present", art)
    return _fail("structured_data.product_image_present", "Product.image present", "schema.org Product.image", "missing", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "Product.image"}, summary="Add Product.image URL", references=[_SCHEMA_REF]))


def check_product_offer_price_present(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.product_offer_price_present", "Offer.price + priceCurrency", "schema.org Offer", CheckSeverity.warning, art)
    p = _product_node(art)
    if p is None:
        return _skip_no_schema("structured_data.product_offer_price_present", "Offer.price + priceCurrency", "schema.org Offer", CheckSeverity.warning, "Product", art)
    offers = jl.find_offers(p)
    for o in offers:
        if jl.has_field(o, "price") and jl.has_field(o, "priceCurrency"):
            return _pass("structured_data.product_offer_price_present", "Offer.price + priceCurrency", "schema.org Offer", "price+currency present", art)
    return _fail("structured_data.product_offer_price_present", "Offer.price + priceCurrency", "schema.org Offer with price + priceCurrency", "missing", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "Offer.price+priceCurrency"}, summary="Add Offer.price and Offer.priceCurrency", references=[_SCHEMA_REF]))


def check_product_availability(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.product_availability", "Offer.availability", "InStock|OutOfStock|PreOrder", CheckSeverity.warning, art)
    p = _product_node(art)
    if p is None:
        return _skip_no_schema("structured_data.product_availability", "Offer.availability", "InStock|OutOfStock|PreOrder", CheckSeverity.warning, "Product", art)
    valid = {"https://schema.org/InStock", "https://schema.org/OutOfStock", "https://schema.org/PreOrder", "InStock", "OutOfStock", "PreOrder"}
    for o in jl.find_offers(p):
        availability = jl.field_value(o, "availability")
        if availability and any(availability.endswith(v) for v in ("InStock", "OutOfStock", "PreOrder")):
            return _pass("structured_data.product_availability", "Offer.availability", "InStock|OutOfStock|PreOrder", availability, art)
    return _fail("structured_data.product_availability", "Offer.availability", "InStock|OutOfStock|PreOrder", "missing or invalid", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "Offer.availability", "values": ["InStock", "OutOfStock", "PreOrder"]}, summary="Set Offer.availability to a standard value", references=[_SCHEMA_REF]))


def check_product_aggregate_rating(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.product_aggregate_rating", "Product.aggregateRating", "ratingValue + reviewCount", CheckSeverity.suggestion, art)
    p = _product_node(art)
    if p is None:
        return _skip_no_schema("structured_data.product_aggregate_rating", "Product.aggregateRating", "ratingValue + reviewCount", CheckSeverity.suggestion, "Product", art)
    ar = p.get("aggregateRating")
    if isinstance(ar, dict) and (ar.get("ratingValue") and (ar.get("reviewCount") or ar.get("ratingCount"))):
        return _pass("structured_data.product_aggregate_rating", "Product.aggregateRating", "ratingValue + reviewCount", "present", art)
    return _fail("structured_data.product_aggregate_rating", "Product.aggregateRating", "ratingValue + reviewCount", "missing or incomplete", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "Product.aggregateRating"}, summary="Add aggregateRating with ratingValue + reviewCount", references=[_SCHEMA_REF]),
                 severity=CheckSeverity.suggestion)


def check_product_variants(store: ArtifactStore, url: str) -> CheckResult:
    """NOT_DETECTED-or-PASS check: variants are optional; we only flag when hasVariant is asserted but malformed."""
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.product_variants", "Product.hasVariant well-formed", "variants with images + options", CheckSeverity.suggestion, art)
    p = _product_node(art)
    if p is None:
        return _skip_no_schema("structured_data.product_variants", "Product.hasVariant well-formed", "variants with images + options", CheckSeverity.suggestion, "Product", art)
    variants = jl.find_variants(p)
    if not variants:
        # No variants asserted — not applicable; mark NOT_DETECTED with not-applicable reason (no fix).
        return CheckResult(
            dimension=DIMENSION,
            check_id="structured_data.product_variants",
            title="Product.hasVariant well-formed",
            goal="variants with distinct images + option names",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.info,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt="no variants declared"),
            reason="precondition_failed:no_hasVariant",
        )
    well_formed = all(v.get("image") for v in variants)
    if well_formed:
        return _pass("structured_data.product_variants", "Product.hasVariant well-formed", "variants have images", f"{len(variants)} variant(s)", art)
    return _fail("structured_data.product_variants", "Product.hasVariant well-formed", "variants have images", f"{len(variants)} variant(s), some missing image", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "Product.hasVariant.image"}, summary="Add per-variant image URLs", references=[_SCHEMA_REF]),
                 severity=CheckSeverity.suggestion)


# ============================================================================
# Article family (also conditional)
# ============================================================================


def _article_node(art: Artifact | None) -> dict | None:
    if art is None or art.capture_status != CaptureStatus.ok:
        return None
    types = (art.payload or {}).get("types") or {}
    return ((types.get("Article") or types.get("NewsArticle") or types.get("BlogPosting")) or [None])[0]


def _article_check(check_id: str, title: str, goal: str, field: str, store: ArtifactStore, url: str, severity: CheckSeverity = CheckSeverity.suggestion) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld(check_id, title, goal, severity, art)
    a = _article_node(art)
    if a is None:
        return _skip_no_schema(check_id, title, goal, severity, "Article", art)
    if jl.has_field(a, field):
        return _pass(check_id, title, goal, f"{field} present", art)
    return _fail(check_id, title, goal, f"{field} missing", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": f"Article.{field}"}, summary=f"Add Article.{field}", references=[_SCHEMA_REF]),
                 severity=severity)


def check_article_headline(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.article_headline", "Article.headline ≤110 chars", "schema.org Article.headline", CheckSeverity.suggestion, art)
    a = _article_node(art)
    if a is None:
        return _skip_no_schema("structured_data.article_headline", "Article.headline ≤110 chars", "schema.org Article.headline", CheckSeverity.suggestion, "Article", art)
    headline = jl.field_value(a, "headline") or ""
    if headline and len(headline) <= 110:
        return _pass("structured_data.article_headline", "Article.headline ≤110 chars", "schema.org Article.headline", f"{len(headline)} chars", art)
    return _fail("structured_data.article_headline", "Article.headline ≤110 chars", "Article.headline ≤110 chars", "missing or too long", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "Article.headline"}, summary="Add or shorten Article.headline", references=[_SCHEMA_REF]),
                 severity=CheckSeverity.suggestion)


def check_article_author(store: ArtifactStore, url: str) -> CheckResult:
    return _article_check("structured_data.article_author", "Article.author", "schema.org Article.author", "author", store, url)


def check_article_datePublished(store: ArtifactStore, url: str) -> CheckResult:
    return _article_check("structured_data.article_datePublished", "Article.datePublished", "schema.org Article.datePublished", "datePublished", store, url)


# ============================================================================
# Other types
# ============================================================================


def check_organization_name(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.organization_name", "Organization.name", "schema.org Organization.name", CheckSeverity.suggestion, art)
    types = (art.payload or {}).get("types") or {}
    orgs = types.get("Organization") or []
    if not orgs:
        return _fail("structured_data.organization_name", "Organization.name", "schema.org Organization.name", "no Organization node", art,
                     Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"type": "Organization"}, summary="Add Organization JSON-LD with name", references=[_SCHEMA_REF]),
                     severity=CheckSeverity.suggestion)
    if any(jl.field_value(o, "name") for o in orgs):
        return _pass("structured_data.organization_name", "Organization.name", "schema.org Organization.name", "Organization.name present", art)
    return _fail("structured_data.organization_name", "Organization.name", "schema.org Organization.name", "Organization missing name", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "Organization.name"}, summary="Add Organization.name", references=[_SCHEMA_REF]),
                 severity=CheckSeverity.suggestion)


def check_faqpage_questions(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.faqpage_questions", "FAQPage.mainEntity ≥1", "schema.org FAQPage", CheckSeverity.suggestion, art)
    types = (art.payload or {}).get("types") or {}
    faqs = types.get("FAQPage") or []
    if not faqs:
        return _skip_no_schema("structured_data.faqpage_questions", "FAQPage.mainEntity ≥1", "schema.org FAQPage", CheckSeverity.suggestion, "FAQPage", art)
    for f in faqs:
        me = f.get("mainEntity") or []
        if isinstance(me, dict):
            me = [me]
        if me:
            return _pass("structured_data.faqpage_questions", "FAQPage.mainEntity ≥1", "schema.org FAQPage", f"{len(me)} question(s)", art)
    return _fail("structured_data.faqpage_questions", "FAQPage.mainEntity ≥1", "schema.org FAQPage", "no questions", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"field": "FAQPage.mainEntity"}, summary="Add FAQPage.mainEntity (Question/Answer)", references=[_SCHEMA_REF]),
                 severity=CheckSeverity.suggestion)


def check_recipe_basics(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None or art.capture_status not in (CaptureStatus.ok, CaptureStatus.not_found):
        return _not_detected_no_jsonld("structured_data.recipe_basics", "Recipe basics", "name + recipeIngredient + recipeInstructions", CheckSeverity.suggestion, art)
    types = (art.payload or {}).get("types") or {}
    recipes = types.get("Recipe") or []
    if not recipes:
        return _skip_no_schema("structured_data.recipe_basics", "Recipe basics", "name + recipeIngredient + recipeInstructions", CheckSeverity.suggestion, "Recipe", art)
    r = recipes[0]
    has_all = jl.has_field(r, "name") and r.get("recipeIngredient") and r.get("recipeInstructions")
    if has_all:
        return _pass("structured_data.recipe_basics", "Recipe basics", "name + recipeIngredient + recipeInstructions", "all present", art)
    return _fail("structured_data.recipe_basics", "Recipe basics", "name + recipeIngredient + recipeInstructions", "incomplete", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"fields": ["Recipe.name", "Recipe.recipeIngredient", "Recipe.recipeInstructions"]}, summary="Add Recipe basics", references=[_SCHEMA_REF]),
                 severity=CheckSeverity.suggestion)


# ============================================================================
# Page-level
# ============================================================================


def check_page_title_length(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.meta_tags, url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION,
            check_id="structured_data.page_title_length",
            title="HTML <title> 30–60 chars",
            goal="page title length 30-60 chars",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.suggestion,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=_ref_or_synthetic(art),
            reason="artifact_unavailable:meta_tags:not_captured",
        )
    title_len = (art.payload or {}).get("title_length", 0)
    if 30 <= title_len <= 60:
        return _pass("structured_data.page_title_length", "HTML <title> 30–60 chars", "title length 30-60 chars", f"{title_len} chars", art)
    return _fail("structured_data.page_title_length", "HTML <title> 30–60 chars", "title length 30-60 chars", f"{title_len} chars", art,
                 Fix(action_type=FixActionType.add_meta_tag, target=url, payload={"target_length": [30, 60]}, summary="Adjust <title> to 30–60 chars"),
                 severity=CheckSeverity.suggestion)


def check_json_ld_validity(store: ArtifactStore, url: str) -> CheckResult:
    art = store.find(ArtifactType.json_ld, url)
    if art is None:
        return CheckResult(
            dimension=DIMENSION,
            check_id="structured_data.json_ld_validity",
            title="JSON-LD parses cleanly",
            goal="all JSON-LD blocks parse without error",
            status=CheckStatus.not_detected,
            severity=CheckSeverity.warning,
            mode=CheckMode.mechanical,
            weight=_V1_WEIGHT,
            evidence=HttpExchange(method="GET", url=url, status=None),
            reason="artifact_unavailable:json_ld:not_captured",
        )
    if art.capture_status == CaptureStatus.not_found:
        # Page has no JSON-LD at all — treat as suggestion-level FAIL with a fix.
        return _fail("structured_data.json_ld_validity", "JSON-LD present", "page has at least one JSON-LD block", "no blocks", art,
                     Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"types": ["WebPage", "Organization"]}, summary="Add at least one JSON-LD block", references=[_SCHEMA_REF]),
                     severity=CheckSeverity.suggestion)
    if art.capture_status != CaptureStatus.ok:
        return _fail("structured_data.json_ld_validity", "JSON-LD parses cleanly", "all JSON-LD blocks parse without error", art.capture_error or "parse error", art,
                     Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"action": "fix malformed JSON-LD blocks"}, summary="Fix malformed JSON-LD blocks", references=[_SCHEMA_REF]))
    payload = art.payload or {}
    blocks = payload.get("blocks") or []
    bad = [b for b in blocks if b.get("error")]
    if not bad:
        return _pass("structured_data.json_ld_validity", "JSON-LD parses cleanly", "all blocks parse cleanly", f"{len(blocks)} block(s)", art)
    return _fail("structured_data.json_ld_validity", "JSON-LD parses cleanly", "all blocks parse cleanly", f"{len(bad)}/{len(blocks)} blocks failed to parse", art,
                 Fix(action_type=FixActionType.add_jsonld_block, target=url, payload={"action": "fix malformed JSON-LD blocks"}, summary="Fix malformed JSON-LD blocks", references=[_SCHEMA_REF]))


# ============================================================================
# Analyzer
# ============================================================================


class StructuredDataAnalyzer:
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
            check_product_name_present(store, url),
            check_product_description_present(store, url),
            check_product_image_present(store, url),
            check_product_offer_price_present(store, url),
            check_product_availability(store, url),
            check_product_aggregate_rating(store, url),
            check_product_variants(store, url),
            check_article_headline(store, url),
            check_article_author(store, url),
            check_article_datePublished(store, url),
            check_organization_name(store, url),
            check_faqpage_questions(store, url),
            check_recipe_basics(store, url),
            check_page_title_length(store, url),
            check_json_ld_validity(store, url),
        ]
        elapsed = (time.perf_counter() - t0) * 1000.0
        for r in results:
            r.elapsed_ms = max(r.elapsed_ms, elapsed / len(results))
        return results


__all__ = ["DIMENSION", "StructuredDataAnalyzer"]
