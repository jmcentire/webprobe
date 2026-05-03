"""Tests for the Structured Data dimension analyzer (Block 5)."""

from __future__ import annotations

import asyncio

import pytest

from webprobe.artifact_store import ArtifactStore
from webprobe.models import (
    Artifact,
    ArtifactType,
    CaptureStatus,
    CheckStatus,
    DimensionId,
    validate_dimension_weights,
)
from webprobe.structured_data import StructuredDataAnalyzer


URL = "https://shop.example/p/widget"


def _put_jsonld(store: ArtifactStore, types: dict, *, url: str = URL) -> None:
    nodes = [n for arr in types.values() for n in arr]
    blocks = [{"raw": "{}", "parsed": {}} for _ in nodes]
    store.put(Artifact(
        artifact_type=ArtifactType.json_ld,
        source_url=url,
        capture_status=CaptureStatus.ok,
        payload={"types": types, "nodes": nodes, "blocks": blocks, "source_url": url},
    ), replace=True)


def _put_meta(store: ArtifactStore, *, title: str, url: str = URL) -> None:
    store.put(Artifact(
        artifact_type=ArtifactType.meta_tags,
        source_url=url,
        capture_status=CaptureStatus.ok,
        payload={"title": title, "title_length": len(title)},
    ), replace=True)


def _run(store: ArtifactStore, url: str = URL) -> list:
    a = StructuredDataAnalyzer()
    return asyncio.run(a.run(store, mode="full", prior_results=[], config={"base_url": url}))


# ---- happy path: complete Product page ----


def test_complete_product_page_passes_or_skips_other_types() -> None:
    store = ArtifactStore()
    _put_jsonld(store, {
        "Product": [{
            "@type": "Product",
            "name": "Widget",
            "description": "A finely-crafted widget for many uses across many places. It comes with a full warranty, premium materials, careful packaging, and lifetime support from our friendly engineering team.",
            "image": "https://shop.example/p/widget.jpg",
            "offers": {"@type": "Offer", "price": "19.99", "priceCurrency": "USD", "availability": "https://schema.org/InStock"},
            "aggregateRating": {"ratingValue": "4.5", "reviewCount": "120"},
        }],
        "Offer": [{"@type": "Offer", "price": "19.99", "priceCurrency": "USD", "availability": "InStock"}],
        "Organization": [{"@type": "Organization", "name": "Shop"}],
    })
    _put_meta(store, title="Widget — A finely-crafted widget by Shop")  # 30-60 chars (~43)

    results = _run(store)
    by_id = {r.check_id: r for r in results}

    # Product checks PASS
    for cid in [
        "structured_data.product_name_present",
        "structured_data.product_description_present",
        "structured_data.product_image_present",
        "structured_data.product_offer_price_present",
        "structured_data.product_availability",
        "structured_data.product_aggregate_rating",
        "structured_data.organization_name",
        "structured_data.json_ld_validity",
        "structured_data.page_title_length",
    ]:
        assert by_id[cid].status == CheckStatus.pass_, f"{cid}: {by_id[cid].status} ({by_id[cid].evidence})"

    # Article / FAQPage / Recipe SKIPPED (not present on a product page)
    for cid in [
        "structured_data.article_headline",
        "structured_data.article_author",
        "structured_data.article_datePublished",
        "structured_data.faqpage_questions",
        "structured_data.recipe_basics",
    ]:
        assert by_id[cid].status == CheckStatus.skipped, f"{cid}: {by_id[cid].status}"
        assert by_id[cid].reason and "schema_type_not_present" in by_id[cid].reason

    # Variants NOT_DETECTED with not-applicable reason (no hasVariant declared)
    assert by_id["structured_data.product_variants"].status == CheckStatus.not_detected
    assert by_id["structured_data.product_variants"].reason == "precondition_failed:no_hasVariant"


def test_dimension_count_is_15() -> None:
    store = ArtifactStore()
    _put_jsonld(store, {})
    _put_meta(store, title="X")
    results = _run(store)
    assert len(results) == 15


def test_weights_sum_to_one() -> None:
    store = ArtifactStore()
    _put_jsonld(store, {})
    _put_meta(store, title="X")
    results = _run(store)
    sums = validate_dimension_weights(results)
    assert sums["structured_data"] == pytest.approx(1.0)


# ---- product fail modes ----


def test_product_missing_required_fields_fail() -> None:
    store = ArtifactStore()
    _put_jsonld(store, {"Product": [{"@type": "Product"}]})  # bare-bones
    _put_meta(store, title="X" * 35)
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    for cid in [
        "structured_data.product_name_present",
        "structured_data.product_description_present",
        "structured_data.product_image_present",
        "structured_data.product_offer_price_present",
        "structured_data.product_availability",
    ]:
        assert by_id[cid].status == CheckStatus.fail, f"{cid}: {by_id[cid].status}"
        assert by_id[cid].fix is not None


# ---- json_ld absent / parse error ----


def test_no_jsonld_artifact_cascades_to_not_detected() -> None:
    store = ArtifactStore()
    _put_meta(store, title="X" * 35)
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    # All json_ld-dependent checks NOT_DETECTED
    for cid in [
        "structured_data.product_name_present",
        "structured_data.organization_name",
        "structured_data.json_ld_validity",
    ]:
        r = by_id[cid]
        assert r.status == CheckStatus.not_detected
        assert r.reason and r.reason.startswith("artifact_unavailable:json_ld")


def test_json_ld_no_blocks_marks_validity_fail() -> None:
    store = ArtifactStore()
    store.put(Artifact(
        artifact_type=ArtifactType.json_ld,
        source_url=URL,
        capture_status=CaptureStatus.not_found,
        capture_error="no_jsonld_blocks_found",
        payload={"types": {}, "blocks": []},
    ))
    _put_meta(store, title="X" * 35)
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    r = by_id["structured_data.json_ld_validity"]
    assert r.status == CheckStatus.fail
    assert r.fix is not None


# ---- title length ----


@pytest.mark.parametrize("title,expected", [
    ("X" * 5, CheckStatus.fail),
    ("X" * 30, CheckStatus.pass_),
    ("X" * 60, CheckStatus.pass_),
    ("X" * 80, CheckStatus.fail),
])
def test_title_length_thresholds(title: str, expected: CheckStatus) -> None:
    store = ArtifactStore()
    _put_jsonld(store, {})
    _put_meta(store, title=title)
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    assert by_id["structured_data.page_title_length"].status == expected
