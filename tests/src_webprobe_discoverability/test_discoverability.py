"""Tests for the Discoverability dimension analyzer (Block 3)."""

from __future__ import annotations

import asyncio

import pytest

from webprobe.artifact_store import ArtifactStore
from webprobe.discoverability import DiscoverabilityAnalyzer
from webprobe.models import (
    Artifact,
    ArtifactType,
    CaptureStatus,
    CheckMode,
    CheckStatus,
    DimensionId,
    validate_dimension_weights,
)
from webprobe.parsers import robots_txt as robots_parser
from webprobe.parsers import sitemap as sitemap_parser


BASE = "https://reeve.tools/"


def _populate_full(store: ArtifactStore) -> None:
    """A 'good' fixture that should make every check pass."""
    robots_text = (
        "User-agent: *\n"
        "Allow: /\n"
        "\n"
        "User-agent: GPTBot\n"
        "Allow: /\n"
        "\n"
        "Sitemap: https://reeve.tools/sitemap.xml\n"
        "Content-Signal: ai-train=yes, search=yes, ai-input=yes\n"
    )
    parsed_robots = robots_parser.parse(robots_text, source_url=BASE + "robots.txt")
    store.put(Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url=BASE + "robots.txt",
        capture_status=CaptureStatus.ok,
        payload=parsed_robots.payload,
    ))

    sitemap_text = (
        '<?xml version="1.0"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        '<url><loc>https://reeve.tools/</loc></url>'
        '</urlset>'
    )
    parsed_sm = sitemap_parser.parse(sitemap_text, source_url=BASE + "sitemap.xml")
    store.put(Artifact(
        artifact_type=ArtifactType.sitemap,
        source_url=BASE + "sitemap.xml",
        capture_status=CaptureStatus.ok,
        payload=parsed_sm.payload,
    ))

    # meta_tags artifact with a Link header
    store.put(Artifact(
        artifact_type=ArtifactType.meta_tags,
        source_url=BASE,
        capture_status=CaptureStatus.ok,
        payload={
            "title": "Home",
            "link_headers": [
                {"url": "/.well-known/api-catalog", "rel": "api-catalog", "params": {}},
            ],
        },
    ))

    # llms.txt with structure
    llms_body = "# Reeve\n\n## What it does\n\nA short description.\n"
    store.put(Artifact(
        artifact_type=ArtifactType.well_known,
        source_url=BASE + "llms.txt",
        capture_status=CaptureStatus.ok,
        raw_bytes=llms_body.encode("utf-8"),
    ))

    # http_response with text/markdown for homepage (markdown negotiation pass)
    store.put(Artifact(
        artifact_type=ArtifactType.http_response,
        source_url=BASE,
        capture_status=CaptureStatus.ok,
        payload={
            "status": 200,
            "headers": {"content-type": "text/markdown"},
        },
    ))


def _run(store: ArtifactStore, base_url: str = BASE) -> list:
    analyzer = DiscoverabilityAnalyzer()
    return asyncio.run(analyzer.run(store, mode="full", prior_results=[], config={"base_url": base_url}))


# ---- happy path ----


def test_full_fixture_all_pass() -> None:
    store = ArtifactStore()
    _populate_full(store)
    results = _run(store)
    statuses = {r.check_id: r.status for r in results}
    failing = {cid: s.value for cid, s in statuses.items() if s != CheckStatus.pass_}
    assert failing == {}, f"unexpected non-PASS: {failing}"


def test_weights_sum_to_one() -> None:
    """CA010: discoverability dimension weights sum to 1.0 (within float epsilon)."""
    store = ArtifactStore()
    _populate_full(store)
    results = _run(store)
    sums = validate_dimension_weights(results)
    assert sums["discoverability"] == pytest.approx(1.0)


def test_dimension_count() -> None:
    """v1 has 9 checks per AUDIT_DIMENSIONS.md."""
    store = ArtifactStore()
    _populate_full(store)
    results = _run(store)
    assert len(results) == 9
    assert all(r.dimension == DimensionId.discoverability for r in results)


# ---- per-check failure modes ----


def test_no_robots_artifact_cascades_to_not_detected() -> None:
    """CA004: missing robots.txt artifact -> dependent checks NOT_DETECTED with reason."""
    store = ArtifactStore()
    # Only homepage meta_tags + llms.txt (no robots, no sitemap)
    store.put(Artifact(
        artifact_type=ArtifactType.meta_tags,
        source_url=BASE,
        capture_status=CaptureStatus.ok,
        payload={"link_headers": []},
    ))
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    for cid in [
        "discoverability.robots_txt_present",
        "discoverability.robots_txt_user_agent_directive",
        "discoverability.sitemap_referenced",
        "discoverability.content_signals_directives",
    ]:
        r = by_id[cid]
        assert r.status == CheckStatus.not_detected, f"{cid}: {r.status}"
        assert r.reason and r.reason.startswith("artifact_unavailable:robots_txt"), r.reason
        assert r.fix is None  # upstream NOT_DETECTED needs no fix


def test_robots_present_but_no_user_agent_groups() -> None:
    store = ArtifactStore()
    # robots payload that parsed OK but has no User-agent groups
    store.put(Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url=BASE + "robots.txt",
        capture_status=CaptureStatus.ok,
        payload={"groups": [], "sitemaps": [], "content_signals": []},
    ))
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    assert by_id["discoverability.robots_txt_present"].status == CheckStatus.pass_
    assert by_id["discoverability.robots_txt_user_agent_directive"].status == CheckStatus.fail
    assert by_id["discoverability.robots_txt_user_agent_directive"].fix is not None


def test_sitemap_invalid_when_present_but_unparseable() -> None:
    store = ArtifactStore()
    _populate_full(store)
    # Replace sitemap artifact with a parse-error one
    store.put(Artifact(
        artifact_type=ArtifactType.sitemap,
        source_url=BASE + "sitemap.xml",
        capture_status=CaptureStatus.parse_error,
        capture_error="xml_parse_error: ...",
        payload={"kind": "unknown", "urls": [], "sitemaps": []},
    ), replace=True)
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    assert by_id["discoverability.sitemap_valid"].status == CheckStatus.fail
    assert by_id["discoverability.sitemap_valid"].fix is not None


def test_link_headers_absent() -> None:
    store = ArtifactStore()
    _populate_full(store)
    store.put(Artifact(
        artifact_type=ArtifactType.meta_tags,
        source_url=BASE,
        capture_status=CaptureStatus.ok,
        payload={"link_headers": []},  # Empty
    ), replace=True)
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    assert by_id["discoverability.link_headers_present"].status == CheckStatus.fail


def test_llms_txt_unstructured() -> None:
    store = ArtifactStore()
    _populate_full(store)
    # Replace llms.txt with unstructured plain text
    store.put(Artifact(
        artifact_type=ArtifactType.well_known,
        source_url=BASE + "llms.txt",
        capture_status=CaptureStatus.ok,
        raw_bytes=b"just one line",
    ), replace=True)
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    assert by_id["discoverability.llms_txt_present"].status == CheckStatus.pass_
    assert by_id["discoverability.llms_txt_structured"].status == CheckStatus.fail


def test_markdown_negotiation_fails_when_html() -> None:
    store = ArtifactStore()
    _populate_full(store)
    # Override homepage http_response to return text/html instead
    store.put(Artifact(
        artifact_type=ArtifactType.http_response,
        source_url=BASE,
        capture_status=CaptureStatus.ok,
        payload={"status": 200, "headers": {"content-type": "text/html"}},
    ), replace=True)
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    r = by_id["discoverability.markdown_negotiation"]
    assert r.status == CheckStatus.fail
    assert r.mode == CheckMode.runtime  # CA006: runtime check
