"""Tests for the canonical Artifact store and per-page artifact collector."""

from __future__ import annotations

import pytest

from webprobe.artifact_collector import collect_from_capture, redact_headers
from webprobe.artifact_store import ArtifactStore, DuplicateArtifactError
from webprobe.models import (
    Artifact,
    ArtifactType,
    AuthContext,
    CaptureStatus,
    NodeCapture,
    ResponseHeaders,
    TimingData,
)


# ---- ArtifactStore ----


def test_put_get() -> None:
    store = ArtifactStore()
    a = Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url="https://x/robots.txt",
        payload={"groups": []},
    )
    aid = store.put(a)
    assert aid in store
    assert store.get(aid).source_url == "https://x/robots.txt"


def test_put_duplicate_raises() -> None:
    store = ArtifactStore()
    a1 = Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url="https://x/robots.txt",
        payload={"v": 1},
    )
    a2 = Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url="https://x/robots.txt",
        payload={"v": 2},
    )
    store.put(a1)
    with pytest.raises(DuplicateArtifactError):
        store.put(a2)


def test_put_replace_overwrites() -> None:
    store = ArtifactStore()
    a1 = Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url="https://x/robots.txt",
        payload={"v": 1},
    )
    a2 = Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url="https://x/robots.txt",
        payload={"v": 2},
    )
    store.put(a1)
    store.put(a2, replace=True)
    found = store.find(ArtifactType.robots_txt, "https://x/robots.txt")
    assert found.payload == {"v": 2}
    assert len(store) == 1  # old artifact id is dropped


def test_find_by_type() -> None:
    store = ArtifactStore()
    store.put(Artifact(artifact_type=ArtifactType.robots_txt, source_url="https://a/robots.txt"))
    store.put(Artifact(artifact_type=ArtifactType.robots_txt, source_url="https://b/robots.txt"))
    store.put(Artifact(artifact_type=ArtifactType.sitemap, source_url="https://a/sitemap.xml"))
    assert len(store.find_by_type(ArtifactType.robots_txt)) == 2
    assert len(store.find_by_type(ArtifactType.sitemap)) == 1
    assert len(store.find_by_type(ArtifactType.openapi)) == 0


def test_find_by_url() -> None:
    store = ArtifactStore()
    store.put(Artifact(artifact_type=ArtifactType.dom, source_url="https://x/p"))
    store.put(Artifact(artifact_type=ArtifactType.json_ld, source_url="https://x/p"))
    store.put(Artifact(artifact_type=ArtifactType.dom, source_url="https://x/q"))
    p_arts = store.find_by_url("https://x/p")
    assert len(p_arts) == 2
    p_dom = store.find_by_url("https://x/p", artifact_type=ArtifactType.dom)
    assert len(p_dom) == 1
    assert p_dom[0].artifact_type == ArtifactType.dom


def test_record_failure_creates_failure_artifact() -> None:
    """CA004: failure markers stored as Artifacts, not raised."""
    store = ArtifactStore()
    aid = store.record_failure(
        ArtifactType.robots_txt, "https://x/robots.txt",
        CaptureStatus.http_error, "http_503",
    )
    art = store.get(aid)
    assert art.capture_status == CaptureStatus.http_error
    assert art.capture_error == "http_503"


def test_record_failure_rejects_ok_status() -> None:
    store = ArtifactStore()
    with pytest.raises(ValueError):
        store.record_failure(
            ArtifactType.robots_txt, "https://x/robots.txt",
            CaptureStatus.ok, "should not be allowed",
        )


def test_persist_and_load_roundtrip(tmp_path) -> None:
    store = ArtifactStore()
    store.put(Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url="https://x/robots.txt",
        payload={"groups": [{"user_agents": ["*"], "rules": [], "crawl_delay": None}]},
    ))
    store.put(Artifact(
        artifact_type=ArtifactType.dom,
        source_url="https://x/",
        raw_bytes=b"<html></html>",
    ))
    store.persist(tmp_path)
    reloaded = ArtifactStore.load(tmp_path)
    assert len(reloaded) == 2
    dom = reloaded.find(ArtifactType.dom, "https://x/")
    assert dom.raw_bytes == b"<html></html>"


# ---- redact_headers ----


def test_redact_known_auth_headers() -> None:
    h = {
        "Authorization": "Bearer abc",
        "Cookie": "session=xxx",
        "X-API-Key": "secret",
        "Content-Type": "text/html",
    }
    r = redact_headers(h)
    assert r["Authorization"] == "[REDACTED]"
    assert r["Cookie"] == "[REDACTED]"
    assert r["X-API-Key"] == "[REDACTED]"
    assert r["Content-Type"] == "text/html"


def test_redact_inline_patterns() -> None:
    """Bearer/Basic/api_key=/token= patterns embedded in non-auth headers."""
    h = {
        "X-Trace": "Bearer ABCDEF preserved",
        "X-Url": "https://x?api_key=SECRET&other=ok",
    }
    r = redact_headers(h)
    assert r["X-Trace"] == "Bearer [REDACTED] preserved"
    assert "api_key=[REDACTED]" in r["X-Url"]
    assert "other=ok" in r["X-Url"]


def test_redact_case_insensitive() -> None:
    """Header name match must be case-insensitive."""
    h = {"AUTHORIZATION": "Bearer x", "x-api-key": "y"}
    r = redact_headers(h)
    assert r["AUTHORIZATION"] == "[REDACTED]"
    assert r["x-api-key"] == "[REDACTED]"


# ---- collect_from_capture ----


def _capture_with_html_and_auth() -> NodeCapture:
    return NodeCapture(
        auth_context=AuthContext.anonymous,
        http_status=200,
        timing=TimingData(started_at="2026-05-03T00:00:00Z", duration_ms=12.0),
        response_headers=ResponseHeaders(raw={
            "content-type": "text/html",
            "authorization": "Bearer SECRET",  # must be redacted
            "link": '</.well-known/api-catalog>; rel="api-catalog"',
        }),
    )


_HTML = (
    '<!DOCTYPE html><html lang="en"><head>'
    '<title>Test Page</title>'
    '<meta name="description" content="A test page">'
    '<script type="application/ld+json">'
    '{"@type":"Product","name":"P","offers":{"@type":"Offer","price":"1"}}'
    '</script>'
    '</head><body><img src="a.png" alt="ok"></body></html>'
)


def test_collect_writes_http_response_with_redaction() -> None:
    store = ArtifactStore()
    cap = _capture_with_html_and_auth()
    collect_from_capture(url="https://x/p", capture=cap, raw_html=_HTML, store=store)

    http = store.find(ArtifactType.http_response, "https://x/p")
    assert http is not None
    assert http.payload["headers"]["authorization"] == "[REDACTED]"


def test_collect_writes_dom_meta_jsonld() -> None:
    store = ArtifactStore()
    cap = _capture_with_html_and_auth()
    collect_from_capture(url="https://x/p", capture=cap, raw_html=_HTML, store=store)

    dom = store.find(ArtifactType.dom, "https://x/p")
    assert dom is not None
    assert dom.raw_bytes is not None
    assert b"Test Page" in dom.raw_bytes

    meta = store.find(ArtifactType.meta_tags, "https://x/p")
    assert meta.payload["title"] == "Test Page"
    assert meta.payload["description_length"] > 0
    # Link header was preserved into parsed link_headers
    assert any(lh["rel"] == "api-catalog" for lh in meta.payload["link_headers"])

    jl = store.find(ArtifactType.json_ld, "https://x/p")
    assert "Product" in jl.payload["types"]


def test_collect_no_html_skips_dom_artifacts() -> None:
    store = ArtifactStore()
    cap = _capture_with_html_and_auth()
    collect_from_capture(url="https://x/p", capture=cap, raw_html=None, store=store)
    assert store.find(ArtifactType.dom, "https://x/p") is None
    assert store.find(ArtifactType.meta_tags, "https://x/p") is None
    assert store.find(ArtifactType.json_ld, "https://x/p") is None
    # http_response is still recorded
    assert store.find(ArtifactType.http_response, "https://x/p") is not None


def test_collect_replaces_on_repeat() -> None:
    """Capture is the source of truth for its URL; re-runs replace artifacts."""
    store = ArtifactStore()
    cap = _capture_with_html_and_auth()
    collect_from_capture(url="https://x/p", capture=cap, raw_html=_HTML, store=store)
    n_first = len(store)
    collect_from_capture(url="https://x/p", capture=cap, raw_html=_HTML, store=store)
    assert len(store) == n_first  # not duplicated


def test_collect_jsonld_no_blocks_marks_not_found() -> None:
    """A page without JSON-LD must record a not_found Artifact, not a parse_error."""
    store = ArtifactStore()
    cap = _capture_with_html_and_auth()
    no_jsonld_html = "<html><head><title>X</title></head><body></body></html>"
    collect_from_capture(url="https://x/p", capture=cap, raw_html=no_jsonld_html, store=store)
    jl = store.find(ArtifactType.json_ld, "https://x/p")
    assert jl.capture_status == CaptureStatus.not_found
