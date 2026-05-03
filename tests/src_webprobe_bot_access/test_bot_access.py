"""Tests for the Bot Access dimension analyzer (Block 3)."""

from __future__ import annotations

import asyncio
import json

import pytest

from webprobe.artifact_store import ArtifactStore
from webprobe.bot_access import BotAccessAnalyzer
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


BASE = "https://reeve.tools/"


def _put_robots(store: ArtifactStore, text: str) -> None:
    parsed = robots_parser.parse(text, source_url=BASE + "robots.txt")
    store.put(Artifact(
        artifact_type=ArtifactType.robots_txt,
        source_url=BASE + "robots.txt",
        capture_status=CaptureStatus.ok,
        payload=parsed.payload,
    ))


def _run(store: ArtifactStore, *, base_url: str = BASE, config: dict | None = None) -> list:
    analyzer = BotAccessAnalyzer()
    cfg = {"base_url": base_url}
    if config:
        cfg.update(config)
    return asyncio.run(analyzer.run(store, mode="full", prior_results=[], config=cfg))


# ---- ai_bot_matrix ----


def test_matrix_pass_when_all_allowed() -> None:
    store = ArtifactStore()
    _put_robots(store, "User-agent: *\nAllow: /\n")
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    r = by_id["bot_access.ai_bot_matrix"]
    assert r.status == CheckStatus.pass_
    assert r.fix is None


def test_matrix_fail_when_one_disallowed() -> None:
    store = ArtifactStore()
    _put_robots(store, (
        "User-agent: *\nAllow: /\n\n"
        "User-agent: GPTBot\nDisallow: /\n"
    ))
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    r = by_id["bot_access.ai_bot_matrix"]
    assert r.status == CheckStatus.fail
    assert r.fix is not None
    # Disallowed UA should appear in the fix payload
    assert "GPTBot" in r.fix.payload["disallowed_user_agents"]


def test_matrix_not_detected_when_no_robots() -> None:
    store = ArtifactStore()
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    r = by_id["bot_access.ai_bot_matrix"]
    assert r.status == CheckStatus.not_detected
    assert r.reason and r.reason.startswith("artifact_unavailable:robots_txt")
    assert r.fix is None


def test_matrix_custom_user_agent_set() -> None:
    """Operators can supply their own UA matrix via config."""
    store = ArtifactStore()
    _put_robots(store, (
        "User-agent: CustomBot\nDisallow: /\n"
    ))
    custom_matrix = ("CustomBot", "OtherBot")
    results = _run(store, config={"ai_user_agent_matrix": custom_matrix})
    by_id = {r.check_id: r for r in results}
    r = by_id["bot_access.ai_bot_matrix"]
    assert r.status == CheckStatus.fail
    assert "CustomBot" in r.fix.payload["disallowed_user_agents"]


def test_matrix_no_rule_for_a_bot_is_not_a_failure() -> None:
    """Bots with no rule aren't disallowed (default is allow per RFC 9309)."""
    store = ArtifactStore()
    _put_robots(store, "User-agent: SomeOtherBot\nDisallow: /\n")
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    r = by_id["bot_access.ai_bot_matrix"]
    # Default matrix bots aren't matched by SomeOtherBot rule, fall through to no_rule -> allow
    assert r.status == CheckStatus.pass_


# ---- web_bot_auth_directory ----


def test_web_bot_auth_pass_when_valid_jwks() -> None:
    store = ArtifactStore()
    _put_robots(store, "User-agent: *\nAllow: /\n")
    jwks = {"keys": [{"kty": "RSA", "kid": "test"}]}
    store.put(Artifact(
        artifact_type=ArtifactType.well_known,
        source_url=BASE + ".well-known/http-message-signatures-directory",
        capture_status=CaptureStatus.ok,
        raw_bytes=json.dumps(jwks).encode("utf-8"),
    ))
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    r = by_id["bot_access.web_bot_auth_directory"]
    assert r.status == CheckStatus.pass_


def test_web_bot_auth_fail_when_malformed_jwks() -> None:
    store = ArtifactStore()
    _put_robots(store, "User-agent: *\nAllow: /\n")
    store.put(Artifact(
        artifact_type=ArtifactType.well_known,
        source_url=BASE + ".well-known/http-message-signatures-directory",
        capture_status=CaptureStatus.ok,
        raw_bytes=b"not json",
    ))
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    r = by_id["bot_access.web_bot_auth_directory"]
    assert r.status == CheckStatus.fail
    assert r.fix is not None


def test_web_bot_auth_not_detected_when_absent() -> None:
    """Absence of Web Bot Auth is informational (NOT_DETECTED), not FAIL."""
    store = ArtifactStore()
    _put_robots(store, "User-agent: *\nAllow: /\n")
    results = _run(store)
    by_id = {r.check_id: r for r in results}
    r = by_id["bot_access.web_bot_auth_directory"]
    assert r.status == CheckStatus.not_detected
    assert r.fix is None


# ---- weight + dimension invariants ----


def test_weights_sum_to_one() -> None:
    store = ArtifactStore()
    _put_robots(store, "User-agent: *\nAllow: /\n")
    results = _run(store)
    sums = validate_dimension_weights(results)
    assert sums["bot_access"] == pytest.approx(1.0)


def test_all_results_in_bot_access_dimension() -> None:
    store = ArtifactStore()
    _put_robots(store, "User-agent: *\nAllow: /\n")
    results = _run(store)
    assert all(r.dimension == DimensionId.bot_access for r in results)
    assert all(r.mode == CheckMode.mechanical for r in results)
    assert len(results) == 2  # v1 has 2 checks
