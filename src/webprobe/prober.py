"""Well-known prober — populates the canonical Artifact store with site-level
fetches that the dimension analyzers need.

Wedged between Phase 1 (mapper) and Phase 3.5 (scheduler). Reads robots.txt
discovered by the mapper, follows its Sitemap directives, and probes a
configurable set of /.well-known/* endpoints, OpenAPI candidates, doc paths,
and trust pages. Each result becomes an Artifact (success or failure).

Dimension analyzers read these artifacts; nothing here writes CheckResults.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urljoin, urlparse

import aiohttp

from webprobe.artifact_store import ArtifactStore
from webprobe.models import Artifact, ArtifactType, CaptureStatus
from webprobe.parsers import openapi as openapi_parser
from webprobe.parsers import robots_txt as robots_parser
from webprobe.parsers import sitemap as sitemap_parser


logger = logging.getLogger(__name__)


@dataclass
class ProberConfig:
    """Per-run prober knobs."""

    timeout_s: float = 10.0
    user_agent: str = "webprobe-prober/0.5"
    concurrency: int = 8
    # Well-known paths to probe (relative to origin). Order matters for the
    # candidate-paths checks (e.g. MCP server card tries multiple).
    well_known_paths: tuple[str, ...] = (
        ".well-known/api-catalog",
        ".well-known/openid-configuration",
        ".well-known/oauth-authorization-server",
        ".well-known/oauth-protected-resource",
        ".well-known/mcp/server-card.json",
        ".well-known/mcp/server-cards.json",
        ".well-known/mcp.json",
        ".well-known/agent-skills/index.json",
        ".well-known/skills/index.json",
        ".well-known/http-message-signatures-directory",
        ".well-known/ucp",
        ".well-known/acp.json",
        "llms.txt",
    )
    openapi_paths: tuple[str, ...] = (
        "openapi.json",
        "openapi.yaml",
        "v1/openapi.json",
        "swagger.json",
        "api/openapi.json",
    )
    docs_paths: tuple[str, ...] = ("docs", "redoc", "swagger", "api-docs", "api/docs")
    trust_pages: tuple[str, ...] = (
        "contact", "contact-us", "support", "about", "about-us",
        "privacy", "privacy-policy", "legal/privacy",
        "terms", "terms-of-service", "tos", "legal/terms",
    )
    bazaar_paths: tuple[str, ...] = ("platform/v2/x402/discovery/resources",)


def _origin(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return url.rstrip("/")
    return f"{p.scheme}://{p.netloc}"


@dataclass
class FetchResult:
    """One HTTP fetch outcome."""

    url: str
    status: int | None
    body: bytes
    headers: dict[str, str]
    error: str = ""
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 400


async def _fetch(session: aiohttp.ClientSession, url: str, *, timeout_s: float) -> FetchResult:
    """One fetch with timeout. Never raises."""
    t0 = time.perf_counter()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout_s)) as resp:
            body = await resp.read()
            elapsed = (time.perf_counter() - t0) * 1000.0
            return FetchResult(
                url=url, status=resp.status, body=body,
                headers={k: v for k, v in resp.headers.items()},
                elapsed_ms=elapsed,
            )
    except asyncio.TimeoutError:
        return FetchResult(url=url, status=None, body=b"", headers={}, error="timeout",
                           elapsed_ms=(time.perf_counter() - t0) * 1000.0)
    except Exception as e:
        return FetchResult(url=url, status=None, body=b"", headers={}, error=f"{type(e).__name__}: {e}",
                           elapsed_ms=(time.perf_counter() - t0) * 1000.0)


def _store_fetch(
    store: ArtifactStore,
    fr: FetchResult,
    *,
    artifact_type: ArtifactType,
    payload_override: dict | None = None,
    raw_bytes_override: bytes | None = None,
) -> str:
    """Write a fetch outcome as an Artifact (success or failure)."""
    if not fr.ok:
        if fr.error == "timeout":
            cs = CaptureStatus.timeout
        elif fr.status == 404:
            cs = CaptureStatus.not_found
        elif fr.status is None:
            cs = CaptureStatus.network_error
        else:
            cs = CaptureStatus.http_error
        return store.record_failure(
            artifact_type, fr.url, cs,
            capture_error=fr.error or f"http_{fr.status}",
            elapsed_ms=fr.elapsed_ms,
            replace=True,
        )
    payload = payload_override if payload_override is not None else {
        "status": fr.status,
        "headers": dict(fr.headers),
    }
    art = Artifact(
        artifact_type=artifact_type,
        source_url=fr.url,
        capture_status=CaptureStatus.ok,
        payload=payload,
        raw_bytes=raw_bytes_override if raw_bytes_override is not None else fr.body,
        elapsed_ms=fr.elapsed_ms,
    )
    return store.put(art, replace=True)


async def probe_site(
    store: ArtifactStore,
    base_url: str,
    config: ProberConfig | None = None,
) -> dict:
    """Run all probes, populating ``store``. Returns a summary.

    The base_url is normalized to its origin; per-page artifacts the capturer
    already collected (http_response, dom, meta_tags, json_ld) are not
    re-fetched.
    """
    cfg = config or ProberConfig()
    origin = _origin(base_url)
    summary = {"fetches": 0, "ok": 0, "errors": 0, "elapsed_ms": 0.0}
    started = time.perf_counter()

    sem = asyncio.Semaphore(cfg.concurrency)
    headers = {"User-Agent": cfg.user_agent, "Accept": "*/*"}

    async with aiohttp.ClientSession(headers=headers) as session:
        async def fetch(url: str) -> FetchResult:
            async with sem:
                return await _fetch(session, url, timeout_s=cfg.timeout_s)

        # Pass 1: robots.txt (drives sitemap discovery).
        robots_url = urljoin(origin + "/", "robots.txt")
        robots_fr = await fetch(robots_url)
        summary["fetches"] += 1
        if robots_fr.ok:
            summary["ok"] += 1
            parsed = robots_parser.parse(robots_fr.body, source_url=robots_url)
            _store_fetch(store, robots_fr, artifact_type=ArtifactType.robots_txt,
                         payload_override=parsed.payload, raw_bytes_override=robots_fr.body)
            sitemap_urls = list(parsed.payload.get("sitemaps") or [])
        else:
            summary["errors"] += 1
            _store_fetch(store, robots_fr, artifact_type=ArtifactType.robots_txt)
            sitemap_urls = [urljoin(origin + "/", "sitemap.xml")]

        # Pass 2: parallel discovery fetches (sitemaps, well-known, openapi, docs, trust, bazaar).
        candidate_fetches: list[tuple[str, ArtifactType]] = []
        # Always probe a default sitemap location even if robots didn't list one.
        for sm in sitemap_urls or [urljoin(origin + "/", "sitemap.xml")]:
            candidate_fetches.append((sm, ArtifactType.sitemap))
        for path in cfg.well_known_paths:
            candidate_fetches.append((urljoin(origin + "/", path), ArtifactType.well_known))
        for path in cfg.openapi_paths:
            candidate_fetches.append((urljoin(origin + "/", path), ArtifactType.openapi))
        for path in cfg.docs_paths:
            candidate_fetches.append((urljoin(origin + "/", path), ArtifactType.http_response))
        for path in cfg.trust_pages:
            candidate_fetches.append((urljoin(origin + "/", path), ArtifactType.http_response))
        for path in cfg.bazaar_paths:
            candidate_fetches.append((urljoin(origin + "/", path), ArtifactType.http_response))

        async def fetch_and_store(url: str, artifact_type: ArtifactType) -> None:
            fr = await fetch(url)
            summary["fetches"] += 1
            if fr.ok:
                summary["ok"] += 1
            else:
                summary["errors"] += 1
            # Type-specific handling
            if artifact_type == ArtifactType.sitemap and fr.ok:
                parsed = sitemap_parser.parse(fr.body, source_url=url)
                _store_fetch(store, fr, artifact_type=artifact_type,
                             payload_override=parsed.payload if parsed.ok else {"kind": "unknown", "source_url": url},
                             raw_bytes_override=fr.body)
                if not parsed.ok:
                    # Override capture_status to parse_error via direct put.
                    art = store.find(ArtifactType.sitemap, url)
                    if art is not None:
                        art.capture_status = CaptureStatus.parse_error
                        art.capture_error = parsed.error
            elif artifact_type == ArtifactType.openapi and fr.ok:
                parsed = openapi_parser.parse(fr.body, source_url=url)
                if parsed.ok:
                    _store_fetch(store, fr, artifact_type=artifact_type,
                                 payload_override=parsed.payload, raw_bytes_override=fr.body)
                else:
                    store.record_failure(artifact_type, url, CaptureStatus.parse_error,
                                          capture_error=parsed.error, elapsed_ms=fr.elapsed_ms,
                                          replace=True)
            else:
                _store_fetch(store, fr, artifact_type=artifact_type)

        await asyncio.gather(*(fetch_and_store(u, t) for u, t in candidate_fetches))

    summary["elapsed_ms"] = (time.perf_counter() - started) * 1000.0
    logger.info("prober.complete", extra=dict(summary))
    return summary


def probe_site_sync(store: ArtifactStore, base_url: str, config: ProberConfig | None = None) -> dict:
    """Synchronous convenience wrapper."""
    return asyncio.run(probe_site(store, base_url, config))


# ============================================================================
# Audit orchestrator — wires probe → scheduler → scorecard
# ============================================================================


def default_analyzers() -> list:
    """Return the standard set of dimension analyzers (one per dimension)."""
    from webprobe.accessibility import AccessibilityAnalyzer
    from webprobe.agent_surface import AgentSurfaceAnalyzer
    from webprobe.agentic_commerce import AgenticCommerceAnalyzer
    from webprobe.api_surface import APISurfaceAnalyzer
    from webprobe.bot_access import BotAccessAnalyzer
    from webprobe.discoverability import DiscoverabilityAnalyzer
    from webprobe.public_facing_signals import PublicFacingSignalsAnalyzer
    from webprobe.structured_data import StructuredDataAnalyzer

    return [
        DiscoverabilityAnalyzer(),
        BotAccessAnalyzer(),
        AgentSurfaceAnalyzer(),
        APISurfaceAnalyzer(),
        StructuredDataAnalyzer(),
        AgenticCommerceAnalyzer(),
        PublicFacingSignalsAnalyzer(),
        AccessibilityAnalyzer(),
        # general_security is consumed via webprobe.security.scan_*_with_check_results,
        # not as a scheduler-driven analyzer. The audit orchestrator merges its results.
    ]


@dataclass
class AuditResult:
    """End-to-end audit outcome."""

    scorecard: object  # Scorecard
    check_results: list  # list[CheckResult]
    probe_summary: dict
    scheduler_summary: dict


async def run_audit_pipeline(
    base_url: str,
    *,
    store: ArtifactStore | None = None,
    mode: str = "full",
    prober_config: ProberConfig | None = None,
    analyzer_config: dict[str, dict] | None = None,
    only: tuple[str, ...] | None = None,
    skip: tuple[str, ...] = (),
    skip_probe: bool = False,
) -> AuditResult:
    """End-to-end: probe site → run analyzers → aggregate scorecard.

    The store can be pre-populated by Phase 2 capture; in that case only the
    well-known/robots/sitemap layer is probed (per-URL artifacts are reused).
    Set ``skip_probe=True`` when the caller has already populated everything.
    """
    from webprobe.scheduler import SchedulerConfig, run_audit
    from webprobe.scorecard import aggregate as aggregate_scorecard

    store = store if store is not None else ArtifactStore()
    probe_summary: dict = {}
    if not skip_probe:
        probe_summary = await probe_site(store, base_url, prober_config)

    analyzers = default_analyzers()
    sched_cfg = SchedulerConfig(
        mode=mode,  # type: ignore[arg-type]
        analyzer_config={a.name: {"base_url": base_url, **(analyzer_config or {}).get(a.name, {})} for a in analyzers},
        only=only,
        skip=skip,
    )
    sched_result = await run_audit(store, analyzers, sched_cfg)
    check_results = list(sched_result.check_results)

    # Merge general_security CheckResults if a graph capture is available.
    # This is opt-in via analyzer_config["general_security"]["graph"].
    gs_cfg = (analyzer_config or {}).get("general_security") or {}
    graph = gs_cfg.get("graph")
    if graph is not None:
        from webprobe.security import scan_graph_with_check_results
        _, gs_results = scan_graph_with_check_results(graph)
        check_results.extend(gs_results)

    # Build run_id for scorecard.
    from webprobe.models import _make_run_id  # type: ignore[attr-defined]
    run_id = _make_run_id()

    scorecard = aggregate_scorecard(
        run_id=run_id,
        target_url=base_url,
        results=check_results,
        mode=mode,
    )

    return AuditResult(
        scorecard=scorecard,
        check_results=check_results,
        probe_summary=probe_summary,
        scheduler_summary={
            "elapsed_ms": sched_result.elapsed_ms,
            "analyzers_run": sched_result.analyzers_run,
            "analyzers_skipped": sched_result.analyzers_skipped,
        },
    )


def run_audit_pipeline_sync(base_url: str, **kwargs) -> AuditResult:
    """Synchronous convenience wrapper."""
    return asyncio.run(run_audit_pipeline(base_url, **kwargs))


__all__ = [
    "AuditResult",
    "FetchResult",
    "ProberConfig",
    "default_analyzers",
    "probe_site",
    "probe_site_sync",
    "run_audit_pipeline",
    "run_audit_pipeline_sync",
]
