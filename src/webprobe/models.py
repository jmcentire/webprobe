"""Stable data models for webprobe. Schema version is pinned for cross-run aggregation."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


SCHEMA_VERSION = "1.2"


# ---- Enums ----


class AuthContext(str, Enum):
    anonymous = "anonymous"
    authenticated = "authenticated"


class DiscoveryMethod(str, Enum):
    sitemap = "sitemap"
    robots = "robots"
    crawl = "crawl"
    framework = "framework"
    manual = "manual"


class ResourceType(str, Enum):
    document = "document"
    script = "script"
    stylesheet = "stylesheet"
    image = "image"
    font = "font"
    media = "media"
    xhr = "xhr"
    fetch = "fetch"
    websocket = "websocket"
    other = "other"


class ConsoleMessageLevel(str, Enum):
    log = "log"
    warning = "warning"
    error = "error"
    info = "info"
    debug = "debug"


# ---- Timing ----


class TimingData(BaseModel):
    """Timing for a single operation. All values in milliseconds."""

    started_at: str  # ISO 8601
    duration_ms: float
    ttfb_ms: float | None = None


# ---- Resources ----


class Resource(BaseModel):
    """A single subresource loaded during a page visit."""

    url: str
    resource_type: ResourceType
    status_code: int | None = None
    size_bytes: int | None = None
    timing: TimingData | None = None
    mime_type: str = ""
    has_integrity: bool = False


class ConsoleMessage(BaseModel):
    """A browser console message captured during page visit."""

    level: ConsoleMessageLevel
    text: str
    url: str = ""
    line: int | None = None


# ---- Node ----


class NodeState(BaseModel):
    """State identity for a node. URL-based, extensible for DOM fingerprinting."""

    url: str

    def identity_key(self) -> str:
        return self.url


class CookieInfo(BaseModel):
    """Security-relevant cookie attributes captured during visit."""

    name: str
    domain: str = ""
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str = ""  # "Strict", "Lax", "None", or ""
    expires: float = -1  # Unix timestamp, -1 = session cookie


class ResponseHeaders(BaseModel):
    """Security-relevant response headers from the document response."""

    raw: dict[str, str] = Field(default_factory=dict)


class FormInfo(BaseModel):
    """A form discovered on the page."""

    action: str = ""
    method: str = "GET"
    has_csrf_token: bool = False
    has_password_field: bool = False
    autocomplete_off: bool = False
    input_names: list[str] = Field(default_factory=list)
    input_types: list[str] = Field(default_factory=list)


class SecuritySeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class SecurityCategory(str, Enum):
    headers = "headers"
    cookies = "cookies"
    xss = "xss"
    mixed_content = "mixed_content"
    cors = "cors"
    information_disclosure = "information_disclosure"
    forms = "forms"
    tls = "tls"
    accessibility = "accessibility"
    visual = "visual"
    exploration = "exploration"
    injection = "injection"
    auth_session = "auth_session"
    privacy = "privacy"
    supply_chain = "supply_chain"
    sensitive_files = "sensitive_files"
    advocate = "advocate"


class ComplianceViolation(BaseModel):
    """A single compliance standard control violated by a finding."""

    standard: str
    standard_name: str
    control_id: str
    control_name: str
    testable: str = "yes"


class SecurityFinding(BaseModel):
    """A single security finding, optionally consolidated across multiple URLs."""

    category: SecurityCategory
    severity: SecuritySeverity
    title: str
    detail: str = ""
    evidence: str = ""
    url: str = ""
    auth_context: AuthContext = AuthContext.anonymous
    affected_urls: list[str] = Field(default_factory=list)
    affected_count: int = 0
    compliance_violations: list[ComplianceViolation] = Field(default_factory=list)


class NodeCapture(BaseModel):
    """Capture data for a single node visit in a single auth context."""

    auth_context: AuthContext
    http_status: int | None = None
    timing: TimingData | None = None
    dom_content_loaded_ms: float | None = None
    load_event_ms: float | None = None
    page_title: str = ""
    page_text: str = ""
    resources: list[Resource] = Field(default_factory=list)
    console_messages: list[ConsoleMessage] = Field(default_factory=list)
    outgoing_links: list[str] = Field(default_factory=list)
    screenshot_path: str = ""
    response_headers: ResponseHeaders = Field(default_factory=ResponseHeaders)
    cookies: list[CookieInfo] = Field(default_factory=list)
    forms: list[FormInfo] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)


class Node(BaseModel):
    """A node in the site state graph."""

    id: str
    state: NodeState
    discovered_via: DiscoveryMethod
    requires_auth: bool | None = None
    auth_contexts_available: list[AuthContext] = Field(default_factory=list)
    captures: list[NodeCapture] = Field(default_factory=list)
    depth: int = 0


# ---- Edge ----


class Edge(BaseModel):
    """A directed edge (link/action) between two nodes."""

    source: str
    target: str
    link_text: str = ""
    discovered_via: DiscoveryMethod = DiscoveryMethod.crawl
    auth_context: AuthContext = AuthContext.anonymous
    verified: bool = False


# ---- TLS ----


class TlsInfo(BaseModel):
    """TLS connection details for the target host."""

    protocol_version: str = ""
    cipher_suite: str = ""
    forward_secrecy: bool = False
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_not_after: str = ""
    cert_days_remaining: int = 0
    cert_self_signed: bool = False
    cert_key_type: str = ""
    cert_key_size: int = 0
    san_names: list[str] = Field(default_factory=list)


# ---- Graph ----


class SiteGraph(BaseModel):
    """The complete site graph discovered during mapping."""

    nodes: dict[str, Node] = Field(default_factory=dict)
    edges: list[Edge] = Field(default_factory=list)
    root_url: str = ""
    seed_urls: list[str] = Field(default_factory=list)
    tls_info: TlsInfo | None = None


# ---- Analysis Results ----


class BrokenLink(BaseModel):
    source: str
    target: str
    status_code: int | None = None
    error: str = ""


class AuthBoundaryViolation(BaseModel):
    """A page that should require auth but is accessible without it."""

    url: str
    expected_auth: bool
    actual_accessible_anonymous: bool
    evidence: str = ""


class TimingOutlier(BaseModel):
    url: str
    auth_context: AuthContext
    metric: str
    value_ms: float
    mean_ms: float
    stddev_ms: float
    z_score: float


class GraphMetrics(BaseModel):
    """Graph-level coverage and structure metrics."""

    total_nodes: int = 0
    total_edges: int = 0
    orphan_nodes: list[str] = Field(default_factory=list)
    dead_end_nodes: list[str] = Field(default_factory=list)
    unreachable_nodes: list[str] = Field(default_factory=list)
    strongly_connected_components: int = 0
    cyclomatic_complexity: int = 0
    max_depth: int = 0
    edge_coverage: float = 0.0


class PrimePath(BaseModel):
    """A prime path through the graph (loop-bounded)."""

    path: list[str]
    length: int
    contains_loop: bool = False


class ComplianceControlSummary(BaseModel):
    """Summary of a single compliance control's test status."""

    standard: str
    standard_name: str
    control_id: str
    control_name: str
    testable: str
    finding_count: int = 0
    max_severity: str = ""
    manual_notes: str = ""


class ComplianceSummary(BaseModel):
    """Aggregate compliance posture across all enabled standards."""

    standards_checked: list[str] = Field(default_factory=list)
    total_violations: int = 0
    violations_by_standard: dict[str, int] = Field(default_factory=dict)
    controls: list[ComplianceControlSummary] = Field(default_factory=list)
    untestable_controls: list[ComplianceControlSummary] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Results from Phase 3 graph analysis."""

    graph_metrics: GraphMetrics = Field(default_factory=GraphMetrics)
    broken_links: list[BrokenLink] = Field(default_factory=list)
    auth_violations: list[AuthBoundaryViolation] = Field(default_factory=list)
    timing_outliers: list[TimingOutlier] = Field(default_factory=list)
    prime_paths: list[PrimePath] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    compliance: ComplianceSummary | None = None


# ---- Run ----


def _make_run_id() -> str:
    now = datetime.now(timezone.utc)
    return f"{now.strftime('%Y%m%dT%H%M%S')}-{uuid4().hex[:8]}"


class PhaseStatus(BaseModel):
    """Status of a single phase execution."""

    phase: Literal["map", "capture", "analyze", "report", "explore", "advocate"]
    status: Literal["pending", "running", "completed", "failed"] = "pending"
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: float | None = None
    error: str | None = None


class CostSummary(BaseModel):
    """LLM cost tracking for the explore phase."""

    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    by_provider: dict = Field(default_factory=dict)


class Run(BaseModel):
    """A complete webprobe run. Top-level aggregation unit."""

    schema_version: str = SCHEMA_VERSION
    run_id: str = Field(default_factory=_make_run_id)
    url: str = ""
    started_at: str = ""
    completed_at: str | None = None
    config_snapshot: dict = Field(default_factory=dict)
    phases: list[PhaseStatus] = Field(default_factory=list)
    graph: SiteGraph = Field(default_factory=SiteGraph)
    analysis: AnalysisResult | None = None
    explore_cost: CostSummary | None = None
    advocate_cost: CostSummary | None = None


# ---- Diff ----


class NodeDiff(BaseModel):
    url: str
    change: Literal["added", "removed", "changed"]
    details: dict = Field(default_factory=dict)


class RunDiff(BaseModel):
    """Comparison between two runs."""

    run_a_id: str
    run_b_id: str
    nodes_added: list[str] = Field(default_factory=list)
    nodes_removed: list[str] = Field(default_factory=list)
    edges_added: list[Edge] = Field(default_factory=list)
    edges_removed: list[Edge] = Field(default_factory=list)
    status_changes: list[NodeDiff] = Field(default_factory=list)
    timing_changes: list[NodeDiff] = Field(default_factory=list)
    new_broken_links: list[BrokenLink] = Field(default_factory=list)
    resolved_broken_links: list[BrokenLink] = Field(default_factory=list)
    new_auth_violations: list[AuthBoundaryViolation] = Field(default_factory=list)
    resolved_auth_violations: list[AuthBoundaryViolation] = Field(default_factory=list)
