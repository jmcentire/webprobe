# === Webprobe Data Models (src_webprobe_models) v1 ===
#  Dependencies: datetime, enum, typing, uuid, pydantic
# Stable data models for webprobe site state-graph auditing. Defines Pydantic schemas for site graph nodes/edges, captures, security findings, analysis results, and run tracking. Schema version 1.1 pinned for cross-run aggregation and diffing.

# Module invariants:
#   - SCHEMA_VERSION = "1.1" - fixed schema version for cross-run compatibility
#   - Run instances default to current SCHEMA_VERSION constant
#   - NodeState.identity_key() always returns self.url (for now, extensible later)
#   - _make_run_id() format is always 'YYYYMMDDTHHmmss-<8-hex-chars>'
#   - All Pydantic models use default_factory for mutable defaults to avoid shared state

class AuthContext(Enum):
    """Authentication context for page visits"""
    anonymous = "anonymous"
    authenticated = "authenticated"

class DiscoveryMethod(Enum):
    """Method by which a node/edge was discovered"""
    sitemap = "sitemap"
    robots = "robots"
    crawl = "crawl"
    framework = "framework"
    manual = "manual"

class ResourceType(Enum):
    """Browser resource type classification"""
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

class ConsoleMessageLevel(Enum):
    """Browser console message severity level"""
    log = "log"
    warning = "warning"
    error = "error"
    info = "info"
    debug = "debug"

class SecuritySeverity(Enum):
    """Severity rating for security findings"""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class SecurityCategory(Enum):
    """Category of security finding"""
    headers = "headers"
    cookies = "cookies"
    xss = "xss"
    mixed_content = "mixed_content"
    cors = "cors"
    information_disclosure = "information_disclosure"
    forms = "forms"
    tls = "tls"

class TimingData:
    """Timing for a single operation. All values in milliseconds."""
    started_at: str                          # required, ISO 8601 timestamp
    duration_ms: float                       # required
    ttfb_ms: float | None = None             # optional

class Resource:
    """A single subresource loaded during a page visit"""
    url: str                                 # required
    resource_type: ResourceType              # required
    status_code: int | None = None           # optional
    size_bytes: int | None = None            # optional
    timing: TimingData | None = None         # optional
    mime_type: str = ""                      # optional

class ConsoleMessage:
    """A browser console message captured during page visit"""
    level: ConsoleMessageLevel               # required
    text: str                                # required
    url: str = ""                            # optional
    line: int | None = None                  # optional

class NodeState:
    """State identity for a node. URL-based, extensible for DOM fingerprinting."""
    url: str                                 # required

class CookieInfo:
    """Security-relevant cookie attributes captured during visit"""
    name: str                                # required
    domain: str = ""                         # optional
    path: str = "/"                          # optional
    secure: bool = False                     # optional
    http_only: bool = False                  # optional
    same_site: str = ""                      # optional, Strict, Lax, None, or empty string

class ResponseHeaders:
    """Security-relevant response headers from the document response"""
    raw: dict[str, str] = dict()             # optional

class FormInfo:
    """A form discovered on the page"""
    action: str = ""                         # optional
    method: str = "GET"                      # optional
    has_csrf_token: bool = False             # optional
    has_password_field: bool = False         # optional
    autocomplete_off: bool = False           # optional

class SecurityFinding:
    """A single security finding for a node"""
    category: SecurityCategory               # required
    severity: SecuritySeverity               # required
    title: str                               # required
    detail: str = ""                         # optional
    evidence: str = ""                       # optional
    url: str = ""                            # optional
    auth_context: AuthContext = AuthContext.anonymous # optional

class NodeCapture:
    """Capture data for a single node visit in a single auth context"""
    auth_context: AuthContext                # required
    http_status: int | None = None           # optional
    timing: TimingData | None = None         # optional
    dom_content_loaded_ms: float | None = None # optional
    load_event_ms: float | None = None       # optional
    page_title: str = ""                     # optional
    page_text: str = ""                      # optional
    resources: list[Resource] = []           # optional
    console_messages: list[ConsoleMessage] = [] # optional
    outgoing_links: list[str] = []           # optional
    screenshot_path: str = ""                # optional
    response_headers: ResponseHeaders = ResponseHeaders() # optional
    cookies: list[CookieInfo] = []           # optional
    forms: list[FormInfo] = []               # optional
    security_findings: list[SecurityFinding] = [] # optional

class Node:
    """A node in the site state graph"""
    id: str                                  # required
    state: NodeState                         # required
    discovered_via: DiscoveryMethod          # required
    requires_auth: bool | None = None        # optional
    auth_contexts_available: list[AuthContext] = [] # optional
    captures: list[NodeCapture] = []         # optional
    depth: int = 0                           # optional

class Edge:
    """A directed edge (link/action) between two nodes"""
    source: str                              # required
    target: str                              # required
    link_text: str = ""                      # optional
    discovered_via: DiscoveryMethod = DiscoveryMethod.crawl # optional
    auth_context: AuthContext = AuthContext.anonymous # optional
    verified: bool = False                   # optional

class SiteGraph:
    """The complete site graph discovered during mapping"""
    nodes: dict[str, Node] = dict()          # optional
    edges: list[Edge] = []                   # optional
    root_url: str = ""                       # optional
    seed_urls: list[str] = []                # optional

class BrokenLink:
    """A broken link detected during analysis"""
    source: str                              # required
    target: str                              # required
    status_code: int | None = None           # optional
    error: str = ""                          # optional

class AuthBoundaryViolation:
    """A page that should require auth but is accessible without it"""
    url: str                                 # required
    expected_auth: bool                      # required
    actual_accessible_anonymous: bool        # required
    evidence: str = ""                       # optional

class TimingOutlier:
    """A timing metric that is a statistical outlier"""
    url: str                                 # required
    auth_context: AuthContext                # required
    metric: str                              # required
    value_ms: float                          # required
    mean_ms: float                           # required
    stddev_ms: float                         # required
    z_score: float                           # required

class GraphMetrics:
    """Graph-level coverage and structure metrics"""
    total_nodes: int = 0                     # optional
    total_edges: int = 0                     # optional
    orphan_nodes: list[str] = []             # optional
    dead_end_nodes: list[str] = []           # optional
    unreachable_nodes: list[str] = []        # optional
    strongly_connected_components: int = 0   # optional
    cyclomatic_complexity: int = 0           # optional
    max_depth: int = 0                       # optional
    edge_coverage: float = 0.0               # optional

class PrimePath:
    """A prime path through the graph (loop-bounded)"""
    path: list[str]                          # required
    length: int                              # required
    contains_loop: bool = False              # optional

class AnalysisResult:
    """Results from Phase 3 graph analysis"""
    graph_metrics: GraphMetrics = GraphMetrics() # optional
    broken_links: list[BrokenLink] = []      # optional
    auth_violations: list[AuthBoundaryViolation] = [] # optional
    timing_outliers: list[TimingOutlier] = [] # optional
    prime_paths: list[PrimePath] = []        # optional
    security_findings: list[SecurityFinding] = [] # optional

class PhaseStatus:
    """Status of a single phase execution"""
    phase: Literal['map', 'capture', 'analyze', 'report', 'explore'] # required
    status: Literal['pending', 'running', 'completed', 'failed'] = 'pending' # optional
    started_at: str | None = None            # optional
    completed_at: str | None = None          # optional
    duration_ms: float | None = None         # optional
    error: str | None = None                 # optional

class CostSummary:
    """LLM cost tracking for the explore phase"""
    total_calls: int = 0                     # optional
    total_input_tokens: int = 0              # optional
    total_output_tokens: int = 0             # optional
    total_cost_usd: float = 0.0              # optional
    by_provider: dict = dict()               # optional

class Run:
    """A complete webprobe run. Top-level aggregation unit."""
    schema_version: str = SCHEMA_VERSION     # optional
    run_id: str = _make_run_id()             # optional
    url: str = ""                            # optional
    started_at: str = ""                     # optional
    completed_at: str | None = None          # optional
    config_snapshot: dict = dict()           # optional
    phases: list[PhaseStatus] = []           # optional
    graph: SiteGraph = SiteGraph()           # optional
    analysis: AnalysisResult | None = None   # optional
    explore_cost: CostSummary | None = None  # optional

class NodeDiff:
    """A change detected in a node between two runs"""
    url: str                                 # required
    change: Literal['added', 'removed', 'changed'] # required
    details: dict = dict()                   # optional

class RunDiff:
    """Comparison between two runs"""
    run_a_id: str                            # required
    run_b_id: str                            # required
    nodes_added: list[str] = []              # optional
    nodes_removed: list[str] = []            # optional
    edges_added: list[Edge] = []             # optional
    edges_removed: list[Edge] = []           # optional
    status_changes: list[NodeDiff] = []      # optional
    timing_changes: list[NodeDiff] = []      # optional
    new_broken_links: list[BrokenLink] = []  # optional
    resolved_broken_links: list[BrokenLink] = [] # optional
    new_auth_violations: list[AuthBoundaryViolation] = [] # optional
    resolved_auth_violations: list[AuthBoundaryViolation] = [] # optional

def _make_run_id() -> str:
    """
    Generates a unique run identifier combining UTC timestamp and UUID hex suffix. Format: YYYYMMDDTHHmmss-<8-char-hex>

    Postconditions:
      - Returns a string matching pattern 'YYYYMMDDTHHmmss-[a-f0-9]{8}'
      - Timestamp is in UTC timezone
      - UUID suffix is 8 characters from uuid4().hex

    Side effects: none
    Idempotent: no
    """
    ...

def identity_key(
    self: NodeState,
) -> str:
    """
    Returns the identity key for a NodeState instance. Currently returns the URL directly, extensible for DOM fingerprinting.

    Preconditions:
      - self.url is set (required field in NodeState)

    Postconditions:
      - Returns the exact value of self.url
      - Return value can be used to uniquely identify the node state

    Side effects: none
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['AuthContext', 'DiscoveryMethod', 'ResourceType', 'ConsoleMessageLevel', 'SecuritySeverity', 'SecurityCategory', 'TimingData', 'Resource', 'ConsoleMessage', 'NodeState', 'CookieInfo', 'ResponseHeaders', 'FormInfo', 'SecurityFinding', 'NodeCapture', 'Node', 'Edge', 'SiteGraph', 'BrokenLink', 'AuthBoundaryViolation', 'TimingOutlier', 'GraphMetrics', 'PrimePath', 'AnalysisResult', 'PhaseStatus', 'CostSummary', 'Run', 'NodeDiff', 'RunDiff', '_make_run_id', 'identity_key']
