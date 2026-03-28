# === WebProbe Security Scanner (src_webprobe_security) v1 ===
#  Dependencies: re, urllib.parse, webprobe.models
# Passive security scanning module that analyzes captured HTTP data for common web vulnerabilities including missing security headers, insecure cookies, mixed content, CORS misconfigurations, information disclosure, form security issues, and XSS signals. Operates on NodeCapture and SiteGraph objects to produce SecurityFinding reports without actively probing the target.

# Module invariants:
#   - HSTS max-age threshold is 31536000 seconds (1 year)
#   - Session-like cookie heuristic keywords: 'session', 'token', 'auth', 'sid', 'jwt', 'access'
#   - Stack trace patterns checked: 'traceback (most recent call last)', 'at .+\\(.+:\\d+:\\d+\\)', 'exception in thread', 'fatal error:.*on line \\d+', 'stack trace:', 'unhandled exception'
#   - High-risk resource types for mixed content: 'script', 'stylesheet'
#   - Valid X-Frame-Options values: 'DENY', 'SAMEORIGIN'
#   - Minimum parameter length for XSS reflection check: 3 characters
#   - Deduplication key for findings: (url, category.value, title)

def check_security_headers(
    url: str,
    headers: ResponseHeaders,
    auth_ctx: AuthContext,
) -> list[SecurityFinding]:
    """
    Analyzes HTTP response headers for missing or misconfigured security headers. Checks HSTS (Strict-Transport-Security), CSP (Content-Security-Policy), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. Returns findings for missing headers, weak HSTS max-age (<1 year), CSP with unsafe-inline or unsafe-eval, weak X-Frame-Options values, and missing nosniff directive.

    Preconditions:
      - headers.raw must be a dict-like object with string keys and values
      - url must be a valid string

    Postconditions:
      - Returns list of SecurityFinding objects (may be empty)
      - All findings have category set to SecurityCategory.headers, SecurityCategory.xss, or related
      - All findings include url and auth_context
      - HSTS max-age findings only created if max-age header exists but value < 31536000

    Errors:
      - header_parsing_error (AttributeError or TypeError): If headers.raw.items() raises exception
      - regex_group_error (IndexError or AttributeError): If max-age regex match exists but group(1) fails
      - int_conversion_error (ValueError): If max-age value cannot be converted to int

    Side effects: Creates new SecurityFinding objects
    Idempotent: yes
    """
    ...

def check_cookies(
    url: str,
    cookies: list[CookieInfo],
    auth_ctx: AuthContext,
) -> list[SecurityFinding]:
    """
    Examines cookie security attributes for all cookies. Detects missing Secure flag on HTTPS sites, missing HttpOnly flag on session-like cookies (heuristic: name contains session/token/auth/sid/jwt/access), and weak SameSite policy (not set or set to 'none'). Severity is elevated for session-like cookies.

    Preconditions:
      - url must be a valid string that urlparse can process
      - cookies must be iterable
      - Each cookie must have name, secure, http_only, same_site, and domain attributes

    Postconditions:
      - Returns list of SecurityFinding objects (may be empty)
      - All findings have category set to SecurityCategory.cookies
      - Session-like cookies get higher severity ratings
      - Findings only created for HTTPS URLs when checking Secure flag

    Errors:
      - url_parse_error (ValueError): If urlparse(url) fails
      - cookie_attribute_error (AttributeError): If cookie object missing required attributes

    Side effects: Creates new SecurityFinding objects
    Idempotent: yes
    """
    ...

def check_mixed_content(
    url: str,
    capture: NodeCapture,
) -> list[SecurityFinding]:
    """
    Detects HTTP resources loaded on HTTPS pages (mixed content). Categorizes by resource type with higher severity for scripts and stylesheets. Only runs checks if the page URL is HTTPS.

    Preconditions:
      - url must be a string
      - capture.resources must be iterable
      - Each resource must have url, resource_type.value, and related attributes

    Postconditions:
      - Returns empty list if URL does not start with 'https://'
      - Returns list of SecurityFinding objects for HTTP resources on HTTPS pages
      - All findings have category SecurityCategory.mixed_content
      - Scripts and stylesheets get SecuritySeverity.high, others get medium

    Errors:
      - resource_attribute_error (AttributeError): If resource object missing url or resource_type.value

    Side effects: Creates new SecurityFinding objects
    Idempotent: yes
    """
    ...

def check_cors(
    url: str,
    headers: ResponseHeaders,
    auth_ctx: AuthContext,
) -> list[SecurityFinding]:
    """
    Checks for CORS misconfigurations in response headers. Detects Access-Control-Allow-Origin: * with credentials (critical severity) or without credentials (low severity).

    Preconditions:
      - headers.raw must be a dict-like object

    Postconditions:
      - Returns list of SecurityFinding objects (may be empty)
      - All findings have category SecurityCategory.cors
      - ACAO=* with ACAC=true gets critical severity
      - ACAO=* without credentials gets low severity

    Errors:
      - header_access_error (AttributeError or TypeError): If headers.raw access fails

    Side effects: Creates new SecurityFinding objects
    Idempotent: yes
    """
    ...

def check_information_disclosure(
    url: str,
    headers: ResponseHeaders,
    capture: NodeCapture,
) -> list[SecurityFinding]:
    """
    Scans for information leakage in headers and page content. Checks: Server header with version numbers, X-Powered-By header, exposed .map files (status 200), and stack traces/error messages in page text using pattern matching.

    Preconditions:
      - headers.raw must be dict-like
      - capture.resources must be iterable
      - capture.page_text must be a string
      - capture.auth_context must exist

    Postconditions:
      - Returns list of SecurityFinding objects (may be empty)
      - All findings have category SecurityCategory.information_disclosure
      - Stack trace findings are limited to one per page (breaks after first match)
      - Source map findings only for .map files with status_code == 200

    Errors:
      - regex_search_error (re.error): If re.search raises exception on malformed pattern or text
      - attribute_error (AttributeError): If capture missing page_text or resources attributes

    Side effects: Creates new SecurityFinding objects
    Idempotent: yes
    """
    ...

def check_forms(
    url: str,
    forms: list[FormInfo],
    auth_ctx: AuthContext,
) -> list[SecurityFinding]:
    """
    Analyzes form security: POST forms without CSRF tokens, password fields with autocomplete enabled, and forms on HTTPS pages that submit to HTTP endpoints.

    Preconditions:
      - forms must be iterable
      - Each form must have method, has_csrf_token, action, has_password_field, and autocomplete_off attributes

    Postconditions:
      - Returns list of SecurityFinding objects (may be empty)
      - Findings have category SecurityCategory.forms or SecurityCategory.mixed_content
      - POST forms without CSRF tokens get medium severity
      - Forms submitting to HTTP from HTTPS get high severity

    Errors:
      - form_attribute_error (AttributeError): If form object missing required attributes

    Side effects: Creates new SecurityFinding objects
    Idempotent: yes
    """
    ...

def check_xss_signals(
    url: str,
    capture: NodeCapture,
) -> list[SecurityFinding]:
    """
    Checks for XSS-related signals by detecting URL query parameters reflected in page content. Basic reflected XSS indicator using string matching.

    Preconditions:
      - url must be parseable by urlparse
      - capture.page_text must be a string
      - capture.auth_context must exist

    Postconditions:
      - Returns list of SecurityFinding objects (may be empty)
      - All findings have category SecurityCategory.xss and severity medium
      - Only checks parameters longer than 3 characters
      - Findings created when parameter value found in page_text

    Errors:
      - url_parse_error (ValueError): If urlparse fails on malformed URL
      - string_split_error (ValueError): If query parameter parsing fails

    Side effects: Creates new SecurityFinding objects
    Idempotent: yes
    """
    ...

def scan_capture(
    url: str,
    capture: NodeCapture,
) -> list[SecurityFinding]:
    """
    Runs all passive security check functions on a single NodeCapture and aggregates results. Invokes check_security_headers, check_cookies, check_mixed_content, check_cors, check_information_disclosure, check_forms, and check_xss_signals.

    Preconditions:
      - capture must have response_headers, cookies, forms, auth_context, resources, and page_text attributes

    Postconditions:
      - Returns aggregated list of all SecurityFinding objects from all check functions
      - Findings are ordered by check function execution order

    Errors:
      - check_function_error (Any exception from check_* functions): If any called check function raises an exception

    Side effects: Calls all check_* functions which create SecurityFinding objects
    Idempotent: yes
    """
    ...

def scan_graph(
    graph: SiteGraph,
) -> list[SecurityFinding]:
    """
    Runs security scans across all captured nodes in a SiteGraph. Deduplicates findings by (url, category, title) tuple and attaches findings to each capture's security_findings list for per-node reporting.

    Preconditions:
      - graph.nodes must be a dict-like object with .values() method
      - Each node must have .id and .captures attributes
      - Each capture must have .security_findings list attribute

    Postconditions:
      - Returns deduplicated list of all SecurityFinding objects across all nodes
      - Each unique finding (by url, category, title) appears only once in return list
      - All findings are also appended to their respective capture.security_findings lists
      - Findings are deduplicated using set of (url, category.value, title) tuples

    Errors:
      - graph_access_error (AttributeError): If graph.nodes access or iteration fails
      - node_access_error (AttributeError): If node missing id or captures attributes
      - scan_capture_error (Any exception from scan_capture): If scan_capture raises exception

    Side effects: Mutates capture.security_findings lists by appending findings, Calls scan_capture for each node/capture pair
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['check_security_headers', 'AttributeError or TypeError', 'IndexError or AttributeError', 'check_cookies', 'check_mixed_content', 'check_cors', 'check_information_disclosure', 'check_forms', 'check_xss_signals', 'scan_capture', 'Any exception from check_* functions', 'scan_graph', 'Any exception from scan_capture']
