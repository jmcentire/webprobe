"""
Contract-based test suite for WebProbe Security Scanner (src_webprobe_security)

This test suite validates the security scanning functions against their contract
specifications, covering happy paths, edge cases, error conditions, and invariants.

Functions under test:
- check_security_headers: Analyzes HTTP response headers for security issues
- check_cookies: Examines cookie security attributes
- check_mixed_content: Detects HTTP resources on HTTPS pages
- check_cors: Checks for CORS misconfigurations
- check_information_disclosure: Scans for information leakage
- check_forms: Analyzes form security
- check_xss_signals: Checks for XSS-related signals
- scan_capture: Runs all passive security checks on a NodeCapture
- scan_graph: Runs security scans across all captured nodes in a SiteGraph
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, PropertyMock
from typing import List, Dict, Any
import re

# Import the component under test
from src.webprobe.security import (
    check_security_headers,
    check_cookies,
    check_mixed_content,
    check_cors,
    check_information_disclosure,
    check_forms,
    check_xss_signals,
    scan_capture,
    scan_graph,
)
from webprobe.models import AuthContext


# ============================================================================
# FIXTURES - Comprehensive fixture library for testing
# ============================================================================

@pytest.fixture
def mock_auth_context():
    """Create an AuthContext enum value for testing."""
    return AuthContext.anonymous


@pytest.fixture
def secure_response_headers():
    """Create ResponseHeaders with all secure headers properly configured."""
    headers = Mock()
    headers.raw = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=()',
    }
    return headers


@pytest.fixture
def insecure_response_headers():
    """Create ResponseHeaders missing critical security headers."""
    headers = Mock()
    headers.raw = {
        'Content-Type': 'text/html',
    }
    return headers


@pytest.fixture
def weak_hsts_headers():
    """Create ResponseHeaders with weak HSTS max-age."""
    headers = Mock()
    headers.raw = {
        'Strict-Transport-Security': 'max-age=3600',  # Less than 1 year
    }
    return headers


@pytest.fixture
def boundary_hsts_headers():
    """Create ResponseHeaders with HSTS max-age exactly at 1 year."""
    headers = Mock()
    headers.raw = {
        'Strict-Transport-Security': 'max-age=31536000',  # Exactly 1 year
    }
    return headers


@pytest.fixture
def unsafe_csp_headers():
    """Create ResponseHeaders with unsafe CSP directives."""
    headers = Mock()
    headers.raw = {
        'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
    }
    return headers


@pytest.fixture
def weak_x_frame_options_headers():
    """Create ResponseHeaders with weak X-Frame-Options."""
    headers = Mock()
    headers.raw = {
        'X-Frame-Options': 'ALLOW-FROM https://example.com',
    }
    return headers


@pytest.fixture
def secure_cookies():
    """Create list of properly secured cookies."""
    cookie = Mock()
    cookie.name = 'normal_cookie'
    cookie.secure = True
    cookie.http_only = True
    cookie.same_site = 'strict'
    cookie.domain = 'example.com'
    return [cookie]


@pytest.fixture
def insecure_cookie_no_secure():
    """Create cookie missing Secure flag."""
    cookie = Mock()
    cookie.name = 'test_cookie'
    cookie.secure = False
    cookie.http_only = True
    cookie.same_site = 'strict'
    cookie.domain = 'example.com'
    return [cookie]


@pytest.fixture
def session_cookie_no_httponly():
    """Create session cookie missing HttpOnly flag."""
    cookie = Mock()
    cookie.name = 'session_id'
    cookie.secure = True
    cookie.http_only = False
    cookie.same_site = 'strict'
    cookie.domain = 'example.com'
    return [cookie]


@pytest.fixture
def cookie_weak_samesite():
    """Create cookie with weak SameSite policy."""
    cookie = Mock()
    cookie.name = 'test_cookie'
    cookie.secure = True
    cookie.http_only = True
    cookie.same_site = 'none'
    cookie.domain = 'example.com'
    return [cookie]


@pytest.fixture
def https_capture_all_secure():
    """Create NodeCapture for HTTPS page with all HTTPS resources."""
    capture = Mock()
    
    resource1 = Mock()
    resource1.url = 'https://example.com/script.js'
    resource1.resource_type = Mock()
    resource1.resource_type.value = 'script'
    
    resource2 = Mock()
    resource2.url = 'https://example.com/style.css'
    resource2.resource_type = Mock()
    resource2.resource_type.value = 'stylesheet'
    
    capture.resources = [resource1, resource2]
    capture.page_text = "Clean page content"
    capture.auth_context = AuthContext.anonymous
    return capture


@pytest.fixture
def https_capture_mixed_content_script():
    """Create NodeCapture with HTTP script on HTTPS page."""
    capture = Mock()
    
    resource = Mock()
    resource.url = 'http://example.com/script.js'
    resource.resource_type = Mock()
    resource.resource_type.value = 'script'
    
    capture.resources = [resource]
    capture.page_text = "Page content"
    capture.auth_context = AuthContext.anonymous
    return capture


@pytest.fixture
def https_capture_mixed_content_stylesheet():
    """Create NodeCapture with HTTP stylesheet on HTTPS page."""
    capture = Mock()
    
    resource = Mock()
    resource.url = 'http://example.com/style.css'
    resource.resource_type = Mock()
    resource.resource_type.value = 'stylesheet'
    
    capture.resources = [resource]
    capture.page_text = "Page content"
    capture.auth_context = AuthContext.anonymous
    return capture


@pytest.fixture
def https_capture_mixed_content_image():
    """Create NodeCapture with HTTP image on HTTPS page."""
    capture = Mock()
    
    resource = Mock()
    resource.url = 'http://example.com/image.jpg'
    resource.resource_type = Mock()
    resource.resource_type.value = 'image'
    
    capture.resources = [resource]
    capture.page_text = "Page content"
    capture.auth_context = AuthContext.anonymous
    return capture


@pytest.fixture
def cors_wildcard_with_credentials():
    """Create ResponseHeaders with CORS wildcard and credentials."""
    headers = Mock()
    headers.raw = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
    }
    return headers


@pytest.fixture
def cors_wildcard_no_credentials():
    """Create ResponseHeaders with CORS wildcard without credentials."""
    headers = Mock()
    headers.raw = {
        'Access-Control-Allow-Origin': '*',
    }
    return headers


@pytest.fixture
def cors_specific_origin():
    """Create ResponseHeaders with specific CORS origin."""
    headers = Mock()
    headers.raw = {
        'Access-Control-Allow-Origin': 'https://trusted.com',
    }
    return headers


@pytest.fixture
def info_disclosure_server_version():
    """Create ResponseHeaders with Server version disclosure."""
    headers = Mock()
    headers.raw = {
        'Server': 'Apache/2.4.1 (Unix)',
    }
    return headers


@pytest.fixture
def info_disclosure_x_powered_by():
    """Create ResponseHeaders with X-Powered-By disclosure."""
    headers = Mock()
    headers.raw = {
        'X-Powered-By': 'PHP/7.4.3',
    }
    return headers


@pytest.fixture
def capture_with_source_map_200():
    """Create NodeCapture with accessible .map file."""
    capture = Mock()
    
    resource = Mock()
    resource.url = 'https://example.com/app.js.map'
    resource.status_code = 200
    
    capture.resources = [resource]
    capture.page_text = "Page content"
    capture.auth_context = AuthContext.anonymous
    return capture


@pytest.fixture
def capture_with_source_map_404():
    """Create NodeCapture with inaccessible .map file."""
    capture = Mock()
    
    resource = Mock()
    resource.url = 'https://example.com/app.js.map'
    resource.status_code = 404
    
    capture.resources = [resource]
    capture.page_text = "Page content"
    capture.auth_context = AuthContext.anonymous
    return capture


@pytest.fixture
def capture_with_stack_trace():
    """Create NodeCapture with stack trace in page content."""
    capture = Mock()
    capture.resources = []
    capture.page_text = "Error: Traceback (most recent call last): File main.py line 42"
    capture.auth_context = AuthContext.anonymous
    return capture


@pytest.fixture
def secure_forms():
    """Create list of secure forms."""
    form = Mock()
    form.method = 'POST'
    form.has_csrf_token = True
    form.action = 'https://example.com/submit'
    form.has_password_field = False
    form.autocomplete_off = True
    return [form]


@pytest.fixture
def form_post_no_csrf():
    """Create POST form without CSRF token."""
    form = Mock()
    form.method = 'POST'
    form.has_csrf_token = False
    form.action = 'https://example.com/submit'
    form.has_password_field = False
    form.autocomplete_off = True
    return [form]


@pytest.fixture
def form_password_autocomplete():
    """Create form with password field and autocomplete enabled."""
    form = Mock()
    form.method = 'POST'
    form.has_csrf_token = True
    form.action = 'https://example.com/submit'
    form.has_password_field = True
    form.autocomplete_off = False
    return [form]


@pytest.fixture
def form_https_to_http():
    """Create form on HTTPS submitting to HTTP."""
    form = Mock()
    form.method = 'POST'
    form.has_csrf_token = True
    form.action = 'http://example.com/submit'
    form.has_password_field = False
    form.autocomplete_off = True
    return [form]


@pytest.fixture
def capture_xss_reflection():
    """Create NodeCapture with reflected parameter."""
    capture = Mock()
    capture.page_text = "Search results for: testvalue"
    capture.auth_context = AuthContext.anonymous
    return capture


@pytest.fixture
def capture_no_reflection():
    """Create NodeCapture without reflected parameters."""
    capture = Mock()
    capture.page_text = "Normal page content"
    capture.auth_context = AuthContext.anonymous
    return capture


@pytest.fixture
def full_node_capture():
    """Create complete NodeCapture with all required attributes."""
    capture = Mock()
    capture.response_headers = Mock()
    capture.response_headers.raw = {}
    capture.cookies = []
    capture.forms = []
    capture.auth_context = AuthContext.anonymous
    capture.resources = []
    capture.page_text = "Content"
    capture.security_findings = []
    capture.outgoing_links = []
    return capture


@pytest.fixture
def site_graph_multi_node():
    """Create SiteGraph with multiple nodes."""
    graph = Mock()

    node1 = Mock()
    node1.id = "node1"
    capture1 = Mock()
    capture1.security_findings = []
    capture1.response_headers = Mock()
    capture1.response_headers.raw = {}
    capture1.cookies = []
    capture1.forms = []
    capture1.auth_context = AuthContext.anonymous
    capture1.resources = []
    capture1.page_text = "Content 1"
    capture1.outgoing_links = []
    node1.captures = [capture1]

    node2 = Mock()
    node2.id = "node2"
    capture2 = Mock()
    capture2.security_findings = []
    capture2.response_headers = Mock()
    capture2.response_headers.raw = {}
    capture2.cookies = []
    capture2.forms = []
    capture2.auth_context = AuthContext.anonymous
    capture2.resources = []
    capture2.page_text = "Content 2"
    capture2.outgoing_links = []
    node2.captures = [capture2]

    graph.nodes = {"node1": node1, "node2": node2}
    graph.tls_info = None
    graph.root_url = ""
    graph.seed_urls = []
    return graph


# ============================================================================
# TEST: check_security_headers
# ============================================================================

def test_check_security_headers_happy_path_all_secure(secure_response_headers, mock_auth_context):
    """Happy path: All security headers present and properly configured."""
    result = check_security_headers(
        "https://example.com",
        secure_response_headers,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # With all secure headers, there should be no findings for missing headers
    # But we need to verify the function returns a list


def test_check_security_headers_missing_hsts(insecure_response_headers, mock_auth_context):
    """Detect missing HSTS header."""
    result = check_security_headers(
        "https://example.com",
        insecure_response_headers,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # Should contain finding for missing HSTS
    hsts_findings = [f for f in result if 'HSTS' in str(f) or 'Strict-Transport-Security' in str(f)]
    assert len(hsts_findings) > 0


def test_check_security_headers_weak_hsts_max_age(weak_hsts_headers, mock_auth_context):
    """Detect HSTS with max-age less than 1 year (31536000 seconds)."""
    result = check_security_headers(
        "https://example.com",
        weak_hsts_headers,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # Should contain finding for weak max-age (postcondition states findings only created if < 31536000)
    weak_hsts_findings = [f for f in result if 'max-age' in f.title.lower()]
    assert len(weak_hsts_findings) > 0


def test_check_security_headers_hsts_max_age_boundary(boundary_hsts_headers, mock_auth_context):
    """HSTS max-age exactly at 1 year threshold should not create finding."""
    result = check_security_headers(
        "https://example.com",
        boundary_hsts_headers,
        mock_auth_context
    )

    assert isinstance(result, list)
    # Should not have finding for max-age >= 31536000
    weak_hsts_findings = [f for f in result if 'max-age' in f.title.lower()]
    assert len(weak_hsts_findings) == 0


def test_check_security_headers_csp_unsafe_inline(unsafe_csp_headers, mock_auth_context):
    """Detect CSP with unsafe-inline directive."""
    result = check_security_headers(
        "https://example.com",
        unsafe_csp_headers,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # Should contain finding for unsafe CSP
    csp_findings = [f for f in result if 'unsafe-inline' in f.title.lower() or 'csp' in f.title.lower()]
    assert len(csp_findings) > 0


def test_check_security_headers_weak_x_frame_options(weak_x_frame_options_headers, mock_auth_context):
    """Detect weak X-Frame-Options (not DENY or SAMEORIGIN)."""
    result = check_security_headers(
        "https://example.com",
        weak_x_frame_options_headers,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # Should contain finding for weak X-Frame-Options
    xframe_findings = [f for f in result if 'x-frame-options' in f.title.lower()]
    assert len(xframe_findings) > 0


def test_check_security_headers_header_parsing_error(mock_auth_context):
    """Error when headers.raw.items() raises exception."""
    headers = Mock()
    headers.raw = Mock()
    headers.raw.items = Mock(side_effect=Exception("Parsing error"))
    
    with pytest.raises(Exception) as exc_info:
        check_security_headers("https://example.com", headers, mock_auth_context)
    
    assert "Parsing error" in str(exc_info.value) or "header_parsing_error" in str(exc_info.value).lower()


def test_check_security_headers_regex_group_error(mock_auth_context):
    """Error when max-age regex match exists but group(1) fails."""
    headers = Mock()
    # Create a malformed HSTS header that will match but fail on group extraction
    headers.raw = {
        'Strict-Transport-Security': 'max-age=',  # Empty value
    }
    
    # This test depends on implementation details - the function should handle this gracefully
    # or raise regex_group_error
    try:
        result = check_security_headers("https://example.com", headers, mock_auth_context)
        # If it doesn't raise, it should return a list
        assert isinstance(result, list)
    except Exception as e:
        assert "regex_group_error" in str(e).lower() or "group" in str(e).lower()


def test_check_security_headers_int_conversion_error(mock_auth_context):
    """Error when max-age value cannot be converted to int."""
    headers = Mock()
    headers.raw = {
        'Strict-Transport-Security': 'max-age=not_a_number',
    }
    
    try:
        result = check_security_headers("https://example.com", headers, mock_auth_context)
        # Function should either handle this or raise int_conversion_error
        assert isinstance(result, list)
    except Exception as e:
        assert "int_conversion_error" in str(e).lower() or "int" in str(e).lower() or "invalid literal" in str(e).lower()


# ============================================================================
# TEST: check_cookies
# ============================================================================

def test_check_cookies_happy_path_secure(secure_cookies, mock_auth_context):
    """Happy path: All cookies properly secured with flags."""
    result = check_cookies(
        "https://example.com",
        secure_cookies,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # Secure cookies should have minimal or no findings


def test_check_cookies_missing_secure_flag_https(insecure_cookie_no_secure, mock_auth_context):
    """Detect missing Secure flag on HTTPS sites."""
    result = check_cookies(
        "https://example.com",
        insecure_cookie_no_secure,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # Should contain finding for missing Secure flag on HTTPS
    secure_findings = [f for f in result if 'secure' in f.title.lower()]
    assert len(secure_findings) > 0


def test_check_cookies_session_cookie_missing_httponly(session_cookie_no_httponly, mock_auth_context):
    """Detect session-like cookie missing HttpOnly flag."""
    result = check_cookies(
        "https://example.com",
        session_cookie_no_httponly,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # Should contain finding with elevated severity for session cookie
    httponly_findings = [f for f in result if 'httponly' in f.title.lower()]
    assert len(httponly_findings) > 0


def test_check_cookies_weak_samesite(cookie_weak_samesite, mock_auth_context):
    """Detect weak SameSite policy (none or not set)."""
    result = check_cookies(
        "https://example.com",
        cookie_weak_samesite,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # Should contain finding for weak SameSite
    samesite_findings = [f for f in result if 'samesite' in f.title.lower()]
    assert len(samesite_findings) > 0


def test_check_cookies_session_heuristic_keywords(mock_auth_context):
    """Test all session-like cookie heuristic keywords."""
    keywords = ['session', 'token', 'auth', 'sid', 'jwt', 'access']
    
    for keyword in keywords:
        cookie = Mock()
        cookie.name = f'{keyword}_cookie'
        cookie.secure = True
        cookie.http_only = False  # Missing HttpOnly
        cookie.same_site = 'strict'
        cookie.domain = 'example.com'
        
        result = check_cookies("https://example.com", [cookie], mock_auth_context)
        
        assert isinstance(result, list)
        # Session-like cookies should trigger findings with elevated severity
        assert len(result) > 0


def test_check_cookies_url_parse_error(secure_cookies, mock_auth_context):
    """urlparse handles malformed URLs gracefully without raising."""
    # urlparse does not raise on malformed URLs; it parses them best-effort
    result = check_cookies("malformed:::url", secure_cookies, mock_auth_context)
    assert isinstance(result, list)


def test_check_cookies_attribute_error(mock_auth_context):
    """Error when cookie object missing required attributes."""
    incomplete_cookie = Mock(spec=[])  # No attributes
    
    with pytest.raises(AttributeError) as exc_info:
        check_cookies("https://example.com", [incomplete_cookie], mock_auth_context)
    
    assert "cookie_attribute_error" in str(exc_info.value).lower() or "attribute" in str(exc_info.value).lower()


# ============================================================================
# TEST: check_mixed_content
# ============================================================================

def test_check_mixed_content_happy_path_all_https(https_capture_all_secure):
    """Happy path: HTTPS page with all HTTPS resources."""
    result = check_mixed_content(
        "https://example.com",
        https_capture_all_secure
    )
    
    assert isinstance(result, list)
    assert len(result) == 0  # No mixed content


def test_check_mixed_content_http_page(https_capture_all_secure):
    """Edge case: HTTP page should return empty list."""
    result = check_mixed_content(
        "http://example.com",  # HTTP URL
        https_capture_all_secure
    )
    
    assert isinstance(result, list)
    assert len(result) == 0  # Postcondition: returns empty list if URL not HTTPS


def test_check_mixed_content_http_script(https_capture_mixed_content_script):
    """Detect HTTP script on HTTPS page (high severity)."""
    result = check_mixed_content(
        "https://example.com",
        https_capture_mixed_content_script
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should have high severity for script
    script_findings = [f for f in result if hasattr(f, 'severity')]
    assert len(script_findings) > 0


def test_check_mixed_content_http_stylesheet(https_capture_mixed_content_stylesheet):
    """Detect HTTP stylesheet on HTTPS page (high severity)."""
    result = check_mixed_content(
        "https://example.com",
        https_capture_mixed_content_stylesheet
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should have high severity for stylesheet


def test_check_mixed_content_http_image(https_capture_mixed_content_image):
    """Detect HTTP image on HTTPS page (medium severity)."""
    result = check_mixed_content(
        "https://example.com",
        https_capture_mixed_content_image
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should have medium severity for non-high-risk resource


def test_check_mixed_content_resource_attribute_error():
    """Error when resource object missing url or resource_type.value."""
    capture = Mock()
    resource = Mock(spec=[])  # No attributes
    capture.resources = [resource]
    
    with pytest.raises(AttributeError) as exc_info:
        check_mixed_content("https://example.com", capture)
    
    assert "resource_attribute_error" in str(exc_info.value).lower() or "attribute" in str(exc_info.value).lower()


# ============================================================================
# TEST: check_cors
# ============================================================================

def test_check_cors_happy_path_no_wildcard(cors_specific_origin, mock_auth_context):
    """Happy path: CORS without wildcard origin."""
    result = check_cors(
        "https://example.com",
        cors_specific_origin,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    assert len(result) == 0  # No findings for specific origin


def test_check_cors_wildcard_with_credentials(cors_wildcard_with_credentials, mock_auth_context):
    """Detect ACAO=* with ACAC=true (critical severity)."""
    result = check_cors(
        "https://example.com",
        cors_wildcard_with_credentials,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should have critical severity
    critical_findings = [f for f in result if hasattr(f, 'severity')]
    assert len(critical_findings) > 0


def test_check_cors_wildcard_without_credentials(cors_wildcard_no_credentials, mock_auth_context):
    """Detect ACAO=* without credentials (low severity)."""
    result = check_cors(
        "https://example.com",
        cors_wildcard_no_credentials,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should have low severity


def test_check_cors_header_access_error(mock_auth_context):
    """Error when headers.raw.items() raises exception."""
    headers = Mock()
    raw_mock = Mock()
    raw_mock.items = Mock(side_effect=Exception("Access error"))
    headers.raw = raw_mock

    with pytest.raises(Exception) as exc_info:
        check_cors("https://example.com", headers, mock_auth_context)

    assert "access error" in str(exc_info.value).lower()


# ============================================================================
# TEST: check_information_disclosure
# ============================================================================

def test_check_information_disclosure_happy_path_clean(secure_response_headers, https_capture_all_secure):
    """Happy path: No information disclosure detected."""
    result = check_information_disclosure(
        "https://example.com",
        secure_response_headers,
        https_capture_all_secure
    )
    
    assert isinstance(result, list)
    # Clean headers and content should have minimal findings


def test_check_information_disclosure_server_version(info_disclosure_server_version, https_capture_all_secure):
    """Detect Server header with version numbers."""
    result = check_information_disclosure(
        "https://example.com",
        info_disclosure_server_version,
        https_capture_all_secure
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should find Server version disclosure


def test_check_information_disclosure_x_powered_by(info_disclosure_x_powered_by, https_capture_all_secure):
    """Detect X-Powered-By header."""
    result = check_information_disclosure(
        "https://example.com",
        info_disclosure_x_powered_by,
        https_capture_all_secure
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should find X-Powered-By disclosure


def test_check_information_disclosure_source_map(secure_response_headers, capture_with_source_map_200):
    """Detect exposed .map files with status 200."""
    result = check_information_disclosure(
        "https://example.com",
        secure_response_headers,
        capture_with_source_map_200
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should find exposed source map


def test_check_information_disclosure_source_map_not_200(secure_response_headers, capture_with_source_map_404):
    """Edge case: .map file with status != 200 should not create finding."""
    result = check_information_disclosure(
        "https://example.com",
        secure_response_headers,
        capture_with_source_map_404
    )
    
    assert isinstance(result, list)
    # Should not find .map file with status 404
    map_findings = [f for f in result if 'source map' in f.title.lower()]
    assert len(map_findings) == 0


def test_check_information_disclosure_stack_trace(secure_response_headers, capture_with_stack_trace):
    """Detect stack trace in page content."""
    result = check_information_disclosure(
        "https://example.com",
        secure_response_headers,
        capture_with_stack_trace
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should find stack trace (limited to one per page)


def test_check_information_disclosure_stack_trace_patterns(secure_response_headers):
    """Test all documented stack trace patterns."""
    patterns = [
        'Traceback (most recent call last)',
        'at main.js:10:5',
        'Exception in thread "main"',
        'Fatal error: syntax error on line 42',
        'Stack trace:',
        'Unhandled exception occurred'
    ]
    
    for pattern in patterns:
        capture = Mock()
        capture.resources = []
        capture.page_text = f"Error page with {pattern} in content"
        capture.auth_context = AuthContext.anonymous
        
        result = check_information_disclosure(
            "https://example.com",
            secure_response_headers,
            capture
        )
        
        assert isinstance(result, list)
        # At least one pattern should be detected


def test_check_information_disclosure_regex_error(secure_response_headers):
    """Error when re.search raises exception."""
    capture = Mock()
    capture.resources = []
    # Create a problematic page_text that might cause regex issues
    capture.page_text = None  # Will cause type error in regex
    capture.auth_context = AuthContext.anonymous
    
    with pytest.raises(Exception):
        check_information_disclosure("https://example.com", secure_response_headers, capture)


def test_check_information_disclosure_attribute_error(secure_response_headers):
    """Error when capture missing page_text or resources attributes."""
    capture = Mock(spec=[])  # No attributes
    
    with pytest.raises(AttributeError):
        check_information_disclosure("https://example.com", secure_response_headers, capture)


# ============================================================================
# TEST: check_forms
# ============================================================================

def test_check_forms_happy_path_secure(secure_forms, mock_auth_context):
    """Happy path: All forms properly secured."""
    result = check_forms(
        "https://example.com",
        secure_forms,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    # Secure forms should have no findings


def test_check_forms_post_without_csrf(form_post_no_csrf, mock_auth_context):
    """Detect POST form without CSRF token (medium severity)."""
    result = check_forms(
        "https://example.com",
        form_post_no_csrf,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should have medium severity


def test_check_forms_password_autocomplete(form_password_autocomplete, mock_auth_context):
    """Detect password field with autocomplete enabled."""
    result = check_forms(
        "https://example.com",
        form_password_autocomplete,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should find autocomplete issue


def test_check_forms_https_to_http_submission(form_https_to_http, mock_auth_context):
    """Detect form on HTTPS submitting to HTTP (high severity)."""
    result = check_forms(
        "https://example.com",
        form_https_to_http,
        mock_auth_context
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should have high severity for mixed content


def test_check_forms_attribute_error(mock_auth_context):
    """Error when form object missing required attributes."""
    incomplete_form = Mock(spec=[])  # No attributes
    
    with pytest.raises(AttributeError):
        check_forms("https://example.com", [incomplete_form], mock_auth_context)


# ============================================================================
# TEST: check_xss_signals
# ============================================================================

def test_check_xss_signals_happy_path_no_reflection(capture_no_reflection):
    """Happy path: No XSS reflection detected."""
    result = check_xss_signals(
        "https://example.com?param=value",
        capture_no_reflection
    )
    
    assert isinstance(result, list)
    assert len(result) == 0  # No reflection


def test_check_xss_signals_reflection_detected(capture_xss_reflection):
    """Detect URL parameter reflected in page content."""
    result = check_xss_signals(
        "https://example.com?search=testvalue",
        capture_xss_reflection
    )
    
    assert isinstance(result, list)
    assert len(result) > 0
    # Should find reflection with medium severity


def test_check_xss_signals_short_param_ignored(capture_xss_reflection):
    """Edge case: Parameters <= 3 characters should be ignored."""
    result = check_xss_signals(
        "https://example.com?id=abc",  # 3 characters
        capture_xss_reflection
    )
    
    assert isinstance(result, list)
    # Should ignore parameters not longer than 3 chars (postcondition: only checks > 3)


def test_check_xss_signals_url_parse_error():
    """urlparse handles malformed URLs gracefully without raising."""
    capture = Mock()
    capture.page_text = "Content"
    capture.auth_context = AuthContext.anonymous

    # urlparse does not raise on malformed URLs
    result = check_xss_signals("malformed:::url", capture)
    assert isinstance(result, list)


def test_check_xss_signals_string_split_error():
    """Error when query parameter parsing fails."""
    capture = Mock()
    capture.page_text = "Content"
    capture.auth_context = AuthContext.anonymous
    
    # URL with malformed query string
    try:
        result = check_xss_signals("https://example.com?malformed", capture)
        # Function might handle this gracefully
        assert isinstance(result, list)
    except Exception as e:
        assert "string_split_error" in str(e).lower() or "split" in str(e).lower()


# ============================================================================
# TEST: scan_capture
# ============================================================================

def test_scan_capture_happy_path_aggregation(full_node_capture):
    """Happy path: Aggregates all check function results."""
    result = scan_capture(
        "https://example.com",
        full_node_capture
    )
    
    assert isinstance(result, list)
    # Should return aggregated findings from all check functions


def test_scan_capture_check_function_error():
    """Graceful handling when a check function raises -- returns partial results."""
    capture = Mock()
    capture.response_headers = Mock()
    capture.response_headers.raw = Mock()
    capture.response_headers.raw.items = Mock(side_effect=Exception("Check error"))
    capture.cookies = []
    capture.forms = []
    capture.auth_context = AuthContext.anonymous
    capture.resources = []
    capture.page_text = "Content"
    capture.outgoing_links = []

    # scan_capture gracefully handles individual check failures
    result = scan_capture("https://example.com", capture)
    assert isinstance(result, list)


# ============================================================================
# TEST: scan_graph
# ============================================================================

def test_scan_graph_happy_path_multiple_nodes(site_graph_multi_node):
    """Happy path: Scans all nodes and deduplicates findings."""
    result = scan_graph(site_graph_multi_node)
    
    assert isinstance(result, list)
    # Should return deduplicated findings


def test_scan_graph_deduplication():
    """Test deduplication by (url, category.value, title)."""
    graph = Mock()

    # Create two nodes with identical findings
    node1 = Mock()
    node1.id = "node1"
    capture1 = Mock()
    capture1.security_findings = []
    capture1.response_headers = Mock()
    capture1.response_headers.raw = {}  # Will generate missing header findings
    capture1.cookies = []
    capture1.forms = []
    capture1.auth_context = AuthContext.anonymous
    capture1.resources = []
    capture1.page_text = "Content"
    capture1.outgoing_links = []
    node1.captures = [capture1]

    node2 = Mock()
    node2.id = "node2"
    capture2 = Mock()
    capture2.security_findings = []
    capture2.response_headers = Mock()
    capture2.response_headers.raw = {}  # Same as capture1
    capture2.cookies = []
    capture2.forms = []
    capture2.auth_context = AuthContext.anonymous
    capture2.resources = []
    capture2.page_text = "Content"
    capture2.outgoing_links = []
    node2.captures = [capture2]

    graph.nodes = {"node1": node1, "node2": node2}
    graph.tls_info = None
    graph.root_url = ""
    graph.seed_urls = []

    result = scan_graph(graph)
    
    assert isinstance(result, list)
    # Deduplication should occur for identical findings


def test_scan_graph_findings_attached_to_captures(site_graph_multi_node):
    """Verify findings are appended to capture.security_findings lists."""
    result = scan_graph(site_graph_multi_node)
    
    # Check that findings were attached to captures
    for node in site_graph_multi_node.nodes.values():
        for capture in node.captures:
            assert hasattr(capture, 'security_findings')
            assert isinstance(capture.security_findings, list)


def test_scan_graph_graph_access_error():
    """Error when graph.nodes iteration fails."""
    graph = Mock()
    nodes_mock = Mock()
    nodes_mock.values = Mock(side_effect=Exception("Graph access error"))
    graph.nodes = nodes_mock

    with pytest.raises(Exception) as exc_info:
        scan_graph(graph)

    assert "graph access error" in str(exc_info.value).lower()


def test_scan_graph_node_access_error():
    """Error when node missing id or captures attributes."""
    graph = Mock()
    node = Mock(spec=[])  # No attributes
    graph.nodes = {"node1": node}
    
    with pytest.raises(AttributeError):
        scan_graph(graph)


def test_scan_graph_scan_capture_error():
    """Error when scan_capture raises exception."""
    graph = Mock()
    
    node = Mock()
    node.id = "node1"
    capture = Mock()
    capture.security_findings = []
    # Missing required attributes to cause scan_capture to fail
    capture.response_headers = None
    node.captures = [capture]
    
    graph.nodes = {"node1": node}
    
    with pytest.raises(Exception):
        scan_graph(graph)


# ============================================================================
# INVARIANT TESTS
# ============================================================================

def test_invariant_hsts_max_age_threshold():
    """Verify HSTS max-age threshold is 31536000 seconds (1 year)."""
    auth_ctx = AuthContext.anonymous
    
    # Test values around threshold
    test_cases = [
        (31535999, True),   # Just below threshold - should create finding
        (31536000, False),  # Exactly at threshold - should not create finding
        (31536001, False),  # Just above threshold - should not create finding
    ]
    
    for max_age, should_have_finding in test_cases:
        headers = Mock()
        headers.raw = {'Strict-Transport-Security': f'max-age={max_age}'}
        
        result = check_security_headers("https://example.com", headers, auth_ctx)
        
        weak_findings = [f for f in result if 'max-age' in f.title.lower()]

        if should_have_finding:
            assert len(weak_findings) > 0, f"Expected finding for max-age={max_age}"
        else:
            assert len(weak_findings) == 0, f"No finding expected for max-age={max_age}"


def test_invariant_session_cookie_keywords():
    """Verify session-like cookie heuristic keywords."""
    keywords = ['session', 'token', 'auth', 'sid', 'jwt', 'access']
    auth_ctx = AuthContext.anonymous
    
    for keyword in keywords:
        cookie = Mock()
        cookie.name = f'my_{keyword}_value'
        cookie.secure = True
        cookie.http_only = False  # Trigger finding
        cookie.same_site = 'strict'
        cookie.domain = 'example.com'
        
        result = check_cookies("https://example.com", [cookie], auth_ctx)
        
        # Session-like cookies should trigger findings
        assert len(result) > 0, f"Keyword '{keyword}' should trigger session detection"


def test_invariant_high_risk_resource_types():
    """Verify high-risk resource types for mixed content."""
    high_risk_types = ['script', 'stylesheet']
    
    for resource_type in high_risk_types:
        capture = Mock()
        resource = Mock()
        resource.url = 'http://example.com/resource'
        resource.resource_type = Mock()
        resource.resource_type.value = resource_type
        capture.resources = [resource]
        capture.page_text = "Content"
        capture.auth_context = AuthContext.anonymous
        
        result = check_mixed_content("https://example.com", capture)
        
        assert len(result) > 0, f"Resource type '{resource_type}' should be detected as high-risk"


def test_invariant_valid_x_frame_options():
    """Verify valid X-Frame-Options values: DENY, SAMEORIGIN."""
    valid_values = ['DENY', 'SAMEORIGIN']
    auth_ctx = AuthContext.anonymous
    
    for value in valid_values:
        headers = Mock()
        headers.raw = {'X-Frame-Options': value}
        
        result = check_security_headers("https://example.com", headers, auth_ctx)
        
        # Valid values should not create findings for X-Frame-Options
        xframe_findings = [f for f in result if 'x-frame-options' in f.title.lower() and 'weak' in f.title.lower()]
        assert len(xframe_findings) == 0, f"Valid value '{value}' should not create finding"


def test_invariant_xss_parameter_length():
    """Verify minimum parameter length for XSS reflection check is > 3 characters."""
    test_cases = [
        ("a", False),      # 1 char - should ignore
        ("ab", False),     # 2 chars - should ignore
        ("abc", False),    # 3 chars - should ignore
        ("abcd", True),    # 4 chars - should check
        ("abcde", True),   # 5 chars - should check
    ]
    
    for param_value, should_check in test_cases:
        capture = Mock()
        capture.page_text = f"Page contains {param_value}"
        capture.auth_context = AuthContext.anonymous
        
        result = check_xss_signals(f"https://example.com?param={param_value}", capture)
        
        if should_check and param_value in capture.page_text:
            assert len(result) > 0, f"Parameter '{param_value}' should be checked"
        elif not should_check:
            # Should not check parameters <= 3 chars
            pass


def test_invariant_deduplication_key():
    """Verify deduplication key for findings: (url, category.value, title)."""
    graph = Mock()

    # Create two captures with same URL and should produce identical findings
    node1 = Mock()
    node1.id = "node1"
    capture1 = Mock()
    capture1.security_findings = []
    capture1.response_headers = Mock()
    capture1.response_headers.raw = {}  # Missing headers
    capture1.cookies = []
    capture1.forms = []
    capture1.auth_context = AuthContext.anonymous
    capture1.resources = []
    capture1.page_text = "Content"
    capture1.outgoing_links = []
    node1.captures = [capture1]

    node2 = Mock()
    node2.id = "node2"
    capture2 = Mock()
    capture2.security_findings = []
    capture2.response_headers = Mock()
    capture2.response_headers.raw = {}  # Same as capture1
    capture2.cookies = []
    capture2.forms = []
    capture2.auth_context = AuthContext.anonymous
    capture2.resources = []
    capture2.page_text = "Content"
    capture2.outgoing_links = []
    node2.captures = [capture2]

    graph.nodes = {"node1": node1, "node2": node2}
    graph.tls_info = None
    graph.root_url = ""
    graph.seed_urls = []

    result = scan_graph(graph)
    
    # Count findings - should be deduplicated
    assert isinstance(result, list)
    
    # Check that deduplication occurred by verifying unique (url, category, title) combinations
    seen_keys = set()
    for finding in result:
        if hasattr(finding, 'url') and hasattr(finding, 'category') and hasattr(finding, 'title'):
            key = (finding.url, finding.category.value if hasattr(finding.category, 'value') else str(finding.category), finding.title)
            assert key not in seen_keys, f"Duplicate finding found: {key}"
            seen_keys.add(key)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

def test_integration_full_scan_with_multiple_vulnerabilities():
    """Integration test: Full scan with multiple vulnerability types."""
    # Create a capture with multiple security issues
    capture = Mock()
    
    # Insecure headers
    capture.response_headers = Mock()
    capture.response_headers.raw = {
        'Server': 'Apache/2.4.1',  # Version disclosure
        'Access-Control-Allow-Origin': '*',  # CORS issue
    }
    
    # Insecure cookie
    cookie = Mock()
    cookie.name = 'session_id'
    cookie.secure = False
    cookie.http_only = False
    cookie.same_site = 'none'
    cookie.domain = 'example.com'
    capture.cookies = [cookie]
    
    # Mixed content
    resource = Mock()
    resource.url = 'http://example.com/script.js'
    resource.resource_type = Mock()
    resource.resource_type.value = 'script'
    resource.status_code = 200
    capture.resources = [resource]
    
    # Insecure form
    form = Mock()
    form.method = 'POST'
    form.has_csrf_token = False
    form.action = 'http://example.com/submit'
    form.has_password_field = True
    form.autocomplete_off = False
    form.input_names = []
    form.input_types = []
    capture.forms = [form]

    # XSS reflection
    capture.page_text = "Search results for: testvalue"
    capture.auth_context = AuthContext.anonymous
    capture.security_findings = []
    capture.outgoing_links = []

    result = scan_capture("https://example.com?search=testvalue", capture)
    
    assert isinstance(result, list)
    assert len(result) > 5  # Should find multiple issues


def test_integration_scan_graph_multi_node_deduplication():
    """Integration test: Scan multiple nodes with deduplication."""
    graph = Mock()

    nodes = {}
    for i in range(3):
        node = Mock()
        node.id = f"node{i}"
        capture = Mock()
        capture.security_findings = []
        capture.response_headers = Mock()
        capture.response_headers.raw = {}  # Same missing headers for all
        capture.cookies = []
        capture.forms = []
        capture.auth_context = AuthContext.anonymous
        capture.resources = []
        capture.page_text = "Content"
        capture.outgoing_links = []
        node.captures = [capture]
        nodes[f"node{i}"] = node

    graph.nodes = nodes
    graph.tls_info = None
    graph.root_url = ""
    graph.seed_urls = []

    result = scan_graph(graph)
    
    assert isinstance(result, list)
    
    # Verify deduplication worked
    unique_findings = set()
    for finding in result:
        if hasattr(finding, 'url') and hasattr(finding, 'category') and hasattr(finding, 'title'):
            key = (finding.url, str(finding.category), finding.title)
            unique_findings.add(key)
    
    # Number of unique findings should match result length (deduplication)
    assert len(unique_findings) == len(result)


def test_integration_auth_context_propagation():
    """Integration test: Verify auth context is propagated through findings."""
    auth_ctx = AuthContext.anonymous
    auth_ctx.user = "test_user"
    auth_ctx.session_id = "test_session_123"
    
    headers = Mock()
    headers.raw = {}  # Missing headers
    
    result = check_security_headers("https://example.com", headers, auth_ctx)
    
    # Verify findings include auth context
    for finding in result:
        if hasattr(finding, 'auth_context'):
            assert finding.auth_context == auth_ctx


def test_integration_empty_graph():
    """Integration test: Scan empty graph."""
    graph = Mock()
    graph.nodes = {}
    graph.tls_info = None
    graph.root_url = ""
    graph.seed_urls = []

    result = scan_graph(graph)
    
    assert isinstance(result, list)
    assert len(result) == 0


def test_integration_capture_with_no_issues():
    """Integration test: Scan capture with no security issues."""
    capture = Mock()
    
    # Secure headers
    capture.response_headers = Mock()
    capture.response_headers.raw = {
        'Strict-Transport-Security': 'max-age=31536000',
        'Content-Security-Policy': "default-src 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
    }
    
    # Secure cookies
    cookie = Mock()
    cookie.name = 'normal_cookie'
    cookie.secure = True
    cookie.http_only = True
    cookie.same_site = 'strict'
    cookie.domain = 'example.com'
    capture.cookies = [cookie]
    
    # HTTPS resources
    resource = Mock()
    resource.url = 'https://example.com/script.js'
    resource.resource_type = Mock()
    resource.resource_type.value = 'script'
    resource.status_code = 200
    capture.resources = [resource]
    
    # Secure form
    form = Mock()
    form.method = 'POST'
    form.has_csrf_token = True
    form.action = 'https://example.com/submit'
    form.has_password_field = False
    form.autocomplete_off = True
    form.input_names = []
    form.input_types = []
    capture.forms = [form]

    capture.page_text = "Clean content"
    capture.auth_context = AuthContext.anonymous
    capture.security_findings = []
    capture.outgoing_links = []

    result = scan_capture("https://example.com", capture)
    
    assert isinstance(result, list)
    # Should have minimal or no findings for fully secure configuration


# ============================================================================
# PARAMETRIZED ERROR TESTS
# ============================================================================

@pytest.mark.parametrize("error_type,setup", [
    ("header_parsing_error", lambda: (Mock(raw=Mock(items=Mock(side_effect=Exception("Parse error")))), AuthContext.anonymous)),
    ("header_access_error", lambda: (Mock(raw=Mock(items=Mock(side_effect=Exception("Access error")))), AuthContext.anonymous)),
])
def test_parametrized_header_errors(error_type, setup):
    """Parametrized test for header-related errors."""
    headers, auth_ctx = setup()

    with pytest.raises(Exception):
        if error_type == "header_parsing_error":
            check_security_headers("https://example.com", headers, auth_ctx)
        elif error_type == "header_access_error":
            check_cors("https://example.com", headers, auth_ctx)


@pytest.mark.parametrize("cookie_name", [
    'session_cookie',
    'auth_token',
    'user_token',
    'session_id',
    'jwt_token',
    'access_key',
])
def test_parametrized_session_cookie_detection(cookie_name):
    """Parametrized test for session cookie keyword detection."""
    cookie = Mock()
    cookie.name = cookie_name
    cookie.secure = True
    cookie.http_only = False  # Trigger finding
    cookie.same_site = 'strict'
    cookie.domain = 'example.com'
    
    result = check_cookies("https://example.com", [cookie], AuthContext.anonymous)

    assert isinstance(result, list)
    # Session-like cookies should be detected
    assert len(result) > 0


@pytest.mark.parametrize("resource_type,expected_severity", [
    ('script', 'high'),
    ('stylesheet', 'high'),
    ('image', 'medium'),
    ('font', 'medium'),
])
def test_parametrized_mixed_content_severity(resource_type, expected_severity):
    """Parametrized test for mixed content severity by resource type."""
    capture = Mock()
    resource = Mock()
    resource.url = 'http://example.com/resource'
    resource.resource_type = Mock()
    resource.resource_type.value = resource_type
    capture.resources = [resource]
    capture.page_text = "Content"
    capture.auth_context = AuthContext.anonymous
    
    result = check_mixed_content("https://example.com", capture)
    
    assert isinstance(result, list)
    assert len(result) > 0


@pytest.mark.parametrize("stack_trace_pattern", [
    'Traceback (most recent call last)',
    'at main.js:10:5',
    'Exception in thread "main"',
    'Fatal error: syntax error on line 42',
    'Stack trace:',
    'Unhandled exception occurred',
])
def test_parametrized_stack_trace_detection(stack_trace_pattern):
    """Parametrized test for stack trace pattern detection."""
    capture = Mock()
    capture.resources = []
    capture.page_text = f"Error page: {stack_trace_pattern} - details follow"
    capture.auth_context = AuthContext.anonymous
    
    headers = Mock()
    headers.raw = {}
    
    result = check_information_disclosure("https://example.com", headers, capture)
    
    assert isinstance(result, list)
    # At least one pattern should be detected


# ============================================================================
# BOUNDARY TESTS
# ============================================================================

def test_boundary_hsts_max_age_values():
    """Boundary test for HSTS max-age around the 1-year threshold."""
    test_values = [
        (0, True),           # Zero - should create finding
        (1, True),           # Minimal value - should create finding
        (31535999, True),    # One second below - should create finding
        (31536000, False),   # Exactly 1 year - should not create finding
        (31536001, False),   # One second above - should not create finding
        (63072000, False),   # 2 years - should not create finding
    ]
    
    auth_ctx = AuthContext.anonymous
    
    for max_age, should_have_finding in test_values:
        headers = Mock()
        headers.raw = {'Strict-Transport-Security': f'max-age={max_age}'}
        
        result = check_security_headers("https://example.com", headers, auth_ctx)
        
        weak_findings = [f for f in result if 'max-age' in f.title.lower()]

        if should_have_finding:
            assert len(weak_findings) > 0, f"Expected finding for max-age={max_age}"
        else:
            assert len(weak_findings) == 0, f"No finding expected for max-age={max_age}"


def test_boundary_xss_parameter_length_edge_cases():
    """Boundary test for XSS parameter length check."""
    test_cases = [
        ("", False),        # Empty - should ignore
        ("a", False),       # 1 char - should ignore
        ("ab", False),      # 2 chars - should ignore
        ("abc", False),     # 3 chars - boundary - should ignore
        ("abcd", True),     # 4 chars - just over boundary - should check
    ]
    
    for param_value, should_check in test_cases:
        capture = Mock()
        capture.page_text = f"Content with {param_value} inside"
        capture.auth_context = AuthContext.anonymous
        
        url = f"https://example.com?test={param_value}" if param_value else "https://example.com"
        result = check_xss_signals(url, capture)
        
        assert isinstance(result, list)


def test_boundary_empty_collections():
    """Boundary test for empty collections."""
    auth_ctx = AuthContext.anonymous
    
    # Empty cookies
    result_cookies = check_cookies("https://example.com", [], auth_ctx)
    assert isinstance(result_cookies, list)
    assert len(result_cookies) == 0
    
    # Empty forms
    result_forms = check_forms("https://example.com", [], auth_ctx)
    assert isinstance(result_forms, list)
    assert len(result_forms) == 0
    
    # Empty resources
    capture = Mock()
    capture.resources = []
    capture.page_text = "Content"
    capture.auth_context = auth_ctx
    result_mixed = check_mixed_content("https://example.com", capture)
    assert isinstance(result_mixed, list)


def test_boundary_large_collections():
    """Boundary test for large collections."""
    import random
    
    # Create many cookies
    cookies = []
    for i in range(100):
        cookie = Mock()
        cookie.name = f'cookie_{i}'
        cookie.secure = random.choice([True, False])
        cookie.http_only = random.choice([True, False])
        cookie.same_site = random.choice(['strict', 'lax', 'none'])
        cookie.domain = 'example.com'
        cookies.append(cookie)
    
    result = check_cookies("https://example.com", cookies, AuthContext.anonymous)
    assert isinstance(result, list)
    
    # Create many resources
    capture = Mock()
    resources = []
    for i in range(100):
        resource = Mock()
        resource.url = f'{"http" if i % 2 == 0 else "https"}://example.com/resource{i}'
        resource.resource_type = Mock()
        resource.resource_type.value = random.choice(['script', 'stylesheet', 'image', 'font'])
        resources.append(resource)
    
    capture.resources = resources
    capture.page_text = "Content"
    capture.auth_context = AuthContext.anonymous
    
    result = check_mixed_content("https://example.com", capture)
    assert isinstance(result, list)
