# === WebProbe Authentication Manager (src_webprobe_auth) v1 ===
#  Dependencies: urllib.parse, aiohttp, playwright.async_api, webprobe.config
# Auth context management: cookie/bearer/header injection and auth detection. Manages authentication injection for both aiohttp sessions (Phase 1 crawling) and Playwright browser contexts (Phase 2 capture), with auth redirect detection and auth indicator validation.

# Module invariants:
#   - AuthManager always maintains a reference to its AuthConfig
#   - Auth method must be one of: 'none', 'cookie', 'bearer', 'header'
#   - Cookie injection sets path='/' for Playwright contexts
#   - Bearer token is always prefixed with 'Bearer ' in Authorization header
#   - All exceptions in check_auth_indicator are caught and return False
#   - URL path comparison for auth redirect uses rstrip('/') for normalization

class AuthManager:
    """Manages authentication injection for both aiohttp and Playwright. Supports cookie, bearer token, and custom header auth methods."""
    config: AuthConfig                       # required, Authentication configuration object

def __init__(
    self: AuthManager,
    config: AuthConfig,
) -> None:
    """
    Initialize AuthManager with authentication configuration.

    Postconditions:
      - self.config is set to the provided config object

    Side effects: Stores config reference in instance state
    Idempotent: no
    """
    ...

def has_auth(
    self: AuthManager,
) -> bool:
    """
    Property that returns whether authentication is configured. Returns True if method is not 'none'.

    Preconditions:
      - self.config.method is set

    Postconditions:
      - Returns True if config.method != 'none', False otherwise

    Side effects: none
    Idempotent: no
    """
    ...

def apply_to_session(
    self: AuthManager,
    session: aiohttp.ClientSession,
) -> None:
    """
    Inject auth into an aiohttp session for Phase 1 crawling. Mutates session by adding cookies or headers based on configured auth method.

    Preconditions:
      - session is a valid aiohttp.ClientSession instance
      - If method='cookie': config.cookie_name and config.cookie_value are set
      - If method='bearer': config.bearer_token is set
      - If method='header': config.header_name and config.header_value are set

    Postconditions:
      - If method='cookie': session.cookie_jar contains the specified cookie
      - If method='bearer': session.headers contains Authorization header with Bearer token
      - If method='header': session.headers contains custom header with specified value
      - If method='none': session is unmodified

    Errors:
      - AttributeError (AttributeError): If config attributes (cookie_name, bearer_token, etc.) are missing for the specified method

    Side effects: Mutates session.cookie_jar if method is 'cookie', Mutates session.headers if method is 'bearer' or 'header'
    Idempotent: no
    """
    ...

async def apply_to_context(
    self: AuthManager,
    context: BrowserContext,
    base_url: str,
) -> None:
    """
    Inject auth into a Playwright browser context for Phase 2 capture. Adds cookies or sets extra HTTP headers based on configured auth method.

    Preconditions:
      - context is a valid Playwright BrowserContext instance
      - base_url is a valid URL string
      - If method='cookie': config.cookie_name and config.cookie_value are set
      - If method='bearer': config.bearer_token is set
      - If method='header': config.header_name and config.header_value are set

    Postconditions:
      - If method='cookie': context has cookie added with parsed domain from base_url, path='/'
      - If method='bearer': context extra HTTP headers include Authorization with Bearer token
      - If method='header': context extra HTTP headers include custom header
      - If method='none': context is unmodified

    Errors:
      - AttributeError (AttributeError): If config attributes are missing for the specified method
      - ValueError (ValueError): If base_url cannot be parsed by urlparse

    Side effects: Awaits context.add_cookies() if method is 'cookie', Awaits context.set_extra_http_headers() if method is 'bearer' or 'header'
    Idempotent: no
    """
    ...

def is_auth_redirect(
    self: AuthManager,
    original_url: str,
    final_url: str,
) -> bool:
    """
    Detect if a response redirected to the login page by comparing original and final URL paths against configured login_url.

    Preconditions:
      - original_url and final_url are valid URL strings

    Postconditions:
      - Returns False if config.login_url is not set
      - Returns True if final_url path matches login_url path (trailing slashes stripped) AND final path differs from original path
      - Returns False otherwise

    Errors:
      - ValueError (ValueError): If original_url or final_url cannot be parsed by urlparse

    Side effects: none
    Idempotent: no
    """
    ...

async def check_auth_indicator(
    self: AuthManager,
    page: Page,
) -> bool:
    """
    Check if the auth_indicator selector is present on the page. Returns True if the selector is found, False otherwise or on any exception.

    Preconditions:
      - page is a valid Playwright Page instance

    Postconditions:
      - Returns False if config.auth_indicator is not set
      - Returns True if element matching auth_indicator selector is found
      - Returns False if element is not found or any exception occurs

    Errors:
      - Exception (Exception): Any exception during page.query_selector() is caught and returns False

    Side effects: Awaits page.query_selector() which may perform DOM query
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['AuthManager', 'has_auth', 'apply_to_session', 'apply_to_context', 'is_auth_redirect', 'check_auth_indicator']
