# === Webprobe Configuration Loader (src_webprobe_config) v1 ===
#  Dependencies: pathlib, typing, yaml, pydantic
# Configuration loading module that reads YAML files from standard search paths and validates them using Pydantic v2 models. Provides structured configuration for authentication, crawling, and capture behavior with fallback to defaults.

# Module invariants:
#   - _SEARCH_PATHS = [Path('webprobe.yaml'), Path.home() / '.webprobe' / 'webprobe.yaml'] - Fixed search order for config files
#   - All Pydantic models use BaseModel from pydantic v2
#   - Default values are immutable or use Field(default_factory=...) for mutable collections

class AuthCredential:
    """A single named credential for auth testing"""
    name: str = "default"                    # optional, Credential identifier
    method: Literal['cookie', 'bearer', 'header'] = "cookie" # optional, Authentication method type
    cookie_name: str = ""                    # optional, Cookie name for cookie-based auth
    cookie_value: str = ""                   # optional, Cookie value for cookie-based auth
    bearer_token: str = ""                   # optional, Bearer token for bearer auth
    header_name: str = ""                    # optional, Header name for header-based auth
    header_value: str = ""                   # optional, Header value for header-based auth

class AuthConfig:
    """Authentication injection settings"""
    method: Literal['cookie', 'bearer', 'header', 'none'] = "none" # optional, Primary authentication method
    cookie_name: str = ""                    # optional, Cookie name for cookie-based auth
    cookie_value: str = ""                   # optional, Cookie value for cookie-based auth
    bearer_token: str = ""                   # optional, Bearer token for bearer auth
    header_name: str = ""                    # optional, Header name for header-based auth
    header_value: str = ""                   # optional, Header value for header-based auth
    login_url: str = "/login"                # optional, URL path for login endpoint
    auth_indicator: str = ""                 # optional, String to detect successful authentication
    credentials: list[AuthCredential] = []   # optional, List of credentials for multi-credential testing

class CrawlConfig:
    """Crawl behavior settings"""
    max_depth: int = 10                      # optional, Maximum crawl depth from seed URL
    max_nodes: int = 500                     # optional, Maximum number of nodes to crawl
    respect_robots: bool = True              # optional, Whether to respect robots.txt
    follow_external: bool = False            # optional, Whether to follow external links
    url_exclude_patterns: list[str] = []     # optional, URL patterns to exclude from crawling
    request_delay_ms: int = 100              # optional, Delay between requests in milliseconds

class CaptureConfig:
    """Capture behavior settings for browser-based operations"""
    concurrency: int = 10                    # optional, Number of concurrent capture operations
    timeout_ms: int = 30000                  # optional, Timeout for capture operations in milliseconds
    screenshot: bool = True                  # optional, Whether to capture screenshots
    viewport_width: int = 1280               # optional, Browser viewport width in pixels
    viewport_height: int = 720               # optional, Browser viewport height in pixels

class WebprobeConfig:
    """Top-level configuration container for all webprobe settings"""
    auth: AuthConfig = AuthConfig()          # optional, Authentication configuration
    crawl: CrawlConfig = CrawlConfig()       # optional, Crawling behavior configuration
    capture: CaptureConfig = CaptureConfig() # optional, Capture behavior configuration
    output_dir: str = "./webprobe-runs"      # optional, Directory for output files

def load_config(
    path: str | Path | None = None,
) -> WebprobeConfig:
    """
    Load configuration from an explicit path, default search paths (./webprobe.yaml, ~/.webprobe/webprobe.yaml), or return defaults if no config file exists.

    Preconditions:
      - If path is provided and not None, it will be converted to a Path object

    Postconditions:
      - Returns a valid WebprobeConfig instance
      - If no config files found, returns WebprobeConfig with all default values
      - If config file found, YAML is parsed and validated against Pydantic models

    Errors:
      - explicit_path_not_found (FileNotFoundError): path is not None and Path(path).exists() returns False
          message: Config not found: {p}
      - yaml_parsing_error (yaml.YAMLError): YAML file contains invalid syntax
      - pydantic_validation_error (pydantic.ValidationError): YAML structure does not match WebprobeConfig schema
      - file_read_error (IOError): File exists but cannot be read (permissions, encoding issues)

    Side effects: Reads from filesystem
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['AuthCredential', 'AuthConfig', 'CrawlConfig', 'CaptureConfig', 'WebprobeConfig', 'load_config']
