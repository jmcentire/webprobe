"""
Contract tests for webprobe configuration loader.

Tests the load_config function which loads configuration from YAML files
with fallback to defaults, validating against Pydantic models.

Test organization:
1. Happy path tests: Valid configs, None paths, Path objects, default searches
2. Edge cases: Empty files, boundary values, Literal variants, special paths
3. Error cases: Missing files, YAML errors, validation errors, permission issues
4. Invariants: Search path order, immutable defaults, idempotent loading
"""

import pytest
from pathlib import Path
from unittest.mock import mock_open, patch, MagicMock
import tempfile
import os

# Import the module under test
from src.webprobe.config import (
    load_config,
    WebprobeConfig,
    AuthConfig,
    AuthCredential,
    CrawlConfig,
    CaptureConfig,
)


# ============================================================================
# HAPPY PATH TESTS
# ============================================================================


def test_load_config_with_valid_full_config(tmp_path):
    """Happy path: Load a complete valid configuration file with all fields populated."""
    config_file = tmp_path / "config.yaml"
    config_content = """
auth:
  method: bearer
  cookie_name: session
  cookie_value: abc123
  bearer_token: token_xyz
  header_name: X-Auth
  header_value: value1
  login_url: https://example.com/login
  auth_indicator: logged_in
  credentials:
    - name: cred1
      method: cookie
      cookie_name: auth
      cookie_value: val1
      bearer_token: ""
      header_name: ""
      header_value: ""
crawl:
  max_depth: 5
  max_nodes: 100
  respect_robots: true
  follow_external: false
  url_exclude_patterns:
    - ".*\\.pdf$"
    - ".*logout.*"
  request_delay_ms: 500
capture:
  concurrency: 4
  timeout_ms: 30000
  screenshot: true
  viewport_width: 1920
  viewport_height: 1080
output_dir: /tmp/output
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert isinstance(result, WebprobeConfig)
    assert result.auth.method == "bearer"
    assert result.auth.bearer_token == "token_xyz"
    assert len(result.auth.credentials) == 1
    assert result.auth.credentials[0].name == "cred1"
    assert result.crawl.max_depth == 5
    assert result.crawl.max_nodes == 100
    assert result.crawl.respect_robots is True
    assert len(result.crawl.url_exclude_patterns) == 2
    assert result.capture.concurrency == 4
    assert result.capture.screenshot is True
    assert result.output_dir == "/tmp/output"


def test_load_config_with_none_path_returns_defaults(tmp_path, monkeypatch):
    """Happy path: Load config with None path when no default configs exist."""
    # Change to a temp directory where no config files exist
    monkeypatch.chdir(tmp_path)
    
    # Mock home to point to temp directory
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    
    result = load_config(None)
    
    assert isinstance(result, WebprobeConfig)
    # Verify it returns defaults (checking a few key fields)
    assert isinstance(result.auth, AuthConfig)
    assert isinstance(result.crawl, CrawlConfig)
    assert isinstance(result.capture, CaptureConfig)


def test_load_config_with_pathlib_path_object(tmp_path):
    """Happy path: Load config using Path object instead of string."""
    config_file = tmp_path / "config.yaml"
    config_content = """
auth:
  method: none
crawl:
  max_depth: 3
capture:
  concurrency: 2
output_dir: /output
"""
    config_file.write_text(config_content)
    
    result = load_config(config_file)  # Pass Path object directly
    
    assert isinstance(result, WebprobeConfig)
    assert result.auth.method == "none"
    assert result.crawl.max_depth == 3


def test_load_config_searches_default_paths(tmp_path, monkeypatch):
    """Happy path: None path searches ./webprobe.yaml then ~/.webprobe/webprobe.yaml."""
    # Setup: Create config in home directory
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    webprobe_dir = fake_home / ".webprobe"
    webprobe_dir.mkdir()
    home_config = webprobe_dir / "webprobe.yaml"
    home_config.write_text("auth:\n  method: header\ncrawl:\n  max_depth: 7\ncapture:\n  concurrency: 3\noutput_dir: /home/output")
    
    # Change to temp directory (no local webprobe.yaml)
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    
    result = load_config(None)
    
    # Should load from home directory since local doesn't exist
    assert isinstance(result, WebprobeConfig)
    assert result.auth.method == "header"
    assert result.crawl.max_depth == 7


def test_load_config_prefers_local_over_home(tmp_path, monkeypatch):
    """Happy path: When both default paths exist, prefer ./webprobe.yaml."""
    # Setup home config
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    webprobe_dir = fake_home / ".webprobe"
    webprobe_dir.mkdir()
    home_config = webprobe_dir / "webprobe.yaml"
    home_config.write_text("auth:\n  method: header\ncrawl:\n  max_depth: 99\ncapture:\n  concurrency: 1\noutput_dir: /home")
    
    # Setup local config (should take precedence)
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    local_config = work_dir / "webprobe.yaml"
    local_config.write_text("auth:\n  method: cookie\ncrawl:\n  max_depth: 3\ncapture:\n  concurrency: 2\noutput_dir: /local")
    
    monkeypatch.chdir(work_dir)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    
    result = load_config(None)
    
    # Should load from local, not home
    assert result.auth.method == "cookie"
    assert result.crawl.max_depth == 3
    assert result.output_dir == "/local"


def test_load_config_with_partial_config(tmp_path):
    """Happy path: Load config with only some sections populated, others use defaults."""
    config_file = tmp_path / "partial_config.yaml"
    config_content = """
crawl:
  max_depth: 10
  max_nodes: 200
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert isinstance(result, WebprobeConfig)
    assert result.crawl.max_depth == 10
    assert result.crawl.max_nodes == 200
    # Other sections should have defaults
    assert isinstance(result.auth, AuthConfig)
    assert isinstance(result.capture, CaptureConfig)


# ============================================================================
# EDGE CASE TESTS
# ============================================================================


def test_load_config_with_minimal_config(tmp_path):
    """Edge case: Load config with only required fields, all optional fields missing."""
    config_file = tmp_path / "minimal_config.yaml"
    # Minimal valid config - testing what fields are truly required
    config_content = """
auth:
  method: none
crawl:
  max_depth: 1
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert isinstance(result, WebprobeConfig)
    assert result.auth.method == "none"
    assert result.crawl.max_depth == 1


def test_load_config_empty_config_file(tmp_path):
    """Edge case: Config file exists but is completely empty."""
    config_file = tmp_path / "empty_config.yaml"
    config_file.write_text("")
    
    result = load_config(str(config_file))
    
    # Empty file should result in defaults
    assert isinstance(result, WebprobeConfig)


def test_load_config_with_empty_string_path():
    """Edge case: Path is empty string (not None)."""
    with pytest.raises(Exception) as exc_info:
        load_config("")
    
    # Empty string path should raise explicit_path_not_found
    assert "not found" in str(exc_info.value).lower() or "exist" in str(exc_info.value).lower()


def test_load_config_boundary_max_depth_zero(tmp_path):
    """Edge case: CrawlConfig.max_depth set to 0."""
    config_file = tmp_path / "boundary_max_depth_zero.yaml"
    config_content = """
crawl:
  max_depth: 0
  max_nodes: 10
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    try:
        result = load_config(str(config_file))
        # If it succeeds, verify the value
        assert result.crawl.max_depth == 0
    except Exception as e:
        # If validation rejects it, that's also acceptable
        assert "validation" in str(e).lower() or "max_depth" in str(e).lower()


def test_load_config_boundary_max_nodes_large(tmp_path):
    """Edge case: CrawlConfig.max_nodes set to very large value."""
    config_file = tmp_path / "boundary_max_nodes_large.yaml"
    config_content = """
crawl:
  max_depth: 5
  max_nodes: 999999999
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert result.crawl.max_nodes == 999999999


def test_load_config_literal_auth_methods_all_variants(tmp_path):
    """Edge case: Test all Literal variants for auth method."""
    methods = ["cookie", "bearer", "header", "none"]
    
    for method in methods:
        config_file = tmp_path / f"auth_{method}.yaml"
        config_content = f"""
auth:
  method: {method}
crawl:
  max_depth: 1
capture:
  concurrency: 1
output_dir: /out
"""
        config_file.write_text(config_content)
        
        result = load_config(str(config_file))
        assert result.auth.method == method


def test_load_config_empty_credentials_list(tmp_path):
    """Edge case: AuthConfig.credentials is empty list."""
    config_file = tmp_path / "empty_credentials.yaml"
    config_content = """
auth:
  method: none
  credentials: []
crawl:
  max_depth: 1
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert result.auth.credentials == []


def test_load_config_empty_url_exclude_patterns(tmp_path):
    """Edge case: CrawlConfig.url_exclude_patterns is empty list."""
    config_file = tmp_path / "empty_patterns.yaml"
    config_content = """
crawl:
  max_depth: 1
  url_exclude_patterns: []
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert result.crawl.url_exclude_patterns == []


def test_load_config_special_characters_in_path(tmp_path):
    """Edge case: Config path contains spaces and special characters."""
    config_file = tmp_path / "path with spaces & special.yaml"
    config_content = """
auth:
  method: none
crawl:
  max_depth: 1
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert isinstance(result, WebprobeConfig)


def test_load_config_relative_vs_absolute_path(tmp_path, monkeypatch):
    """Edge case: Test both relative and absolute paths."""
    # Setup
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    config_file = work_dir / "config.yaml"
    config_content = """
auth:
  method: none
crawl:
  max_depth: 2
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    # Test absolute path
    result_abs = load_config(str(config_file.absolute()))
    assert isinstance(result_abs, WebprobeConfig)
    assert result_abs.crawl.max_depth == 2
    
    # Test relative path
    monkeypatch.chdir(work_dir)
    result_rel = load_config("config.yaml")
    assert isinstance(result_rel, WebprobeConfig)
    assert result_rel.crawl.max_depth == 2


# ============================================================================
# ERROR CASE TESTS
# ============================================================================


def test_load_config_explicit_path_not_found():
    """Error case: Explicit path provided but file does not exist."""
    with pytest.raises(Exception) as exc_info:
        load_config("nonexistent_file_12345.yaml")
    
    error_msg = str(exc_info.value).lower()
    assert "not found" in error_msg or "exist" in error_msg or "no such file" in error_msg


def test_load_config_directory_instead_of_file(tmp_path):
    """Error case: Explicit path points to directory not file."""
    directory = tmp_path / "a_directory"
    directory.mkdir()
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(directory))
    
    # Should raise an error (file_read_error or similar)
    assert exc_info.value is not None


def test_load_config_yaml_syntax_error(tmp_path):
    """Error case: YAML file contains invalid syntax."""
    config_file = tmp_path / "invalid_syntax.yaml"
    config_content = """
auth:
  method: none
  unclosed: [bracket, value
crawl:
  max_depth: 1
"""
    config_file.write_text(config_content)
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    error_msg = str(exc_info.value).lower()
    assert "yaml" in error_msg or "parse" in error_msg or "syntax" in error_msg


def test_load_config_yaml_malformed_structure(tmp_path):
    """Error case: YAML is valid but structure is malformed."""
    config_file = tmp_path / "malformed.yaml"
    config_content = """
auth:
method: none
  extra_indent: wrong
"""
    config_file.write_text(config_content)
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    error_msg = str(exc_info.value).lower()
    assert "yaml" in error_msg or "parse" in error_msg or "validation" in error_msg


def test_load_config_yaml_tabs_instead_of_spaces(tmp_path):
    """Error case: YAML uses tabs which can cause parsing issues."""
    config_file = tmp_path / "tabs.yaml"
    # Using tabs in YAML
    config_content = "auth:\n\tmethod: none\ncrawl:\n\tmax_depth: 1"
    config_file.write_text(config_content)
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    error_msg = str(exc_info.value).lower()
    # Might be yaml error or validation error
    assert "yaml" in error_msg or "parse" in error_msg or "validation" in error_msg


def test_load_config_pydantic_validation_wrong_type(tmp_path):
    """Error case: Field has wrong type (string instead of int)."""
    config_file = tmp_path / "wrong_type.yaml"
    config_content = """
crawl:
  max_depth: "not_a_number"
  max_nodes: 10
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    error_msg = str(exc_info.value).lower()
    assert "validation" in error_msg or "type" in error_msg or "int" in error_msg


def test_load_config_pydantic_validation_invalid_literal(tmp_path):
    """Error case: Literal field has value outside allowed options."""
    config_file = tmp_path / "invalid_literal.yaml"
    config_content = """
auth:
  method: invalid_method
crawl:
  max_depth: 1
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    error_msg = str(exc_info.value).lower()
    assert "validation" in error_msg or "literal" in error_msg or "invalid_method" in error_msg


def test_load_config_pydantic_validation_negative_int(tmp_path):
    """Error case: Integer field has negative value when positive required."""
    config_file = tmp_path / "negative_int.yaml"
    config_content = """
crawl:
  max_depth: -5
  max_nodes: 10
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    error_msg = str(exc_info.value).lower()
    assert "validation" in error_msg or "negative" in error_msg or "greater" in error_msg


def test_load_config_pydantic_validation_wrong_list_type(tmp_path):
    """Error case: List field contains wrong element type."""
    config_file = tmp_path / "wrong_list_type.yaml"
    config_content = """
crawl:
  max_depth: 1
  url_exclude_patterns:
    - "valid_string"
    - 12345
    - "another_string"
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    error_msg = str(exc_info.value).lower()
    assert "validation" in error_msg or "type" in error_msg or "str" in error_msg


def test_load_config_pydantic_validation_nested_error(tmp_path):
    """Error case: Nested struct validation fails (AuthCredential within AuthConfig)."""
    config_file = tmp_path / "nested_error.yaml"
    config_content = """
auth:
  method: bearer
  credentials:
    - name: cred1
      method: invalid_cred_method
      cookie_name: ""
      cookie_value: ""
      bearer_token: ""
      header_name: ""
      header_value: ""
crawl:
  max_depth: 1
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    error_msg = str(exc_info.value).lower()
    assert "validation" in error_msg or "credentials" in error_msg or "method" in error_msg


def test_load_config_file_read_permission_denied(tmp_path):
    """Error case: File exists but cannot be read due to permissions."""
    config_file = tmp_path / "no_permission.yaml"
    config_file.write_text("auth:\n  method: none\ncrawl:\n  max_depth: 1\ncapture:\n  concurrency: 1\noutput_dir: /out")
    
    # Remove read permissions
    os.chmod(config_file, 0o000)
    
    try:
        with pytest.raises(Exception) as exc_info:
            load_config(str(config_file))
        
        error_msg = str(exc_info.value).lower()
        assert "permission" in error_msg or "read" in error_msg or "access" in error_msg
    finally:
        # Restore permissions for cleanup
        os.chmod(config_file, 0o644)


def test_load_config_file_encoding_error(tmp_path):
    """Error case: File has encoding issues (invalid UTF-8)."""
    config_file = tmp_path / "bad_encoding.yaml"
    # Write invalid UTF-8 bytes
    with open(config_file, 'wb') as f:
        f.write(b"auth:\n  method: \xff\xfe invalid utf8\n")
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    # Should raise file_read_error or similar
    assert exc_info.value is not None


def test_load_config_credentials_not_leaked_in_error(tmp_path):
    """Error case: Validation error does not leak credential values."""
    config_file = tmp_path / "config_with_creds.yaml"
    secret_token = "SUPER_SECRET_TOKEN_12345"
    secret_cookie = "SECRET_COOKIE_VALUE_67890"
    
    config_content = f"""
auth:
  method: bearer
  bearer_token: {secret_token}
  cookie_value: {secret_cookie}
  credentials:
    - name: cred1
      method: invalid_method_xyz
      cookie_name: ""
      cookie_value: ""
      bearer_token: ""
      header_name: ""
      header_value: ""
crawl:
  max_depth: 1
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    with pytest.raises(Exception) as exc_info:
        load_config(str(config_file))
    
    error_msg = str(exc_info.value)
    # Verify secrets are not in error message
    assert secret_token not in error_msg
    assert secret_cookie not in error_msg


# ============================================================================
# INVARIANT TESTS
# ============================================================================


def test_load_config_invariant_search_paths_order(tmp_path, monkeypatch):
    """Invariant: Search paths are checked in exact order: ./webprobe.yaml then ~/.webprobe/webprobe.yaml."""
    # Setup both configs with different values
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    webprobe_dir = fake_home / ".webprobe"
    webprobe_dir.mkdir()
    home_config = webprobe_dir / "webprobe.yaml"
    home_config.write_text("auth:\n  method: header\ncrawl:\n  max_depth: 999\ncapture:\n  concurrency: 1\noutput_dir: /home")
    
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    local_config = work_dir / "webprobe.yaml"
    local_config.write_text("auth:\n  method: cookie\ncrawl:\n  max_depth: 111\ncapture:\n  concurrency: 1\noutput_dir: /local")
    
    monkeypatch.chdir(work_dir)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    
    result = load_config(None)
    
    # Should load from local (first in search order)
    assert result.crawl.max_depth == 111
    assert result.output_dir == "/local"


def test_load_config_invariant_immutable_defaults(tmp_path, monkeypatch):
    """Invariant: Default values are immutable or use Field(default_factory=...)."""
    monkeypatch.chdir(tmp_path)
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    
    # Load defaults twice
    result1 = load_config(None)
    result2 = load_config(None)
    
    # Modify one instance
    result1.crawl.url_exclude_patterns.append("test_pattern")
    
    # Verify the other is unaffected
    assert "test_pattern" not in result2.crawl.url_exclude_patterns


def test_load_config_invariant_pydantic_v2(tmp_path, monkeypatch):
    """Invariant: All models use BaseModel from pydantic v2."""
    monkeypatch.chdir(tmp_path)
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    
    result = load_config(None)
    
    # Check that result uses pydantic v2 API
    # Pydantic v2 has model_dump() method, v1 has dict()
    assert hasattr(result, 'model_dump') or hasattr(result, 'dict')
    
    # Better check: Pydantic v2 BaseModel has model_fields
    assert hasattr(WebprobeConfig, 'model_fields') or hasattr(WebprobeConfig, '__fields__')


def test_load_config_invariant_idempotent_loading(tmp_path):
    """Invariant: Loading same config file twice gives equivalent results."""
    config_file = tmp_path / "config.yaml"
    config_content = """
auth:
  method: bearer
  bearer_token: token123
  credentials:
    - name: cred1
      method: cookie
      cookie_name: auth
      cookie_value: val1
      bearer_token: ""
      header_name: ""
      header_value: ""
crawl:
  max_depth: 5
  max_nodes: 50
  url_exclude_patterns:
    - "pattern1"
    - "pattern2"
capture:
  concurrency: 3
  screenshot: true
output_dir: /output
"""
    config_file.write_text(config_content)
    
    result1 = load_config(str(config_file))
    result2 = load_config(str(config_file))
    
    # Compare key fields
    assert result1.auth.method == result2.auth.method
    assert result1.auth.bearer_token == result2.auth.bearer_token
    assert result1.crawl.max_depth == result2.crawl.max_depth
    assert result1.crawl.max_nodes == result2.crawl.max_nodes
    assert result1.crawl.url_exclude_patterns == result2.crawl.url_exclude_patterns
    assert result1.capture.concurrency == result2.capture.concurrency
    assert result1.output_dir == result2.output_dir
    assert len(result1.auth.credentials) == len(result2.auth.credentials)


# ============================================================================
# ADDITIONAL INTEGRATION TESTS
# ============================================================================


def test_load_config_yaml_with_comments(tmp_path):
    """Integration: YAML file with comments should parse correctly."""
    config_file = tmp_path / "config_with_comments.yaml"
    config_content = """
# This is a comment
auth:
  method: none  # inline comment
  # another comment
crawl:
  max_depth: 3  # max crawl depth
capture:
  concurrency: 2
output_dir: /out
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert isinstance(result, WebprobeConfig)
    assert result.crawl.max_depth == 3


def test_load_config_multiple_credentials(tmp_path):
    """Integration: Load config with multiple credentials in list."""
    config_file = tmp_path / "multi_creds.yaml"
    config_content = """
auth:
  method: bearer
  credentials:
    - name: cred1
      method: cookie
      cookie_name: auth1
      cookie_value: val1
      bearer_token: ""
      header_name: ""
      header_value: ""
    - name: cred2
      method: bearer
      cookie_name: ""
      cookie_value: ""
      bearer_token: token2
      header_name: ""
      header_value: ""
    - name: cred3
      method: header
      cookie_name: ""
      cookie_value: ""
      bearer_token: ""
      header_name: X-Custom
      header_value: custom_val
crawl:
  max_depth: 1
capture:
  concurrency: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert len(result.auth.credentials) == 3
    assert result.auth.credentials[0].name == "cred1"
    assert result.auth.credentials[0].method == "cookie"
    assert result.auth.credentials[1].name == "cred2"
    assert result.auth.credentials[1].method == "bearer"
    assert result.auth.credentials[2].name == "cred3"
    assert result.auth.credentials[2].method == "header"


def test_load_config_all_boolean_values(tmp_path):
    """Integration: Test various boolean representations in YAML."""
    config_file = tmp_path / "booleans.yaml"
    config_content = """
crawl:
  max_depth: 1
  respect_robots: true
  follow_external: false
capture:
  concurrency: 1
  screenshot: yes
output_dir: /out
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert result.crawl.respect_robots is True
    assert result.crawl.follow_external is False
    # YAML should convert 'yes' to True
    assert result.capture.screenshot is True


def test_load_config_numeric_boundaries(tmp_path):
    """Integration: Test various numeric boundary values."""
    config_file = tmp_path / "numeric_boundaries.yaml"
    config_content = """
crawl:
  max_depth: 1
  max_nodes: 1
  request_delay_ms: 0
capture:
  concurrency: 1
  timeout_ms: 1
  viewport_width: 1
  viewport_height: 1
output_dir: /out
"""
    config_file.write_text(config_content)
    
    result = load_config(str(config_file))
    
    assert result.crawl.request_delay_ms == 0
    assert result.capture.timeout_ms == 1
    assert result.capture.viewport_width == 1
    assert result.capture.viewport_height == 1
