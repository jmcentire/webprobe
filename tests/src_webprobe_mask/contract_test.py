"""
Contract tests for webprobe mask system.

Tests cover load_mask and apply_mask functions with happy paths, edge cases,
error cases, and invariants as specified in the contract.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
from typing import Any
import yaml as yaml_lib
import re

# Import the module under test
from src.webprobe.mask import load_mask, apply_mask, MaskConfig, MaskRule


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_mask_rules():
    """Sample mask rules for testing."""
    return [
        MaskRule(
            url_pattern=r".*example\.com.*",
            title_pattern=r".*XSS.*",
            category="xss",
            reason="Test XSS suppression"
        ),
        MaskRule(
            url_pattern=r".*test\.com.*",
            title_pattern=r".*SQL.*",
            category="sqli",
            reason="Test SQL injection suppression"
        )
    ]


@pytest.fixture
def sample_mask_config(sample_mask_rules):
    """Sample MaskConfig for testing."""
    return MaskConfig(rules=sample_mask_rules)


@pytest.fixture
def sample_security_finding():
    """Create a mock SecurityFinding."""
    finding = Mock()
    finding.url = "https://example.com/page"
    finding.title = "Potential XSS vulnerability"
    finding.category = "xss"
    return finding


@pytest.fixture
def sample_findings_list():
    """Create a list of mock SecurityFindings."""
    finding1 = Mock()
    finding1.url = "https://example.com/page"
    finding1.title = "Potential XSS vulnerability"
    finding1.category = "xss"
    
    finding2 = Mock()
    finding2.url = "https://test.com/login"
    finding2.title = "SQL Injection detected"
    finding2.category = "sqli"
    
    finding3 = Mock()
    finding3.url = "https://other.com/api"
    finding3.title = "CSRF vulnerability"
    finding3.category = "csrf"
    
    return [finding1, finding2, finding3]


# =============================================================================
# load_mask tests - Happy Path
# =============================================================================

@pytest.mark.unit
def test_load_mask_happy_path_valid_yaml_file(tmp_path):
    """Load a valid YAML configuration file with multiple mask rules."""
    yaml_content = """
rules:
  - url_pattern: ".*example\\.com.*"
    title_pattern: ".*XSS.*"
    category: "xss"
    reason: "Test XSS suppression"
  - url_pattern: ".*test\\.com.*"
    title_pattern: ".*SQL.*"
    category: "sqli"
    reason: "Test SQL suppression"
"""
    test_file = tmp_path / "test_mask.yaml"
    test_file.write_text(yaml_content)
    
    result = load_mask(str(test_file))
    
    assert result is not None
    assert isinstance(result, MaskConfig)
    assert len(result.rules) == 2
    assert result.rules[0].category == "xss"
    assert result.rules[1].category == "sqli"


@pytest.mark.unit
def test_load_mask_happy_path_none_path_with_default(tmp_path, monkeypatch):
    """Load mask from default location when path is None and default file exists."""
    yaml_content = """
rules:
  - url_pattern: ".*"
    title_pattern: ".*"
    category: "test"
    reason: "Test rule"
"""
    # Change to tmp directory and create default file
    monkeypatch.chdir(tmp_path)
    default_file = tmp_path / "webprobe-mask.yaml"
    default_file.write_text(yaml_content)
    
    result = load_mask(None)
    
    assert result is not None
    assert isinstance(result, MaskConfig)
    assert len(result.rules) > 0


# =============================================================================
# load_mask tests - Edge Cases
# =============================================================================

@pytest.mark.unit
def test_load_mask_edge_case_none_path_no_defaults(tmp_path, monkeypatch):
    """Load mask with None path when no default files exist."""
    # Change to empty tmp directory
    monkeypatch.chdir(tmp_path)
    
    result = load_mask(None)
    
    assert result is not None
    assert isinstance(result, MaskConfig)
    assert result.rules == []
    assert len(result.rules) == 0


@pytest.mark.unit
def test_load_mask_edge_case_nonexistent_path():
    """Load mask with path that doesn't exist."""
    result = load_mask("/nonexistent/path/mask.yaml")
    
    assert result is not None
    assert isinstance(result, MaskConfig)
    assert result.rules == []


@pytest.mark.unit
def test_load_mask_edge_case_empty_yaml_file(tmp_path):
    """Load mask from empty YAML file."""
    empty_file = tmp_path / "empty.yaml"
    empty_file.write_text("")
    
    result = load_mask(str(empty_file))
    
    assert result is not None
    assert isinstance(result, MaskConfig)


@pytest.mark.unit
def test_load_mask_edge_case_pathlib_path(tmp_path):
    """Load mask using pathlib.Path object."""
    yaml_content = """
rules:
  - url_pattern: ".*"
    title_pattern: ".*"
    category: "test"
    reason: "Test"
"""
    test_file = tmp_path / "test_mask.yaml"
    test_file.write_text(yaml_content)
    
    result = load_mask(Path(test_file))
    
    assert result is not None
    assert isinstance(result, MaskConfig)


@pytest.mark.unit
def test_load_mask_edge_case_unicode_content(tmp_path):
    """Load mask from YAML with Unicode content."""
    yaml_content = """
rules:
  - url_pattern: ".*测试.*"
    title_pattern: ".*テスト.*"
    category: "test"
    reason: "Unicode test: 你好 مرحبا"
"""
    test_file = tmp_path / "unicode_mask.yaml"
    test_file.write_text(yaml_content, encoding='utf-8')
    
    result = load_mask(str(test_file))
    
    assert result is not None
    assert isinstance(result, MaskConfig)
    assert "测试" in result.rules[0].url_pattern


# =============================================================================
# load_mask tests - Error Cases
# =============================================================================

@pytest.mark.unit
def test_load_mask_error_invalid_yaml_syntax(tmp_path):
    """Load mask from file with invalid YAML syntax."""
    invalid_yaml = """
rules:
  - url_pattern: "test"
    title_pattern: "test
    category: broken
"""
    test_file = tmp_path / "invalid.yaml"
    test_file.write_text(invalid_yaml)
    
    with pytest.raises(Exception) as exc_info:
        load_mask(str(test_file))
    
    # Check that some YAML-related error was raised
    assert "yaml" in str(type(exc_info.value).__name__).lower() or "parse" in str(exc_info.value).lower()


@pytest.mark.unit
def test_load_mask_error_invalid_schema(tmp_path):
    """Load mask from YAML with structure that doesn't match MaskConfig schema."""
    invalid_schema = """
rules:
  - invalid_field: "value"
    another_wrong_field: 123
"""
    test_file = tmp_path / "invalid_schema.yaml"
    test_file.write_text(invalid_schema)
    
    with pytest.raises(Exception) as exc_info:
        load_mask(str(test_file))
    
    # Check that validation error was raised
    assert exc_info.value is not None


@pytest.mark.unit
def test_load_mask_error_file_read_permission(tmp_path):
    """Load mask from file without read permissions."""
    yaml_content = """
rules:
  - url_pattern: ".*"
    title_pattern: ".*"
    category: "test"
    reason: "Test"
"""
    test_file = tmp_path / "no_read.yaml"
    test_file.write_text(yaml_content)
    
    # Remove read permissions
    os.chmod(test_file, 0o000)
    
    try:
        with pytest.raises(Exception) as exc_info:
            load_mask(str(test_file))
        assert exc_info.value is not None
    finally:
        # Restore permissions for cleanup
        os.chmod(test_file, 0o644)


# =============================================================================
# load_mask tests - Invariants
# =============================================================================

@pytest.mark.unit
def test_load_mask_invariant_default_search_paths(tmp_path, monkeypatch):
    """Verify default search paths are checked in correct order."""
    monkeypatch.chdir(tmp_path)
    
    # Create second default file
    subdir = tmp_path / ".webprobe"
    subdir.mkdir()
    second_file = subdir / "mask.yaml"
    second_file.write_text("""
rules:
  - url_pattern: "second"
    title_pattern: "second"
    category: "second"
    reason: "Second file"
""")
    
    # Create first default file (should be loaded)
    first_file = tmp_path / "webprobe-mask.yaml"
    first_file.write_text("""
rules:
  - url_pattern: "first"
    title_pattern: "first"
    category: "first"
    reason: "First file"
""")
    
    result = load_mask(None)
    
    # Should load from first default path
    assert result.rules[0].category == "first"


# =============================================================================
# apply_mask tests - Happy Path
# =============================================================================

@pytest.mark.unit
def test_apply_mask_happy_path_basic_matching(sample_findings_list):
    """Apply mask rules to findings with basic pattern matching."""
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*example\.com.*",
            title_pattern=r".*XSS.*",
            category="xss",
            reason="Test"
        )
    ])
    
    findings = sample_findings_list
    result = apply_mask(findings, mask)
    
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert len(result[0]) + len(result[1]) == len(findings)
    assert len(result[1]) > 0  # At least one finding suppressed


@pytest.mark.unit
def test_apply_mask_happy_path_empty_findings():
    """Apply mask to empty findings list."""
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=".*",
            title_pattern=".*",
            category="test",
            reason="Test"
        )
    ])
    
    result = apply_mask([], mask)
    
    assert result == ([], [])
    assert len(result[0]) == 0
    assert len(result[1]) == 0


# =============================================================================
# apply_mask tests - Edge Cases
# =============================================================================

@pytest.mark.unit
def test_apply_mask_edge_case_empty_mask_rules(sample_findings_list):
    """Apply mask with empty rules list to findings."""
    mask = MaskConfig(rules=[])
    findings = sample_findings_list
    
    result = apply_mask(findings, mask)
    
    assert result[0] == findings
    assert result[1] == []
    assert len(result[0]) == len(findings)


@pytest.mark.unit
def test_apply_mask_edge_case_finding_with_none_url():
    """Apply mask to finding with None URL."""
    finding = Mock()
    finding.url = None
    finding.title = "Test vulnerability"
    finding.category = "test"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*anything.*",
            title_pattern=r".*Test.*",
            category="test",
            reason="Test"
        )
    ])
    
    result = apply_mask([finding], mask)
    
    # url_pattern check treated as True when url is None
    assert len(result[1]) == 1  # Finding suppressed


@pytest.mark.unit
def test_apply_mask_edge_case_default_patterns():
    """Apply mask rule with default patterns '.*'."""
    finding = Mock()
    finding.url = "https://any-url.com"
    finding.title = "Any title"
    finding.category = "test"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*",
            title_pattern=r".*",
            category="test",
            reason="Match all"
        )
    ])
    
    result = apply_mask([finding], mask)
    
    # All findings with matching category suppressed
    assert len(result[1]) == 1


@pytest.mark.unit
def test_apply_mask_edge_case_empty_category_matches_any():
    """Apply mask rule with empty category string."""
    finding1 = Mock()
    finding1.url = "https://test.com"
    finding1.title = "Test"
    finding1.category = "xss"
    
    finding2 = Mock()
    finding2.url = "https://test.com"
    finding2.title = "Test"
    finding2.category = "sqli"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*test\.com.*",
            title_pattern=r".*Test.*",
            category="",
            reason="Match any category"
        )
    ])
    
    result = apply_mask([finding1, finding2], mask)
    
    # Both findings matched regardless of category
    assert len(result[1]) == 2


@pytest.mark.unit
def test_apply_mask_edge_case_no_overlap_in_partitions(sample_findings_list):
    """Verify no finding appears in both kept and suppressed lists."""
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*example\.com.*",
            title_pattern=r".*XSS.*",
            category="xss",
            reason="Test"
        )
    ])
    
    findings = sample_findings_list
    result = apply_mask(findings, mask)
    
    kept, suppressed = result
    assert set(kept).isdisjoint(set(suppressed))


@pytest.mark.unit
def test_apply_mask_edge_case_all_conditions_required():
    """Verify finding suppressed only when ALL conditions match."""
    finding = Mock()
    finding.url = "https://example.com/page"
    finding.title = "XSS vulnerability"
    finding.category = "xss"
    
    # Rule that matches URL and title but not category
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*example\.com.*",
            title_pattern=r".*XSS.*",
            category="sqli",  # Wrong category
            reason="Test"
        )
    ])
    
    result = apply_mask([finding], mask)
    
    # Finding kept because category doesn't match
    assert len(result[0]) == 1
    assert len(result[1]) == 0


@pytest.mark.unit
def test_apply_mask_edge_case_regex_special_characters():
    """Apply mask with regex special characters in patterns."""
    finding = Mock()
    finding.url = "https://test.com/page?id=123"
    finding.title = "Test [vuln] (critical)"
    finding.category = "test"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*test\.com/page\?id=\d+",
            title_pattern=r".*\[vuln\].*",
            category="test",
            reason="Special chars"
        )
    ])
    
    result = apply_mask([finding], mask)
    
    # Special regex characters handled properly
    assert len(result[1]) == 1


# =============================================================================
# apply_mask tests - Error Cases
# =============================================================================

@pytest.mark.unit
def test_apply_mask_error_invalid_regex_url_pattern():
    """Apply mask with invalid regex in url_pattern."""
    finding = Mock()
    finding.url = "https://test.com"
    finding.title = "Test"
    finding.category = "test"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r"[invalid(regex",  # Invalid regex
            title_pattern=r".*",
            category="test",
            reason="Test"
        )
    ])
    
    with pytest.raises(Exception) as exc_info:
        apply_mask([finding], mask)
    
    # Exception raised for invalid regex
    assert exc_info.value is not None


@pytest.mark.unit
def test_apply_mask_error_invalid_regex_title_pattern():
    """Apply mask with invalid regex in title_pattern."""
    finding = Mock()
    finding.url = "https://test.com"
    finding.title = "Test"
    finding.category = "test"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*",
            title_pattern=r"*invalid+regex(",  # Invalid regex
            category="test",
            reason="Test"
        )
    ])
    
    with pytest.raises(Exception) as exc_info:
        apply_mask([finding], mask)
    
    # Exception raised for invalid regex
    assert exc_info.value is not None


@pytest.mark.unit
def test_apply_mask_error_missing_finding_attributes():
    """Apply mask to finding missing required attributes."""
    finding = Mock(spec=['url'])  # Missing title and category
    finding.url = "https://test.com"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*",
            title_pattern=r".*",
            category="test",
            reason="Test"
        )
    ])
    
    with pytest.raises(AttributeError):
        apply_mask([finding], mask)


# =============================================================================
# apply_mask tests - Invariants
# =============================================================================

@pytest.mark.unit
def test_apply_mask_invariant_partition_completeness(sample_findings_list):
    """Verify all findings are preserved across partitions."""
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*example\.com.*",
            title_pattern=r".*XSS.*",
            category="xss",
            reason="Test"
        )
    ])
    
    findings = sample_findings_list
    kept, suppressed = apply_mask(findings, mask)
    
    # All findings preserved
    assert len(kept) + len(suppressed) == len(findings)
    assert set(kept + suppressed) == set(findings)


@pytest.mark.unit
def test_apply_mask_invariant_first_matching_rule():
    """Verify first matching rule suppresses finding (rules evaluated in order)."""
    finding = Mock()
    finding.url = "https://test.com"
    finding.title = "Test vulnerability"
    finding.category = "test"
    
    # Multiple overlapping rules
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*test\.com.*",
            title_pattern=r".*Test.*",
            category="test",
            reason="First rule"
        ),
        MaskRule(
            url_pattern=r".*test\.com.*",
            title_pattern=r".*vulnerability.*",
            category="test",
            reason="Second rule"
        )
    ])
    
    result = apply_mask([finding], mask)
    
    # Finding suppressed by first matching rule
    assert len(result[1]) == 1


# =============================================================================
# Additional comprehensive tests
# =============================================================================

@pytest.mark.unit
def test_load_mask_with_minimal_valid_yaml(tmp_path):
    """Test loading YAML with minimal required fields."""
    yaml_content = """
rules:
  - url_pattern: ".*"
    title_pattern: ".*"
    category: "test"
    reason: "Minimal"
"""
    test_file = tmp_path / "minimal.yaml"
    test_file.write_text(yaml_content)
    
    result = load_mask(str(test_file))
    
    assert isinstance(result, MaskConfig)
    assert len(result.rules) == 1


@pytest.mark.unit
def test_apply_mask_preserves_finding_order():
    """Verify that findings order is preserved in output."""
    findings = []
    for i in range(5):
        f = Mock()
        f.url = f"https://test{i}.com"
        f.title = f"Title {i}"
        f.category = "test"
        findings.append(f)
    
    mask = MaskConfig(rules=[])
    kept, suppressed = apply_mask(findings, mask)
    
    # Order preserved in kept findings
    assert kept == findings


@pytest.mark.unit
def test_apply_mask_case_sensitive_patterns():
    """Verify regex patterns are case-sensitive by default."""
    finding = Mock()
    finding.url = "https://TEST.COM"
    finding.title = "XSS Vulnerability"
    finding.category = "xss"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*test\.com.*",  # lowercase
            title_pattern=r".*xss.*",      # lowercase
            category="xss",
            reason="Case test"
        )
    ])
    
    result = apply_mask([finding], mask)
    
    # Finding not matched due to case sensitivity
    assert len(result[0]) == 1  # Kept
    assert len(result[1]) == 0  # Not suppressed


@pytest.mark.unit
def test_apply_mask_multiple_rules_different_categories():
    """Test multiple rules matching different categories."""
    finding1 = Mock()
    finding1.url = "https://test.com"
    finding1.title = "XSS found"
    finding1.category = "xss"
    
    finding2 = Mock()
    finding2.url = "https://test.com"
    finding2.title = "SQL injection found"
    finding2.category = "sqli"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*test\.com.*",
            title_pattern=r".*XSS.*",
            category="xss",
            reason="XSS rule"
        ),
        MaskRule(
            url_pattern=r".*test\.com.*",
            title_pattern=r".*SQL.*",
            category="sqli",
            reason="SQLi rule"
        )
    ])
    
    result = apply_mask([finding1, finding2], mask)
    
    # Both findings should be suppressed
    assert len(result[1]) == 2


@pytest.mark.unit
def test_load_mask_yaml_with_comments(tmp_path):
    """Test loading YAML file with comments."""
    yaml_content = """
# This is a comment
rules:
  # Rule for XSS
  - url_pattern: ".*example\\.com.*"
    title_pattern: ".*XSS.*"
    category: "xss"
    reason: "Test"  # Inline comment
"""
    test_file = tmp_path / "commented.yaml"
    test_file.write_text(yaml_content)
    
    result = load_mask(str(test_file))
    
    assert isinstance(result, MaskConfig)
    assert len(result.rules) == 1


@pytest.mark.unit
def test_apply_mask_with_multiline_patterns():
    """Test patterns with newlines and multiline content."""
    finding = Mock()
    finding.url = "https://test.com/page"
    finding.title = "Test vulnerability with\nmultiple lines"
    finding.category = "test"
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*test\.com.*",
            title_pattern=r".*vulnerability.*",
            category="test",
            reason="Multiline test"
        )
    ])
    
    result = apply_mask([finding], mask)
    
    # Should still match
    assert len(result[1]) == 1


@pytest.mark.unit
def test_load_mask_returns_new_instance_each_time(tmp_path):
    """Verify each load_mask call returns a new instance."""
    yaml_content = """
rules:
  - url_pattern: ".*"
    title_pattern: ".*"
    category: "test"
    reason: "Test"
"""
    test_file = tmp_path / "test.yaml"
    test_file.write_text(yaml_content)
    
    result1 = load_mask(str(test_file))
    result2 = load_mask(str(test_file))
    
    assert result1 is not result2
    assert result1.rules == result2.rules


@pytest.mark.unit
def test_apply_mask_does_not_modify_input_findings():
    """Verify apply_mask doesn't modify the input findings list."""
    findings = []
    for i in range(3):
        f = Mock()
        f.url = f"https://test{i}.com"
        f.title = f"Title {i}"
        f.category = "test"
        findings.append(f)
    
    original_findings = findings.copy()
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*test0\.com.*",
            title_pattern=r".*",
            category="test",
            reason="Test"
        )
    ])
    
    apply_mask(findings, mask)
    
    # Original list unchanged
    assert findings == original_findings


@pytest.mark.unit  
def test_apply_mask_empty_string_patterns():
    """Test behavior with empty string patterns."""
    finding = Mock()
    finding.url = "https://test.com"
    finding.title = "Test"
    finding.category = "test"
    
    # Empty patterns might be treated differently
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern="",
            title_pattern="",
            category="test",
            reason="Empty patterns"
        )
    ])
    
    # Should handle empty patterns gracefully
    result = apply_mask([finding], mask)
    assert result is not None


@pytest.mark.unit
def test_load_mask_large_yaml_file(tmp_path):
    """Test loading a large YAML file with many rules."""
    rules = []
    for i in range(100):
        rules.append(f"""
  - url_pattern: ".*test{i}\\.com.*"
    title_pattern: ".*pattern{i}.*"
    category: "cat{i}"
    reason: "Rule {i}"
""")
    
    yaml_content = "rules:" + "".join(rules)
    test_file = tmp_path / "large.yaml"
    test_file.write_text(yaml_content)
    
    result = load_mask(str(test_file))
    
    assert len(result.rules) == 100


@pytest.mark.unit
def test_apply_mask_with_many_findings():
    """Test apply_mask with a large number of findings."""
    findings = []
    for i in range(100):
        f = Mock()
        f.url = f"https://test{i}.com"
        f.title = f"Title {i}"
        f.category = "test"
        findings.append(f)
    
    mask = MaskConfig(rules=[
        MaskRule(
            url_pattern=r".*test[0-4]\.com.*",
            title_pattern=r".*",
            category="test",
            reason="Test"
        )
    ])
    
    kept, suppressed = apply_mask(findings, mask)
    
    assert len(kept) + len(suppressed) == 100
    assert len(suppressed) == 5  # test0-test4


@pytest.mark.unit
def test_mask_rule_reason_preserved():
    """Verify MaskRule reason field is preserved."""
    rule = MaskRule(
        url_pattern=".*",
        title_pattern=".*",
        category="test",
        reason="This is the reason"
    )
    
    assert rule.reason == "This is the reason"


@pytest.mark.unit
def test_load_mask_alternative_default_path(tmp_path, monkeypatch):
    """Test loading from second default path when first doesn't exist."""
    monkeypatch.chdir(tmp_path)
    
    # Only create second default file
    subdir = tmp_path / ".webprobe"
    subdir.mkdir()
    second_file = subdir / "mask.yaml"
    second_file.write_text("""
rules:
  - url_pattern: "second"
    title_pattern: "second"
    category: "second"
    reason: "Second file"
""")
    
    result = load_mask(None)
    
    assert result.rules[0].category == "second"
