"""
Contract tests for src_webprobe_reporter component.

This test suite validates the generate_report function against its contract,
covering happy paths, edge cases, error cases, and invariants.

Test structure:
- Happy path tests: Verify basic functionality with typical inputs
- Edge case tests: Test boundary conditions and unusual inputs
- Error case tests: Verify proper error handling for all declared exceptions
- Invariant tests: Verify contract invariants are maintained
"""

import pytest
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open
from jinja2 import Template

# Import the component under test
from src.webprobe.reporter import generate_report, HTML_TEMPLATE


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def minimal_run():
    """Minimal Run instance with empty graph."""
    run = Mock()
    run.model_dump_json = Mock(return_value='{"run_id": "test-minimal", "graph": {"nodes": []}}')
    run.graph = Mock()
    run.graph.nodes = []
    run.analysis = Mock()
    run.phases = []
    run.explore_cost = Mock()
    run.run_id = "test-minimal"
    run.started_at = "2024-01-01T00:00:00Z"
    return run


@pytest.fixture
def typical_run():
    """Typical Run instance with populated graph and data."""
    run = Mock()
    
    # Create mock nodes
    node1 = Mock()
    node1.id = "page-1"
    node1.url = "https://example.com/page1"
    
    node2 = Mock()
    node2.id = "page-2"
    node2.url = "https://example.com/page2"
    
    # Setup graph
    run.graph = Mock()
    run.graph.nodes = [node1, node2]
    
    # Setup analysis
    run.analysis = Mock()
    run.analysis.total_pages = 2
    run.analysis.security_findings = []
    run.analysis.broken_links = []
    
    # Setup phases
    run.phases = [
        Mock(phase="explore", status="completed", duration_ms=100),
        Mock(phase="analyze", status="completed", duration_ms=50)
    ]
    
    run.explore_cost = Mock()
    run.explore_cost.total_requests = 10
    
    run.run_id = "test-typical"
    run.started_at = "2024-01-01T00:00:00Z"
    run.completed_at = "2024-01-01T00:01:00Z"
    
    # Mock serialization
    run.model_dump_json = Mock(return_value=json.dumps({
        "run_id": "test-typical",
        "graph": {"nodes": [{"id": "page-1"}, {"id": "page-2"}]},
        "analysis": {"total_pages": 2}
    }, indent=2))
    
    return run


@pytest.fixture
def maximal_run():
    """Maximal Run instance with many nodes, findings, and metrics."""
    run = Mock()
    
    # Create many mock nodes
    nodes = []
    for i in range(100):
        node = Mock()
        node.id = f"page-{i:03d}"
        node.url = f"https://example.com/page{i}"
        nodes.append(node)
    
    run.graph = Mock()
    run.graph.nodes = nodes
    
    # Setup analysis with findings
    run.analysis = Mock()
    run.analysis.total_pages = 100
    run.analysis.security_findings = [
        Mock(severity="high", description="XSS vulnerability"),
        Mock(severity="medium", description="Missing CSP header")
    ]
    run.analysis.broken_links = [
        Mock(url="https://example.com/broken", status_code=404)
    ]
    run.analysis.auth_violations = []
    run.analysis.timing_outliers = [
        Mock(url="https://example.com/slow", duration_ms=5000)
    ]
    
    run.phases = [
        Mock(phase="explore", status="completed", duration_ms=1000),
        Mock(phase="analyze", status="completed", duration_ms=500)
    ]
    
    run.explore_cost = Mock()
    run.explore_cost.total_requests = 200
    
    run.run_id = "test-maximal"
    run.started_at = "2024-01-01T00:00:00Z"
    run.completed_at = "2024-01-01T00:10:00Z"
    
    # Mock serialization
    run.model_dump_json = Mock(return_value=json.dumps({
        "run_id": "test-maximal",
        "graph": {"nodes": [{"id": n.id} for n in nodes]},
        "analysis": {
            "total_pages": 100,
            "security_findings": [{"severity": "high"}]
        }
    }, indent=2))
    
    return run


@pytest.fixture
def temp_run_dir(tmp_path):
    """Temporary directory for test outputs."""
    run_dir = tmp_path / "test_run"
    run_dir.mkdir()
    return run_dir


# ============================================================================
# Happy Path Tests
# ============================================================================

def test_generate_report_happy_path_both_formats(typical_run, temp_run_dir):
    """Generate both JSON and HTML reports successfully with typical Run data."""
    result = generate_report(typical_run, temp_run_dir, formats=['json', 'html'])
    
    # Verify PhaseStatus
    assert result.phase == 'report'
    assert result.status == 'completed'
    assert result.duration_ms > 0
    assert result.started_at is not None
    assert result.completed_at is not None
    
    # Verify files written
    assert (temp_run_dir / "report.json").exists()
    assert (temp_run_dir / "report.html").exists()
    
    # Verify timestamps are ISO format
    datetime.fromisoformat(result.started_at.replace('Z', '+00:00'))
    datetime.fromisoformat(result.completed_at.replace('Z', '+00:00'))


def test_generate_report_json_only(typical_run, temp_run_dir):
    """Generate only JSON report when formats=['json']."""
    result = generate_report(typical_run, temp_run_dir, formats=['json'])
    
    assert result.phase == 'report'
    assert result.status == 'completed'
    assert (temp_run_dir / "report.json").exists()
    assert not (temp_run_dir / "report.html").exists()


def test_generate_report_html_only(typical_run, temp_run_dir):
    """Generate only HTML report when formats=['html']."""
    result = generate_report(typical_run, temp_run_dir, formats=['html'])
    
    assert result.phase == 'report'
    assert result.status == 'completed'
    assert (temp_run_dir / "report.html").exists()
    assert not (temp_run_dir / "report.json").exists()


def test_generate_report_default_formats(typical_run, temp_run_dir):
    """Generate both reports when formats=None (default behavior)."""
    result = generate_report(typical_run, temp_run_dir, formats=None)
    
    assert result.phase == 'report'
    assert result.status == 'completed'
    assert (temp_run_dir / "report.json").exists()
    assert (temp_run_dir / "report.html").exists()


def test_run_with_all_expected_attributes(typical_run, temp_run_dir):
    """Verify HTML template renders with Run containing all expected attributes."""
    result = generate_report(typical_run, temp_run_dir, formats=['html'])
    
    assert result.status == 'completed'
    
    # Read and verify HTML content
    html_content = (temp_run_dir / "report.html").read_text()
    assert len(html_content) > 0
    assert "example.com" in html_content or "test-typical" in html_content


# ============================================================================
# Edge Case Tests
# ============================================================================

def test_generate_report_minimal_run(minimal_run, temp_run_dir):
    """Generate reports with minimal Run instance (edge case: empty graph)."""
    result = generate_report(minimal_run, temp_run_dir, formats=['json', 'html'])
    
    assert result.status == 'completed'
    assert (temp_run_dir / "report.json").exists()
    assert (temp_run_dir / "report.html").exists()


def test_generate_report_maximal_run(maximal_run, temp_run_dir):
    """Generate reports with maximal Run instance (many nodes, findings, metrics)."""
    result = generate_report(maximal_run, temp_run_dir, formats=['json', 'html'])
    
    assert result.status == 'completed'
    
    # Verify JSON contains all data
    json_content = json.loads((temp_run_dir / "report.json").read_text())
    assert "run_id" in json_content
    assert json_content["run_id"] == "test-maximal"
    
    # Verify HTML was generated
    html_content = (temp_run_dir / "report.html").read_text()
    assert len(html_content) > 0


def test_generate_report_empty_formats_list(typical_run, temp_run_dir):
    """Handle empty formats list (edge case: no files to write)."""
    result = generate_report(typical_run, temp_run_dir, formats=[])
    
    assert result.status == 'completed'
    assert not (temp_run_dir / "report.json").exists()
    assert not (temp_run_dir / "report.html").exists()


def test_invalid_formats_parameter(typical_run, temp_run_dir):
    """Handle formats parameter with invalid values (violates precondition)."""
    # Test that function handles invalid formats gracefully
    # Could either raise error or ignore unknown formats
    try:
        result = generate_report(typical_run, temp_run_dir, formats=['json', 'pdf', 'xml'])
        # If it succeeds, check that at least json was written
        assert result.status == 'completed'
        # Should have written json, ignored pdf and xml
        assert (temp_run_dir / "report.json").exists()
    except (ValueError, TypeError):
        # Or it might raise an error for invalid formats
        pass


# ============================================================================
# Error Case Tests
# ============================================================================

def test_generate_report_file_write_error_nonexistent_dir(typical_run):
    """Raise FileWriteError when run_dir does not exist."""
    from src.webprobe.reporter import FileWriteError
    
    nonexistent_dir = Path("/nonexistent/path/to/nowhere")
    
    with pytest.raises(FileWriteError) as exc_info:
        generate_report(typical_run, nonexistent_dir, formats=['json'])
    
    assert "does not exist" in str(exc_info.value).lower() or "directory" in str(exc_info.value).lower()


def test_generate_report_file_write_error_readonly_dir(typical_run, temp_run_dir):
    """Raise FileWriteError when run_dir is not writable."""
    from src.webprobe.reporter import FileWriteError
    
    # Make directory read-only
    os.chmod(temp_run_dir, stat.S_IRUSR | stat.S_IXUSR)
    
    try:
        with pytest.raises(FileWriteError):
            generate_report(typical_run, temp_run_dir, formats=['json'])
    finally:
        # Restore permissions for cleanup
        os.chmod(temp_run_dir, stat.S_IRWXU)


def test_generate_report_serialization_error(typical_run, temp_run_dir):
    """Raise SerializationError when run.model_dump_json() fails."""
    from src.webprobe.reporter import SerializationError
    
    # Mock model_dump_json to raise exception
    typical_run.model_dump_json = Mock(side_effect=TypeError("Cannot serialize object"))
    
    with pytest.raises(SerializationError) as exc_info:
        generate_report(typical_run, temp_run_dir, formats=['json'])
    
    assert "serializ" in str(exc_info.value).lower()


def test_generate_report_template_render_error(typical_run, temp_run_dir):
    """Raise TemplateRenderError when HTML_TEMPLATE.render() fails."""
    from src.webprobe.reporter import TemplateRenderError
    
    # Mock the template to raise an exception
    with patch('src.webprobe.reporter.HTML_TEMPLATE') as mock_template:
        mock_template.render = Mock(side_effect=Exception("Template syntax error"))
        
        with pytest.raises(TemplateRenderError) as exc_info:
            generate_report(typical_run, temp_run_dir, formats=['html'])
        
        assert "template" in str(exc_info.value).lower() or "render" in str(exc_info.value).lower()


def test_generate_report_import_error(typical_run, temp_run_dir):
    """Raise ImportError when webprobe.__version__ cannot be imported."""
    # Mock the import to fail
    original_webprobe = sys.modules.get('webprobe')
    
    # Create a mock module without __version__
    mock_webprobe = Mock(spec=[])
    del mock_webprobe.__version__  # Ensure __version__ doesn't exist
    
    with patch.dict('sys.modules', {'webprobe': mock_webprobe}):
        with pytest.raises(ImportError):
            generate_report(typical_run, temp_run_dir, formats=['html'])


# ============================================================================
# Invariant Tests
# ============================================================================

def test_phase_status_invariants(typical_run, temp_run_dir):
    """Verify all PhaseStatus invariants are satisfied."""
    result = generate_report(typical_run, temp_run_dir, formats=['json'])
    
    # Verify phase is always 'report'
    assert result.phase == 'report'
    
    # Verify status is 'completed'
    assert result.status == 'completed'
    
    # Verify timestamps are in ISO format UTC
    assert result.started_at is not None
    assert result.completed_at is not None
    
    # Parse timestamps to verify format
    started = datetime.fromisoformat(result.started_at.replace('Z', '+00:00'))
    completed = datetime.fromisoformat(result.completed_at.replace('Z', '+00:00'))
    
    # Verify UTC timezone
    assert started.tzinfo is not None
    assert completed.tzinfo is not None
    
    # Verify duration is non-negative
    assert result.duration_ms >= 0
    
    # Verify completed >= started
    assert completed >= started


def test_html_nodes_sorted_by_id(temp_run_dir):
    """Verify HTML output contains nodes sorted by node.id."""
    run = Mock()
    
    # Create nodes in unsorted order
    node_z = Mock()
    node_z.id = "page-z"
    node_z.url = "https://example.com/z"
    
    node_a = Mock()
    node_a.id = "page-a"
    node_a.url = "https://example.com/a"
    
    node_m = Mock()
    node_m.id = "page-m"
    node_m.url = "https://example.com/m"
    
    run.graph = Mock()
    run.graph.nodes = [node_z, node_a, node_m]
    
    run.analysis = Mock()
    run.phases = []
    run.explore_cost = Mock()
    run.run_id = "test-sorted"
    run.started_at = "2024-01-01T00:00:00Z"
    
    run.model_dump_json = Mock(return_value='{}')
    
    result = generate_report(run, temp_run_dir, formats=['html'])
    
    assert result.status == 'completed'
    
    # Read HTML and check node ordering
    html_content = (temp_run_dir / "report.html").read_text()
    
    # Find positions of node IDs in HTML
    pos_a = html_content.find("page-a")
    pos_m = html_content.find("page-m")
    pos_z = html_content.find("page-z")
    
    # If all nodes are present, verify sorted order
    if pos_a != -1 and pos_m != -1 and pos_z != -1:
        assert pos_a < pos_m < pos_z


def test_json_content_matches_model_dump(typical_run, temp_run_dir):
    """Verify JSON file content matches run.model_dump_json(indent=2)."""
    expected_json = typical_run.model_dump_json(indent=2)
    
    result = generate_report(typical_run, temp_run_dir, formats=['json'])
    
    assert result.status == 'completed'
    
    actual_json = (temp_run_dir / "report.json").read_text()
    
    # Verify content matches
    assert actual_json == expected_json


def test_html_template_constant():
    """Verify HTML_TEMPLATE is a module-level Template instance."""
    from src.webprobe.reporter import HTML_TEMPLATE
    
    # Verify it's a Jinja2 Template instance
    assert isinstance(HTML_TEMPLATE, Template)
    
    # Verify it's the same instance across imports
    from src.webprobe.reporter import HTML_TEMPLATE as template2
    assert HTML_TEMPLATE is template2


def test_timing_uses_monotonic_and_utc(typical_run, temp_run_dir):
    """Verify time measurements use monotonic for duration and UTC for timestamps."""
    result = generate_report(typical_run, temp_run_dir, formats=['json'])
    
    # Verify timestamps contain UTC indicators
    assert 'Z' in result.started_at or '+00:00' in result.started_at
    assert 'Z' in result.completed_at or '+00:00' in result.completed_at
    
    # Verify duration is positive and reasonable
    assert result.duration_ms >= 0
    assert result.duration_ms < 10000  # Should complete in less than 10 seconds
    
    # Parse timestamps and verify they're UTC
    started = datetime.fromisoformat(result.started_at.replace('Z', '+00:00'))
    completed = datetime.fromisoformat(result.completed_at.replace('Z', '+00:00'))
    
    assert started.tzinfo == timezone.utc or started.tzinfo.utcoffset(None).total_seconds() == 0
    assert completed.tzinfo == timezone.utc or completed.tzinfo.utcoffset(None).total_seconds() == 0


def test_json_round_trip(typical_run, temp_run_dir):
    """Verify JSON output can be parsed back as valid JSON."""
    result = generate_report(typical_run, temp_run_dir, formats=['json'])
    
    assert result.status == 'completed'
    
    # Read JSON file
    json_content = (temp_run_dir / "report.json").read_text()
    
    # Parse it back
    parsed = json.loads(json_content)
    
    # Verify structure matches
    assert "run_id" in parsed
    assert parsed["run_id"] == "test-typical"
    assert "graph" in parsed
    assert "analysis" in parsed


# ============================================================================
# Additional Integration Tests
# ============================================================================

def test_generate_both_formats_files_independent(typical_run, temp_run_dir):
    """Verify both formats can be generated and are independent."""
    result = generate_report(typical_run, temp_run_dir, formats=['json', 'html'])
    
    assert result.status == 'completed'
    
    # Read both files
    json_content = (temp_run_dir / "report.json").read_text()
    html_content = (temp_run_dir / "report.html").read_text()
    
    # Verify both have content
    assert len(json_content) > 0
    assert len(html_content) > 0
    
    # Verify they're different
    assert json_content != html_content


def test_phase_status_timing_accuracy(typical_run, temp_run_dir):
    """Verify PhaseStatus timing is accurate."""
    import time
    
    start = time.monotonic()
    result = generate_report(typical_run, temp_run_dir, formats=['json', 'html'])
    end = time.monotonic()
    
    elapsed_ms = (end - start) * 1000
    
    # Duration should be within reasonable range of actual elapsed time
    assert result.duration_ms > 0
    assert result.duration_ms <= elapsed_ms * 1.5  # Allow 50% margin for timing variance


def test_multiple_runs_same_directory(typical_run, temp_run_dir):
    """Verify multiple calls to generate_report overwrite previous files."""
    # First run
    result1 = generate_report(typical_run, temp_run_dir, formats=['json'])
    assert result1.status == 'completed'
    
    first_content = (temp_run_dir / "report.json").read_text()
    
    # Modify run data
    typical_run.run_id = "test-modified"
    typical_run.model_dump_json = Mock(return_value='{"run_id": "test-modified"}')
    
    # Second run
    result2 = generate_report(typical_run, temp_run_dir, formats=['json'])
    assert result2.status == 'completed'
    
    second_content = (temp_run_dir / "report.json").read_text()
    
    # Verify file was overwritten
    assert first_content != second_content
    assert "test-modified" in second_content
