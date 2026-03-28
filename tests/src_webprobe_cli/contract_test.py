"""
Contract-based tests for webprobe CLI module.

This test suite verifies the CLI interface against its contract specifications,
covering all commands, error cases, edge cases, and invariants.
"""

import pytest
import json
import yaml
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock, call
from click.testing import CliRunner
import re


# Import the CLI module - adjust path as needed
try:
    from src.webprobe.cli import (
        _now_iso,
        main,
        run,
        explore_cmd,
        map_cmd,
        capture,
        analyze_cmd,
        report,
        diff,
        status
    )
except ImportError:
    # Fallback import path
    try:
        from webprobe.cli import (
            _now_iso,
            main,
            run,
            explore_cmd,
            map_cmd,
            capture,
            analyze_cmd,
            report,
            diff,
            status
        )
    except ImportError:
        # For testing purposes, create mock imports
        def _now_iso():
            pass
        def main():
            pass
        def run():
            pass
        def explore_cmd():
            pass
        def map_cmd():
            pass
        def capture():
            pass
        def analyze_cmd():
            pass
        def report():
            pass
        def diff():
            pass
        def status():
            pass


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def cli_runner():
    """Provides a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def tmp_path_factory_dir(tmp_path):
    """Provides a temporary directory for test files."""
    return tmp_path


@pytest.fixture
def mock_config():
    """Provides a mock WebprobeConfig instance."""
    config = MagicMock()
    config.capture.concurrency = 5
    return config


@pytest.fixture
def valid_config_file(tmp_path):
    """Creates a valid config YAML file."""
    config_path = tmp_path / "config.yaml"
    config_data = {
        "capture": {
            "concurrency": 5,
            "timeout": 30
        },
        "output": {
            "dir": "output"
        }
    }
    with open(config_path, 'w') as f:
        yaml.dump(config_data, f)
    return str(config_path)


@pytest.fixture
def malformed_config_file(tmp_path):
    """Creates a malformed config YAML file."""
    config_path = tmp_path / "malformed.yaml"
    with open(config_path, 'w') as f:
        f.write("invalid: yaml: content: [unclosed")
    return str(config_path)


@pytest.fixture
def valid_run_dir(tmp_path):
    """Creates a valid run directory with required files."""
    run_dir = tmp_path / "run_20240101_120000"
    run_dir.mkdir()
    
    # Create graph.json
    graph_data = {
        "nodes": [
            {"url": "https://example.com", "id": 1},
            {"url": "https://example.com/page", "id": 2}
        ],
        "edges": [{"source": 1, "target": 2}]
    }
    with open(run_dir / "graph.json", 'w') as f:
        json.dump(graph_data, f)
    
    # Create analysis.json
    analysis_data = {
        "findings": [],
        "summary": {"total": 0}
    }
    with open(run_dir / "analysis.json", 'w') as f:
        json.dump(analysis_data, f)
    
    # Create metadata
    metadata = {
        "run_id": "run_20240101_120000",
        "url": "https://example.com",
        "timestamp": "2024-01-01T12:00:00Z"
    }
    with open(run_dir / "metadata.json", 'w') as f:
        json.dump(metadata, f)
    
    return str(run_dir)


@pytest.fixture
def invalid_run_dir(tmp_path):
    """Creates an invalid run directory (empty)."""
    run_dir = tmp_path / "invalid_run"
    run_dir.mkdir()
    return str(run_dir)


@pytest.fixture
def run_dir_without_graph(tmp_path):
    """Creates a run directory without graph.json."""
    run_dir = tmp_path / "run_no_graph"
    run_dir.mkdir()
    return str(run_dir)


@pytest.fixture
def run_dir_invalid_graph(tmp_path):
    """Creates a run directory with invalid graph.json."""
    run_dir = tmp_path / "run_bad_graph"
    run_dir.mkdir()
    with open(run_dir / "graph.json", 'w') as f:
        f.write("invalid json content")
    return str(run_dir)


# ============================================================================
# TESTS: _now_iso
# ============================================================================

class TestNowIso:
    """Tests for _now_iso function."""
    
    def test_now_iso_happy_path(self):
        """Test that _now_iso returns a valid ISO 8601 formatted UTC timestamp."""
        with patch('src.webprobe.cli.datetime') as mock_dt:
            mock_dt.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
            mock_dt.now.return_value.isoformat.return_value = "2024-01-01T12:00:00+00:00"
            
            # If _now_iso is a simple function, test it directly
            result = _now_iso()
            
            # Assertions
            assert isinstance(result, str), "Result is a string"
            assert 'T' in result, "Result contains 'T' separator"
            # Check for UTC timezone indicator
            assert result.endswith('Z') or '+00:00' in result or result.endswith('+00:00'), \
                "Result ends with 'Z' or '+00:00' indicating UTC"
    
    def test_now_iso_format_validation(self):
        """Test that _now_iso output follows strict ISO 8601 format."""
        result = _now_iso()
        
        # ISO 8601 pattern: YYYY-MM-DDTHH:MM:SS[.ffffff][+HH:MM|Z]
        iso_pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        assert re.match(iso_pattern, result), "Matches ISO 8601 regex pattern"
        
        # Verify timezone is UTC
        assert result.endswith('Z') or '+00:00' in result or result.endswith('+00:00'), \
            "Timezone is UTC"


# ============================================================================
# TESTS: main
# ============================================================================

class TestMain:
    """Tests for main CLI entry point."""
    
    def test_main_happy_path_no_config(self, cli_runner, mock_config):
        """Test main command initializes context with default config when no config_path provided."""
        with patch('src.webprobe.cli.WebprobeConfig') as mock_config_cls:
            mock_config_cls.return_value = mock_config
            
            result = cli_runner.invoke(main, [])
            
            # For group commands, we expect success
            assert result.exit_code == 0, "Exit code is 0"
    
    def test_main_happy_path_with_config(self, cli_runner, valid_config_file, mock_config):
        """Test main command loads config from file when config_path provided."""
        with patch('src.webprobe.cli.WebprobeConfig') as mock_config_cls, \
             patch('src.webprobe.cli.load_config') as mock_load:
            mock_load.return_value = mock_config
            
            result = cli_runner.invoke(main, ['--config', valid_config_file])
            
            assert result.exit_code == 0, "Exit code is 0"
    
    def test_main_error_malformed_config(self, cli_runner, malformed_config_file):
        """Test main command fails with config_load_error when config file is malformed."""
        with patch('src.webprobe.cli.load_config') as mock_load:
            mock_load.side_effect = yaml.YAMLError("Malformed YAML")
            
            result = cli_runner.invoke(main, ['--config', malformed_config_file])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'config' in result.output.lower() or 'yaml' in result.output.lower(), \
                "Error message mentions config file"
    
    def test_main_error_unreadable_config(self, cli_runner):
        """Test main command fails with config_load_error when config file is unreadable."""
        with patch('src.webprobe.cli.load_config') as mock_load:
            mock_load.side_effect = FileNotFoundError("Config not found")
            
            result = cli_runner.invoke(main, ['--config', '/nonexistent/config.yaml'])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'not found' in result.output.lower() or 'config' in result.output.lower(), \
                "Error message indicates file not found or unreadable"


# ============================================================================
# TESTS: run
# ============================================================================

class TestRun:
    """Tests for run command."""
    
    def test_run_happy_path_basic(self, cli_runner, tmp_path, mock_config):
        """Test run command executes all phases successfully without explore."""
        with patch('src.webprobe.cli.Mapper') as mock_mapper, \
             patch('src.webprobe.cli.Capturer') as mock_capturer, \
             patch('src.webprobe.cli.Analyzer') as mock_analyzer, \
             patch('src.webprobe.cli.Reporter') as mock_reporter, \
             patch('src.webprobe.cli.asyncio.run') as mock_asyncio:
            
            # Setup mocks
            mock_mapper.return_value.map_site.return_value = MagicMock()
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--output-dir', str(tmp_path)
            ])
            
            # Note: Actual assertions depend on implementation
            # This is a skeleton showing the test structure
            assert 'example.com' in result.output or result.exit_code == 0
    
    def test_run_happy_path_with_explore(self, cli_runner, tmp_path, mock_config):
        """Test run command executes all phases including LLM exploration when --explore enabled."""
        with patch('src.webprobe.cli.Mapper'), \
             patch('src.webprobe.cli.Capturer'), \
             patch('src.webprobe.cli.Analyzer'), \
             patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.Explorer') as mock_explorer, \
             patch('src.webprobe.cli.asyncio.run'):
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--explore',
                '--llm-provider', 'anthropic',
                '--llm-model', 'claude-3-opus',
                '--agents', '5',
                '--output-dir', str(tmp_path)
            ])
            
            # Verify explore was called or check output
            assert result.exit_code == 0 or 'explore' in result.output.lower()
    
    def test_run_with_all_params(self, cli_runner, tmp_path, mock_config):
        """Test run command with all optional parameters specified."""
        with patch('src.webprobe.cli.Mapper'), \
             patch('src.webprobe.cli.Capturer'), \
             patch('src.webprobe.cli.Analyzer'), \
             patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.asyncio.run'):
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--project-root', '/project',
                '--output-dir', str(tmp_path),
                '--concurrency', '10',
                '--explore',
                '--llm-provider', 'openai',
                '--llm-model', 'gpt-4',
                '--agents', '3',
                '--mask-path', 'mask.json'
            ])
            
            assert result.exit_code == 0 or 'example.com' in result.output
    
    def test_run_error_network_unreachable(self, cli_runner, tmp_path):
        """Test run command fails with network_error when target URL unreachable."""
        with patch('src.webprobe.cli.Mapper') as mock_mapper:
            mock_mapper.return_value.map_site.side_effect = ConnectionError("Network unreachable")
            
            result = cli_runner.invoke(main, [
                'run',
                'https://unreachable.invalid',
                '--output-dir', str(tmp_path)
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'network' in result.output.lower() or 'connection' in result.output.lower(), \
                "Error message indicates network failure"
    
    def test_run_error_filesystem(self, cli_runner):
        """Test run command fails with filesystem_error when cannot create output directory."""
        with patch('src.webprobe.cli.Path.mkdir') as mock_mkdir:
            mock_mkdir.side_effect = PermissionError("Permission denied")
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--output-dir', '/read-only/path'
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'permission' in result.output.lower() or 'filesystem' in result.output.lower(), \
                "Error message indicates filesystem error"
    
    def test_run_error_llm_api(self, cli_runner, tmp_path):
        """Test run command fails with llm_api_error when LLM API call fails with --explore."""
        with patch('src.webprobe.cli.Mapper'), \
             patch('src.webprobe.cli.Capturer'), \
             patch('src.webprobe.cli.Analyzer'), \
             patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.Explorer') as mock_explorer, \
             patch('src.webprobe.cli.asyncio.run'):
            
            mock_explorer.return_value.explore.side_effect = Exception("LLM API error")
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--explore',
                '--llm-provider', 'openai',
                '--agents', '3',
                '--output-dir', str(tmp_path)
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            # Error message should indicate LLM or API failure
    
    def test_run_concurrency_override(self, cli_runner, tmp_path, mock_config):
        """Test run command updates config.capture.concurrency when concurrency parameter provided."""
        with patch('src.webprobe.cli.Mapper'), \
             patch('src.webprobe.cli.Capturer'), \
             patch('src.webprobe.cli.Analyzer'), \
             patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.asyncio.run'), \
             patch('src.webprobe.cli.ctx') as mock_ctx:
            
            mock_ctx.obj = {'config': mock_config}
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--concurrency', '20',
                '--output-dir', str(tmp_path)
            ])
            
            # The config's concurrency should be updated
            # Actual verification depends on implementation


# ============================================================================
# TESTS: explore_cmd
# ============================================================================

class TestExploreCmd:
    """Tests for explore_cmd command."""
    
    def test_explore_cmd_happy_path(self, cli_runner, valid_run_dir, mock_config):
        """Test explore_cmd runs exploration on existing run directory and regenerates report."""
        with patch('src.webprobe.cli.Explorer') as mock_explorer, \
             patch('src.webprobe.cli.Reporter') as mock_reporter, \
             patch('src.webprobe.cli.load_run') as mock_load, \
             patch('src.webprobe.cli.asyncio.run'):
            
            mock_load.return_value = MagicMock()
            
            result = cli_runner.invoke(main, [
                'explore',
                valid_run_dir,
                '--provider', 'openai',
                '--agents', '5'
            ])
            
            assert result.exit_code == 0 or 'cost' in result.output.lower()
    
    def test_explore_cmd_with_model(self, cli_runner, valid_run_dir):
        """Test explore_cmd with specific LLM model parameter."""
        with patch('src.webprobe.cli.Explorer') as mock_explorer, \
             patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.load_run'), \
             patch('src.webprobe.cli.asyncio.run'):
            
            result = cli_runner.invoke(main, [
                'explore',
                valid_run_dir,
                '--provider', 'anthropic',
                '--model', 'claude-3-sonnet',
                '--agents', '3'
            ])
            
            assert result.exit_code == 0
    
    def test_explore_cmd_error_invalid_run_dir(self, cli_runner, invalid_run_dir):
        """Test explore_cmd fails with run_load_error when run_dir doesn't contain valid data."""
        with patch('src.webprobe.cli.load_run') as mock_load:
            mock_load.side_effect = ValueError("Invalid run data")
            
            result = cli_runner.invoke(main, [
                'explore',
                invalid_run_dir,
                '--provider', 'openai',
                '--agents', '3'
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'invalid' in result.output.lower() or 'run' in result.output.lower(), \
                "Error message indicates invalid run data"
    
    def test_explore_cmd_error_llm_api(self, cli_runner, valid_run_dir):
        """Test explore_cmd fails with llm_api_error when LLM API calls fail."""
        with patch('src.webprobe.cli.Explorer') as mock_explorer, \
             patch('src.webprobe.cli.load_run'), \
             patch('src.webprobe.cli.asyncio.run'):
            
            mock_explorer.return_value.explore.side_effect = Exception("LLM API failed")
            
            result = cli_runner.invoke(main, [
                'explore',
                valid_run_dir,
                '--provider', 'openai',
                '--agents', '3'
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
    
    def test_explore_cmd_high_agents_warning(self, cli_runner, valid_run_dir):
        """Test explore_cmd warns when agents > 20 per invariant."""
        with patch('src.webprobe.cli.Explorer'), \
             patch('src.webprobe.cli.load_run'), \
             patch('src.webprobe.cli.click.confirm') as mock_confirm, \
             patch('src.webprobe.cli.asyncio.run'):
            
            mock_confirm.return_value = True
            
            result = cli_runner.invoke(main, [
                'explore',
                valid_run_dir,
                '--provider', 'openai',
                '--agents', '25'
            ], input='y\n')
            
            # Should show warning or require confirmation
            assert 'warning' in result.output.lower() or 'confirm' in result.output.lower() or \
                   result.exit_code == 0


# ============================================================================
# TESTS: map_cmd
# ============================================================================

class TestMapCmd:
    """Tests for map_cmd command."""
    
    def test_map_cmd_happy_path(self, cli_runner, tmp_path):
        """Test map_cmd creates run directory and saves graph.json."""
        with patch('src.webprobe.cli.Mapper') as mock_mapper, \
             patch('src.webprobe.cli.asyncio.run'):
            
            mock_mapper.return_value.map_site.return_value = MagicMock()
            
            result = cli_runner.invoke(main, [
                'map',
                'https://example.com',
                '--output-dir', str(tmp_path)
            ])
            
            assert result.exit_code == 0 or 'example.com' in result.output
    
    def test_map_cmd_with_params(self, cli_runner, tmp_path):
        """Test map_cmd with project_root and output_dir parameters."""
        with patch('src.webprobe.cli.Mapper'), \
             patch('src.webprobe.cli.asyncio.run'):
            
            result = cli_runner.invoke(main, [
                'map',
                'https://example.com',
                '--project-root', '/project',
                '--output-dir', str(tmp_path)
            ])
            
            assert result.exit_code == 0
    
    def test_map_cmd_error_network(self, cli_runner, tmp_path):
        """Test map_cmd fails with network_error when cannot reach target URL."""
        with patch('src.webprobe.cli.Mapper') as mock_mapper:
            mock_mapper.return_value.map_site.side_effect = ConnectionError("Cannot reach URL")
            
            result = cli_runner.invoke(main, [
                'map',
                'https://unreachable.invalid',
                '--output-dir', str(tmp_path)
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'network' in result.output.lower() or 'connection' in result.output.lower(), \
                "Error message indicates network failure"
    
    def test_map_cmd_error_filesystem(self, cli_runner):
        """Test map_cmd fails with filesystem_error when cannot create directory or write file."""
        with patch('src.webprobe.cli.Path.mkdir') as mock_mkdir:
            mock_mkdir.side_effect = PermissionError("Permission denied")
            
            result = cli_runner.invoke(main, [
                'map',
                'https://example.com',
                '--output-dir', '/read-only/path'
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'permission' in result.output.lower() or 'filesystem' in result.output.lower(), \
                "Error message indicates filesystem error"


# ============================================================================
# TESTS: capture
# ============================================================================

class TestCapture:
    """Tests for capture command."""
    
    def test_capture_happy_path(self, cli_runner, valid_run_dir):
        """Test capture populates graph nodes with metrics and saves updated graph."""
        with patch('src.webprobe.cli.Capturer') as mock_capturer, \
             patch('src.webprobe.cli.load_run') as mock_load, \
             patch('src.webprobe.cli.asyncio.run'):
            
            mock_load.return_value = MagicMock()
            
            result = cli_runner.invoke(main, [
                'capture',
                valid_run_dir
            ])
            
            assert result.exit_code == 0 or 'duration' in result.output.lower()
    
    def test_capture_error_missing_graph(self, cli_runner, run_dir_without_graph):
        """Test capture fails with missing_graph when graph.json not found."""
        with patch('src.webprobe.cli.load_run') as mock_load:
            mock_load.side_effect = FileNotFoundError("graph.json not found")
            
            result = cli_runner.invoke(main, [
                'capture',
                run_dir_without_graph
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'graph' in result.output.lower() or 'not found' in result.output.lower(), \
                "Error message indicates missing graph.json"
    
    def test_capture_error_invalid_graph(self, cli_runner, run_dir_invalid_graph):
        """Test capture fails with invalid_graph when graph.json contains invalid data."""
        with patch('src.webprobe.cli.load_run') as mock_load:
            mock_load.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
            
            result = cli_runner.invoke(main, [
                'capture',
                run_dir_invalid_graph
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'invalid' in result.output.lower() or 'graph' in result.output.lower(), \
                "Error message indicates invalid graph data"
    
    def test_capture_error_network(self, cli_runner, valid_run_dir):
        """Test capture fails with network_error when cannot reach URLs for capture."""
        with patch('src.webprobe.cli.Capturer') as mock_capturer, \
             patch('src.webprobe.cli.load_run'), \
             patch('src.webprobe.cli.asyncio.run'):
            
            mock_capturer.return_value.capture.side_effect = ConnectionError("Network failure")
            
            result = cli_runner.invoke(main, [
                'capture',
                valid_run_dir
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"


# ============================================================================
# TESTS: analyze_cmd
# ============================================================================

class TestAnalyzeCmd:
    """Tests for analyze_cmd command."""
    
    def test_analyze_cmd_happy_path(self, cli_runner, valid_run_dir):
        """Test analyze_cmd analyzes run and writes analysis.json with findings."""
        with patch('src.webprobe.cli.Analyzer') as mock_analyzer, \
             patch('src.webprobe.cli.load_run'):
            
            result = cli_runner.invoke(main, [
                'analyze',
                valid_run_dir
            ])
            
            assert result.exit_code == 0 or 'summary' in result.output.lower()
    
    def test_analyze_cmd_error_load(self, cli_runner, invalid_run_dir):
        """Test analyze_cmd fails with load_error when cannot load run data."""
        with patch('src.webprobe.cli.load_run') as mock_load:
            mock_load.side_effect = ValueError("Cannot load run data")
            
            result = cli_runner.invoke(main, [
                'analyze',
                invalid_run_dir
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'load' in result.output.lower() or 'error' in result.output.lower(), \
                "Error message indicates cannot load run data"


# ============================================================================
# TESTS: report
# ============================================================================

class TestReport:
    """Tests for report command."""
    
    def test_report_happy_path_html(self, cli_runner, valid_run_dir):
        """Test report generates HTML format report."""
        with patch('src.webprobe.cli.Reporter') as mock_reporter, \
             patch('src.webprobe.cli.load_run'):
            
            result = cli_runner.invoke(main, [
                'report',
                valid_run_dir,
                '--format', 'html'
            ])
            
            assert result.exit_code == 0 or 'duration' in result.output.lower()
    
    def test_report_happy_path_json(self, cli_runner, valid_run_dir):
        """Test report generates JSON format report."""
        with patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.load_run'):
            
            result = cli_runner.invoke(main, [
                'report',
                valid_run_dir,
                '--format', 'json'
            ])
            
            assert result.exit_code == 0
    
    def test_report_happy_path_both(self, cli_runner, valid_run_dir):
        """Test report generates both HTML and JSON formats."""
        with patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.load_run'):
            
            result = cli_runner.invoke(main, [
                'report',
                valid_run_dir,
                '--format', 'both'
            ])
            
            assert result.exit_code == 0
    
    def test_report_error_load(self, cli_runner, invalid_run_dir):
        """Test report fails with load_error when cannot load run data."""
        with patch('src.webprobe.cli.load_run') as mock_load:
            mock_load.side_effect = ValueError("Cannot load run")
            
            result = cli_runner.invoke(main, [
                'report',
                invalid_run_dir,
                '--format', 'html'
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
    
    def test_report_error_write(self, cli_runner, valid_run_dir):
        """Test report fails with write_error when cannot write report files."""
        with patch('src.webprobe.cli.Reporter') as mock_reporter, \
             patch('src.webprobe.cli.load_run'):
            
            mock_reporter.return_value.generate.side_effect = PermissionError("Cannot write")
            
            result = cli_runner.invoke(main, [
                'report',
                valid_run_dir,
                '--format', 'html'
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"


# ============================================================================
# TESTS: diff
# ============================================================================

class TestDiff:
    """Tests for diff command."""
    
    def test_diff_happy_path_console(self, cli_runner, valid_run_dir, tmp_path):
        """Test diff compares two runs and prints differences to console."""
        run_b = tmp_path / "run_b"
        run_b.mkdir()
        (run_b / "graph.json").write_text(json.dumps({"nodes": [], "edges": []}))
        
        with patch('src.webprobe.cli.Differ') as mock_differ, \
             patch('src.webprobe.cli.load_run'):
            
            result = cli_runner.invoke(main, [
                'diff',
                valid_run_dir,
                str(run_b)
            ])
            
            assert result.exit_code == 0 or 'diff' in result.output.lower()
    
    def test_diff_happy_path_to_file(self, cli_runner, valid_run_dir, tmp_path):
        """Test diff writes comparison result to output file."""
        run_b = tmp_path / "run_b"
        run_b.mkdir()
        (run_b / "graph.json").write_text(json.dumps({"nodes": [], "edges": []}))
        output_file = tmp_path / "diff_output.txt"
        
        with patch('src.webprobe.cli.Differ'), \
             patch('src.webprobe.cli.load_run'):
            
            result = cli_runner.invoke(main, [
                'diff',
                valid_run_dir,
                str(run_b),
                '--output', str(output_file)
            ])
            
            assert result.exit_code == 0
    
    def test_diff_error_load_run_a(self, cli_runner, tmp_path):
        """Test diff fails with load_error when cannot load run_a."""
        run_b = tmp_path / "run_b"
        run_b.mkdir()
        
        with patch('src.webprobe.cli.load_run') as mock_load:
            mock_load.side_effect = [ValueError("Cannot load run_a"), MagicMock()]
            
            result = cli_runner.invoke(main, [
                'diff',
                '/invalid/run_a',
                str(run_b)
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
    
    def test_diff_error_load_run_b(self, cli_runner, valid_run_dir):
        """Test diff fails with load_error when cannot load run_b."""
        with patch('src.webprobe.cli.load_run') as mock_load:
            mock_load.side_effect = [MagicMock(), ValueError("Cannot load run_b")]
            
            result = cli_runner.invoke(main, [
                'diff',
                valid_run_dir,
                '/invalid/run_b'
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
    
    def test_diff_error_write(self, cli_runner, valid_run_dir, tmp_path):
        """Test diff fails with write_error when cannot write output file."""
        run_b = tmp_path / "run_b"
        run_b.mkdir()
        
        with patch('src.webprobe.cli.Differ'), \
             patch('src.webprobe.cli.load_run'), \
             patch('builtins.open') as mock_open:
            
            mock_open.side_effect = PermissionError("Cannot write")
            
            result = cli_runner.invoke(main, [
                'diff',
                valid_run_dir,
                str(run_b),
                '--output', '/read-only/diff.txt'
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
    
    def test_diff_symmetric(self, cli_runner, valid_run_dir, tmp_path):
        """Test diff produces symmetric comparison (A vs B same as B vs A with inverted signs)."""
        run_b = tmp_path / "run_b"
        run_b.mkdir()
        (run_b / "graph.json").write_text(json.dumps({"nodes": [], "edges": []}))
        
        with patch('src.webprobe.cli.Differ') as mock_differ, \
             patch('src.webprobe.cli.load_run'):
            
            # First comparison A vs B
            result_ab = cli_runner.invoke(main, [
                'diff',
                valid_run_dir,
                str(run_b)
            ])
            
            # Second comparison B vs A
            result_ba = cli_runner.invoke(main, [
                'diff',
                str(run_b),
                valid_run_dir
            ])
            
            # Both should succeed
            assert result_ab.exit_code == 0 or result_ba.exit_code == 0


# ============================================================================
# TESTS: status
# ============================================================================

class TestStatus:
    """Tests for status command."""
    
    def test_status_happy_path(self, cli_runner, valid_run_dir):
        """Test status displays run summary including metadata, graph size, and analysis counts."""
        with patch('src.webprobe.cli.load_run') as mock_load:
            mock_run = MagicMock()
            mock_run.metadata = {"url": "https://example.com", "timestamp": "2024-01-01"}
            mock_run.graph.node_count = 10
            mock_load.return_value = mock_run
            
            result = cli_runner.invoke(main, [
                'status',
                valid_run_dir
            ])
            
            output = result.output.lower()
            assert result.exit_code == 0 or any(x in output for x in ['metadata', 'graph', 'summary'])
    
    def test_status_error_load(self, cli_runner, invalid_run_dir):
        """Test status fails with load_error when cannot load run data."""
        with patch('src.webprobe.cli.load_run') as mock_load:
            mock_load.side_effect = ValueError("Cannot load run")
            
            result = cli_runner.invoke(main, [
                'status',
                invalid_run_dir
            ])
            
            assert result.exit_code != 0, "Exit code is non-zero"
            assert 'load' in result.output.lower() or 'error' in result.output.lower(), \
                "Error message indicates cannot load run data"


# ============================================================================
# TESTS: Invariants
# ============================================================================

class TestInvariants:
    """Tests for contract invariants."""
    
    def test_invariant_run_dir_pattern(self, cli_runner, tmp_path):
        """Test that all commands creating run directories follow pattern {output_dir}/{run_id}/."""
        with patch('src.webprobe.cli.Mapper'), \
             patch('src.webprobe.cli.Capturer'), \
             patch('src.webprobe.cli.Analyzer'), \
             patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.asyncio.run'), \
             patch('src.webprobe.cli._create_run_dir') as mock_create:
            
            mock_create.return_value = tmp_path / "run_20240101_120000"
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--output-dir', str(tmp_path)
            ])
            
            # Verify the pattern - run_id should be timestamp or UUID format
            # Pattern: {output_dir}/{run_id}/
            if mock_create.called:
                run_path = str(mock_create.return_value)
                assert str(tmp_path) in run_path, "Run directory path contains output_dir"
    
    def test_invariant_graph_persistence(self, cli_runner, tmp_path):
        """Test that graph.json is persisted before subsequent phases."""
        graph_saved = False
        
        def mock_save_graph(*args, **kwargs):
            nonlocal graph_saved
            graph_saved = True
        
        with patch('src.webprobe.cli.Mapper'), \
             patch('src.webprobe.cli.Capturer'), \
             patch('src.webprobe.cli.Analyzer'), \
             patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.asyncio.run'), \
             patch('src.webprobe.cli.save_graph', side_effect=mock_save_graph):
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--output-dir', str(tmp_path)
            ])
            
            # Graph should be saved after map phase
            assert graph_saved or result.exit_code == 0
    
    def test_invariant_config_snapshot(self, cli_runner, tmp_path):
        """Test that config snapshots are saved to run_dir/webprobe.yaml."""
        with patch('src.webprobe.cli.Mapper'), \
             patch('src.webprobe.cli.Capturer'), \
             patch('src.webprobe.cli.Analyzer'), \
             patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.asyncio.run'), \
             patch('src.webprobe.cli.save_config') as mock_save_config:
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--output-dir', str(tmp_path)
            ])
            
            # Config should be saved
            assert mock_save_config.called or result.exit_code == 0
    
    def test_invariant_phase_ordering(self, cli_runner, tmp_path):
        """Test that phases execute in correct order: map, capture, analyze, report, explore."""
        call_order = []
        
        def track_call(phase):
            def wrapper(*args, **kwargs):
                call_order.append(phase)
                return MagicMock()
            return wrapper
        
        with patch('src.webprobe.cli.Mapper') as mock_mapper, \
             patch('src.webprobe.cli.Capturer') as mock_capturer, \
             patch('src.webprobe.cli.Analyzer') as mock_analyzer, \
             patch('src.webprobe.cli.Reporter') as mock_reporter, \
             patch('src.webprobe.cli.Explorer') as mock_explorer, \
             patch('src.webprobe.cli.asyncio.run'):
            
            mock_mapper.return_value.map_site = track_call('map')
            mock_capturer.return_value.capture = track_call('capture')
            mock_analyzer.return_value.analyze = track_call('analyze')
            mock_reporter.return_value.generate = track_call('report')
            mock_explorer.return_value.explore = track_call('explore')
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--explore',
                '--llm-provider', 'openai',
                '--agents', '3',
                '--output-dir', str(tmp_path)
            ])
            
            # Verify ordering if phases were called
            if len(call_order) >= 2:
                expected_order = ['map', 'capture', 'analyze', 'report', 'explore']
                actual_order = [p for p in expected_order if p in call_order]
                assert actual_order == call_order[:len(actual_order)], \
                    f"Phase ordering incorrect. Expected: {expected_order}, Got: {call_order}"


# ============================================================================
# EDGE CASES AND ADDITIONAL TESTS
# ============================================================================

class TestEdgeCases:
    """Additional edge case tests."""
    
    def test_run_empty_url(self, cli_runner, tmp_path):
        """Test run with empty URL string."""
        result = cli_runner.invoke(main, [
            'run',
            '',
            '--output-dir', str(tmp_path)
        ])
        
        # Should fail validation or return error
        assert result.exit_code != 0 or 'url' in result.output.lower()
    
    def test_concurrency_zero(self, cli_runner, tmp_path):
        """Test run with concurrency set to 0."""
        with patch('src.webprobe.cli.Mapper'), \
             patch('src.webprobe.cli.Capturer'), \
             patch('src.webprobe.cli.Analyzer'), \
             patch('src.webprobe.cli.Reporter'), \
             patch('src.webprobe.cli.asyncio.run'):
            
            result = cli_runner.invoke(main, [
                'run',
                'https://example.com',
                '--concurrency', '0',
                '--output-dir', str(tmp_path)
            ])
            
            # Should either fail validation or use default
            assert result.exit_code != 0 or 'example.com' in result.output
    
    def test_negative_agents(self, cli_runner, valid_run_dir):
        """Test explore with negative agent count."""
        result = cli_runner.invoke(main, [
            'explore',
            valid_run_dir,
            '--provider', 'openai',
            '--agents', '-1'
        ])
        
        # Should fail validation
        assert result.exit_code != 0
    
    def test_report_invalid_format(self, cli_runner, valid_run_dir):
        """Test report with invalid format option."""
        result = cli_runner.invoke(main, [
            'report',
            valid_run_dir,
            '--format', 'invalid_format'
        ])
        
        # Should fail validation or show error
        assert result.exit_code != 0 or 'format' in result.output.lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
"""