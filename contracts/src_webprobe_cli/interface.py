# === Webprobe CLI Entry Point (src_webprobe_cli) v1 ===
#  Dependencies: asyncio, json, sys, datetime, pathlib, click, yaml, webprobe.config, webprobe.models, webprobe.mapper, webprobe.capturer, webprobe.analyzer, webprobe.reporter, webprobe.frameworks, webprobe.explorer, webprobe.differ
# CLI interface for webprobe, a generic site state-graph auditor. Provides commands for running security audits on websites through multiple phases: mapping site structure, capturing metrics, analyzing for vulnerabilities, and generating reports. Supports optional LLM-driven exploration for intelligent security testing. Built with Click for command-line interface and asyncio for concurrent operations.

# Module invariants:
#   - All CLI commands operate on immutable run directories identified by run_id
#   - Output directories follow pattern: {output_dir}/{run_id}/
#   - Graph is persisted as graph.json before subsequent phases
#   - Config snapshots are saved to run_dir/webprobe.yaml
#   - Async operations use asyncio.run() for execution
#   - LLM exploration warns if agents > 20 and requires confirmation
#   - Phase ordering: 1=map, 2=capture, 3=analyze, 4=report, 5=explore (optional)

def _now_iso() -> str:
    """
    Returns current UTC timestamp in ISO 8601 format

    Postconditions:
      - Returns ISO 8601 formatted string with timezone UTC

    Side effects: reads_file
    Idempotent: no
    """
    ...

def main(
    ctx: click.Context,
    config_path: str | None = None,
) -> None:
    """
    Click group entry point for webprobe CLI. Loads config and initializes context.

    Postconditions:
      - ctx.obj['config'] is populated with WebprobeConfig instance

    Errors:
      - config_load_error (yaml.YAMLError | FileNotFoundError | IOError): Config file is malformed or unreadable

    Side effects: Loads config from file if config_path provided, Mutates ctx.obj dictionary
    Idempotent: no
    """
    ...

def run(
    ctx: click.Context,
    url: str,
    project_root: str | None = None,
    output_dir: str | None = None,
    concurrency: int | None = None,
    explore: bool,
    llm_provider: str,
    llm_model: str | None = None,
    agents: int,
    mask_path: str | None = None,
) -> None:
    """
    Runs all webprobe phases: map site structure, capture metrics, analyze for issues, generate report. Optionally runs LLM-driven exploration with --explore flag.

    Preconditions:
      - ctx.obj['config'] must be populated by main()

    Postconditions:
      - Run directory created with graph.json, analysis.json, report.html, report.json
      - All phases completed and logged to console
      - Config snapshot saved to run_dir/webprobe.yaml

    Errors:
      - network_error (aiohttp.ClientError | playwright errors): Target URL unreachable or network failure
      - filesystem_error (OSError | PermissionError): Cannot create output directory or write files
      - llm_api_error (API-specific exceptions): LLM API call fails when --explore enabled

    Side effects: Creates run directory structure, Writes graph.json, analysis.json, report files, Makes HTTP/HTTPS requests to target URL, Prints status to console via click.echo, May make LLM API calls if --explore enabled, May prompt user for confirmation if agents > 20
    Idempotent: no
    """
    ...

def explore_cmd(
    ctx: click.Context,
    run_dir: str,
    provider: str,
    model: str | None = None,
    agents: int,
    mask_path: str | None = None,
) -> None:
    """
    Phase 5 only: Runs LLM-driven exploration on an existing run directory, adds findings to analysis, and regenerates report.

    Preconditions:
      - run_dir must exist and contain valid run data
      - ctx.obj['config'] populated

    Postconditions:
      - Exploration findings added to run analysis
      - Report regenerated with new findings
      - Cost summary logged to console

    Errors:
      - run_load_error (FileNotFoundError | json.JSONDecodeError | ValidationError): run_dir doesn't contain valid run data
      - llm_api_error (API-specific exceptions): LLM API calls fail

    Side effects: Makes LLM API calls, Writes updated report files, Prompts user for confirmation if agents > 20, Prints status to console
    Idempotent: no
    """
    ...

def map_cmd(
    ctx: click.Context,
    url: str,
    project_root: str | None = None,
    output_dir: str | None = None,
) -> None:
    """
    Phase 1 only: Maps site structure and builds graph, saves to graph.json.

    Preconditions:
      - ctx.obj['config'] populated

    Postconditions:
      - Run directory created
      - graph.json written with site structure
      - Summary printed to console

    Errors:
      - network_error (aiohttp.ClientError): Cannot reach target URL
      - filesystem_error (OSError | PermissionError): Cannot create directory or write file

    Side effects: Creates run directory, Makes HTTP requests to crawl site, Writes graph.json, Prints to console
    Idempotent: no
    """
    ...

def capture(
    ctx: click.Context,
    run_dir: str,
) -> None:
    """
    Phase 2 only: Captures metrics for an existing graph in run directory.

    Preconditions:
      - run_dir exists and contains graph.json
      - ctx.obj['config'] populated

    Postconditions:
      - Graph nodes populated with captured metrics
      - Updated graph saved
      - Duration logged to console

    Errors:
      - missing_graph (FileNotFoundError): graph.json not found in run_dir
          exit_code: 1
      - invalid_graph (json.JSONDecodeError | ValidationError): graph.json contains invalid data
      - network_error (playwright errors): Cannot reach URLs for capture

    Side effects: Reads graph.json, Makes network requests with Playwright, Writes updated graph, Prints to console, Exits with code 1 if graph.json missing
    Idempotent: no
    """
    ...

def analyze_cmd(
    run_dir: str,
) -> None:
    """
    Phase 3 only: Analyzes existing run for security issues, broken links, auth violations, timing outliers.

    Preconditions:
      - run_dir exists with valid run data

    Postconditions:
      - analysis.json written with findings
      - Summary printed to console

    Errors:
      - load_error (FileNotFoundError | json.JSONDecodeError | ValidationError): Cannot load run data from directory

    Side effects: Reads run data from run_dir, Writes analysis.json, Prints to console
    Idempotent: no
    """
    ...

def report(
    run_dir: str,
    fmt: str,
) -> None:
    """
    Phase 4 only: Generates report (HTML, JSON, or both) from existing run.

    Preconditions:
      - run_dir exists with valid run data

    Postconditions:
      - Report files generated in specified format(s)
      - Duration logged to console

    Errors:
      - load_error (FileNotFoundError | json.JSONDecodeError | ValidationError): Cannot load run data
      - write_error (OSError | PermissionError): Cannot write report files

    Side effects: Reads run data, Writes report.html and/or report.json, Prints to console
    Idempotent: no
    """
    ...

def diff(
    run_a: str,
    run_b: str,
    output: str | None = None,
) -> None:
    """
    Compares two runs and outputs differences, optionally writing to file.

    Preconditions:
      - Both run_a and run_b exist with valid run data

    Postconditions:
      - Diff result printed to console or written to file
      - If output specified, file written and path confirmed

    Errors:
      - load_error (FileNotFoundError | json.JSONDecodeError | ValidationError): Cannot load one or both runs
      - write_error (OSError | PermissionError): Cannot write output file

    Side effects: Reads both run directories, Optionally writes diff JSON, Prints to console
    Idempotent: no
    """
    ...

def status(
    run_dir: str,
) -> None:
    """
    Shows summary of a run including metadata, graph size, phase status, and analysis counts.

    Preconditions:
      - run_dir exists with valid run data

    Postconditions:
      - Summary printed to console

    Errors:
      - load_error (FileNotFoundError | json.JSONDecodeError | ValidationError): Cannot load run data

    Side effects: Reads run data, Prints to console
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['_now_iso', 'main', 'run', 'OSError | PermissionError', 'API-specific exceptions', 'explore_cmd', 'map_cmd', 'capture', 'playwright errors', 'analyze_cmd', 'report', 'diff', 'status']
