# === WebProbe Differ (src_webprobe_differ) v1 ===
#  Dependencies: json, pathlib, webprobe.models
# Cross-run diffing and trending module for webprobe. Compares two Run snapshots to detect changes in site structure (nodes/edges), HTTP status codes, response timings, broken links, and authentication boundary violations.

# Module invariants:
#   - Timing change threshold is fixed at 20% (0.20)
#   - Edge identity is determined by (source, target) tuple
#   - BrokenLink identity is determined by (source, target) tuple
#   - AuthBoundaryViolation identity is determined by url field
#   - All diff lists are sorted for deterministic output
#   - Status comparison uses first capture (index 0) when available
#   - Delta percentage for timing is rounded to 1 decimal place

def load_run(
    run_dir: Path,
) -> Run:
    """
    Load a Run object from a run directory by reading and parsing report.json

    Preconditions:
      - run_dir must be a valid Path object

    Postconditions:
      - Returns a validated Run object parsed from report.json
      - Run object passes model_validate validation

    Errors:
      - missing_report_file (FileNotFoundError): report.json does not exist in run_dir
          message: No report.json in {run_dir}
      - invalid_json (json.JSONDecodeError): report.json contains invalid JSON
      - validation_error (ValidationError): JSON does not match Run model schema

    Side effects: Reads file from filesystem
    Idempotent: no
    """
    ...

def diff_runs(
    run_a: Run,
    run_b: Run,
) -> RunDiff:
    """
    Compare two Run objects and produce a comprehensive RunDiff showing all structural and content changes including nodes, edges, HTTP status changes, timing changes (>20% threshold), broken link changes, and auth violation changes

    Preconditions:
      - run_a.schema_version == run_b.schema_version
      - Both runs must have valid graph objects with nodes and edges
      - run_a and run_b must be valid Run objects

    Postconditions:
      - Returns RunDiff with all detected changes
      - nodes_added contains sorted list of new node IDs in run_b
      - nodes_removed contains sorted list of node IDs removed from run_a
      - edges_added/edges_removed are sorted by (source, target) tuple
      - status_changes only includes nodes present in both runs with different HTTP status codes
      - timing_changes only includes nodes with >20% duration_ms delta where t_a.duration_ms > 0
      - new_broken_links/resolved_broken_links are sorted by (source, target) tuple
      - new_auth_violations/resolved_auth_violations are sorted by URL

    Errors:
      - schema_version_mismatch (ValueError): run_a.schema_version != run_b.schema_version
          message: Schema version mismatch: {run_a.schema_version} vs {run_b.schema_version}
      - missing_graph_attribute (AttributeError): Either run lacks graph attribute
      - index_error (IndexError): Node has empty captures list when accessing captures[0]
      - zero_division (ZeroDivisionError): t_a.duration_ms is exactly 0 (should not occur due to guard, but possible in edge case)

    Side effects: None - pure computation
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['load_run', 'ValidationError', 'diff_runs', 'ZeroDivisionError']
