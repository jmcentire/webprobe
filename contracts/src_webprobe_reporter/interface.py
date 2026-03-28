# === Webprobe Reporter (src_webprobe_reporter) v1 ===
#  Dependencies: json, time, datetime, pathlib, jinja2, webprobe.models
# Phase 4 report generation module that produces JSON and HTML output files from webprobe Run data. Generates comprehensive HTML reports with embedded CSS styling using Jinja2 templates, displaying site graph metrics, page details, security findings, broken links, auth violations, timing outliers, and exploration costs. Also exports raw JSON reports of the complete run data.

# Module invariants:
#   - HTML_TEMPLATE is a module-level constant Template instance initialized once
#   - Default formats are ['json', 'html'] when formats parameter is None
#   - PhaseStatus.phase is always set to 'report'
#   - PhaseStatus.status transitions from 'running' to 'completed' on success
#   - Time measurements use time.monotonic() for duration and datetime.now(timezone.utc) for timestamps
#   - HTML template expects specific Run model structure with graph.nodes, analysis, phases, and explore_cost attributes
#   - Nodes in HTML are sorted by node.id for consistent output ordering

HTML_TEMPLATE = primitive  # Jinja2 Template instance containing the full HTML report structure with embedded CSS. Uses GitHub dark theme styling and renders run metadata, analysis metrics, phase timing, page details, security findings, broken links, auth violations, and timing outliers.

def generate_report(
    run: Run,
    run_dir: Path,
    formats: list[str] | None = None,
) -> PhaseStatus:
    """
    Phase 4: Generate JSON and/or HTML reports from a webprobe Run. Writes report.json (full run data dump) and/or report.html (styled visual report) to the specified run directory. Returns a PhaseStatus tracking execution timing and completion status.

    Preconditions:
      - run_dir must be a valid Path object
      - run must be a valid Run instance with populated graph
      - formats if provided must contain only 'json' and/or 'html' strings

    Postconditions:
      - Returns PhaseStatus with phase='report', status='completed', and duration_ms populated
      - If 'json' in formats: report.json file written to run_dir containing run.model_dump_json(indent=2)
      - If 'html' in formats: report.html file written to run_dir with rendered HTML template
      - PhaseStatus.started_at and completed_at are set to ISO format UTC timestamps
      - PhaseStatus.duration_ms contains elapsed time in milliseconds

    Errors:
      - FileWriteError (OSError | PermissionError): run_dir does not exist or is not writable
      - SerializationError (TypeError | ValueError): run.model_dump_json() fails due to non-serializable data
      - TemplateRenderError (jinja2.TemplateError): HTML_TEMPLATE.render() fails due to missing attributes in run object or template syntax issues
      - ImportError (ImportError): webprobe.__version__ cannot be imported when generating HTML

    Side effects: Writes report.json to filesystem if 'json' in formats, Writes report.html to filesystem if 'html' in formats, Imports webprobe.__version__ dynamically when HTML format is requested
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['generate_report', 'OSError | PermissionError', 'TypeError | ValueError', 'ImportError']
