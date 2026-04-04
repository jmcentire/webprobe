"""CLI entry point for webprobe."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import click
import yaml

from webprobe.config import load_config, WebprobeConfig


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@click.group()
@click.option("--config", "config_path", type=click.Path(exists=False), default=None,
              help="Path to webprobe.yaml config file.")
@click.pass_context
def main(ctx: click.Context, config_path: str | None) -> None:
    """webprobe -- Generic site state-graph auditor."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config_path)


@main.command()
@click.argument("url")
@click.option("--project-root", type=click.Path(exists=True), default=None,
              help="Project root for framework route detection.")
@click.option("--output-dir", type=click.Path(), default=None,
              help="Output directory for runs.")
@click.option("--concurrency", type=int, default=None,
              help="Override capture concurrency.")
@click.option("--explore", is_flag=True, default=False,
              help="Run Phase 5: LLM-driven exploration after mechanical phases.")
@click.option("--llm-provider", type=click.Choice(["anthropic", "openai", "gemini", "apprentice"]),
              default="anthropic", help="LLM provider for exploration.")
@click.option("--llm-model", default=None, help="Override LLM model name.")
@click.option("--agents", type=int, default=5, help="Number of concurrent exploration agents.")
@click.option("--mask", "mask_path", type=click.Path(exists=True), default=None,
              help="Path to mask YAML for suppressing known findings.")
@click.option("--js", "render_js", is_flag=True, default=False,
              help="Use Playwright for JS rendering during site mapping.")
@click.option("--advocate", is_flag=True, default=False,
              help="Run Phase 6: LLM advocate review after analysis.")
@click.option("--advocate-roles", default=None,
              help="Comma-separated advocate roles (pentester,security_engineer,privacy_expert,compliance_officer).")
@click.option("--advocate-model", default=None,
              help="Override LLM model for advocates.")
@click.option("--advocate-cost-limit", type=float, default=5.0,
              help="Cost limit in USD for advocate phase.")
@click.pass_context
def run(ctx: click.Context, url: str, project_root: str | None, output_dir: str | None,
        concurrency: int | None, explore: bool, llm_provider: str, llm_model: str | None,
        agents: int, mask_path: str | None, render_js: bool, advocate: bool,
        advocate_roles: str | None, advocate_model: str | None,
        advocate_cost_limit: float) -> None:
    """Run all phases: map, capture, analyze, report (+ explore with --explore, + advocate with --advocate)."""
    config: WebprobeConfig = ctx.obj["config"]
    if concurrency is not None:
        config.capture.concurrency = concurrency
    if render_js:
        config.crawl.render_js = True

    async def _run() -> None:
        from webprobe.models import Run
        from webprobe.mapper import map_site
        from webprobe.capturer import capture_site
        from webprobe.analyzer import analyze
        from webprobe.reporter import generate_report
        from webprobe.frameworks import detect_framework

        run_obj = Run(url=url, started_at=_now_iso(), config_snapshot=config.model_dump())
        run_dir = Path(output_dir or config.output_dir) / run_obj.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        # Save config snapshot
        (run_dir / "webprobe.yaml").write_text(yaml.dump(config.model_dump(), default_flow_style=False))

        # Framework detection
        framework_routes: list[str] | None = None
        if project_root:
            fw_name, routes = detect_framework(Path(project_root))
            if fw_name:
                click.echo(f"Detected framework: {fw_name} ({len(routes)} routes)")
                framework_routes = routes

        # Phase 1: Map
        click.echo(f"Phase 1: Mapping {url}...")
        graph, map_phase = await map_site(config, url, framework_routes)
        run_obj.phases.append(map_phase)
        run_obj.graph = graph
        (run_dir / "graph.json").write_text(graph.model_dump_json(indent=2))
        click.echo(f"  {len(graph.nodes)} nodes, {len(graph.edges)} edges ({map_phase.duration_ms:.0f} ms)")

        # Phase 2: Capture
        click.echo("Phase 2: Capturing...")
        graph, capture_phase = await capture_site(config, graph, run_dir)
        run_obj.phases.append(capture_phase)
        run_obj.graph = graph
        click.echo(f"  Done ({capture_phase.duration_ms:.0f} ms)")

        # Phase 3: Analyze
        click.echo("Phase 3: Analyzing...")
        analysis_result, analyze_phase = analyze(graph, config)
        run_obj.phases.append(analyze_phase)
        run_obj.analysis = analysis_result
        (run_dir / "analysis.json").write_text(analysis_result.model_dump_json(indent=2))
        m = analysis_result.graph_metrics
        click.echo(f"  Cyclomatic complexity: {m.cyclomatic_complexity}")
        click.echo(f"  Broken links: {len(analysis_result.broken_links)}")
        click.echo(f"  Auth violations: {len(analysis_result.auth_violations)}")
        click.echo(f"  Timing outliers: {len(analysis_result.timing_outliers)}")
        if analysis_result.security_findings:
            by_sev: dict[str, int] = {}
            for sf in analysis_result.security_findings:
                by_sev[sf.severity.value] = by_sev.get(sf.severity.value, 0) + 1
            parts = [f"{v} {k}" for k, v in sorted(by_sev.items())]
            click.echo(f"  Security findings: {len(analysis_result.security_findings)} ({', '.join(parts)})")

        # Phase 5: Explore (optional)
        do_explore = explore
        if do_explore:
            from webprobe.explorer import ExploreConfig, explore_site
            from webprobe.models import CostSummary

            if agents > 20:
                click.echo(f"\n  WARNING: {agents} concurrent agents will make many LLM API calls.")
                click.echo(f"  Estimated cost depends on pages and actions per agent.")
                if not click.confirm("  Continue?"):
                    click.echo("  Skipping exploration.")
                    do_explore = False

            if do_explore:
                from webprobe.explorer import ScanMode
                explore_cfg = ExploreConfig(
                    provider=llm_provider,
                    model=llm_model,
                    concurrency=agents,
                    mask_path=mask_path,
                    scan_mode=ScanMode.full,
                )
                click.echo(f"Phase 5: Exploring with {agents} {llm_provider} agents...")
                explore_findings, explore_phase, cost_tracker = await explore_site(
                    config, explore_cfg, graph, run_dir
                )
                run_obj.phases.append(explore_phase)

                # Merge explore findings into analysis
                if run_obj.analysis:
                    run_obj.analysis.security_findings.extend(explore_findings)
                click.echo(f"  {len(explore_findings)} findings ({explore_phase.duration_ms:.0f} ms)")

                # Cost summary
                cost_summary = cost_tracker.summary()
                run_obj.explore_cost = CostSummary(**cost_summary)
                click.echo(f"  LLM cost: ${cost_summary['total_cost_usd']:.4f} "
                           f"({cost_summary['total_calls']} calls, "
                           f"{cost_summary['total_input_tokens'] + cost_summary['total_output_tokens']} tokens)")

        # Phase 6: Advocate (optional)
        do_advocate = advocate
        if do_advocate:
            from webprobe.advocate import AdvocateConfig, AdvocateRole, run_advocates
            from webprobe.models import CostSummary

            adv_roles = None
            if advocate_roles:
                adv_roles = [AdvocateRole(r.strip()) for r in advocate_roles.split(",")]

            advocate_cfg = AdvocateConfig(
                provider=llm_provider,
                model=advocate_model or llm_model,
                roles=adv_roles,
                cost_limit_usd=advocate_cost_limit,
                mask_path=mask_path,
            )
            click.echo(f"Phase 6: Running advocate review ({len(advocate_cfg.roles)} personas)...")
            adv_findings, adv_phase, adv_cost_tracker = await run_advocates(
                config, advocate_cfg, run_obj.graph, run_obj.analysis, run_dir
            )
            run_obj.phases.append(adv_phase)
            if run_obj.analysis:
                run_obj.analysis.security_findings.extend(adv_findings)
            click.echo(f"  {len(adv_findings)} findings ({adv_phase.duration_ms:.0f} ms)")

            adv_cost_summary = adv_cost_tracker.summary()
            run_obj.advocate_cost = CostSummary(**adv_cost_summary)
            click.echo(f"  Advocate cost: ${adv_cost_summary['total_cost_usd']:.4f}")

        # Phase 4: Report (runs last so it includes explore + advocate findings)
        click.echo("Phase 4: Generating report...")
        run_obj.completed_at = _now_iso()
        report_phase = generate_report(run_obj, run_dir)
        run_obj.phases.append(report_phase)
        click.echo(f"  Done ({report_phase.duration_ms:.0f} ms)")

        click.echo(f"\nReport: {run_dir / 'report.html'}")
        click.echo(f"JSON:   {run_dir / 'report.json'}")

    asyncio.run(_run())


@main.command("explore")
@click.argument("run_dir", type=click.Path(exists=True))
@click.option("--provider", type=click.Choice(["anthropic", "openai", "gemini", "apprentice"]),
              default="anthropic", help="LLM provider.")
@click.option("--model", default=None, help="Override LLM model name.")
@click.option("--agents", type=int, default=5, help="Number of concurrent agents.")
@click.option("--mask", "mask_path", type=click.Path(exists=True), default=None,
              help="Path to mask YAML.")
@click.pass_context
def explore_cmd(ctx: click.Context, run_dir: str, provider: str, model: str | None,
                agents: int, mask_path: str | None) -> None:
    """Phase 5 only: LLM-driven exploration of an existing run."""
    config: WebprobeConfig = ctx.obj["config"]

    async def _explore() -> None:
        from webprobe.differ import load_run
        from webprobe.explorer import ExploreConfig, explore_site
        from webprobe.models import CostSummary
        from webprobe.reporter import generate_report

        rd = Path(run_dir)
        run_obj = load_run(rd)

        if agents > 20:
            click.echo(f"WARNING: {agents} concurrent agents will make many LLM API calls.")
            if not click.confirm("Continue?"):
                return

        explore_cfg = ExploreConfig(
            provider=provider,
            model=model,
            concurrency=agents,
            mask_path=mask_path,
        )
        click.echo(f"Exploring with {agents} {provider} agents...")
        findings, phase, cost_tracker = await explore_site(config, explore_cfg, run_obj.graph, rd)
        run_obj.phases.append(phase)

        if run_obj.analysis:
            run_obj.analysis.security_findings.extend(findings)
        click.echo(f"{len(findings)} findings ({phase.duration_ms:.0f} ms)")

        cost_summary = cost_tracker.summary()
        run_obj.explore_cost = CostSummary(**cost_summary)
        click.echo(f"LLM cost: ${cost_summary['total_cost_usd']:.4f}")

        # Regenerate report
        generate_report(run_obj, rd)
        click.echo(f"Report updated: {rd / 'report.html'}")

    asyncio.run(_explore())


@main.command("advocate")
@click.argument("run_dir", type=click.Path(exists=True))
@click.option("--provider", type=click.Choice(["anthropic", "openai", "gemini", "apprentice"]),
              default="anthropic", help="LLM provider.")
@click.option("--model", default=None, help="Override LLM model name.")
@click.option("--roles", default=None,
              help="Comma-separated advocate roles (pentester,security_engineer,privacy_expert,compliance_officer).")
@click.option("--cost-limit", type=float, default=5.0, help="Cost limit in USD.")
@click.option("--mask", "mask_path", type=click.Path(exists=True), default=None,
              help="Path to mask YAML.")
@click.pass_context
def advocate_cmd(ctx: click.Context, run_dir: str, provider: str, model: str | None,
                 roles: str | None, cost_limit: float, mask_path: str | None) -> None:
    """Phase 6 only: LLM advocate review of an existing run."""
    config: WebprobeConfig = ctx.obj["config"]

    async def _advocate() -> None:
        from webprobe.advocate import AdvocateConfig, AdvocateRole, run_advocates
        from webprobe.differ import load_run
        from webprobe.models import CostSummary
        from webprobe.reporter import generate_report

        rd = Path(run_dir)
        run_obj = load_run(rd)

        adv_roles = None
        if roles:
            adv_roles = [AdvocateRole(r.strip()) for r in roles.split(",")]

        advocate_cfg = AdvocateConfig(
            provider=provider,
            model=model,
            roles=adv_roles,
            cost_limit_usd=cost_limit,
            mask_path=mask_path,
        )
        click.echo(f"Running advocate review ({len(advocate_cfg.roles)} personas)...")
        findings, phase, cost_tracker = await run_advocates(
            config, advocate_cfg, run_obj.graph, run_obj.analysis, rd
        )
        run_obj.phases.append(phase)
        if run_obj.analysis:
            run_obj.analysis.security_findings.extend(findings)
        click.echo(f"{len(findings)} findings ({phase.duration_ms:.0f} ms)")

        cost_summary = cost_tracker.summary()
        run_obj.advocate_cost = CostSummary(**cost_summary)
        click.echo(f"Advocate cost: ${cost_summary['total_cost_usd']:.4f}")

        generate_report(run_obj, rd)
        click.echo(f"Report updated: {rd / 'report.html'}")

    asyncio.run(_advocate())


@main.command("map")
@click.argument("url")
@click.option("--project-root", type=click.Path(exists=True), default=None)
@click.option("--output-dir", type=click.Path(), default=None)
@click.option("--js", "render_js", is_flag=True, default=False,
              help="Use Playwright for JS rendering during site mapping.")
@click.pass_context
def map_cmd(ctx: click.Context, url: str, project_root: str | None, output_dir: str | None,
            render_js: bool) -> None:
    """Phase 1 only: Map the site and build the graph."""
    config: WebprobeConfig = ctx.obj["config"]
    if render_js:
        config.crawl.render_js = True

    async def _map() -> None:
        from webprobe.models import Run
        from webprobe.mapper import map_site
        from webprobe.frameworks import detect_framework

        run_obj = Run(url=url, started_at=_now_iso())
        run_dir = Path(output_dir or config.output_dir) / run_obj.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        framework_routes: list[str] | None = None
        if project_root:
            fw_name, routes = detect_framework(Path(project_root))
            if fw_name:
                click.echo(f"Detected framework: {fw_name} ({len(routes)} routes)")
                framework_routes = routes

        click.echo(f"Mapping {url}...")
        graph, phase = await map_site(config, url, framework_routes)
        (run_dir / "graph.json").write_text(graph.model_dump_json(indent=2))
        click.echo(f"{len(graph.nodes)} nodes, {len(graph.edges)} edges")
        click.echo(f"Graph: {run_dir / 'graph.json'}")

    asyncio.run(_map())


@main.command()
@click.argument("run_dir", type=click.Path(exists=True))
@click.pass_context
def capture(ctx: click.Context, run_dir: str) -> None:
    """Phase 2 only: Capture metrics for an existing graph."""
    config: WebprobeConfig = ctx.obj["config"]

    async def _capture() -> None:
        from webprobe.models import SiteGraph
        from webprobe.capturer import capture_site

        rd = Path(run_dir)
        graph_path = rd / "graph.json"
        if not graph_path.exists():
            click.echo("Error: No graph.json in run directory.", err=True)
            sys.exit(1)
        graph = SiteGraph.model_validate_json(graph_path.read_text())
        click.echo(f"Capturing {len(graph.nodes)} nodes...")
        graph, phase = await capture_site(config, graph, rd)
        click.echo(f"Done ({phase.duration_ms:.0f} ms)")

    asyncio.run(_capture())


@main.command()
@click.argument("run_dir", type=click.Path(exists=True))
def analyze_cmd(run_dir: str) -> None:
    """Phase 3 only: Analyze an existing run."""
    from webprobe.analyzer import analyze
    from webprobe.reporter import generate_report

    rd = Path(run_dir)

    # Try loading from complete run first, fall back to graph.json for partial runs
    graph = None
    if (rd / "report.json").exists():
        from webprobe.differ import load_run
        run_obj = load_run(rd)
        graph = run_obj.graph
    elif (rd / "graph.json").exists():
        from webprobe.models import SiteGraph
        graph = SiteGraph.model_validate_json((rd / "graph.json").read_text())
    else:
        raise click.ClickException(f"No graph.json or report.json in {rd}")

    click.echo("Analyzing...")
    result, phase = analyze(graph)
    (rd / "analysis.json").write_text(result.model_dump_json(indent=2))

    m = result.graph_metrics
    click.echo(f"  Cyclomatic complexity: {m.cyclomatic_complexity}")
    click.echo(f"  Broken links: {len(result.broken_links)}")
    click.echo(f"  Auth violations: {len(result.auth_violations)}")
    click.echo(f"  Timing outliers: {len(result.timing_outliers)}")
    click.echo(f"  Prime paths: {len(result.prime_paths)}")
    if result.security_findings:
        by_sev: dict[str, int] = {}
        for sf in result.security_findings:
            by_sev[sf.severity.value] = by_sev.get(sf.severity.value, 0) + 1
        parts = [f"{v} {k}" for k, v in sorted(by_sev.items())]
        click.echo(f"  Security findings: {len(result.security_findings)} ({', '.join(parts)})")

    # Generate report
    from webprobe.models import Run
    site_url = graph.root_url or next(iter(graph.nodes), "")
    run_obj = Run(url=site_url, graph=graph, analysis=result, phases=[phase])
    (rd / "report.json").write_text(run_obj.model_dump_json(indent=2))
    generate_report(run_obj, rd)
    click.echo(f"  Report: {rd / 'report.html'}")


@main.command()
@click.argument("run_dir", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["json", "html", "both"]), default="both")
def report(run_dir: str, fmt: str) -> None:
    """Phase 4 only: Generate report from an existing run."""
    from webprobe.differ import load_run
    from webprobe.reporter import generate_report

    rd = Path(run_dir)
    run_obj = load_run(rd)
    formats = ["json", "html"] if fmt == "both" else [fmt]
    phase = generate_report(run_obj, rd, formats)
    click.echo(f"Report generated ({phase.duration_ms:.0f} ms)")


@main.command()
@click.argument("run_a", type=click.Path(exists=True))
@click.argument("run_b", type=click.Path(exists=True))
@click.option("--output", type=click.Path(), default=None, help="Write diff JSON to file.")
def diff(run_a: str, run_b: str, output: str | None) -> None:
    """Compare two runs."""
    from webprobe.differ import load_run, diff_runs

    a = load_run(Path(run_a))
    b = load_run(Path(run_b))
    result = diff_runs(a, b)

    text = result.model_dump_json(indent=2)
    if output:
        Path(output).write_text(text)
        click.echo(f"Diff written to {output}")
    else:
        click.echo(text)


@main.command()
@click.argument("run_dir", type=click.Path(exists=True))
def status(run_dir: str) -> None:
    """Show summary of a run."""
    from webprobe.differ import load_run

    rd = Path(run_dir)
    run_obj = load_run(rd)
    click.echo(f"Run:     {run_obj.run_id}")
    click.echo(f"URL:     {run_obj.url}")
    click.echo(f"Started: {run_obj.started_at}")
    click.echo(f"Nodes:   {len(run_obj.graph.nodes)}")
    click.echo(f"Edges:   {len(run_obj.graph.edges)}")
    for p in run_obj.phases:
        dur = f"{p.duration_ms:.0f} ms" if p.duration_ms else "—"
        click.echo(f"  {p.phase}: {p.status} ({dur})")
    if run_obj.analysis:
        a = run_obj.analysis
        click.echo(f"Broken links:    {len(a.broken_links)}")
        click.echo(f"Auth violations: {len(a.auth_violations)}")
        click.echo(f"Timing outliers: {len(a.timing_outliers)}")


if __name__ == "__main__":
    main()
