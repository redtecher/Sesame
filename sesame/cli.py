import json
import os
from pathlib import Path

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.setdefault("CREWAI_TELEMETRY_OPT_OUT", "true")

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sesame.bootstrap import get_settings
from sesame.config import build_runtime_bundle
from sesame.domain.input import AnalysisInput
from sesame.pipeline import run_enablement_pipeline

app = typer.Typer(add_completion=False)
console = Console()


def _write_run_summary(result, log_path: Path) -> None:
    """Append a structured summary block to the run log file."""
    import logging
    summary_logger = logging.getLogger("sesame.summary")

    summary_logger.info("=" * 60)
    summary_logger.info("RUN SUMMARY")
    summary_logger.info("=" * 60)
    summary_logger.info(f"Summary: {result.report.summary}")
    summary_logger.info(f"  Reachable Pages: {result.metrics.reachable_pages_before} -> {result.metrics.reachable_pages_after}")
    summary_logger.info(f"  Post-Auth Targets: {result.metrics.post_auth_targets_before} -> {result.metrics.post_auth_targets_after}")
    summary_logger.info(f"  Fuzzable Targets: {result.metrics.fuzzable_targets_before} -> {result.metrics.fuzzable_targets_after}")

    if result.targets:
        fuzz_ready = [t for t in result.targets if t.reachability.value == "fuzz_ready"]
        login_blocked = [t for t in result.targets if t.reachability.value == "login_page"]
        unreachable = [t for t in result.targets if t.reachability.value == "unreachable"]

        summary_logger.info(f"  fuzz_ready: {len(fuzz_ready)}")
        summary_logger.info(f"  login_page: {len(login_blocked)}")
        for t in login_blocked[:10]:
            blockers = ",".join(t.blockers) if t.blockers else ""
            summary_logger.info(f"    {t.method} {t.url} blockers={blockers}")

        summary_logger.info(f"  unreachable: {len(unreachable)}")
        for t in unreachable[:5]:
            summary_logger.info(f"    {t.method} {t.url} blockers={','.join(t.blockers)}")

    if result.artifacts:
        summary_logger.info(f"  Fuzz artifacts: {len(result.artifacts)}")
        for a in result.artifacts[:20]:
            chain = " -> ".join(a.request_chain[:4]) if a.request_chain else a.target_url
            summary_logger.info(f"    {a.target_url}  chain: {chain}")

    if result.report.hypotheses:
        summary_logger.info("  Mismatch Hypotheses:")
        for h in result.report.hypotheses[:5]:
            summary_logger.info(f"    [{h.confidence:.0%}] {h.title} ({h.mismatch_layer})")

    summary_logger.info(f"Log file: {log_path}")


def _run(input_data: AnalysisInput, output_json: bool = False) -> None:
    from sesame.utils.logger import setup_run_logging, get_run_log_file

    settings = get_settings()

    # Initialize file logging for this run
    run_label = input_data.web_url.replace("http://", "").replace("https://", "")
    log_path = setup_run_logging(run_label=run_label)
    console.print(f"[dim]Run log: {log_path}[/dim]")

    bundle = build_runtime_bundle(input_data=input_data, settings=settings)
    try:
        result = run_enablement_pipeline(bundle=bundle, settings=settings)
    except Exception as e:
        console.print(f"[bold red]Pipeline error: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        raise SystemExit(1)

    if output_json:
        console.print_json(result.model_dump_json(indent=2))
        return

    console.print(Panel("Test Enablement Result", style="bold cyan"))
    console.print(f"Summary: {result.report.summary}")

    metrics_table = Table(title="Rehosting Metrics")
    metrics_table.add_column("Metric", style="cyan")
    metrics_table.add_column("Before", style="red")
    metrics_table.add_column("After", style="green")
    metrics_table.add_row("Reachable Pages", str(result.metrics.reachable_pages_before), str(result.metrics.reachable_pages_after))
    metrics_table.add_row("Post-Auth Targets", str(result.metrics.post_auth_targets_before), str(result.metrics.post_auth_targets_after))
    metrics_table.add_row("Fuzzable Targets", str(result.metrics.fuzzable_targets_before), str(result.metrics.fuzzable_targets_after))
    console.print(metrics_table)

    # Pipeline metrics
    pm = result.pipeline_metrics
    if pm.total_wall_time_s > 0:
        pm_table = Table(title="Pipeline Metrics")
        pm_table.add_column("Stage", style="cyan")
        pm_table.add_column("Time (s)", style="yellow")
        pm_table.add_column("Input Tokens", style="blue")
        pm_table.add_column("Output Tokens", style="blue")
        pm_table.add_column("Tool Calls", style="magenta")
        for name, stage in [("Discovery", pm.discovery), ("Stage 1", pm.stage1_architecture), ("Stage 2", pm.stage2_mismatch), ("Stage 3", pm.stage3_recovery), ("Verification", pm.verification)]:
            tools_str = ", ".join(f"{k}={v}" for k, v in stage.tool_calls.items()) if stage.tool_calls else ""
            pm_table.add_row(name, f"{stage.wall_time_s:.1f}", str(stage.input_tokens), str(stage.output_tokens), tools_str)
        pm_table.add_row("[bold]Total[/bold]", f"[bold]{pm.total_wall_time_s:.1f}[/bold]", "", "", "")
        console.print(pm_table)

        if pm.recovery_technique:
            console.print(f"[bold]Recovery technique:[/bold] {pm.recovery_technique}")
        if pm.mismatch_distribution:
            console.print(f"[bold]Mismatch distribution:[/bold] {pm.mismatch_distribution}")

    if result.targets:
        console.print(f"\n[bold]Target Reachability ({len(result.targets)} targets):[/bold]")
        for target in result.targets[:30]:
            extra = ""
            topicurl = target.request_template.get("topicurl", "") if target.request_template else ""
            if topicurl:
                extra = f" [topicurl={topicurl}]"
            blockers = f" blockers={','.join(target.blockers)}" if target.blockers else ""
            color = {
                "unreachable": "red",
                "login_page": "yellow",
                "post_auth_page": "green",
                "api_ready": "green",
                "fuzz_ready": "bold green",
            }.get(target.reachability.value, "white")
            console.print(f"  [{color}]{target.target_type.upper():6} {target.method:4} {target.url}{extra} -> {target.reachability.value}{blockers}[/{color}]")

    if result.artifacts:
        console.print(f"\n[bold]Fuzz Artifacts ({len(result.artifacts)}):[/bold]")
        for artifact in result.artifacts[:15]:
            console.print(f"  - {artifact.target_url}")
            if artifact.request_chain:
                console.print(f"    chain: {' -> '.join(artifact.request_chain[:4])}")

    if result.report.hypotheses:
        console.print(f"\n[bold]Top Mismatch Hypotheses:[/bold]")
        for h in result.report.hypotheses[:5]:
            console.print(f"  [{h.confidence:.0%}] {h.title} ({h.mismatch_layer})")

    if result.report.runtime_state_evidence:
        console.print(f"\n[bold]Runtime Evidence ({len(result.report.runtime_state_evidence)}):[/bold]")
        for evidence in result.report.runtime_state_evidence[:6]:
            console.print(f"  - {evidence.source}: {evidence.command}")

    # Display bypass plan
    bp = result.bypass_plan
    if bp and bp.bypass_strategy:
        console.print(Panel("Bypass Plan", style="bold yellow"))
        console.print(f"[bold]Strategy:[/bold] {bp.bypass_strategy}")
        console.print(f"[bold]Description:[/bold] {bp.description}")
        console.print(f"[bold]Confidence:[/bold] {bp.confidence:.0%}")

        if bp.vm_commands:
            console.print(f"\n[bold red]Step 1: Execute in QEMU VM Shell[/bold red]")
            for i, cmd in enumerate(bp.vm_commands, 1):
                console.print(f"  [cyan]{i}.[/cyan] {cmd}")

        if bp.host_commands:
            console.print(f"\n[bold green]Step 2: Verify from Attacker Host[/bold green]")
            for i, cmd in enumerate(bp.host_commands, 1):
                console.print(f"  [green]{i}.[/green] {cmd}")

        if bp.credentials_to_try:
            console.print(f"\n[bold]Credentials to Try:[/bold]")
            for cred in bp.credentials_to_try:
                console.print(f"  username={cred.get('username', '')} password={cred.get('password', '(empty)')}")

        if bp.fallback_strategies:
            console.print(f"\n[bold]Fallback Strategies:[/bold]")
            for s in bp.fallback_strategies:
                console.print(f"  - {s}")

    # Write summary to log file
    _write_run_summary(result, log_path)


@app.command()
def audit(
    rootfs: Path = typer.Option(..., exists=True, file_okay=False, dir_okay=True, help="Extracted firmware rootfs"),
    web: str = typer.Option(..., help="Reachable web base URL"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    input_data = AnalysisInput(
        web_url=web,
        rootfs_path=str(rootfs),
    )
    _run(input_data, output_json=json_output)
