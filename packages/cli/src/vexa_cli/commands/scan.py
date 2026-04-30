"""Scan command."""

import asyncio
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.panel import Panel
from rich.prompt import Confirm

from vexa.common.models import ScanMode, ScanResult
from vexa.common.cloud_provider import (
    CloudProvider,
    PROVIDER_CAPABILITIES,
    ProviderAvailability,
)
from vexa.common.config_manager import load_config

from vexa_cli.ui.output import (
    print_banner,
    print_success,
    print_error,
    print_info,
    print_warning,
    console,
)
from vexa_cli.commands.report import _generate_report
from vexa_cli.gates.quality_gate import evaluate_quality_gate

import importlib.metadata

QualityGateEvaluator = None
SecurityScorer = None
BaselineManager = None
ComplianceAnalyzer = None
ShadowDecorator = None

try:
    eps = importlib.metadata.entry_points(group="vexa.plugins.cicd")
    for ep in eps:
        cls = ep.load()
        if ep.name == "QualityGateEvaluator":
            QualityGateEvaluator = cls
        elif ep.name == "SecurityScorer":
            SecurityScorer = cls
        elif ep.name == "BaselineManager":
            BaselineManager = cls
        elif ep.name == "ComplianceAnalyzer":
            ComplianceAnalyzer = cls
        elif ep.name == "ShadowDecorator":
            ShadowDecorator = cls
except Exception:
    pass


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["html", "json", "sarif", "markdown", "all"]),
    multiple=True,
    default=["all"],
    help="Output report format (default: all)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory for reports (default: 'vexa_scan_reports' in the scanned directory)",
)
@click.option(
    "--scanners",
    "-s",
    multiple=True,
    help="Specific scanners to run (default: all available)",
)
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["local", "container"]),
    default="local",
    help="Execution mode (default: local)",
)
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=480,
    help="Timeout per scanner in seconds (default: 480)",
)
@click.option(
    "--ai-provider",
    type=click.Choice(
        ["google", "openai", "anthropic", "ollama", "none"], case_sensitive=False
    ),
    default=None,
    help="AI provider override for explicit false positive filtering (e.g., 'openai', 'ollama' for local)",
)
@click.option(
    "--ai-api-key",
    type=str,
    default=None,
    envvar="VEXA_AI_API_KEY",
    help="API Key for the chosen AI provider (also via VEXA_AI_API_KEY)",
)
@click.option(
    "--fail-on",
    "-F",
    type=str,
    default=None,
    help="Comma-separated list of severities to fail the pipeline (e.g., 'critical,high')",
)
@click.option(
    "--ai-min-severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="medium",
    help="Minimum severity threshold for AI enrichment (default: medium)",
)
@click.option(
    "--max-findings",
    type=int,
    default=0,
    help="Maximum total findings allowed before failing the quality gate (default: 0 = unlimited)",
)
@click.option(
    "--new-only",
    is_flag=True,
    default=False,
    help="Only fail on findings that are not in the baseline file.",
)
@click.option(
    "--baseline-file",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the baseline file (.vexa-baseline.json)",
)
@click.option(
    "--min-score",
    type=str,
    default=None,
    help="Minimum security score grade (e.g., 'B+') required to pass.",
)
@click.option(
    "--shadow",
    is_flag=True,
    default=False,
    help="Enable Shadow Mode: execute PR decoration silently and always exit with code 0 (Recommended default for CI/CD).",
)
@click.option(
    "--decorate-pr",
    type=click.Choice(["github", "gitlab", "auto"]),
    default=None,
    help="Post scan findings as a PR/MR comment to the specified platform.",
)
@click.option(
    "--compliance-framework",
    type=click.Choice(["soc2", "pci", "hipaa", "nist", "all"]),
    default=None,
    help="Map findings to the specified compliance framework.",
)
@click.option(
    "--exclude",
    "-x",
    multiple=True,
    help="Paths to exclude from scanning (e.g. 'test/,*.md')",
)
@click.option(
    "--incremental",
    is_flag=True,
    default=False,
    help="Only scan files modified in git (uses git diff --name-only HEAD).",
)
@click.option(
    "--fast",
    is_flag=True,
    default=False,
    help="Run fast mode (bandit + detect-secrets only) suitable for pre-commit.",
)
@click.option(
    "--pre-commit",
    is_flag=True,
    default=False,
    help="Run in pre-commit hook mode (enforces guardrails).",
)
def scan(
    path: Path,
    format: tuple,
    output: Optional[Path],
    scanners: tuple,
    mode: str,
    timeout: int,
    ai_provider: Optional[str] = None,
    ai_api_key: Optional[str] = None,
    fail_on: Optional[str] = None,
    ai_min_severity: str = "medium",
    max_findings: int = 0,
    new_only: bool = False,
    baseline_file: Optional[Path] = None,
    min_score: Optional[str] = None,
    shadow: bool = False,
    decorate_pr: Optional[str] = None,
    compliance_framework: Optional[str] = None,
    exclude: tuple = (),
    incremental: bool = False,
    fast: bool = False,
    pre_commit: bool = False,
):
    """
    Run security scan on target path.
    """
    # Load project configuration early
    config = load_config(path)

    # Merge CLI options with config file defaults
    if not fail_on and config.quality_gate.fail_on:
        fail_on = ",".join(config.quality_gate.fail_on)
    if (
        max_findings == 0 and config.quality_gate.max_total != 50
    ):  # 50 is the pydantic default
        max_findings = config.quality_gate.max_total
    if not new_only and config.quality_gate.new_only:
        new_only = config.quality_gate.new_only
    if not baseline_file and config.quality_gate.baseline:
        baseline_file = Path(config.quality_gate.baseline)
    if not min_score and config.quality_gate.min_score != "C":
        min_score = config.quality_gate.min_score

    print_banner()

    start_time = datetime.now()
    console.print(
        f"\n[bold white]🚀 Scan Initiated:[/bold white] [bright_cyan]{start_time.strftime('%Y-%m-%d %H:%M:%S')}[/bright_cyan]"
    )
    console.print("─" * 50)

    logging.getLogger("vexa.reports.generator").setLevel(logging.WARNING)
    for l in ["mcp", "fastmcp", "starlette", "uvicorn", "httpcore", "httpx"]:
        logging.getLogger(l).setLevel(logging.WARNING)

    if output:
        base_output_dir = output
    else:
        base_path = path if path.is_dir() else path.parent
        base_output_dir = base_path / "vexa_scan_reports"

    try:
        base_output_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError) as e:
        print_warning(f"Output directory '{base_output_dir}' is not writable: {e}")
        import tempfile

        fallback_dir = Path(tempfile.gettempdir()) / "vexa_scan_reports"
        print_info(f"Falling back to temporary output directory: {fallback_dir}")
        base_output_dir = fallback_dir
        base_output_dir.mkdir(parents=True, exist_ok=True)

    scan_mode = ScanMode.LOCAL if mode == "local" else ScanMode.CONTAINER

    scanner_list = []
    if fast:
        scanner_list = ["bandit", "detect-secrets"]
        print_info("Fast mode enabled: Using bandit and detect-secrets only.")
    elif scanners:
        for s in scanners:
            scanner_list.extend([x.strip() for x in s.split(",") if x.strip()])
    elif config.scanners.enabled:
        scanner_list = config.scanners.enabled
        print_info(
            f"Using scanners from project configuration: {', '.join(scanner_list)}"
        )
    else:
        scanner_list = None

    ctx = click.get_current_context(silent=True)
    is_non_interactive = (
        ctx.obj.get("non_interactive", False) if ctx and ctx.obj else False
    )
    is_ci = os.environ.get("CI", "").lower() == "true"

    if pre_commit:
        print_info("Pre-commit mode enabled. Disabling AI features for speed.")
        cloud_provider = CloudProvider.NONE
        ai_provider = None
    elif ai_provider is None:
        # Check if AI is configured in .vexa.yml
        if config.ai.enabled and config.ai.provider != CloudProvider.NONE:
            cloud_provider = config.ai.provider
            print_info(
                f"Using AI provider '{cloud_provider.value}' from project configuration"
            )
        elif not is_ci and not is_non_interactive:
            # ZF-01: Simplify AI prompt down to one string using init.py's implementation
            try:
                from vexa_cli.commands.init import configure_ai

                ai_config = configure_ai()
                if ai_config["enabled"]:
                    cloud_provider = CloudProvider(ai_config["provider"])
                else:
                    print_info("Proceeding with AI features disabled (None).")
                    cloud_provider = CloudProvider.NONE
            except ImportError:
                print_info("Proceeding with AI features disabled (None).")
                cloud_provider = CloudProvider.NONE
        else:
            if os.environ.get("GOOGLE_API_KEY"):
                cloud_provider = CloudProvider.GOOGLE
                print_info("Auto-detecting Google Gemini via GOOGLE_API_KEY")
            elif os.environ.get("VEXA_ANTHROPIC_API_KEY"):
                cloud_provider = CloudProvider.ANTHROPIC
                print_info("Auto-detecting Anthropic via VEXA_ANTHROPIC_API_KEY")
            elif os.environ.get("VEXA_OPENAI_API_KEY"):
                cloud_provider = CloudProvider.OPENAI
                print_info("Auto-detecting OpenAI via VEXA_OPENAI_API_KEY")
            else:
                cloud_provider = CloudProvider.NONE
    else:
        cloud_provider = CloudProvider(ai_provider)

    if cloud_provider != CloudProvider.NONE:
        status = asyncio.run(
            ProviderAvailability.check_provider(cloud_provider, check_quota=True)
        )
        if not status["available"]:
            console.print(
                f"\n[bold yellow]⚠ AI Provider '{cloud_provider.value}' not ready: {status['error']}[/bold yellow]"
            )

            # If interactive mode, offer to enter key
            if not is_ci and not is_non_interactive:
                key_var = {
                    CloudProvider.GOOGLE: "GOOGLE_API_KEY",
                    CloudProvider.OPENAI: "OPENAI_API_KEY",
                    CloudProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
                }.get(cloud_provider)

                if key_var and not os.environ.get(key_var):
                    from rich.prompt import Prompt

                    new_key = Prompt.ask(
                        f"Enter your {cloud_provider.value.title()} API Key now",
                        password=True,
                    )
                    if new_key:
                        os.environ[key_var] = new_key
                        # Re-check availability with the new key
                        status = asyncio.run(
                            ProviderAvailability.check_provider(
                                cloud_provider, check_quota=True
                            )
                        )
                        if status["available"]:
                            print_success("API Key accepted for this session.")

            if not status["available"]:
                if is_ci or is_non_interactive:
                    print_warning(
                        "Non-interactive / CI environment detected. Automatically proceeding without AI enrichment."
                    )
                    cloud_provider = CloudProvider.NONE
                    ai_provider = None
                elif Confirm.ask(
                    "Would you like to proceed with the scan without AI enrichment?",
                    default=False,
                    console=console,
                ):
                    print_info("Proceeding with AI capabilities disabled.")
                    cloud_provider = CloudProvider.NONE
                    ai_provider = None
                else:
                    print_error(
                        "Scan aborted. Please configure the AI provider and try again."
                    )
                    sys.exit(0)

    formats_to_gen = list(format)
    if "all" in formats_to_gen:
        formats_to_gen = ["html", "json", "sarif", "markdown"]

    scan_output_dir = base_output_dir / f"scan_{start_time.strftime('%Y%m%d_%H%M%S')}"
    scan_output_dir.mkdir(parents=True, exist_ok=True)

    caps = PROVIDER_CAPABILITIES.get(cloud_provider)
    display_map = {
        "google": "GOOGLE GEMINI",
        "openai": "OPENAI",
        "anthropic": "ANTHROPIC",
        "none": "None",
    }
    effective_ai_display = (
        display_map.get(ai_provider.lower(), ai_provider.upper())
        if ai_provider
        else display_map.get(cloud_provider.value.lower(), "None")
        if cloud_provider != CloudProvider.NONE
        else "None"
    )

    conf_content = (
        f"[bold sky_blue1]Target:[/bold sky_blue1]   [blue]{path.resolve()}[/blue]\n"
        f"[bold sky_blue1]Mode:[/bold sky_blue1]     [white]{mode.capitalize()}[/white]\n"
        f"[bold sky_blue1]Output:[/bold sky_blue1]   [white]{', '.join([f.upper() for f in formats_to_gen])}[/white]\n"
        f"[bold sky_blue1]Provider:[/bold sky_blue1] [bright_cyan]{effective_ai_display}[/bright_cyan]\n"
        f"[bold sky_blue1]AI Threshold:[/bold sky_blue1] [yellow]{ai_min_severity.upper()}+[/yellow]\n"
        f"[dim]AI Review: {'✅' if caps and (caps.code_review_enabled or ai_provider) else '❌'}  |  FP Detection: {'✅' if caps and (caps.false_positive_detection or ai_provider) else '❌'}[/dim]"
    )
    console.print(
        Panel(
            conf_content,
            title="[bold white]Scan Configuration[/bold white]",
            border_style="bright_cyan",
            expand=False,
        )
    )
    console.print()

    if sys.platform == "win32":
        print_warning(
            "Semgrep is not supported natively on Windows. For full coverage, use WSL2 or Docker mode (--mode container)."
        )

    cli_excludes = list(exclude) if exclude else None

    try:
        result = asyncio.run(
            _run_scan(
                path,
                scanner_list,
                scan_mode,
                timeout,
                cloud_provider,
                ai_provider_override=ai_provider,
                api_key_override=ai_api_key,
                ai_min_severity=ai_min_severity,
                cli_excludes=cli_excludes,
                incremental=incremental,
            )
        )
    except Exception as e:
        print_error(f"Scan failed: {e}")
        sys.exit(1)

    end_time = datetime.now()
    duration = end_time - start_time

    console.print("─" * 50)
    console.print("\n[bold white]📊 Scan Summary[/bold white]")
    console.print("─" * 50)

    gate_failed = False
    if result.success:
        files_suffix = (
            f" across {result.scanned_files} files" if result.scanned_files > 0 else ""
        )
        if result.total_findings > 0:
            print_success(
                f"Scan completed: {result.total_findings} findings identified{files_suffix}"
            )
        else:
            print_success(f"Scan completed: No security issues found{files_suffix} 🎉")

        if result.errors:
            print_warning(
                f"Note: {len(result.errors)} tool errors occurred during execution"
            )

        score_grade = "N/A"
        if SecurityScorer:
            scorer = SecurityScorer()
            score_result = scorer.calculate(result)
            score_grade = score_result.grade

            # GOV-01: Plain English explanation map
            grade_explanations = {
                "A+": "Excellent — secure code",
                "A": "Excellent — secure code",
                "A-": "Very Good — minor issues",
                "B+": "Good — watch hardcoded rules",
                "B": "Good — monitor findings",
                "B-": "Fair — needs some review",
                "C+": "Fair — beginning to accrue risk",
                "C": "Needs Improvement — several issues",
                "C-": "Needs Improvement — elevated risk",
                "D+": "Poor — significant issues found",
                "D": "Poor — critical review needed",
                "D-": "Poor — immediate attention required",
                "F": "Failing — do not deploy",
            }
            explanation = grade_explanations.get(score_grade, "Unknown")

            console.print(
                f"\n[bold white]🛡️  Security Grade:[/bold white] {score_result.grade_emoji} [bold {score_result.color}]{score_grade} ({explanation})[/bold {score_result.color}] [dim](Score: {score_result.numeric_score})[/dim]"
            )

            # Automatically save to baseline
            if BaselineManager:
                try:
                    bm = BaselineManager()
                    bm.save_baseline(
                        result, path / ".vexa-baseline.json", score_grade=score_grade
                    )
                    console.print(
                        "   [dim]Saved score and baseline to .vexa-baseline.json[/dim]"
                    )
                except Exception as e:
                    console.print(f"   [dim red]Failed to save baseline: {e}[/dim red]")

        severity_counts = result.findings_by_severity
        if result.total_findings > 0:
            console.print("\n[dim]Findings Breakdown:[/dim]")
            for sev in ["critical", "high", "medium", "low"]:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    color = {
                        "critical": "bold red",
                        "high": "orange_red1",
                        "medium": "gold1",
                        "low": "deep_sky_blue1",
                    }[sev]
                    console.print(
                        f"  [bold {color}]• {sev.upper():<8}:[/bold {color}] [white]{count}[/white]"
                    )

        console.print("\n[dim]Scanner Summary:[/dim]")
        from vexa.scanners.engine import get_scanner_engine

        engine = get_scanner_engine()
        all_expected_scanners = engine.get_available_scanners(scan_mode)

        for scanner_name in scanner_list or all_expected_scanners:
            if scanner_name in result.scanners_run:
                scanner_res_dict = result.scanner_results.get(scanner_name, {})
                findings_list = (
                    getattr(scanner_res_dict, "findings", [])
                    if not isinstance(scanner_res_dict, dict)
                    else scanner_res_dict.get("findings", [])
                )
                fn_count = len(findings_list)
                console.print(
                    f"  [bold green]✔[/bold green] [white]{scanner_name:<16}[/white] [dim]({fn_count} findings)[/dim]"
                )
            else:
                if sys.platform == "win32" and scanner_name == "semgrep":
                    console.print(
                        f"  [bold red]✖[/bold red] [white]{scanner_name:<16}[/white] [dim](not available on Windows)[/dim]"
                    )
                else:
                    console.print(
                        f"  [bold yellow]⬚[/bold yellow] [white]{scanner_name:<16}[/white] [dim](not installed/available)[/dim]"
                    )

        gate_failed, diff, gate_status = evaluate_quality_gate(
            result,
            score_grade,
            new_only,
            baseline_file,
            path,
            fail_on,
            max_findings,
            min_score,
            QualityGateEvaluator,
            BaselineManager,
        )

        if result.total_false_positives > 0:
            console.print(
                f"\n[dim]AI suppressed {result.total_false_positives} false positive(s)[/dim]"
            )

        if result.errors:
            console.print("\n[bold gold1]⚠️  Scanner Diagnostics[/bold gold1]")
            for error in result.errors:
                print_error(f"  {error}")

    else:
        print_error(f"Scan failed with {len(result.errors)} errors")
        for error in result.errors:
            print_error(f"  {error}")

    console.print("\n[bold white]📂 Evidence Location[/bold white]")
    console.print(f"   [dim cyan]{scan_output_dir}[/dim cyan]")

    console.print("\n[bold white]📝 Security Reports Generated[/bold white]")
    report_files = []
    for fmt in formats_to_gen:
        try:
            report_path = _generate_report(result, fmt, scan_output_dir, path)
            report_files.append((fmt.upper(), report_path.name))
        except Exception as e:
            print_error(f"  • {fmt.upper():<8} : Failed ({e})")

    for fmt_name, filename in report_files:
        console.print(
            f"  • [bold sky_blue1]{fmt_name:<10}:[/bold sky_blue1] [white]{filename}[/white]"
        )

    console.print("─" * 50)
    console.print(
        f"[bold white]🏁 Scan Finished:[/bold white] [bright_cyan]{end_time.strftime('%Y-%m-%d %H:%M:%S')}[/bright_cyan]"
    )

    mins, secs = divmod(int(duration.total_seconds()), 60)
    duration_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
    console.print(
        f"[bold spring_green3]⏱️  Total Duration:[/bold spring_green3] [white]{duration_str}[/white]\n"
    )

    console.print(
        "[dim italic cyan]💡 Have feedback? Run 'vexa feedback' to help us improve![/dim italic cyan]\n"
    )

    comp_report = None
    if compliance_framework and QualityGateEvaluator:
        if ComplianceAnalyzer:
            analyzer = ComplianceAnalyzer()
            frames = (
                ["soc2", "pci-dss", "hipaa", "nist"]
                if compliance_framework == "all"
                else [compliance_framework]
            )
            comp_report = analyzer.analyze(result, frameworks=frames)
            print_success(f"Compliance mapping generated for {', '.join(frames)}")
        else:
            pass

    if decorate_pr and QualityGateEvaluator:
        if ShadowDecorator:
            decorator = ShadowDecorator(platform=decorate_pr)

            gate_res = gate_status
            score_res = score_grade if score_grade != "N/A" else None
            diff_res = locals().get("diff", None)

            markdown = decorator.generate_summary_comment(
                scan_result=result,
                gate_result=gate_res,
                score=score_res,
                diff=diff_res,
                compliance=comp_report,
            )
            print_info(f"Posting PR Decoration to {decorator.platform}...")
            if decorator.post_or_update_summary(markdown):
                print_success("PR Decoration posted successfully.")
            else:
                print_warning(
                    "PR Decoration failed or was skipped (Shadow Mode prevents crash)."
                )
        else:
            print_warning("Cannot decorate PR: cicd package components missing.")

    if shadow:
        print_info(
            "Shadow Mode explicitly enabled. Suppressing exit code to keep pipeline green."
        )
        sys.exit(0)
    elif pre_commit:
        block_on_sev = (
            config.guardrails.block_on.lower()
            if hasattr(config, "guardrails")
            else "critical"
        )
        weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        threshold_weight = weight.get(block_on_sev, 4)

        blocking_findings = []
        for sev in ["critical", "high", "medium", "low"]:
            if (
                weight.get(sev, 0) >= threshold_weight
                and severity_counts.get(sev, 0) > 0
            ):
                blocking_findings.append(sev)
                break

        if blocking_findings:
            highest_sev = blocking_findings[0]
            print_error(
                f"Commit blocked: Your code contains a {highest_sev} severity finding. Fix it and try again."
            )
            sys.exit(1)

        print_success("Pre-commit guardrails passed.")
        sys.exit(0)
    elif gate_failed:
        print_error("Quality Gate Failed: Found findings matching thresholds.")
        sys.exit(1)


async def _run_scan(
    path: Path,
    scanners: Optional[List[str]],
    mode: ScanMode,
    timeout: int,
    cloud_provider: CloudProvider,
    ai_provider_override: Optional[str] = None,
    api_key_override: Optional[str] = None,
    ai_min_severity: str = "medium",
    cli_excludes: Optional[List[str]] = None,
    incremental: bool = False,
) -> ScanResult:
    """Run the scan asynchronously via Direct Python Core API."""
    from vexa.scanners.engine import get_scanner_engine
    from vexa.jobs.manager import get_job_manager
    from vexa.ai_providers.manager import get_ai_manager
    from vexa_cli.commands._scan_helpers import (
        run_scan_with_job_manager,
        poll_scan_progress,
    )

    get_ai_manager(
        cloud_provider=cloud_provider,
        ai_provider_override=ai_provider_override,
        api_key_override=api_key_override,
        min_severity=ai_min_severity,
    )

    engine = get_scanner_engine()
    job_manager = get_job_manager()

    print_info("Initializing Hexagonal Core...")

    scan_job_id = await run_scan_with_job_manager(
        engine,
        job_manager,
        path,
        scanners,
        mode,
        timeout,
        cloud_provider,
        ai_min_severity=ai_min_severity,
        cli_excludes=cli_excludes,
        incremental=incremental,
    )

    click.echo(click.style("➜ ", fg="cyan") + "Scan Engine Started")

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40, style="blue", complete_style="green"),
        TaskProgressColumn(),
        "•",
        TimeElapsedColumn(),
        console=console,
    ) as progress_bar:
        scan_task_bar = progress_bar.add_task("Initializing...", total=100)
        await poll_scan_progress(job_manager, scan_job_id, progress_bar, scan_task_bar)

    result = await job_manager.get_result(scan_job_id)
    if not result:
        raise Exception("Scan completed but no result was found.")
    return result
