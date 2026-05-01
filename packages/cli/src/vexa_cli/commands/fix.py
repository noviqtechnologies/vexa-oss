"""
vexa fix — The Primary CLI Command.

Implements FIX-01: The most important command in Vexa. Takes a directory,
scans it for security issues, uses AI to triage and prioritise the top findings,
generates plain-English descriptions and code fixes, and lets the developer
approve each fix interactively.

The developer never needs to understand what a scanner is, what a CVE is,
or how to read a vulnerability report. The AI does all the work — the
developer only approves or rejects.

Usage:
    vexa fix .                    # Fix top 3 issues in current directory
    vexa fix . --limit 5          # Fix top 5 issues
    vexa fix . --dry-run          # Show fixes without applying
    vexa fix . --yes              # Apply all fixes without asking
    vexa fix . --ai-provider ollama  # Use local AI (Privacy Vault)
"""

import asyncio
import os
import sys
import difflib
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.panel import Panel
from rich.syntax import Syntax
from rich.prompt import Confirm
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)

from vexa.common.models import ScanMode, CloudProvider
from vexa.common.cloud_provider import ProviderAvailability
from vexa.common.config_manager import load_config
from vexa_cli.ui.output import (
    print_banner,
    print_error,
    print_info,
    print_warning,
    console,
)


# ---------------------------------------------------------------------------
# The Fix Command
# ---------------------------------------------------------------------------


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option(
    "--limit",
    "-n",
    type=int,
    default=3,
    help="Maximum number of fixes to present. Default: 3.",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default="medium",
    help="Minimum severity to fix. Default: medium.",
)
@click.option(
    "--ai-provider",
    type=click.Choice(
        ["google", "openai", "anthropic", "ollama", "none"], case_sensitive=False
    ),
    default=None,
    help="AI provider override. Default: auto-detect from config.",
)
@click.option(
    "--ai-model",
    type=str,
    default=None,
    help="AI model name override (e.g., 'llama3:8b', 'mistral').",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be fixed without applying changes.",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Apply all fixes without asking for confirmation.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Path for the fix report.",
)
@click.option(
    "--incremental",
    is_flag=True,
    default=False,
    help="Only fix issues in files changed since last commit.",
)
def fix(
    path: Path,
    limit: int,
    severity: str,
    ai_provider: Optional[str],
    ai_model: Optional[str],
    dry_run: bool,
    yes: bool,
    output: Optional[Path],
    incremental: bool,
):
    """
    Find and fix security issues in your code.

    Scans your project, identifies real security issues using AI, and
    presents fixes you can apply with one keystroke. No security expertise
    required.
    """
    try:
        asyncio.run(
            _run_fix(
                path=path,
                limit=limit,
                severity=severity,
                ai_provider_override=ai_provider,
                ai_model_override=ai_model,
                dry_run=dry_run,
                auto_apply=yes,
                output_path=output,
                incremental=incremental,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[dim]Fix cancelled.[/dim]")
        sys.exit(0)
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        print_info("If this keeps happening, run 'vexa doctor' to check your setup.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Core Fix Orchestration
# ---------------------------------------------------------------------------


async def _run_fix(
    path: Path,
    limit: int,
    severity: str,
    ai_provider_override: Optional[str],
    ai_model_override: Optional[str],
    dry_run: bool,
    auto_apply: bool,
    output_path: Optional[Path],
    incremental: bool,
):
    """
    The main fix pipeline: scan → triage → present → apply.

    This is where the "AI Security Autopilot" mission comes to life.
    """
    from vexa import __version__
    from vexa.scanners.engine import get_scanner_engine
    from vexa.jobs.manager import get_job_manager
    from vexa.ai_providers.manager import get_ai_manager
    from vexa.ai_providers.triage import prioritise_findings

    import logging

    # Suppress noisy loggers so the fix output is clean
    for logger_name in [
        "vexa",
        "mcp",
        "fastmcp",
        "starlette",
        "uvicorn",
        "httpcore",
        "httpx",
    ]:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    path = path.resolve()
    is_ci = os.environ.get("CI", "").lower() == "true"
    ctx = click.get_current_context(silent=True)
    is_non_interactive = (
        ctx.obj.get("non_interactive", False) if ctx and ctx.obj else False
    )

    # ── ZF-01 Zero-Friction Onboarding ─────────────────────────────────
    config_exists = (path / ".vexa.yml").exists() or (path / ".vexa.yaml").exists()
    has_env_keys = any(
        os.environ.get(k)
        for k in ["GOOGLE_API_KEY", "VEXA_ANTHROPIC_API_KEY", "VEXA_OPENAI_API_KEY"]
    )

    if not config_exists and not ai_provider_override and not has_env_keys:
        console.print(
            "\n[bold deep_sky_blue1]Welcome to Vexa! No configuration file found.[/bold deep_sky_blue1]"
        )
        try:
            from vexa_cli.commands.init import configure_ai

            ai_config = configure_ai()
            if ai_config["enabled"]:
                ai_provider_override = ai_config["provider"]
        except ImportError:
            pass
        console.print()

    config = load_config(path)

    # ── Resolve AI provider ────────────────────────────────────────────
    cloud_provider = _resolve_ai_provider(config, ai_provider_override)
    is_local_mode = cloud_provider == CloudProvider.OLLAMA

    # ── Check AI provider availability ─────────────────────────────────
    from vexa_cli.commands._scan_helpers import (
        run_scan_with_job_manager,
        poll_scan_progress,
        ensure_ai_availability,
    )

    cloud_provider = await ensure_ai_availability(
        cloud_provider, is_ci, is_non_interactive, console
    )

    if cloud_provider == CloudProvider.OLLAMA:
        # Verify Ollama is running before scanning
        from vexa.ai_providers.ollama_provider import get_ollama_wrapper

        ollama = get_ollama_wrapper(
            model=config.ai.model,
            host=config.ai.ollama_host,
            port=config.ai.ollama_port,
        )
        from vexa.ai_providers.base import AIProviderStatus

        oll_status, oll_msg = await ollama.check_availability()
        if oll_status != AIProviderStatus.AVAILABLE:
            print_error(oll_msg)
            sys.exit(1)

    # ── Print Header ───────────────────────────────────────────────────
    from vexa.common.cloud_provider import PROVIDER_CAPABILITIES

    _print_fix_header(
        version=__version__,
        path=path,
        cloud_provider=cloud_provider,
        severity=severity,
        config=config,
        capabilities=PROVIDER_CAPABILITIES.get(cloud_provider),
    )
    console.print()
    if sys.platform == "win32":
        print_warning(
            "Semgrep is not supported natively on Windows. For full coverage, use WSL2 or Docker mode (--mode container)."
        )

    # ── Initialize AI manager ──────────────────────────────────────────
    ai_manager = get_ai_manager(
        cloud_provider=cloud_provider,
        ai_provider_override=ai_provider_override,
        ai_model_override=ai_model_override,
        min_severity=severity,
    )

    # ── Phase 1: Scan ──────────────────────────────────────────────────
    console.print("\n🔍 Analysing your code...", style="bold white")

    engine = get_scanner_engine()
    job_manager = get_job_manager()

    from vexa_cli.commands._scan_helpers import (
        run_scan_with_job_manager,
        poll_scan_progress,
    )

    scan_job_id = await run_scan_with_job_manager(
        engine,
        job_manager,
        path,
        scanners=None,  # Use all available
        mode=ScanMode.LOCAL,
        timeout=480,
        cloud_provider=cloud_provider,
        ai_min_severity=severity,
        incremental=incremental,
    )

    fix_description_map = {
        5: "Starting security analysis...",
        15: "Starting security analysis...",
        75: "Analysing your code...",
        90: "AI is reviewing findings..."
        if cloud_provider != CloudProvider.NONE
        else "Processing results...",
        100: "Finishing up...",
    }
    prefix = "[local] " if is_local_mode else ""

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40, style="blue", complete_style="green"),
        TaskProgressColumn(),
        "•",
        TimeElapsedColumn(),
        console=console,
    ) as progress_bar:
        scan_bar = progress_bar.add_task("Scanning...", total=100)
        try:
            await poll_scan_progress(
                job_manager,
                scan_job_id,
                progress_bar,
                scan_bar,
                description_map=fix_description_map,
                prefix=prefix,
            )
        except Exception as e:
            print_error(f"Analysis failed: {e}")
            print_info("Try running 'vexa doctor' to check your setup.")
            sys.exit(1)

    result = await job_manager.get_result(scan_job_id)
    if not result:
        print_error("Analysis completed but no results were returned.")
        print_info("Try running 'vexa doctor' to check your setup.")
        sys.exit(1)

    # ── Phase 2: Triage ────────────────────────────────────────────────
    findings = result.findings
    false_positives_count = result.total_false_positives

    if not findings:
        if result.errors:
            console.print()
            print_warning("Scan completed with errors.")
            print_info(
                f"No security issues were found in the tools that succeeded on [bold]{path}[/bold]."
            )
            print_info("However, some security checks were skipped due to errors.")
            if false_positives_count > 0:
                console.print(
                    f"   [dim](Filtered out {false_positives_count} false alarm{'s' if false_positives_count != 1 else ''})[/dim]"
                )
        else:
            _print_no_issues_found(false_positives_count, path)
        sys.exit(0)

    # Prioritise findings using FIX-02 triage engine
    all_prioritised = prioritise_findings(
        findings,
        limit=len(findings),  # Get all prioritized findings for batching
        severity_filter=severity,
    )

    if not all_prioritised:
        _print_no_fixable_issues(len(findings), false_positives_count)
        sys.exit(0)

    # ── Phase 2.5: Summary Panel ───────────────────────────────────────
    # Calculate totals for the summary panel
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    console.print()
    summary_content = ""
    for sev in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = {
                "critical": "bold red",
                "high": "orange_red1",
                "medium": "gold1",
                "low": "deep_sky_blue1",
            }[sev]
            summary_content += f"  [bold {color}]• {sev.upper():<8}:[/bold {color}] [white]{count} issue{'s' if count != 1 else ''}[/white]\n"

    if false_positives_count > 0:
        summary_content += f"\n[dim]Filtered out {false_positives_count} false alarm{'s' if false_positives_count != 1 else ''}.[/dim]"

    console.print(
        Panel(
            summary_content.strip(),
            title="[bold white]Overall Scan Results[/bold white]",
            border_style="dim",
            expand=False,
        )
    )

    # ── Phase 3: Present & Fix (Batched) ───────────────────────────────
    fixes_applied = 0
    fixes_skipped = 0
    dry_run_diffs = []

    current_idx = 0
    total_fixable = len(all_prioritised)

    while current_idx < total_fixable:
        batch = all_prioritised[current_idx : current_idx + limit]

        console.print(
            f"\n🔍 [bold]AI Triage Selection:[/bold] Presenting [bold]{len(batch)}[/bold] top "
            f"issue{'s' if len(batch) != 1 else ''} for immediate fix "
            f"[dim](Batch {(current_idx // limit) + 1} of {(total_fixable - 1) // limit + 1})[/dim]."
        )
        if current_idx == 0 and false_positives_count > 0:
            console.print(
                f"   [dim](Filtered out {false_positives_count} false alarm"
                f"{'s' if false_positives_count != 1 else ''} so you don't have to.)[/dim]"
            )

        console.print("─" * 60)

        for i, finding in enumerate(batch, 1):
            finding_number_overall = current_idx + i
            console.print()

            # Get triage metadata (set by prioritise_findings)
            plain_title = getattr(finding, "_plain_title", finding.title)
            plain_explanation = getattr(
                finding, "_plain_explanation", finding.description
            )
            confidence = getattr(finding, "_fix_confidence", 50.0)
            confidence_level = getattr(finding, "_confidence_level", "Medium")

            remediation_code = getattr(finding, "remediation_code", "")
            has_fix = (
                remediation_code
                and len(remediation_code.strip()) > 10
                and not remediation_code.strip().startswith("# AI")
            )

            # Determine risk label
            risk_label = finding.severity.upper() + " RISK"

            if confidence < 50.0 or not has_fix:
                # ── Low confidence / no fix — awareness only ───────────
                _print_low_confidence_issue(
                    finding_number_overall,
                    total_fixable,
                    risk_label,
                    finding.file_path,
                    finding.line_start,
                    plain_title,
                    plain_explanation,
                    confidence,
                    confidence_level,
                )
                fixes_skipped += 1
            else:
                # ── Fixable issue — show diff and ask ──────────────────
                applied = _present_and_apply_fix(
                    finding_number_overall,
                    total_fixable,
                    risk_label,
                    finding,
                    plain_title,
                    plain_explanation,
                    confidence,
                    confidence_level,
                    path,
                    dry_run,
                    auto_apply,
                    is_local_mode,
                )

                if dry_run and has_fix:
                    # Collect unified diff for --dry-run output
                    diff_text = _generate_unified_diff(finding, path)
                    if diff_text:
                        dry_run_diffs.append(diff_text)
                    fixes_applied += 1
                elif applied:
                    fixes_applied += 1
                else:
                    fixes_skipped += 1

        current_idx += limit

        # Prompt user to continue if more issues remain
        if current_idx < total_fixable and not dry_run and not auto_apply:
            remaining = total_fixable - current_idx
            try:
                console.print()
                continue_fixing = Confirm.ask(
                    f"[bold sky_blue1]You have {remaining} prioritised issue{'s' if remaining != 1 else ''} remaining. Would you like to review the next batch?[/bold sky_blue1]",
                    default=True,
                    console=console,
                )
                if not continue_fixing:
                    console.print("\n[dim]Skipping remaining issues.[/dim]")
                    break
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Skipping remaining issues.[/dim]")
                break

    # ── Summary ────────────────────────────────────────────────────────
    console.print()
    console.print("─" * 60)

    if dry_run:
        console.print(
            f"\n[bold]📋 Dry run complete.[/bold] {len(dry_run_diffs)} fix{'es' if len(dry_run_diffs) != 1 else ''} ready to apply."
        )
        if dry_run_diffs:
            console.print("\n[dim]Apply these fixes with:[/dim]")
            console.print("  [bold]vexa fix . --yes[/bold]")
            console.print("\n[dim]Or save as a patch file:[/dim]")
            console.print("  [bold]vexa fix . --dry-run > fixes.patch[/bold]")
            # Print unified diffs to stdout for piping
            for diff_text in dry_run_diffs:
                print(diff_text)
    else:
        if fixes_applied > 0:
            console.print(
                f"\n[bold green]✅ {fixes_applied} fix{'es' if fixes_applied != 1 else ''} applied.[/bold green]"
            )
        if fixes_skipped > 0:
            reason = (
                "AI enrichment unavailable"
                if cloud_provider == CloudProvider.NONE
                else "low confidence"
            )
            console.print(
                f"[dim]{fixes_skipped} issue{'s' if fixes_skipped != 1 else ''} shown for awareness only ({reason}).[/dim]"
            )
        if fixes_applied == 0 and fixes_skipped == 0:
            console.print(
                "[bold green]No fixes needed — your code looks good![/bold green]"
            )

    console.print()
    sys.exit(0)


# ---------------------------------------------------------------------------
# AI Provider Resolution
# ---------------------------------------------------------------------------


def _resolve_ai_provider(config, ai_provider_override: Optional[str]) -> CloudProvider:
    """Delegate to shared helper. Kept for backward compatibility."""
    from vexa_cli.commands._scan_helpers import resolve_ai_provider

    return resolve_ai_provider(config, ai_provider_override)


# ---------------------------------------------------------------------------
# Output Formatting — PRD Section 8.3/8.4
# ---------------------------------------------------------------------------


def _print_fix_header(
    version: str,
    path: Path,
    cloud_provider: CloudProvider,
    severity: str,
    config,
    capabilities=None,
):
    """Print the fix command header with professional configuration summary."""
    print_banner(version=version)

    start_time = datetime.now()
    console.print(
        f"\n[bold white]🚀 Fix Initiated:[/bold white] [bright_cyan]{start_time.strftime('%Y-%m-%d %H:%M:%S')}[/bright_cyan]"
    )
    console.print("─" * 50)

    # Resolve display name
    display_map = {
        "google": "GOOGLE GEMINI",
        "openai": "OPENAI",
        "anthropic": "ANTHROPIC",
        "ollama": "LOCAL OLLAMA",
        "none": "None",
    }
    effective_ai_display = display_map.get(
        cloud_provider.value.lower(), cloud_provider.value.upper()
    )

    # Check if a model override is active for display
    if cloud_provider == CloudProvider.OLLAMA and hasattr(config.ai, "model"):
        effective_ai_display = f"LOCAL OLLAMA ({config.ai.model})"

    conf_content = (
        f"[bold sky_blue1]Target:[/bold sky_blue1]   [blue]{path.resolve()}[/blue]\n"
        f"[bold sky_blue1]Mode:[/bold sky_blue1]     [white]Local Fix[/white]\n"
        f"[bold sky_blue1]AI Threshold:[/bold sky_blue1] [yellow]{severity.upper()}+[/yellow]\n"
        f"[bold sky_blue1]Provider:[/bold sky_blue1] [bright_cyan]{effective_ai_display}[/bright_cyan]\n"
        f"[dim]AI Review: {'✅' if capabilities and capabilities.code_review_enabled else '❌'}  |  FP Detection: {'✅' if capabilities and capabilities.false_positive_detection else '❌'}[/dim]"
    )

    if cloud_provider == CloudProvider.OLLAMA:
        conf_content += (
            "\n\n[bold green]🔒 Privacy Vault Active[/bold green] — Zero data egress."
        )

    console.print(
        Panel(
            conf_content,
            title="[bold white]Fix Configuration[/bold white]",
            border_style="bright_cyan",
            expand=False,
        )
    )


def _print_no_issues_found(false_positives_count: int, path: Path):
    """Print encouraging message when no issues are found."""
    console.print()
    console.print("[bold green]🎉 Your code looks great![/bold green]")
    console.print(f"   No security issues found in [bold]{path}[/bold].")
    if false_positives_count > 0:
        console.print(
            f"   [dim](We checked {false_positives_count} potential issue"
            f"{'s' if false_positives_count != 1 else ''} and confirmed "
            f"{'they were' if false_positives_count != 1 else 'it was'} all false alarms.)[/dim]"
        )
    console.print()


def _print_no_fixable_issues(total_findings: int, false_positives_count: int):
    """Print message when there are findings but none are fixable."""
    console.print()
    console.print(
        "[bold yellow]📋 Issues found, but none are ready for auto-fix.[/bold yellow]"
    )
    console.print(
        f"   Found {total_findings} issue{'s' if total_findings != 1 else ''}, "
        f"but the AI confidence is too low to suggest automatic fixes."
    )
    console.print("   Run [bold]vexa scan .[/bold] for a full detailed report.")
    console.print()


def _print_low_confidence_issue(
    idx: int,
    total: int,
    risk_label: str,
    file_path: str,
    line_start: int,
    plain_title: str,
    plain_explanation: str,
    confidence: float,
    confidence_level: str,
):
    """
    Print a finding where the AI is not confident enough to fix.
    PRD Section 8.4 format.
    """
    console.print(
        Panel(
            f"[bold]Issue {idx} of {total}[/bold] — [bold yellow]{risk_label}[/bold yellow]\n"
            f"📍 [bold]{_clean_file_path(file_path)}[/bold], line {line_start}\n\n"
            f"{plain_title}\n\n"
            f"[dim]{plain_explanation}[/dim]\n\n"
            f"[yellow]Review Mode[/yellow] — Showing for awareness only.\n"
            f"[dim]A human review is recommended (Confidence: {confidence:.0f}%).[/dim]",
            border_style="yellow",
            expand=True,
        )
    )


def _present_and_apply_fix(
    idx: int,
    total: int,
    risk_label: str,
    finding,
    plain_title: str,
    plain_explanation: str,
    confidence: float,
    confidence_level: str,
    workspace_path: Path,
    dry_run: bool,
    auto_apply: bool,
    is_local_mode: bool,
) -> bool:
    """
    Present a fixable issue to the developer and optionally apply it.
    PRD Section 8.3 format.

    Returns True if the fix was applied, False if skipped.
    """
    # Build the before/after display
    before_code = finding.code_snippet or ""
    after_code = finding.remediation_code or ""

    # Determine confidence color
    conf_color = (
        "green" if confidence >= 70 else "yellow" if confidence >= 40 else "red"
    )

    # Build the panel content
    content = (
        f"[bold]Issue {idx} of {total}[/bold] — [bold red]{risk_label}[/bold red]\n"
        f"📍 [bold]{_clean_file_path(finding.file_path)}[/bold], line {finding.line_start}\n\n"
        f"{plain_title}\n\n"
        f"[dim]{plain_explanation}[/dim]\n\n"
        f"[{conf_color}]AI Confidence: {confidence_level} ({confidence:.0f}%)[/{conf_color}]"
    )

    if is_local_mode:
        content += "\n[dim]🔒 Analysed locally[/dim]"

    console.print(
        Panel(
            content,
            border_style="red"
            if "CRITICAL" in risk_label or "HIGH" in risk_label
            else "yellow",
            expand=True,
        )
    )

    # Show the diff
    if before_code.strip() and after_code.strip():
        console.print("\n[bold]Here is the fix:[/bold]\n")
        
        diff_text = _generate_unified_diff(finding, workspace_path)
        if diff_text:
            # Skip file headers and @@ range markers
            clean_lines = [
                line for line in diff_text.splitlines()[2:] 
                if not line.startswith("@@")
            ]
            clean_diff = "\n".join(clean_lines)
            console.print(Syntax(clean_diff, "diff", theme="monokai", line_numbers=False))
        else:
            console.print("[red]Before:[/red]")
            console.print(Syntax(before_code.strip()[:500], "python", theme="monokai", line_numbers=False))
            console.print("\n[green]After:[/green]")
            console.print(Syntax(after_code.strip()[:500], "python", theme="monokai", line_numbers=False))

        # Show implementation steps if available
        if finding.implementation_steps:
            console.print()
            for step in finding.implementation_steps[:3]:  # Max 3 steps
                console.print(f"  [dim]💡 {step}[/dim]")
    elif after_code.strip():
        console.print("\n[bold]Suggested fix:[/bold]")
        console.print(
            Syntax(
                after_code.strip()[:500], "python", theme="monokai", line_numbers=False
            )
        )

    if dry_run:
        console.print("\n[dim]  (Dry run — fix not applied)[/dim]")
        return False

    # Ask for approval
    if auto_apply:
        applied = _apply_fix(finding, workspace_path)
        if applied:
            console.print(
                f"\n[bold green]✅ Fixed.[/bold green] {_clean_file_path(finding.file_path)} updated."
            )
            return True
        else:
            console.print(
                f"\n[bold yellow]⚠ Could not apply fix to {_clean_file_path(finding.file_path)}.[/bold yellow]"
            )
            return False

    try:
        apply = Confirm.ask(
            "\nApply this fix?",
            default=True,
            console=console,
        )
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Skipped.[/dim]")
        return False

    if apply:
        applied = _apply_fix(finding, workspace_path)
        if applied:
            console.print(
                f"\n[bold green]✅ Fixed.[/bold green] {_clean_file_path(finding.file_path)} updated."
            )
            return True
        else:
            console.print(
                "\n[bold yellow]⚠ Could not apply fix automatically.[/bold yellow]"
            )
            console.print(
                "[dim]The fix is shown above — you can apply it manually.[/dim]"
            )
            return False
    else:
        console.print("[dim]Skipped.[/dim]")
        return False


# ---------------------------------------------------------------------------
# Fix Application
# ---------------------------------------------------------------------------


def _apply_fix(finding, workspace_path: Path) -> bool:
    """
    Apply a single fix to a file using the RemediationEngine.

    Uses line-range replacement with string-match fallback for robustness.
    """
    try:
        from vexa_mcp.scanner.remediation_engine import RemediationEngine

        engine = RemediationEngine(workspace_path)

        # Resolve the file path
        file_path = finding.file_path
        if not Path(file_path).is_absolute():
            file_path = str(workspace_path / file_path)

        result = engine.apply_patch(
            file_path=file_path,
            finding_id=finding.id,
            finding_title=finding.title,
            severity=finding.severity,
            line_start=finding.line_start,
            line_end=finding.line_end,
            original_code=finding.code_snippet or "",
            patched_code=finding.remediation_code,
        )

        engine.finalize()
        return result is not None

    except ImportError:
        # MCP server package not installed — do inline fix
        return _apply_fix_inline(finding, workspace_path)
    except Exception:
        return False


def _apply_fix_inline(finding, workspace_path: Path) -> bool:
    """
    Fallback fix application when RemediationEngine is not available.

    Applies the fix directly using line-range replacement.
    """
    try:
        file_path = finding.file_path
        if not Path(file_path).is_absolute():
            file_path = str(workspace_path / file_path)

        target = Path(file_path)
        if not target.exists():
            return False

        lines = target.read_text(encoding="utf-8").splitlines(keepends=True)

        line_start = finding.line_start
        line_end = finding.line_end
        patched_code = finding.remediation_code

        if line_start < 1 or line_end > len(lines):
            return False

        # Ensure patched code ends with newline
        if patched_code and not patched_code.endswith("\n"):
            patched_code += "\n"

        before = lines[: line_start - 1]
        after = lines[line_end:]
        new_content = "".join(before) + patched_code + "".join(after)
        target.write_text(new_content, encoding="utf-8")

        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Diff Generation (for --dry-run)
# ---------------------------------------------------------------------------


def _generate_unified_diff(finding, workspace_path: Path) -> Optional[str]:
    """Generate a unified diff for a single fix."""
    try:
        file_path = finding.file_path
        if not Path(file_path).is_absolute():
            file_path = str(workspace_path / file_path)

        target = Path(file_path)
        if not target.exists():
            return None

        original_lines = target.read_text(encoding="utf-8").splitlines(keepends=True)

        line_start = finding.line_start
        line_end = finding.line_end
        patched_code = finding.remediation_code

        if not patched_code or line_start < 1 or line_end > len(original_lines):
            return None

        if not patched_code.endswith("\n"):
            patched_code += "\n"

        before = original_lines[: line_start - 1]
        after = original_lines[line_end:]
        new_lines = before + [patched_code] + after

        diff = difflib.unified_diff(
            original_lines,
            new_lines,
            fromfile=f"a/{finding.file_path}",
            tofile=f"b/{finding.file_path}",
        )
        return "".join(diff)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _clean_file_path(file_path: str) -> str:
    """
    Clean up a file path for display.

    Removes common prefixes and normalises slashes for readability.
    """
    path = file_path.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    return path
