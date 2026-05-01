"""
Shared scan orchestration helpers for CLI commands.

Eliminates duplication between scan.py and fix.py by centralizing:
- AI provider auto-detection from config / environment
- Scan job creation + progress bar polling loop
"""

import asyncio
import os
from pathlib import Path
from typing import List, Optional

from vexa.common.models import ScanMode, ScanResult, JobStatus
from vexa.common.cloud_provider import CloudProvider, ProviderAvailability


async def ensure_ai_availability(
    cloud_provider: CloudProvider,
    is_ci: bool,
    is_non_interactive: bool,
    console,
) -> CloudProvider:
    """
    Ensure the AI provider is available, prompting for API keys if needed in interactive mode.
    Returns the (possibly updated) CloudProvider.
    """
    if cloud_provider == CloudProvider.NONE:
        return cloud_provider

    status = await ProviderAvailability.check_provider(cloud_provider, check_quota=True)
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
                    status = await ProviderAvailability.check_provider(
                        cloud_provider, check_quota=True
                    )
                    if status["available"]:
                        console.print(
                            "[bold green]✔[/bold green] API Key accepted for this session."
                        )

        if not status["available"]:
            from rich.prompt import Confirm

            if is_ci or is_non_interactive:
                console.print(
                    "[bold yellow]⚠[/bold yellow] Non-interactive / CI environment detected. Automatically proceeding without AI enrichment."
                )
                return CloudProvider.NONE
            elif Confirm.ask(
                "Would you like to proceed without AI enrichment?",
                default=False,
                console=console,
            ):
                console.print("➜ Proceeding with AI capabilities disabled.")
                return CloudProvider.NONE
            else:
                console.print(
                    "[bold red]✖[/bold red] Aborted. Please configure the AI provider and try again."
                )
                import sys

                sys.exit(0)

    return cloud_provider


def resolve_ai_provider(
    config, ai_provider_override: Optional[str] = None
) -> CloudProvider:
    """
    Determine which AI provider to use, in priority order:
    1. CLI --ai-provider flag
    2. .vexa.yml config
    3. Auto-detect from environment variables
    4. None (scan-only mode)
    """
    if ai_provider_override:
        return CloudProvider(ai_provider_override)

    if config.ai.enabled and config.ai.provider != CloudProvider.NONE:
        return config.ai.provider

    # Auto-detect from environment
    if os.environ.get("GOOGLE_API_KEY"):
        return CloudProvider.GOOGLE
    if os.environ.get("VEXA_ANTHROPIC_API_KEY"):
        return CloudProvider.ANTHROPIC
    if os.environ.get("VEXA_OPENAI_API_KEY"):
        return CloudProvider.OPENAI

    return CloudProvider.NONE


async def run_scan_with_job_manager(
    engine,
    job_manager,
    path: Path,
    scanners: Optional[List[str]],
    mode: ScanMode,
    timeout: int,
    cloud_provider: CloudProvider,
    ai_min_severity: str = "medium",
    cli_excludes: Optional[List[str]] = None,
    incremental: bool = False,
) -> ScanResult:
    """
    Create a scan job, execute it via the scanner engine, and return the result.

    This is the shared core that both `scan` and `fix` commands use.
    The caller is responsible for polling `job_manager.get_status()` for progress.
    """
    job_id_box = {"id": None}

    async def scan_task():
        for _ in range(50):
            if job_id_box["id"]:
                break
            await asyncio.sleep(0.01)

        job_id = job_id_box["id"]

        async def progress_cb(pct, msg):
            if job_id:
                await job_manager.update_job(job_id, pct, status=JobStatus.RUNNING)

        return await engine.run_scan_with_progress(
            path,
            job_id,
            scanners,
            mode,
            timeout=timeout,
            progress_callback=progress_cb,
            cloud_provider=cloud_provider,
            cli_excludes=cli_excludes,
            incremental=incremental,
            ai_min_severity=ai_min_severity,
        )

    scan_job_id = await job_manager.create_job("scan", scan_task())
    job_id_box["id"] = scan_job_id
    return scan_job_id


async def poll_scan_progress(
    job_manager,
    scan_job_id: str,
    progress_bar,
    task_bar,
    description_map: Optional[dict] = None,
    prefix: str = "",
) -> None:
    """
    Poll the job manager for scan progress and update a Rich progress bar.

    Args:
        job_manager: The JobManager instance to poll.
        scan_job_id: The job ID to monitor.
        progress_bar: Rich Progress instance.
        task_bar: The task handle from progress_bar.add_task().
        description_map: Optional dict mapping progress thresholds to descriptions.
            Default: {5: "Initializing...", 15: "Starting tools...", 75: "Running...",
                      80: "Merging...", 90: "AI analysis...", 100: "Finalizing..."}
        prefix: Optional prefix for descriptions (e.g., "[local] ").

    Raises:
        Exception: If the scan fails, is cancelled, or times out.
    """
    if description_map is None:
        description_map = {
            5: "Initializing scan engine...",
            15: "Starting security tools...",
            75: "Running scanners...",
            80: "Merging findings...",
            90: "Enriching with AI analysis...",
            100: "Finalizing results...",
        }

    # Sort thresholds ascending for ordered lookup
    thresholds = sorted(description_map.keys())

    while True:
        status_data = await job_manager.get_status(scan_job_id)
        if not status_data:
            await asyncio.sleep(0.5)
            continue

        progress_val = status_data.get("progress", 0)
        state = status_data.get("state", "pending").lower()

        # Find the appropriate description for the current progress level
        desc = description_map[thresholds[0]]  # default to first
        for t in thresholds:
            if progress_val < t:
                break
            desc = description_map[t]

        if prefix:
            desc = f"{prefix}{desc}"

        progress_bar.update(task_bar, completed=progress_val, description=desc)

        if state == "completed":
            progress_bar.update(
                task_bar,
                completed=100,
                description="[bold green]Scan completed successfully[/bold green]",
            )
            break
        elif state in ["failed", "cancelled", "timeout"]:
            error = status_data.get("error", "Unknown error")
            progress_bar.update(
                task_bar, description=f"[bold red]Scan {state}[/bold red]"
            )
            raise Exception(f"Scan failed: {error}")

        await asyncio.sleep(0.5)
