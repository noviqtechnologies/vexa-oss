"""
FastMCP Server for Vexa Scanner.

Exposes security scanning capabilities via MCP protocol.

Implements:
- SS-001: Orchestrates security tool execution via MCP
- SS-013: MCP server with all tools for IDE integration
- SS-007: Async job management with progress tracking
"""

import asyncio
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

# Suppress all deprecation warnings to prevent MCP JSON-RPC corruption on stdout
warnings.filterwarnings("ignore")

from fastmcp import FastMCP, Context

from vexa.common.logging import get_logger
from vexa.common.models import JobStatus, ScanMode
from vexa.common.cloud_provider import CloudProvider
from vexa.jobs.manager import get_job_manager
from vexa.scanners.engine import get_scanner_engine
from vexa.ai_providers.manager import get_ai_manager
from vexa.reports.generator import get_report_generator
from vexa.common.models import Finding
from vexa.common.models import ScanResult
from vexa.common.config_manager import load_config

logger = get_logger(__name__)

# Create FastMCP server
server = FastMCP("Vexa Scanner")


async def create_scan_job(
    path: str,
    scanners: Optional[List[str]] = None,
    mode: str = "local",
    cloud_provider: str = "none",
    cli_excludes: Optional[List[str]] = None,
    incremental: bool = False,
    ctx_logger: Any = None,
) -> Dict[str, str]:
    """Core logic to create a scan job."""
    scan_path = Path(path).resolve()
    if not scan_path.exists():
        raise ValueError(f"Path does not exist: {path}")

    # Parse enums
    try:
        scan_mode = ScanMode(mode.lower())
    except ValueError:
        scan_mode = ScanMode.LOCAL

    try:
        provider = CloudProvider(cloud_provider.lower())
    except ValueError:
        provider = CloudProvider.NONE

    job_manager = get_job_manager()

    # define container for job_id
    job_id_box = {"id": None}

    async def scan_task():
        # Wait briefly for ID to be populated
        for _ in range(50):
            if job_id_box["id"]:
                break
            await asyncio.sleep(0.01)

        job_id = job_id_box["id"]
        scanner_engine = get_scanner_engine()

        if not job_id:
            logger.error("Failed to acquire job ID for progress tracking")
            return await scanner_engine.run_scan(scan_path, scanners, scan_mode)

        async def progress_cb(pct, msg):
            await job_manager.update_job(job_id, pct, status=JobStatus.RUNNING)
            # Log specific progress points
            if pct % 10 == 0:
                logger.debug(f"Job {job_id} progress {pct}%: {msg}")

        try:
            # Run scan
            result = await scanner_engine.run_scan_with_progress(
                scan_path,
                job_id,
                scanners,
                scan_mode,
                timeout=480,
                progress_callback=progress_cb,
                cloud_provider=provider,
                cli_excludes=cli_excludes,
                incremental=incremental,
            )

            return result

        except Exception as e:
            logger.error(f"Scan job {job_id} failed: {e}")
            raise

    # Create the job with the task
    scan_job_id = await job_manager.create_job("scan", scan_task())

    # Populate the box so the task can use it
    job_id_box["id"] = scan_job_id

    if ctx_logger:
        res = ctx_logger(f"Started scan job: {scan_job_id}")
        if asyncio.iscoroutine(res):
            await res

    return {
        "job_id": scan_job_id,
        "status": "pending",
        "message": "Scan job created successfully",
    }


@server.tool()
async def run_scan_local(
    path: str,
    scanners: Optional[List[str]] = None,
    mode: str = "local",
    cloud_provider: str = "none",
    cli_excludes: Optional[List[str]] = None,
    incremental: bool = False,
    ctx: Context = None,
) -> Dict[str, str]:
    """
    Start a security scan on a local path.

    Returns a job_id immediately for progress tracking.

    Args:
        path: Absolute path to the directory to scan
        scanners: Optional list of specific scanners to run (default: all)
        mode: Execution mode ("local" or "container")
        cloud_provider: Cloud provider for AI analysis ("google", "aws", "azure", "none")
        incremental: If True, only scan files modified in git.

    Returns:
        Dictionary containing job_id and status
    """
    return await create_scan_job(
        path,
        scanners,
        mode,
        cloud_provider,
        cli_excludes,
        incremental=incremental,
        ctx_logger=ctx.info if ctx else None,
    )


@server.tool()
async def get_scan_status(
    job_id: str,
) -> Dict[str, Any]:
    """
    Get the status of a running scan job.

    Args:
        job_id: The job ID returned by run_scan_local

    Returns:
        Status dictionary with progress, state, and errors
    """
    return await fetch_scan_status(job_id)


@server.tool()
async def enrich_findings(
    findings: List[Dict[str, Any]],
    ai_provider: str = "none",
    api_key: Optional[str] = None,
    ai_model: Optional[str] = None,
    ollama_url: Optional[str] = None,
) -> str:
    """
    Enrich findings with centralized AI analysis (including False Positive evaluation).

    Args:
        findings: Array of finding dict objects from a scan result.
        ai_provider: Provider name ('google', 'openai', 'anthropic', 'ollama', or 'none').
        api_key: Optional API key override for the chosen provider.
        ai_model: Optional model name override.
        ollama_url: Optional URL for local Ollama instance.

    Returns:
        JSON string of enriched finding objects to prevent fastmcp List serialization.
    """
    import json

    if not findings or ai_provider.lower() == "none":
        return json.dumps(findings)

    manager = get_ai_manager(
        ai_provider_override=ai_provider,
        api_key_override=api_key,
        ai_model_override=ai_model,
        ollama_url_override=ollama_url,
    )

    if not manager._primary_provider or not manager._primary_provider.is_available:
        logger.warning(f"AI Provider {ai_provider} unavailable for enrichment.")
        return json.dumps(findings)

    try:
        # Convert dicts back to Finding models for the Core Engine
        finding_models = []
        for f in findings:
            # Use the basic fields to reconstruct.
            model = Finding(
                id=f.get("id", ""),
                scanner=f.get("scanner", ""),
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=f.get(
                    "severity", "info"
                ),  # String severity works generally in parser
                file_path=f.get("filePath", ""),
                line_start=f.get("line", 0),
                line_end=f.get("endLine", 0),
                code_snippet=f.get("codeSnippet", ""),
            )
            finding_models.append(model)

        # Call the Core Manager (batch size and FP thresholds are central)
        # enrich_findings returns (valid_findings, false_positives)
        enhanced_models, _fps = await manager.enrich_findings(
            finding_models, is_workspace_scan=True
        )

        # Merge back to raw dicts for transport
        enhanced_dict = {em.id: em for em in enhanced_models}

        results = []
        for raw in findings:
            fid = raw.get("id")
            if fid in enhanced_dict:
                em = enhanced_dict[fid]

                # Expand standard raw with enriched fields
                # Filter out anything flagged > 90% confidence as False Positive
                if (
                    em.is_false_positive
                    and (em.false_positive_confidence or 0.0) >= 0.90
                ):
                    continue  # Exclude from returned list natively

                raw["remediationCode"] = em.remediation_code
                raw["remediationDescription"] = em.remediation_guidance
                raw["isFalsePositive"] = em.is_false_positive
                raw["falsePositiveConfidence"] = em.false_positive_confidence
                raw["falsePositiveReason"] = em.fp_explanation
                results.append(raw)
            else:
                results.append(raw)

        return json.dumps(results)

    except Exception as e:
        logger.error(f"Enrichment failed in MCP: {e}")
        return json.dumps(findings)


async def fetch_scan_status(job_id: str) -> Dict[str, Any]:
    """Core logic to fetch scan status."""
    job_manager = get_job_manager()
    status_data = await job_manager.get_status(job_id)

    if not status_data:
        return {"error": "Job not found", "jobId": job_id, "status": "failed"}

    # Map to VS Code ScanStatusResponse interface
    return {
        "jobId": job_id,
        "status": status_data.get("state", "PENDING").lower(),
        "progress": status_data.get("progress", 0),
        "message": status_data.get("error", ""),
        "error": status_data.get("error"),
    }


@server.tool()
async def get_scan_result(
    job_id: str,
) -> Dict[str, Any]:
    """
    Get the final results of a completed scan.

    Args:
        job_id: The job ID

    Returns:
        Scan result dictionary containing findings or error details
    """
    return await fetch_scan_result(job_id)


@server.tool()
async def list_scanners(
    mode: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    List available security scanners.

    Args:
        mode: Optional mode to filter by ("local" or "container")
    """
    engine = get_scanner_engine()
    scan_mode = None
    if mode:
        try:
            scan_mode = ScanMode(mode.lower())
        except ValueError:
            pass

    return engine.get_scanners_metadata(scan_mode)


@server.tool()
async def generate_report(
    job_id: str, formats: List[str] = ["html"], output_dir: str = "./vexa_reports"
) -> Dict[str, str]:
    """
    Generate reports from a completed scan job.

    Args:
        job_id: The ID of the completed scan job
        formats: List of formats to generate ("html", "json", "sarif", "markdown")
        output_dir: Output directory relative to workspace or absolute path

    Returns:
        Dictionary mapping format to generated file path
    """
    job_manager = get_job_manager()
    result = await job_manager.get_result(job_id)

    if result is None:
        return {"error": f"Job {job_id} not found or not completed."}

    # Rehydrate if it's a dict
    if isinstance(result, dict):
        try:
            result = ScanResult.model_validate(result)
        except Exception as e:
            return {"error": f"Failed to parse result model: {e}"}

    try:
        generator = get_report_generator()
        out_path = Path(output_dir).resolve()

        generated_files = {}
        for fmt in formats:
            try:
                path = generator.generate(result, fmt, out_path)
                generated_files[fmt] = str(path)
            except Exception as e:
                generated_files[fmt] = f"Error: {str(e)}"

        return generated_files
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return {"error": str(e)}


async def fetch_scan_result(job_id: str) -> Dict[str, Any]:
    """Core logic to fetch scan result and transform for VS Code (CamelCase)."""
    job_manager = get_job_manager()
    result = await job_manager.get_result(job_id)

    if result is None:
        status_data = await job_manager.get_status(job_id)
        if status_data:
            return {
                "status": status_data["state"].lower(),
                "message": "Result not available yet",
            }
        return {"error": "Job not found"}

    # If it's already an error dict, return it
    if isinstance(result, dict) and "error" in result:
        return result

    # Convert Pydantic/Dataclass model to dict if needed
    data = result.model_dump() if hasattr(result, "model_dump") else result
    if hasattr(result, "__dict__") and not isinstance(result, dict):
        data = result.__dict__

    raw_findings = data.get("findings", [])
    logger.info("Found %d findings in job %s", len(raw_findings), job_id)

    # 1. Map findings to CamelCase for VS Code
    findings = []
    for f in raw_findings:
        # Handle both dict and object finding representation
        f_id = f.get("id") if isinstance(f, dict) else getattr(f, "id", "")
        f_scanner = (
            f.get("scanner") if isinstance(f, dict) else getattr(f, "scanner", "")
        )
        f_title = f.get("title") if isinstance(f, dict) else getattr(f, "title", "")
        f_desc = (
            f.get("description")
            if isinstance(f, dict)
            else getattr(f, "description", "")
        )

        # Severity might be an enum
        f_sev = f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "")
        if hasattr(f_sev, "value"):
            f_sev = f_sev.value

        f_path = (
            f.get("file_path") if isinstance(f, dict) else getattr(f, "file_path", "")
        )
        f_line = (
            f.get("line_start") if isinstance(f, dict) else getattr(f, "line_start", 0)
        )
        f_end = f.get("line_end") if isinstance(f, dict) else getattr(f, "line_end", 0)

        f_rem_code = (
            f.get("remediation_code")
            if isinstance(f, dict)
            else getattr(f, "remediation_code", "")
        )
        f_rem_desc = (
            f.get("remediation_guidance")
            if isinstance(f, dict)
            else getattr(f, "remediation_guidance", "")
        )
        f_cwe = f.get("cwe_ids") if isinstance(f, dict) else getattr(f, "cwe_ids", [])
        f_code_snippet = (
            f.get("code_snippet")
            if isinstance(f, dict)
            else getattr(f, "code_snippet", "")
        )

        findings.append(
            {
                "id": f_id,
                "ruleId": f_id,  # Fallback ruleId to ID
                "scanner": f_scanner,
                "title": f_title,
                "description": f_desc,
                "severity": f_sev,
                "filePath": f_path,
                "lineStart": f_line,
                "column": 0,
                "lineEnd": f_end,
                "codeSnippet": f_code_snippet,
                "remediationCode": f_rem_code,
                "remediationDescription": f_rem_desc,
                "cweIds": f_cwe,
            }
        )

    # 2. Build scanSummary block (required by TS interface)
    counts = {}
    for f in findings:
        sev = str(f["severity"]).lower()
        counts[sev] = counts.get(sev, 0) + 1

    summary = {
        "totalFindings": len(findings),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "scannersRun": data.get("scanners_run", [])
        if isinstance(data, dict)
        else getattr(result, "scanners_run", []),
        "scannersFailed": data.get("errors", [])
        if isinstance(data, dict)
        else getattr(result, "errors", []),
        "durationSeconds": data.get("duration_seconds", 0)
        if isinstance(data, dict)
        else getattr(result, "duration_seconds", 0),
    }

    # 3. Final TS-compatible structure
    return {
        "jobId": job_id,
        "findings": findings,
        "scanSummary": summary,
        "success": data.get("success", True)
        if isinstance(data, dict)
        else getattr(result, "success", True),
    }


@server.tool()
async def get_configuration(directory: str) -> Dict[str, Any]:
    """
    Fetch the centralized .vexa.yml configuration for a given directory.

    Args:
        directory: Path to the workspace or project directory

    Returns:
        JSON representation of the parsed VexaConfig
    """
    try:
        config = load_config(directory)
        return config.model_dump()
    except Exception as e:
        logger.error(f"Failed to load configuration for {directory}: {e}")
        return {}


@server.tool()
async def auto_remediate_workspace(
    path: str = ".",
    severity_threshold: str = "medium",
    dry_run: bool = True,
    max_iterations: int = 1,
    verify_only: bool = False,
    ctx: Context = None,
) -> str:
    """
    Autonomous Security Agent: Scans the workspace, generates AI remediation code, and optionally applies it.

    Args:
        path: Directory to scan and remediate.
        severity_threshold: Minimum severity to remediate ("critical", "high", "medium", "low").
        dry_run: If True, returns a Fix Plan (diffs). If False, applies patches directly to the workspace safely.
        max_iterations: Number of scan-patch-verify cycles (default 1). Set >1 for iterative self-healing.
        verify_only: If True, only re-scans to verify previous remediations without applying new patches.

    Returns:
        LLM-readable Fix Plan detailing what was (or will be) changed. Exit code is always 0.
    """
    return await _auto_remediate_workspace_internal(
        path=path,
        severity_threshold=severity_threshold,
        dry_run=dry_run,
        max_iterations=max_iterations,
        verify_only=verify_only,
        ctx=ctx,
    )


async def _auto_remediate_workspace_internal(
    path: str = ".",
    severity_threshold: str = "medium",
    dry_run: bool = True,
    max_iterations: int = 1,
    verify_only: bool = False,
    ctx: Any = None,
) -> str:
    """Internal logic for autonomous remediation."""
    import uuid
    from vexa.common.models import ScanMode, CloudProvider as CP
    from vexa_mcp.scanner.remediation_engine import RemediationEngine

    scan_path = Path(path).resolve()
    if not scan_path.exists():
        return f"Error: Path {path} does not exist."

    engine = RemediationEngine(scan_path)

    # 1. Snapshot for safety (only for active patching)
    if not dry_run and not verify_only:
        try:
            backup = engine.create_snapshot()
            if ctx:
                ctx.info(f"Created workspace snapshot at {backup}")
        except RuntimeError as e:
            return f"Error: {e}. Aborting remediation for safety."

    # Resolve AI provider
    ai_manager = get_ai_manager()
    provider = CP.NONE
    if (
        getattr(ai_manager, "_primary_provider", None)
        and ai_manager._primary_provider.is_available
    ):
        provider = ai_manager._primary_provider.PROVIDER_TYPE

    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    target_sev_val = severity_map.get(severity_threshold.lower(), 2)

    iteration_reports = []

    for iteration in range(1, max_iterations + 1):
        if ctx:
            ctx.info(f"Iteration {iteration}/{max_iterations}: Scanning...")

        # 2. Scan
        try:
            scanner_engine = get_scanner_engine()
            job_id = f"auto_rem_{uuid.uuid4().hex[:8]}"

            async def dummy_cb(pct, msg):
                pass

            result = await scanner_engine.run_scan_with_progress(
                scan_path,
                job_id,
                None,
                ScanMode.LOCAL,
                timeout=480,
                progress_callback=dummy_cb,
                cloud_provider=provider,
            )
        except Exception as e:
            iteration_reports.append(f"Iteration {iteration}: Scan failed — {e}")
            break

        # Filter findings by severity
        actionable = [
            f
            for f in result.findings
            if severity_map.get(str(f.severity).lower(), 0) >= target_sev_val
            and getattr(f, "remediation_code", None)
        ]

        if not actionable:
            iteration_reports.append(
                f"Iteration {iteration}: {len(result.findings)} total findings, "
                f"0 actionable at severity >= {severity_threshold}. Clean!"
            )
            break

        # 3. Generate fix plan
        if dry_run or verify_only:
            plan = engine.generate_fix_plan(actionable, severity_threshold)
            iteration_reports.append(
                f"Iteration {iteration}: {len(actionable)} remediable findings.\n{plan}"
            )
            break  # Dry run / verify only runs once

        # 4. Apply patches
        if ctx:
            ctx.info(f"Iteration {iteration}: Applying {len(actionable)} patches...")

        for f in actionable:
            engine.apply_patch(
                file_path=str(getattr(f, "file_path", "")),
                finding_id=str(getattr(f, "id", "")),
                finding_title=str(getattr(f, "title", "")),
                severity=str(getattr(f, "severity", "")),
                line_start=int(getattr(f, "line_start", 0)),
                line_end=int(getattr(f, "line_end", 0)),
                original_code=str(getattr(f, "code_snippet", "")),
                patched_code=str(getattr(f, "remediation_code", "")),
            )

        applied = engine.ledger.get_applied_count()
        iteration_reports.append(
            f"Iteration {iteration}: Applied {applied} patches from {len(actionable)} actionable findings."
        )

    # Finalize
    engine.finalize()

    header = "Vexa Autonomous Agency — Remediation Report\n"
    header += f"Workspace: {scan_path}\n"
    header += f"Mode: {'Dry Run' if dry_run else ('Verify Only' if verify_only else 'Active Patching')}\n"
    header += f"Iterations: {len(iteration_reports)}/{max_iterations}\n"
    if engine.backup_dir:
        header += f"Snapshot: {engine.backup_dir}\n"
    header += "---\n"

    return header + "\n".join(iteration_reports)


def main():
    """Entry point for the FastMCP server."""
    import sys
    from vexa import __version__

    print(
        f"Vexa MCP Server: Starting initialization (Version: {__version__})...",
        file=sys.stderr,
    )
    from vexa.common.config import ensure_storage_dirs

    ensure_storage_dirs()
    print("Vexa MCP Server: Storage verified. Starting FastMCP...", file=sys.stderr)
    server.run()


if __name__ == "__main__":
    main()
