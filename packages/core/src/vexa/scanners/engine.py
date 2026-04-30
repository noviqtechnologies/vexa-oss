"""
Scanner Engine Orchestrator for Vexa.

SS-001: Orchestrates security tool execution
SS-002: Support local and container mode
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from vexa.scanners.base import (
    BaseScanner,
    Finding,
    ScanMode,
    ScannerResult,
)
from vexa.scanners.bandit import BanditScanner
from vexa.scanners.semgrep import SemgrepScanner
from vexa.scanners.checkov import CheckovScanner
from vexa.scanners.detect_secrets import DetectSecretsScanner
from vexa.scanners.npm_audit import NpmAuditScanner
from vexa.scanners.grype import GrypeScanner
from vexa.scanners.syft import SyftScanner
from vexa.scanners.pip_audit import PipAuditScanner
from vexa.scanners.pip_licenses import PipLicensesScanner
from vexa.common.logging import get_logger
from vexa.common.models import ScanResult
from vexa.common.cloud_provider import CloudProvider

logger = get_logger(__name__)


class ScannerEngine:
    """
    SS-001: Orchestrates security tool execution.
    SS-002: Support local and container mode.
    
    Usage:
        engine = ScannerEngine()
        result = await engine.run_scan(
            path=Path("/project"),
            scanners=["bandit", "semgrep"],
            mode=ScanMode.LOCAL
        )
    """
    
    # Registry of available scanners
    SCANNERS: Dict[str, Type[BaseScanner]] = {
        "bandit": BanditScanner,
        "semgrep": SemgrepScanner,
        "checkov": CheckovScanner,
        "detect-secrets": DetectSecretsScanner,
        "npm-audit": NpmAuditScanner,
        "grype": GrypeScanner,
        "syft": SyftScanner,
        "pip-audit": PipAuditScanner,
        "pip-licenses": PipLicensesScanner,
    }
    
    def __init__(self):
        """Initialize the scanner engine."""
        self.logger = logger
    
    def get_available_scanners(self, mode: ScanMode = None) -> List[str]:
        """
        Get list of available scanners, optionally filtered by mode.
        
        Args:
            mode: Optional mode to filter by
            
        Returns:
            List of scanner names
        """
        if mode is None:
            return list(self.SCANNERS.keys())
        
        available = []
        for name, scanner_cls in self.SCANNERS.items():
            if mode in scanner_cls.supported_modes:
                available.append(name)
        return available

    def get_scanners_metadata(self, mode: ScanMode = None) -> List[Dict[str, Any]]:
        """
        Get list of available scanners with metadata.
        
        Args:
            mode: Optional mode to filter by
            
        Returns:
            List of scanner metadata dictionaries
        """
        results = []
        for name, scanner_cls in self.SCANNERS.items():
            if mode and mode not in scanner_cls.supported_modes:
                continue
                
            try:
                # Use a lightweight check if possible, otherwise instantiate
                scanner = scanner_cls(mode=mode or ScanMode.LOCAL)
                is_available = scanner.is_available()
            except Exception:
                is_available = False
                
            results.append({
                "name": name,
                "available": is_available,
                "languages": scanner_cls.supported_languages if hasattr(scanner_cls, "supported_languages") else []
            })
        return results
    
    async def run_scan_with_progress(
        self,
        path: Path,
        job_id: str,
        scanners: Optional[List[str]] = None,
        mode: ScanMode = ScanMode.LOCAL,
        timeout: int = 600,
        progress_callback: Optional[callable] = None,
        cloud_provider: CloudProvider = CloudProvider.NONE,
        cli_excludes: Optional[List[str]] = None,
        incremental: bool = False,
        ai_min_severity: str = "medium",
    ) -> ScanResult:
        """
        Run security scans with progress updates - SS-007.
        
        Args:
            path: Target path to scan
            job_id: Associated job ID
            scanners: List of scanners to run
            mode: Execution mode
            timeout: Timeout per scanner
            progress_callback: Callback(percentage, status_text)
            
        Returns:
            ScanResult with merged and validated findings
        """
        import time
        from vexa.scanners.data_merger import get_data_merger
        from vexa.common.performance import PerformanceManager
        from vexa.common.config_manager import load_config
        from vexa.common.path_filter import PathFilter
        
        start_time = time.time()
        started_at = datetime.now(timezone.utc)
        
        config = load_config(path)
        path_filter = PathFilter(
            workspace_root=path if path.is_dir() else path.parent,
            user_config_ignores=config.ignore,
            cli_excludes=cli_excludes,
        )
        exclusions = path_filter.get_scanner_exclusion_list()

        # Dynamic Performance Analysis
        perf_config = PerformanceManager.analyze_repository(path)
        scanned_files = perf_config.file_count
        
        # Only override timeout if using default (600 or 480 from CLI), 
        # allowing PerformanceManager to set the strict PRD-compliant limit.
        if timeout in [480, 600]:
            timeout = perf_config.timeout_seconds
        
        # Initialize false positives list (populated by AI enrichment if enabled)
        fps = []
        
        # Default to all available scanners
        if scanners is None:
            scanners = self.get_available_scanners(mode)
            
        # Optimization: Skip workspace-level scanners for single file scans
        if path.is_file():
            workspace_scanners = {"pip-audit", "pip-licenses", "npm-audit", "grype", "syft", "checkov"}
            original_count = len(scanners)
            scanners = [s for s in scanners if s not in workspace_scanners]
            if len(scanners) < original_count:
                self.logger.info(f"Single file scan detected. Skipping workspace-level scanners: {workspace_scanners & set(scanners if isinstance(scanners, list) else [])}")
        
        # Initial progress
        if progress_callback:
            await progress_callback(0, f"Initializing {len(scanners)} scanners (timeout: {timeout}s)...")
            
        # Instantiate scanners
        scanner_instances = []
        errors = []
        warnings = []
        
        if scanners:
            self.logger.info("Initializing scanners: %s", scanners)
            
        for scanner_name in scanners:
            if scanner_name not in self.SCANNERS:
                self.logger.warning(f"Unknown scanner: {scanner_name}")
                warnings.append(f"Unknown scanner requested: {scanner_name}")
                continue
                
            scanner_cls = self.SCANNERS[scanner_name]
            if mode not in scanner_cls.supported_modes:
                self.logger.warning(f"Scanner {scanner_name} not supported in {mode.value} mode")
                warnings.append(f"Scanner {scanner_name} not supported in {mode.value} mode")
                continue
                
            try:
                scanner = scanner_cls(mode=mode)
                if scanner.is_available():
                    self.logger.info(f"Scanner {scanner_name} is available and active")
                    scanner_instances.append(scanner)
                else:
                    self.logger.warning(f"Scanner {scanner_name} is not available on this system, skipping.")
                    instructions = {
                        "semgrep": "For multi-language analysis, install Semgrep: `pip install semgrep` (Requires WSL2/Linux on Windows)",
                        "bandit": "For Python security analysis, install Bandit: `pip install bandit`",
                        "detect-secrets": "For secret detection, install detect-secrets: `pip install detect-secrets`",
                        "checkov": "For Infrastructure-as-Code analysis, install Checkov: `pip install checkov`",
                    }
                    if scanner_name in instructions:
                        warnings.append(instructions[scanner_name])
            except Exception as e:
                self.logger.error(f"Failed to init {scanner_name}: {e}")
                errors.append(f"Failed to init {scanner_name}: {e}")
        
        if not scanner_instances:
            self.logger.info("No valid scanners available for this scan")
            return ScanResult(
                job_id=job_id,
                success=True,
                errors=errors,
                warnings=warnings + (["No valid scanners available for the selected mode/platform"] if not errors else []),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )
            
        # Run scanners in parallel
        if progress_callback:
            await progress_callback(10, f"Running {len(scanner_instances)} tools in parallel...")
            
        total_scanners = len(scanner_instances)
        completed_scanners = 0
        scanner_results = {}
        
        async def run_wrapper(scanner, idx):
            nonlocal completed_scanners
            try:
                self.logger.info(f"Starting {scanner.name} on {path}")
                # Apply scanner-specific multiplier if available
                scanner_timeout = int(timeout * getattr(scanner, "timeout_multiplier", 1.0))
                result = await scanner.run(path, timeout=scanner_timeout, exclusions=exclusions)
                self.logger.info(f"Completed {scanner.name} with {len(result.findings)} findings")
                
                # Update progress
                completed_scanners += 1
                completion_pct = 10 + (completed_scanners / total_scanners * 60)  # 10% to 70%
                if progress_callback:
                    await progress_callback(
                        completion_pct, 
                        f"Completed {scanner.name} ({completed_scanners}/{total_scanners})"
                    )
                return (scanner.name, result)
            except Exception as e:
                self.logger.error(f"Scanner {scanner.name} execution failed: {e}")
                completed_scanners += 1
                return (scanner.name, e)

        # Execute parallel tasks
        tasks = [run_wrapper(s, i) for i, s in enumerate(scanner_instances)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for name, result in results:
            if isinstance(result, Exception):
                errors.append(f"{name}: {str(result)}")
                scanner_results[name] = ScannerResult(scanner_name=name, success=False, error=str(result))
            else:
                scanner_results[name] = result
                if result.success:
                    self.logger.info(f"Adding {len(result.findings)} findings from {name}")
                else:
                    self.logger.warning(f"Scanner {name} failed: {result.error}")
                    errors.append(f"{name} failure: {result.error}")
        
        # Merge and Deduplicate
        if progress_callback:
            await progress_callback(75, "Merging and deduplicating findings...")
            
        merger = get_data_merger()
        
        from vexa.common.models import Finding as ModelFinding
        
        # Group by scanner for merger
        findings_map = {}
        for name, result in scanner_results.items():
            if result.success:
                # Convert lightweight ScannerFinding dataclasses to Pydantic models
                # Pydantic V2 handles dict/dataclass coercion automatically if field names match.
                # Use TypeAdapter or dump to dicts if required, but model_validate is safer.
                findings_map[name] = [
                    ModelFinding.model_validate(f, from_attributes=True) 
                    for f in result.findings
                ]
        
        self.logger.info(f"Merging findings from {list(findings_map.keys())}")
        merged_findings = merger.merge_findings(findings_map)
        self.logger.info(f"Total merged findings before filtering: {len(merged_findings)}")
        
        # Filter Findings on Commented Lines [SV-011]
        active_findings = []
        for f in merged_findings:
            if not self._is_finding_commented(path, f):
                active_findings.append(f)
            else:
                self.logger.info(f"Filtered finding {f.id} ({f.title}) as it resides on a commented or reference line")
        
        merged_findings = active_findings
        self.logger.info(f"Total merged findings after filtering: {len(merged_findings)}")
        
        # Apply Incremental Filter
        if incremental:
            try:
                import subprocess
                cwd = path if path.is_dir() else path.parent
                # Get modified, added, and untracked files
                git_diff = subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], cwd=cwd).decode('utf-8')
                git_untracked = subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], cwd=cwd).decode('utf-8')
                
                # Normalize modified file paths for exact comparison
                norm_modified = set(
                    m.strip().replace("\\", "/").lstrip("./") for m in 
                    (git_diff.splitlines() + git_untracked.splitlines()) if m.strip()
                )
                
                incremental_findings = []
                for finding in merged_findings:
                    f_path = finding.file_path.replace("\\", "/")
                    if f_path.startswith("./"):
                        f_path = f_path[2:]
                    # Exact match or suffix match with path separator to avoid partial overlaps
                    if f_path in norm_modified or any(f_path.endswith("/" + m) for m in norm_modified):
                        incremental_findings.append(finding)
                
                self.logger.info(f"Incremental scan filtered findings from {len(merged_findings)} down to {len(incremental_findings)}")
                merged_findings = incremental_findings
            except Exception as e:
                self.logger.warning(f"Failed to get git diff for incremental scan: {e}")
                
        # Apply Framework Mapping [SS-014]
        try:
            from vexa.scanners.framework_mapper import get_framework_mapper
            mapper = get_framework_mapper()
            merged_findings = mapper.map_findings(merged_findings)
        except Exception as e:
            self.logger.error(f"Framework mapping failed: {e}")
            errors.append(f"Framework mapping failed: {str(e)}")
        
        # AI Enrichment [G-002]
        if cloud_provider != CloudProvider.NONE:
            if progress_callback:
                await progress_callback(80, f"Enriching findings with {cloud_provider.value} AI...")
                
            # Populate missing snippets from filesystem before sending to AI
            # This is critical for tools like detect-secrets or checkov that might miss snippets.
            for finding in merged_findings:
                if not finding.code_snippet and finding.file_path:
                    try:
                        # Normalize finding path and target path
                        f_path = finding.file_path.replace("\\", "/")
                        if f_path.startswith("./"):
                            f_path = f_path[2:]
                        
                        filepath = path / f_path if not Path(f_path).is_absolute() else Path(f_path)
                        filepath = filepath.resolve()
                        
                        if filepath.exists() and filepath.is_file():
                            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                                lines = f.readlines()
                                if 1 <= finding.line_start <= len(lines):
                                    finding.code_snippet = lines[finding.line_start-1].strip()
                    except Exception as e:
                        self.logger.debug(f"Failed to auto-populate snippet for {finding.file_path}: {e}")

            try:
                from vexa.ai_providers.manager import get_ai_manager
                ai_manager = get_ai_manager(cloud_provider, min_severity=ai_min_severity)
                
                # Enrich findings using AI manager
                self.logger.info(f"Sending {len(merged_findings)} findings for AI enrichment")
                enriched, fps = await ai_manager.enrich_findings(merged_findings)
                merged_findings = enriched
                self.logger.info(f"AI enrichment complete, got {len(merged_findings)} valid findings and {len(fps)} false positives back")
                
            except ImportError:
                self.logger.warning("AI Providers module not found, skipping enrichment.")
            except Exception as e:
                self.logger.error(f"AI Enrichment failed: {e}")
                errors.append(f"AI Enrichment failed: {str(e)}")
        
        # Finalization
        execution_time = time.time() - start_time
        
        if progress_callback:
            await progress_callback(90, "Finalizing results...")
        
        any_success = any(r.success for r in scanner_results.values() if isinstance(r, ScannerResult))
        
        return ScanResult(
            job_id=job_id,
            success=any_success,
            findings=merged_findings,
            false_positives=fps,
            scanner_results={name: r.__dict__ if hasattr(r, '__dict__') else r for name, r in scanner_results.items()},
            scanners_run=list(scanner_results.keys()),
            errors=errors,
            warnings=warnings,
            duration_seconds=execution_time,
            scanned_files=scanned_files,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc)
        )

    def _is_finding_commented(self, base_path: Path, finding: Finding) -> bool:
        """
        Check if a finding resides on a commented line or Vexa reference block.
        
        This prevents fixed code (kept as comments for reference) from being re-flagged.
        """
        try:
            # 1. Resolve the absolute path of the file being checked
            f_path = finding.file_path.replace("\\", "/")
            if f_path.startswith("./"):
                f_path = f_path[2:]
            
            # If base_path is a file, use its parent as the root for relative paths
            root_dir = base_path if base_path.is_dir() else base_path.parent
            
            filepath = root_dir / f_path if not Path(f_path).is_absolute() else Path(f_path)
            filepath = filepath.resolve()
            
            if not filepath.exists() or not filepath.is_file():
                return False
                
            # Read only the necessary line
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f):
                    if idx == finding.line_start - 1:
                        stripped = line.strip()
                        self.logger.debug(f"Checking line {finding.line_start} content: '{stripped}'")
                        
                        # 1. Check for Vexa [Original] marker (Highest priority)
                        if "[Original]" in stripped or "[Vexa] Fixed" in stripped:
                            self.logger.info(f"Found commented/reference line {finding.line_start}")
                            return True
                            
                        # 2. Check for standard language-specific comments
                        ext = filepath.suffix.lower()
                        
                        # Python/Shell/Yaml
                        if ext in [".py", ".sh", ".yaml", ".yml", ".dockerfile"]:
                            if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
                                return True
                            return False
                            
                        # JS/TS/C/Java/Go/etc.
                        if ext in [".js", ".ts", ".java", ".c", ".cpp", ".h", ".go", ".cs"] and stripped.startswith("//"):
                            return True
                            
                        # Handle Ruby/Perl/etc.
                        if ext in [".rb", ".pl"] and stripped.startswith("#"):
                            return True
                            
                        break
            return False
        except Exception as e:
            self.logger.debug(f"Error checking if finding {finding.id} is commented: {e}")
            return False

    # run_scan legacy method removed - use run_scan_with_progress via JobManager


# Singleton instance
_scanner_engine: Optional[ScannerEngine] = None


def get_scanner_engine() -> ScannerEngine:
    """Get the global ScannerEngine singleton."""
    global _scanner_engine
    if _scanner_engine is None:
        _scanner_engine = ScannerEngine()
    return _scanner_engine
