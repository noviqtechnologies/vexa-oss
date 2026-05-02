"""
Base Scanner Framework for Vexa.

Implements:
- SS-001: Base class for security scanning tools
- SS-002: Support for local and container execution modes
"""

import shutil
import sys
import subprocess
import importlib.util
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from vexa.security.subprocess_runner import SecureSubprocessRunner, SubprocessResult
from vexa.common.logging import get_logger


logger = get_logger(__name__)


class ScanMode(str, Enum):
    """Execution mode for scanners."""

    LOCAL = "local"
    CONTAINER = "container"


class ScannerSeverity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Backward-compatible alias (deprecated — use ScannerSeverity)
FindingSeverity = ScannerSeverity


@dataclass
class ScannerFinding:
    """
    Normalized security finding output from scanner adapters.

    This is the lightweight dataclass used by scanner parse_output() methods.
    The ScannerEngine converts these into Pydantic models.Finding for the rest
    of the pipeline. Do NOT confuse with vexa.common.models.Finding.
    """

    id: str
    scanner: str
    title: str
    description: str
    severity: ScannerSeverity
    file_path: str
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    confidence: str = "medium"

    # Framework mappings (populated by FrameworkMapper)
    cwe_ids: List[str] = field(default_factory=list)
    owasp_category: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    nist_controls: List[str] = field(default_factory=list)

    # Raw data from scanner
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "id": self.id,
            "scanner": self.scanner,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value
            if hasattr(self.severity, "value")
            else self.severity,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "confidence": self.confidence,
            "cwe_ids": self.cwe_ids,
            "owasp_category": self.owasp_category,
            "mitre_attack_id": self.mitre_attack_id,
            "nist_controls": self.nist_controls,
        }


# Backward-compatible alias (deprecated — use ScannerFinding)
Finding = ScannerFinding


@dataclass
class ScannerResult:
    """Result from a single scanner execution."""

    scanner_name: str
    success: bool
    findings: List[ScannerFinding] = field(default_factory=list)
    error: Optional[str] = None
    execution_time: float = 0.0
    raw_output: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.

    SS-001: Provides common interface for security tool integration.
    SS-002: Supports local and container execution modes.

    Subclasses must implement:
    - name: Scanner name property
    - supported_modes: List of supported execution modes
    - get_command(): Build command for execution
    - parse_output(): Parse JSON output to findings
    """

    # Subclasses must set these
    name: str = "base"
    executable: str = ""  # The binary name to check for availability
    supported_modes: List[ScanMode] = [ScanMode.LOCAL, ScanMode.CONTAINER]

    # Default timeout in seconds
    default_timeout: int = 300

    # Multiplier for the dynamically calculated category timeout
    timeout_multiplier: float = 1.0

    def __init__(self, mode: ScanMode = ScanMode.LOCAL):
        """
        Initialize scanner with execution mode.

        Args:
            mode: Execution mode (local or container)
        """
        self.mode = mode
        self.subprocess_runner = SecureSubprocessRunner()

        # Validate mode is supported
        if mode not in self.supported_modes:
            raise ValueError(
                f"Scanner {self.name} does not support mode '{mode.value}'. "
                f"Supported: {[m.value for m in self.supported_modes]}"
            )

    @abstractmethod
    def get_command(
        self, path: Path, exclusions: Optional[List[str]] = None
    ) -> List[str]:
        """
        Build command line arguments for this scanner.

        Args:
            path: Target path to scan
            exclusions: Optional list of paths/patterns to exclude

        Returns:
            List of command arguments
        """
        pass

    @abstractmethod
    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """
        Parse scanner output into normalized findings.

        Args:
            output: Raw JSON/text output from scanner
            target_path: Original target path for context

        Returns:
            List of normalized Finding objects
        """
        pass

    def is_available(self) -> bool:
        """
        Check if the scanner tool is installed and available.

        Returns:
            True if scanner executable is found in PATH, available via python -m,
            or present in the current Python's bin/Scripts directory.
        """
        if self.executable:
            executable = self.executable
        else:
            cmd = self.get_command(Path("."))
            if not cmd:
                # If command can't be built (e.g. missing requirements.txt),
                # fallback to checking if the scanner name itself is an executable
                executable = self.name
            else:
                executable = cmd[0]

        # 1. Check if executable exists in system PATH
        if shutil.which(executable):
            return True

        # 2. Check in current Python's bin/Scripts directory (important for virtualenvs/uv tools)
        executable_path = Path(sys.executable).parent / executable
        if sys.platform == "win32" and not executable.lower().endswith(".exe"):
            executable_exe = Path(sys.executable).parent / f"{executable}.exe"
            if executable_exe.exists():
                return True
        if executable_path.exists():
            return True

        # 3. Check for python module (for python-based tools like bandit, checkov, etc.)
        module_name = executable.replace("-", "_")

        # 3a. Use importlib for fast check if it's in site-packages
        try:
            if importlib.util.find_spec(module_name):
                return True
        except (ImportError, ValueError):
            pass

        # 3b. Fallback to python -m (checks if it's actually runnable as a module)
        try:
            result = subprocess.run(
                [sys.executable, "-m", module_name, "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def run(
        self,
        path: Path,
        timeout: Optional[int] = None,
        exclusions: Optional[List[str]] = None,
    ) -> ScannerResult:
        """
        Execute the scanner on the target path.

        Args:
            path: Target path to scan
            timeout: Optional timeout in seconds
            exclusions: Optional list of paths/patterns to exclude

        Returns:
            ScannerResult with findings or error
        """
        import time

        start_time = time.time()
        timeout = timeout or self.default_timeout

        logger.info(
            "Running scanner %s on %s (mode=%s)", self.name, path, self.mode.value
        )

        try:
            # Resolve paths for robust execution
            abs_path = path.resolve()
            if abs_path.is_file():
                run_cwd = abs_path.parent
                run_path = Path(abs_path.name)
            else:
                run_cwd = abs_path
                run_path = Path(".")

            # Build command
            cmd = self.get_command(run_path, exclusions)

            if not cmd:
                return ScannerResult(
                    scanner_name=self.name,
                    success=False,
                    error="Failed to build command",
                )

            # Execute command
            result: SubprocessResult = await self.subprocess_runner.run(
                cmd=cmd,
                cwd=run_cwd,
                timeout=timeout,
            )

            execution_time = time.time() - start_time

            # Check return code and report crashes
            if result.returncode != 0:
                # Some scanners (like semgrep) return non-zero if findings are found.
                # However, if stdout is empty, it's almost certainly a crash.
                if not result.stdout.strip():
                    # Handle Checkov external module warning specifically
                    if (
                        self.name == "checkov"
                        and "download-external-modules" in result.stderr
                    ):
                        logger.debug(
                            "Checkov failed to download external modules. Run with --download-external-modules for full context."
                        )
                    else:
                        logger.warning(
                            f"Scanner {self.name} returned exit code {result.returncode} with empty stdout."
                        )
                    return ScannerResult(
                        scanner_name=self.name,
                        success=False,
                        error=f"Scanner returned exit code {result.returncode} (Tool may be missing or failed to scan some files.)",
                        raw_output=result.stderr[:1000],
                        execution_time=execution_time,
                    )
                # If there's stdout, we assume it might be a valid run with findings despite non-zero exit code
                logger.debug(
                    f"Scanner {self.name} exited with code {result.returncode} but has stdout. Proceeding to parse."
                )

            # log stderr if stdout is empty but return code was 0 - unusual but possible
            if (
                result.returncode == 0
                and not result.stdout.strip()
                and result.stderr.strip()
            ):
                logger.warning(
                    f"Scanner {self.name} returned empty stdout but has stderr: {result.stderr[:500]}"
                )

            # Parse output
            try:
                findings = self.parse_output(result.stdout, path)
            except Exception as e:
                logger.error("Failed to parse %s output: %s", self.name, e)
                return ScannerResult(
                    scanner_name=self.name,
                    success=False,
                    error=f"Failed to parse output: {e}",
                    raw_output=result.stdout[:1000],
                    execution_time=execution_time,
                )

            logger.info(
                "Scanner %s completed: %d findings in %.2fs",
                self.name,
                len(findings),
                execution_time,
            )

            return ScannerResult(
                scanner_name=self.name,
                success=True,
                findings=findings,
                execution_time=execution_time,
                raw_output=result.stdout[:1000]
                if len(result.stdout) > 1000
                else result.stdout,
            )

        except FileNotFoundError:
            return ScannerResult(
                scanner_name=self.name,
                success=False,
                error=f"Scanner '{self.name}' not found. Please install it first.",
            )
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error("Scanner %s failed: %s", self.name, e)
            return ScannerResult(
                scanner_name=self.name,
                success=False,
                error=str(e),
                execution_time=execution_time,
            )

    def _normalize_severity(self, severity: str) -> ScannerSeverity:
        """
        Normalize severity string to FindingSeverity enum.

        Args:
            severity: Raw severity string from scanner

        Returns:
            Normalized FindingSeverity
        """
        severity_lower = severity.lower()

        if severity_lower in ["critical", "crit"]:
            return FindingSeverity.CRITICAL
        elif severity_lower in ["high", "error"]:
            return FindingSeverity.HIGH
        elif severity_lower in ["medium", "warning", "warn", "moderate"]:
            return FindingSeverity.MEDIUM
        elif severity_lower in ["low", "info", "informational", "note"]:
            return FindingSeverity.LOW
        else:
            return FindingSeverity.INFO

    def _generate_finding_id(
        self, scanner: str, file_path: str, line: int, rule: str
    ) -> str:
        """Generate a unique finding ID."""
        import hashlib

        content = f"{scanner}:{file_path}:{line}:{rule}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]
