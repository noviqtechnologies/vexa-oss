"""
Report Generator Framework for Vexa.

SS-006: Multi-format report generation (HTML, JSON, SARIF, Markdown)
TM-008: Threat model report generation
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from vexa.scanners.base import Finding, FindingSeverity
from vexa.scanners.engine import ScanResult
from vexa.common.logging import get_logger
from vexa import __version__


logger = get_logger(__name__)


@dataclass
class ReportMetadata:
    """Metadata for generated reports."""
    title: str = "Security Scan Report"
    generated_at: datetime = None
    scan_target: str = ""
    scan_duration: float = 0.0
    tool_version: str = __version__
    job_id: str = ""
    
    def __post_init__(self):
        if self.generated_at is None:
            self.generated_at = datetime.now(timezone.utc)


class BaseReportGenerator(ABC):
    """
    Abstract base class for report generators.
    
    SS-006: All report generators must implement generate() method.
    """
    
    # Format name (e.g., "html", "json", "sarif", "markdown")
    format_name: str = "base"
    
    # File extension for output
    file_extension: str = ".txt"
    
    @abstractmethod
    def generate(
        self,
        result: ScanResult,
        output_path: Path,
        metadata: Optional[ReportMetadata] = None,
    ) -> Path:
        """
        Generate a report from scan results.
        
        Args:
            result: ScanResult from ScannerEngine
            output_path: Directory or file path for output
            metadata: Optional report metadata
            
        Returns:
            Path to the generated report file
        """
        pass
    
    def _prepare_output_path(self, output_path: Path) -> Path:
        """Prepare output path, creating directories if needed."""
        if output_path.is_dir():
            filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}{self.file_extension}"
            output_path = output_path / filename
        
        # Ensure parent directory exists
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError) as e:
            # Fallback to /tmp if target is not writable (common in Docker/CI)
            import tempfile
            fallback_dir = Path(tempfile.gettempdir()) / "vexa_scan_reports"
            logger.warning("Output path '%s' is not writable: %s. Falling back to %s", output_path.parent, e, fallback_dir)
            
            # Recompute path with fallback
            fallback_dir.mkdir(parents=True, exist_ok=True)
            output_path = fallback_dir / output_path.name
            
        return output_path
    
    def _get_severity_counts(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        # Using string keys from the Pydantic Finding model
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            # Handle both Enum and string severity
            sev = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
            if sev in counts:
                counts[sev] += 1
            else:
                counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _get_scanner_counts(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by scanner."""
        counts = {}
        for finding in findings:
            counts[finding.scanner] = counts.get(finding.scanner, 0) + 1
        return counts


class ReportGenerator:
    """
    SS-006, TM-008: Multi-format report generation orchestrator.
    
    Usage:
        generator = ReportGenerator()
        path = generator.generate(result, "html", Path("/output"))
    """
    
    # Registry of format generators (populated by format modules)
    _generators: Dict[str, Type[BaseReportGenerator]] = {}
    
    @classmethod
    def register(cls, generator_class: Type[BaseReportGenerator]) -> None:
        """Register a report generator for a format."""
        cls._generators[generator_class.format_name] = generator_class
    
    @classmethod
    def get_available_formats(cls) -> List[str]:
        """Get list of available report formats."""
        return list(cls._generators.keys())
    
    def generate(
        self,
        result: ScanResult,
        format: str,
        output_path: Path,
        metadata: Optional[ReportMetadata] = None,
    ) -> Path:
        """
        Generate a report in the specified format.
        
        Args:
            result: ScanResult from ScannerEngine
            format: Report format (html, json, sarif, markdown)
            output_path: Output directory or file path
            metadata: Optional report metadata
            
        Returns:
            Path to generated report
            
        Raises:
            ValueError: If format is not supported
        """
        if format not in self._generators:
            available = ", ".join(self._generators.keys()) or "none"
            raise ValueError(
                f"Unsupported report format: '{format}'. "
                f"Available formats: {available}"
            )
        
        if metadata is None:
            metadata = ReportMetadata(job_id=result.job_id)
        elif not metadata.job_id:
            metadata.job_id = result.job_id
            
        generator = self._generators[format]()
        
        logger.info("Generating %s report to %s", format, output_path)
        
        path = generator.generate(result, output_path, metadata)
        
        logger.info("Report generated: %s", path)
        
        return path
    
    def generate_all(
        self,
        result: ScanResult,
        output_dir: Path,
        metadata: Optional[ReportMetadata] = None,
    ) -> Dict[str, Path]:
        """
        Generate reports in all available formats.
        
        Args:
            result: ScanResult from ScannerEngine
            output_dir: Output directory
            metadata: Optional report metadata
            
        Returns:
            Dict mapping format name to generated file path
        """
        reports = {}
        
        for format_name in self._generators:
            try:
                path = self.generate(result, format_name, output_dir, metadata)
                reports[format_name] = path
            except Exception as e:
                logger.error("Failed to generate %s report: %s", format_name, e)
        
        return reports


# Singleton instance
_report_generator: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    """Get the global ReportGenerator singleton."""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator
