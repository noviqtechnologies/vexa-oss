"""
Common data models for Vexa.

This module defines the core data models used across the application.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Literal, Union
from pydantic import BaseModel, Field, ConfigDict, field_validator


def utc_now() -> datetime:
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


class CloudProvider(str, Enum):
    """Supported cloud providers for AI capabilities - G-001."""
    GOOGLE = "google"
    AWS = "aws"
    AZURE = "azure"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    NONE = "none"


class ScanMode(str, Enum):
    """Scan execution mode - SS-002."""
    LOCAL = "local"
    CONTAINER = "container"


class JobStatus(str, Enum):
    """Job execution status - SS-007, SV-007."""
    PENDING = "pending"
    RUNNING = "running"
    MERGING = "merging"  # New: Combining findings from multiple tools
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"  # New: Job exceeded maximum execution time


class Job(BaseModel):
    """
    Async job state model - SS-007, SV-007.
    
    Tracks the lifecycle of async operations including scans,
    threat model generation, and drift detection.
    """
    model_config = ConfigDict(use_enum_values=True)
    
    id: str = Field(..., description="Unique job identifier ({type}_{uuid[:12]})")
    type: str = Field(..., description="Job type (scan, threat_model, drift_detection)")
    status: JobStatus = Field(default=JobStatus.PENDING, description="Current job status")
    progress: float = Field(default=0.0, ge=0.0, le=100.0, description="Progress percentage (0-100)")
    created_at: datetime = Field(default_factory=utc_now, description="Job creation timestamp")
    started_at: Optional[datetime] = Field(default=None, description="Job start timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Job completion timestamp")
    result: Optional[Any] = Field(default=None, description="Job result when completed")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    intermediate_findings: List[Any] = Field(default_factory=list, description="Intermediate findings during processing")


class JobResult(BaseModel):
    """Generic job result container."""
    success: bool = Field(..., description="Whether the job succeeded")
    data: Optional[Any] = Field(default=None, description="Result data")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    duration_seconds: Optional[float] = Field(default=None, description="Job duration in seconds")


class Finding(BaseModel):
    """
    Base security finding from scanners - SS-001.
    """
    id: str = Field(..., description="Unique finding identifier")
    scanner: str = Field(..., description="Source scanner (bandit, semgrep, etc.)")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        ..., description="Finding severity level"
    )
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Finding description")
    file_path: str = Field(..., description="Affected file path")
    line_start: int = Field(..., description="Starting line number")
    line_end: int = Field(..., description="Ending line number")
    code_snippet: str = Field(default="", description="Relevant code snippet")
    
    # Framework mappings - SS-014
    cwe_ids: List[str] = Field(default_factory=list, description="CWE identifiers")
    owasp_category: Optional[str] = Field(default=None, description="OWASP category")
    mitre_attack_id: Optional[str] = Field(default=None, description="MITRE ATT&CK ID")
    nist_controls: List[str] = Field(default_factory=list, description="NIST control mappings")

    model_config = {
        "from_attributes": True
    }


class EnhancedFinding(Finding):
    """
    Enhanced security finding with AI-generated remediation details.
    
    SS-003, SS-004: AI-powered code review
    SS-010, SS-011: False positive detection >90%
    """
    # AI-enhanced fields [SS-003, SS-010]
    detailed_description: str = Field(default="", description="AI-generated detailed description")
    attack_scenario: str = Field(default="", description="Potential attack scenario")
    business_impact: str = Field(default="", description="Business impact description")
    exploitability: Literal["easy", "medium", "hard", "unknown"] = Field(
        default="unknown", description="Exploitability level"
    )
    
    # Remediation
    remediation_code: str = Field(default="", description="Suggested code fix")
    remediation_guidance: str = Field(default="", description="Remediation guidance")
    implementation_steps: List[str] = Field(default_factory=list, description="Step-by-step fix")
    
    # Cloud provider specific recommendations
    google_cloud_recommendation: str = Field(default="", description="GCP-specific recommendation")
    google_cloud_doc_links: List[str] = Field(default_factory=list, description="Google Cloud documentation links")
    rollback_procedure: str = Field(default="", description="Rollback procedure")
    
    # Common new fields requested
    code_snippet_before: str = Field(default="", description="Original code before fix")
    code_snippet_after: str = Field(default="", description="Fixed code snippet")
    cli_commands: List[str] = Field(default_factory=list, description="Implementation CLI commands")
    test_cases: List[str] = Field(default_factory=list, description="Verification test cases")

    # False positive analysis
    false_positive_confidence: float = Field(
        default=0.0, ge=0.0, le=100.0, description="FP confidence percentage"
    )
    is_false_positive: bool = Field(default=False, description="Whether flagged as FP")
    fp_explanation: str = Field(default="", description="FP reasoning")





class Threat(BaseModel):
    """
    STRIDE threat model entry - TM-001 to TM-009.
    """
    id: str = Field(..., description="Unique threat identifier")
    category: Literal[
        "spoofing", "tampering", "repudiation",
        "information_disclosure", "denial_of_service", "elevation_of_privilege"
    ] = Field(..., description="STRIDE category")
    description: str = Field(..., description="Threat description")
    impact: str = Field(..., description="Impact description")
    likelihood: Literal["high", "medium", "low"] = Field(..., description="Likelihood level")
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Risk score (0-10)")
    affected_components: List[str] = Field(default_factory=list, description="Affected components")
    mitigations: List[str] = Field(default_factory=list, description="Mitigation strategies")
    implementation_guidance: str = Field(default="", description="Implementation guidance - TM-007")


class ThreatModel(BaseModel):
    """
    Complete threat model result - TM-001 to TM-009.
    """
    id: str = Field(..., description="Unique threat model identifier")
    repository_path: str = Field(..., description="Analyzed repository path")
    generated_at: datetime = Field(default_factory=utc_now, description="Generation timestamp")
    cloud_provider: CloudProvider = Field(..., description="Cloud provider used for analysis")
    threats: Dict[str, List[Threat]] = Field(default_factory=dict, description="Category -> Threats mapping")
    architecture_diagram: str = Field(default="", description="Mermaid format diagram - TM-006")
    action_plan: List[Dict[str, Any]] = Field(default_factory=list, description="Action items - TM-007")


class DriftProperty(BaseModel):
    """
    Property-level drift information - SV-004.
    """
    property_name: str = Field(..., description="Property name")
    expected_value: Any = Field(..., description="Expected value from IaC")
    actual_value: Any = Field(..., description="Actual value from cloud")
    severity: Literal["high", "medium", "low", "info"] = Field(..., description="Drift severity - SV-005")


class DriftFinding(BaseModel):
    """
    Drift detection finding - SV-001 to SV-008.
    """
    resource_id: str = Field(..., description="Cloud resource identifier")
    resource_type: str = Field(..., description="Resource type")
    iac_tool: Literal["terraform", "cdk", "cloudformation"] = Field(
        ..., description="IaC tool type - SV-008"
    )
    drift_type: Literal["modified", "deleted", "unmanaged"] = Field(..., description="Type of drift")
    properties: List[DriftProperty] = Field(default_factory=list, description="Drifted properties")
    remediation: str = Field(default="", description="Remediation recommendation - SV-006")


class ScanResult(BaseModel):
    """
    Aggregated scan result - SS-001.
    """
    job_id: str = Field(..., description="Associated job ID")
    success: bool = Field(default=True, description="Whether the scan was successful")
    # SS-001: Aggregated findings from all scanners
    # Using Union with discriminated types to preserve subclass fields during serialization
    findings: List[Union[EnhancedFinding, Finding]] = Field(
        default_factory=list, description="All findings (including AI-enhanced)"
    )
    false_positives: List[Union[EnhancedFinding, Finding]] = Field(
        default_factory=list, description="Findings flagged as false positives by AI"
    )
    scanners_run: List[str] = Field(default_factory=list, description="Scanners that were run")
    duration_seconds: float = Field(default=0.0, description="Total scan duration")
    scanned_files: int = Field(default=0, description="Number of files scanned")
    errors: List[str] = Field(default_factory=list, description="Any errors during scan")
    warnings: List[str] = Field(default_factory=list, description="Any non-critical warnings during scan")
    scanner_results: Dict[str, Any] = Field(default_factory=dict, description="Per-scanner results")
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def total_false_positives(self) -> int:
        return len(self.false_positives)

    @property
    def findings_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for finding in self.findings:
            sev = finding.severity
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @property
    def findings_by_scanner(self) -> Dict[str, int]:
        """Count findings by scanner."""
        counts = {}
        for finding in self.findings:
            scanner = finding.scanner
            counts[scanner] = counts.get(scanner, 0) + 1
        return counts
