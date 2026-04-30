"""
Common module for Vexa.

Provides shared models, configuration, and utilities.
"""

from vexa.common.models import (
    CloudProvider,
    Job,
    JobStatus,
    JobResult,
    Finding,
    Threat,
    ThreatModel,
    DriftProperty,
    DriftFinding,
    ScanResult,
)
from vexa.common.config import (
    MAX_CONCURRENT_JOBS,
    JOB_TTL_HOURS,
    VEXA_HOME,
    JOBS_STORAGE_PATH,
    SCANS_STORAGE_PATH,
    REPORTS_STORAGE_PATH,
    THREAT_MODELS_STORAGE_PATH,
    LOGS_STORAGE_PATH,
    ensure_storage_dirs,
)
from vexa.common.logging import (
    get_logger,
    audit_logger,
    AuditLogger,
    sanitize_log_message,
)

__all__ = [
    # Models
    "CloudProvider",
    "Job",
    "JobStatus",
    "JobResult",
    "Finding",
    "Threat",
    "ThreatModel",
    "DriftProperty",
    "DriftFinding",
    "ScanResult",
    # Config
    "MAX_CONCURRENT_JOBS",
    "JOB_TTL_HOURS",
    "VEXA_HOME",
    "JOBS_STORAGE_PATH",
    "SCANS_STORAGE_PATH",
    "REPORTS_STORAGE_PATH",
    "THREAT_MODELS_STORAGE_PATH",
    "LOGS_STORAGE_PATH",
    "ensure_storage_dirs",
    # Logging
    "get_logger",
    "audit_logger",
    "AuditLogger",
    "sanitize_log_message",
]
