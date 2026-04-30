"""
Jobs module for Vexa.

Provides async job management with progress tracking.

Requirements:
- SS-007: Async job management with progress tracking
- SV-007: Async job management for drift detection
- REL-002: Automatic job cleanup for expired jobs
- REL-005: Thread-safe job tracking operations
"""

from vexa.jobs.manager import JobManager, get_job_manager

__all__ = [
    "JobManager",
    "get_job_manager",
]
