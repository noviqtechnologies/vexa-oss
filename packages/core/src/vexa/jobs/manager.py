"""
Job Manager for Vexa.

Implements:
- SS-007: Async job management with progress tracking
- SV-007: Async job management for drift detection
- REL-002: Automatic job cleanup for expired jobs
- REL-005: Thread-safe job tracking operations
- PERF-007: Maximum concurrent jobs (25)
- PERF-008: Job TTL for cleanup (24 hours)
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Coroutine, Dict, List, Optional

from vexa.common.models import Job, JobStatus
from vexa.common.config import MAX_CONCURRENT_JOBS, JOB_TTL_HOURS
from vexa.common.logging import get_logger, audit_logger


logger = get_logger(__name__)


class JobManager:
    """
    Async job management with progress tracking - SS-007, SV-007.

    Provides:
    - Async job creation and execution
    - Real-time progress tracking
    - Thread-safe operations using asyncio locks (REL-005)
    - Automatic TTL-based cleanup (REL-002)
    - Concurrency control with semaphore (PERF-007)

    Usage:
        manager = JobManager()

        async def my_task():
            return {"result": "success"}

        job_id = await manager.create_job("scan", my_task())
        job = await manager.get_job(job_id)
    """

    MAX_CONCURRENT = MAX_CONCURRENT_JOBS  # PERF-007: 25 jobs
    JOB_TTL_HOURS = JOB_TTL_HOURS  # PERF-008: 24 hours

    def __init__(self):
        """Initialize JobManager with thread-safe structures."""
        self._jobs: Dict[str, Job] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()  # REL-005: Thread-safe operations
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)  # PERF-007
        logger.info(
            "JobManager initialized with max_concurrent=%d, ttl_hours=%d",
            self.MAX_CONCURRENT,
            self.JOB_TTL_HOURS,
        )

    async def create_job(self, job_type: str, task: Coroutine) -> str:
        """
        Create and start an async job with progress tracking.

        Args:
            job_type: Type of job (e.g., "scan", "threat_model", "drift_detection")
            task: Coroutine to execute

        Returns:
            Job ID in format {type}_{uuid[:12]}

        Example:
            job_id = await manager.create_job("scan", scan_repository(path))
        """
        # Generate unique job ID
        job_id = f"{job_type}_{uuid.uuid4().hex[:12]}"

        # Create job record with lock for thread safety - REL-005
        async with self._lock:
            job = Job(
                id=job_id,
                type=job_type,
                status=JobStatus.RUNNING,
                progress=0.0,
                created_at=datetime.now(timezone.utc),
                started_at=datetime.now(timezone.utc),
            )
            self._jobs[job_id] = job

        # Start background task with semaphore for concurrency control - PERF-007
        background_task = asyncio.create_task(self._run_job(job_id, task))
        self._tasks[job_id] = background_task

        # Log job creation
        logger.info("Job created: id=%s, type=%s", job_id, job_type)
        audit_logger.log_job_event(job_id, "created", {"type": job_type})

        return job_id

    async def _run_job(self, job_id: str, task: Coroutine) -> None:
        """
        Execute job with error handling and automatic status updates.

        Uses semaphore to respect concurrency limits - PERF-007.
        """
        async with self._semaphore:
            try:
                # Execute the task
                result = await task

                # Update job as completed
                async with self._lock:
                    if job_id in self._jobs:
                        job = self._jobs[job_id]
                        job.status = JobStatus.COMPLETED
                        job.result = result
                        job.progress = 100.0
                        job.completed_at = datetime.now(timezone.utc)

                logger.info("Job completed: id=%s", job_id)
                audit_logger.log_job_event(
                    job_id, "completed", {"result_type": type(result).__name__}
                )

            except asyncio.CancelledError:
                # Job was cancelled
                async with self._lock:
                    if job_id in self._jobs:
                        job = self._jobs[job_id]
                        job.status = JobStatus.CANCELLED
                        job.completed_at = datetime.now(timezone.utc)

                logger.info("Job cancelled: id=%s", job_id)
                audit_logger.log_job_event(job_id, "cancelled")
                raise

            except Exception as e:
                # Job failed with error
                error_message = str(e)

                async with self._lock:
                    if job_id in self._jobs:
                        job = self._jobs[job_id]
                        job.status = JobStatus.FAILED
                        job.error = error_message
                        job.completed_at = datetime.now(timezone.utc)

                logger.error("Job failed: id=%s, error=%s", job_id, error_message)
                audit_logger.log_job_event(job_id, "failed", {"error": error_message})

    async def get_job(self, job_id: str) -> Optional[Job]:
        """
        Get job by ID.

        Args:
            job_id: The job ID to retrieve

        Returns:
            Job object if found, None otherwise
        """
        async with self._lock:
            return self._jobs.get(job_id)

    async def update_progress(self, job_id: str, progress: float) -> None:
        """
        Update job progress - SS-007.

        Progress is clamped to range [0, 100].

        Args:
            job_id: The job ID to update
            progress: Progress percentage (0-100)

        Raises:
            KeyError: If job_id does not exist
        """
        # Clamp progress to valid range
        clamped_progress = max(0.0, min(100.0, progress))

        async with self._lock:
            if job_id not in self._jobs:
                raise KeyError(f"Job not found: {job_id}")

            job = self._jobs[job_id]
            job.progress = clamped_progress

        logger.debug(
            "Job progress updated: id=%s, progress=%.1f%%", job_id, clamped_progress
        )

    async def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get job status with progress - matches TDD interface.

        Args:
            job_id: The job ID to check

        Returns:
            Dictionary with progress percentage and state, or None if not found
            Example: {"progress": 60, "state": "RUNNING"}
        """
        async with self._lock:
            if job_id not in self._jobs:
                return None

            job = self._jobs[job_id]
            # status is a string because of use_enum_values=True
            state = (
                job.status.upper()
                if isinstance(job.status, str)
                else job.status.value.upper()
            )

            return {
                "progress": job.progress,
                "state": state,
                "error": job.error,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
            }

    async def update_job(
        self,
        job_id: str,
        progress: float,
        findings: Optional[List[Any]] = None,
        status: Optional[JobStatus] = None,
    ) -> None:
        """
        Update job progress and intermediate findings - matches TDD interface.

        Args:
            job_id: The job ID to update
            progress: Progress percentage (0-100)
            findings: Optional list of intermediate findings
            status: Optional status update (e.g., MERGING)

        Raises:
            KeyError: If job_id does not exist
        """
        # Clamp progress to valid range
        clamped_progress = max(0.0, min(100.0, progress))

        async with self._lock:
            if job_id not in self._jobs:
                raise KeyError(f"Job not found: {job_id}")

            job = self._jobs[job_id]
            job.progress = clamped_progress

            if findings is not None:
                job.intermediate_findings = findings

            if status is not None:
                job.status = status

        logger.debug(
            "Job updated: id=%s, progress=%.1f%%, findings=%d",
            job_id,
            clamped_progress,
            len(findings) if findings else 0,
        )

        # Helper to get status string safe for logging
        status_val = status.value if hasattr(status, "value") else status

        audit_logger.log_job_event(
            job_id,
            "updated",
            {
                "progress": clamped_progress,
                "findings_count": len(findings) if findings else 0,
                "status": status_val if status else None,
            },
        )

    async def get_result(self, job_id: str) -> Optional[Any]:
        """
        Get final job result - matches TDD interface.

        Args:
            job_id: The job ID to get result for

        Returns:
            Job result if completed, None if not found or still running
        """
        async with self._lock:
            if job_id not in self._jobs:
                return None

            job = self._jobs[job_id]

            if job.status == JobStatus.COMPLETED:
                return job.result
            elif job.status == JobStatus.FAILED:
                return {"error": job.error, "status": "failed"}
            elif job.status == JobStatus.TIMEOUT:
                # Return partial results on timeout
                return {
                    "status": "timeout",
                    "partial_findings": job.intermediate_findings,
                    "error": job.error or "Job exceeded maximum execution time",
                }
            else:
                # Job still running
                return None

    async def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a running job.

        Args:
            job_id: The job ID to cancel

        Returns:
            True if job was cancelled, False if not found or already completed
        """
        # Check if job exists and is cancellable
        async with self._lock:
            if job_id not in self._jobs:
                return False

            job = self._jobs[job_id]
            if job.status not in [JobStatus.PENDING, JobStatus.RUNNING]:
                return False

        # Cancel the background task if it exists
        if job_id in self._tasks:
            task = self._tasks[job_id]
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Update job status
        async with self._lock:
            if job_id in self._jobs:
                job = self._jobs[job_id]
                job.status = JobStatus.CANCELLED
                job.completed_at = datetime.now(timezone.utc)

        logger.info("Job cancelled: id=%s", job_id)
        audit_logger.log_job_event(job_id, "cancelled")

        return True

    async def list_jobs(self, status: Optional[JobStatus] = None) -> List[Job]:
        """
        List all jobs, optionally filtered by status.

        Args:
            status: Optional status filter

        Returns:
            List of Job objects matching the filter
        """
        async with self._lock:
            jobs = list(self._jobs.values())

        if status is not None:
            jobs = [j for j in jobs if j.status == status]

        return jobs

    async def cleanup_expired(self) -> int:
        """
        Clean up expired jobs based on TTL - REL-002.

        Removes jobs older than JOB_TTL_HOURS (default: 24 hours).

        Returns:
            Number of jobs cleaned up
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.JOB_TTL_HOURS)

        async with self._lock:
            expired_ids = [
                job_id for job_id, job in self._jobs.items() if job.created_at < cutoff
            ]

            for job_id in expired_ids:
                del self._jobs[job_id]
                # Also clean up task reference if exists
                if job_id in self._tasks:
                    del self._tasks[job_id]

                logger.info("REL-002: Cleaned up expired job %s", job_id)
                audit_logger.log_job_event(job_id, "expired_cleanup")

        if expired_ids:
            logger.info("REL-002: Cleaned up %d expired jobs", len(expired_ids))

        return len(expired_ids)

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get job manager statistics.

        Returns:
            Dictionary with current job statistics
        """
        async with self._lock:
            jobs = list(self._jobs.values())

        stats = {
            "total_jobs": len(jobs),
            "pending": sum(1 for j in jobs if j.status == JobStatus.PENDING),
            "running": sum(1 for j in jobs if j.status == JobStatus.RUNNING),
            "completed": sum(1 for j in jobs if j.status == JobStatus.COMPLETED),
            "failed": sum(1 for j in jobs if j.status == JobStatus.FAILED),
            "cancelled": sum(1 for j in jobs if j.status == JobStatus.CANCELLED),
            "max_concurrent": self.MAX_CONCURRENT,
            "ttl_hours": self.JOB_TTL_HOURS,
        }

        return stats


# Global singleton instance
_job_manager: Optional[JobManager] = None


def get_job_manager() -> JobManager:
    """
    Get the global JobManager singleton instance.

    Returns:
        The global JobManager instance
    """
    global _job_manager
    if _job_manager is None:
        _job_manager = JobManager()
    return _job_manager
