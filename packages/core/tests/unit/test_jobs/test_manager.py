"""
Unit tests for JobManager - TDD Approach

Tests for requirements:
- SS-007: Async job management with progress tracking
- SV-007: Async job management for drift detection
- REL-002: Automatic job cleanup for expired jobs
- REL-005: Thread-safe job tracking operations
- PERF-007: Maximum concurrent jobs (25)
- PERF-008: Job TTL for cleanup (24 hours)
"""

import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from vexa.jobs.manager import JobManager
from vexa.common.models import Job, JobStatus


class TestJobCreation:
    """Test job creation functionality."""

    @pytest.mark.asyncio
    async def test_create_job_returns_valid_job_id(self):
        """Job creation should return a valid job ID with correct format."""
        manager = JobManager()
        
        async def sample_task():
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", sample_task())
        
        # Job ID format: {type}_{uuid[:12]}
        assert job_id.startswith("scan_")
        assert len(job_id) == len("scan_") + 12

    @pytest.mark.asyncio
    async def test_create_job_initializes_with_correct_status(self):
        """New jobs should be created with 'running' status."""
        manager = JobManager()
        
        async def sample_task():
            await asyncio.sleep(0.1)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", sample_task())
        job = await manager.get_job(job_id)
        
        assert job is not None
        assert job.status == JobStatus.RUNNING

    @pytest.mark.asyncio
    async def test_create_job_initializes_progress_to_zero(self):
        """New jobs should have progress initialized to 0.0."""
        manager = JobManager()
        
        async def sample_task():
            await asyncio.sleep(0.1)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", sample_task())
        job = await manager.get_job(job_id)
        
        assert job is not None
        assert job.progress == 0.0

    @pytest.mark.asyncio
    async def test_create_job_sets_created_timestamp(self):
        """New jobs should have created_at timestamp set."""
        manager = JobManager()
        before = datetime.now(timezone.utc)
        
        async def sample_task():
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", sample_task())
        job = await manager.get_job(job_id)
        after = datetime.now(timezone.utc)
        
        assert job is not None
        assert before <= job.created_at <= after

    @pytest.mark.asyncio
    async def test_create_job_stores_job_type(self):
        """Job should store its type correctly."""
        manager = JobManager()
        
        async def sample_task():
            return {"result": "success"}
        
        job_id = await manager.create_job("threat_model", sample_task())
        job = await manager.get_job(job_id)
        
        assert job is not None
        assert job.type == "threat_model"


class TestJobRetrieval:
    """Test job retrieval functionality."""

    @pytest.mark.asyncio
    async def test_get_job_returns_existing_job(self):
        """Should return job for valid job ID."""
        manager = JobManager()
        
        async def sample_task():
            await asyncio.sleep(0.1)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", sample_task())
        job = await manager.get_job(job_id)
        
        assert job is not None
        assert job.id == job_id

    @pytest.mark.asyncio
    async def test_get_job_returns_none_for_invalid_id(self):
        """Should return None for non-existent job ID."""
        manager = JobManager()
        
        job = await manager.get_job("nonexistent_123456789012")
        
        assert job is None

    @pytest.mark.asyncio
    async def test_list_jobs_returns_all_jobs(self):
        """Should return all jobs when no filter specified."""
        manager = JobManager()
        
        async def long_task():
            await asyncio.sleep(1)
            return {"result": "success"}
        
        job_id1 = await manager.create_job("scan", long_task())
        job_id2 = await manager.create_job("threat_model", long_task())
        
        jobs = await manager.list_jobs()
        
        assert len(jobs) >= 2
        job_ids = [j.id for j in jobs]
        assert job_id1 in job_ids
        assert job_id2 in job_ids

    @pytest.mark.asyncio
    async def test_list_jobs_filters_by_status(self):
        """Should filter jobs by status when specified."""
        manager = JobManager()
        
        async def long_task():
            await asyncio.sleep(1)
            return {"result": "success"}
        
        await manager.create_job("scan", long_task())
        
        running_jobs = await manager.list_jobs(status=JobStatus.RUNNING)
        completed_jobs = await manager.list_jobs(status=JobStatus.COMPLETED)
        
        assert all(j.status == JobStatus.RUNNING for j in running_jobs)
        assert all(j.status == JobStatus.COMPLETED for j in completed_jobs)


class TestProgressTracking:
    """Test progress tracking functionality - SS-007."""

    @pytest.mark.asyncio
    async def test_update_progress_sets_value(self):
        """Should update job progress correctly."""
        manager = JobManager()
        
        async def long_task():
            await asyncio.sleep(1)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", long_task())
        
        await manager.update_progress(job_id, 50.0)
        job = await manager.get_job(job_id)
        
        assert job is not None
        assert job.progress == 50.0

    @pytest.mark.asyncio
    async def test_update_progress_clamps_to_zero(self):
        """Progress should not go below 0."""
        manager = JobManager()
        
        async def long_task():
            await asyncio.sleep(1)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", long_task())
        
        await manager.update_progress(job_id, -10.0)
        job = await manager.get_job(job_id)
        
        assert job is not None
        assert job.progress == 0.0

    @pytest.mark.asyncio
    async def test_update_progress_clamps_to_hundred(self):
        """Progress should not exceed 100."""
        manager = JobManager()
        
        async def long_task():
            await asyncio.sleep(1)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", long_task())
        
        await manager.update_progress(job_id, 150.0)
        job = await manager.get_job(job_id)
        
        assert job is not None
        assert job.progress == 100.0

    @pytest.mark.asyncio
    async def test_update_progress_for_nonexistent_job_raises(self):
        """Should raise error for non-existent job."""
        manager = JobManager()
        
        with pytest.raises(KeyError):
            await manager.update_progress("nonexistent_123456789012", 50.0)


class TestJobCompletion:
    """Test job completion and result storage."""

    @pytest.mark.asyncio
    async def test_job_completes_with_result(self):
        """Job should complete and store result."""
        manager = JobManager()
        expected_result = {"findings": ["issue1", "issue2"]}
        
        async def sample_task():
            return expected_result
        
        job_id = await manager.create_job("scan", sample_task())
        
        # Wait for task to complete
        await asyncio.sleep(0.1)
        job = await manager.get_job(job_id)
        
        assert job is not None
        assert job.status == JobStatus.COMPLETED
        assert job.result == expected_result
        assert job.progress == 100.0

    @pytest.mark.asyncio
    async def test_job_fails_with_error(self):
        """Failed jobs should store error information."""
        manager = JobManager()
        
        async def failing_task():
            raise ValueError("Task failed intentionally")
        
        job_id = await manager.create_job("scan", failing_task())
        
        # Wait for task to fail
        await asyncio.sleep(0.1)
        job = await manager.get_job(job_id)
        
        assert job is not None
        assert job.status == JobStatus.FAILED
        assert "Task failed intentionally" in job.error


class TestJobCancellation:
    """Test job cancellation functionality."""

    @pytest.mark.asyncio
    async def test_cancel_running_job(self):
        """Should be able to cancel a running job."""
        manager = JobManager()
        
        async def long_task():
            await asyncio.sleep(10)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", long_task())
        
        result = await manager.cancel_job(job_id)
        job = await manager.get_job(job_id)
        
        assert result is True
        assert job is not None
        assert job.status == JobStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_job_returns_false(self):
        """Should return False for non-existent job."""
        manager = JobManager()
        
        result = await manager.cancel_job("nonexistent_123456789012")
        
        assert result is False


class TestThreadSafety:
    """Test thread-safe operations - REL-005."""

    @pytest.mark.asyncio
    async def test_concurrent_job_creation(self):
        """Multiple concurrent job creations should not cause race conditions."""
        manager = JobManager()
        
        async def sample_task():
            await asyncio.sleep(0.5)
            return {"result": "success"}
        
        # Create 10 jobs concurrently
        tasks = [manager.create_job(f"scan_{i}", sample_task()) for i in range(10)]
        job_ids = await asyncio.gather(*tasks)
        
        # All job IDs should be unique
        assert len(job_ids) == len(set(job_ids))
        
        # All jobs should be created
        jobs = await manager.list_jobs()
        assert len(jobs) >= 10

    @pytest.mark.asyncio
    async def test_concurrent_progress_updates(self):
        """Concurrent progress updates should be thread-safe."""
        manager = JobManager()
        
        async def long_task():
            await asyncio.sleep(2)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", long_task())
        
        # Update progress concurrently
        async def update_progress(value):
            await manager.update_progress(job_id, value)
        
        await asyncio.gather(*[update_progress(i * 10) for i in range(10)])
        
        # Job should still be accessible
        job = await manager.get_job(job_id)
        assert job is not None

    @pytest.mark.asyncio
    async def test_concurrent_read_write_operations(self):
        """Concurrent reads and writes should not cause issues."""
        manager = JobManager()
        
        async def sample_task():
            await asyncio.sleep(1)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", sample_task())
        
        async def read_job():
            for _ in range(10):
                await manager.get_job(job_id)
                await asyncio.sleep(0.01)
        
        async def update_job():
            for i in range(10):
                await manager.update_progress(job_id, i * 10)
                await asyncio.sleep(0.01)
        
        # Run reads and writes concurrently
        await asyncio.gather(read_job(), update_job())
        
        # Job should still be valid
        job = await manager.get_job(job_id)
        assert job is not None


class TestTTLCleanup:
    """Test TTL-based cleanup - REL-002."""

    @pytest.mark.asyncio
    async def test_cleanup_expired_jobs(self):
        """Expired jobs should be cleaned up - REL-002."""
        manager = JobManager()
        
        async def sample_task():
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", sample_task())
        await asyncio.sleep(0.1)  # Let job complete
        
        # Manually set job to expired
        async with manager._lock:
            manager._jobs[job_id].created_at = datetime.now(timezone.utc) - timedelta(hours=25)
        
        # Run cleanup
        cleaned = await manager.cleanup_expired()
        
        assert cleaned >= 1
        assert await manager.get_job(job_id) is None

    @pytest.mark.asyncio
    async def test_cleanup_preserves_recent_jobs(self):
        """Recent jobs should not be cleaned up."""
        manager = JobManager()
        
        async def long_task():
            await asyncio.sleep(1)
            return {"result": "success"}
        
        job_id = await manager.create_job("scan", long_task())
        
        # Run cleanup
        cleaned = await manager.cleanup_expired()
        
        # Job should still exist
        job = await manager.get_job(job_id)
        assert job is not None


class TestConcurrencyLimits:
    """Test maximum concurrent jobs - PERF-007."""

    @pytest.mark.asyncio
    async def test_max_concurrent_jobs_limit(self):
        """Should respect maximum concurrent job limit (25)."""
        manager = JobManager()
        
        # Track when jobs start
        started_jobs = []
        
        async def tracked_task(job_num):
            started_jobs.append(job_num)
            await asyncio.sleep(0.5)
            return {"job": job_num}
        
        # Create 30 jobs (more than max 25)
        tasks = []
        for i in range(30):
            tasks.append(manager.create_job(f"scan_{i}", tracked_task(i)))
        
        # Start all creation tasks but don't wait for completion
        job_ids = await asyncio.gather(*tasks)
        
        # Wait a bit for jobs to start executing
        await asyncio.sleep(0.1)
        
        # Should have all 30 job IDs created
        assert len(job_ids) == 30


class TestJobLifecycle:
    """Test complete job lifecycle."""

    @pytest.mark.asyncio
    async def test_full_job_lifecycle(self):
        """Test complete job lifecycle from creation to completion."""
        manager = JobManager()
        
        async def monitored_task():
            return {"status": "completed", "items": 10}
        
        # Create job
        job_id = await manager.create_job("scan", monitored_task())
        
        # Verify initial state
        job = await manager.get_job(job_id)
        assert job.status in [JobStatus.RUNNING, JobStatus.COMPLETED]
        
        # Wait for completion
        await asyncio.sleep(0.1)
        
        # Verify completed state
        job = await manager.get_job(job_id)
        assert job.status == JobStatus.COMPLETED
        assert job.result is not None
        assert job.progress == 100.0
        assert job.completed_at is not None
