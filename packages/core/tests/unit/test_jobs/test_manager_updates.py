"""
Tests for JobManager updates including status objects and AI fields.
"""

import pytest
import asyncio
from vexa.jobs.manager import JobManager
from vexa.common.models import JobStatus


@pytest.mark.asyncio
async def test_get_status_returns_dict():
    """get_status should return dictionary with state and progress."""
    manager = JobManager()

    async def sample_task():
        await asyncio.sleep(0.1)
        return {"result": "success"}

    job_id = await manager.create_job("scan", sample_task())
    status = await manager.get_status(job_id)

    assert status is not None
    assert "progress" in status
    assert "state" in status
    assert status["state"] == "RUNNING"
    assert status["progress"] == 0.0


@pytest.mark.asyncio
async def test_update_job_status():
    """update_job should assume new parameters."""
    manager = JobManager()

    async def sample_task():
        await asyncio.sleep(1)
        return "done"

    job_id = await manager.create_job("scan", sample_task())

    # Update status to MERGING
    await manager.update_job(job_id, 50.0, status=JobStatus.MERGING)
    status = await manager.get_status(job_id)

    assert status["state"] == "MERGING"
    assert status["progress"] == 50.0


@pytest.mark.asyncio
async def test_get_result_partial():
    """get_result should return partial results if requested or available."""
    manager = JobManager()
    # ... assuming get_result fetches completed job result
    # If job is running, get_result might return None or raise.

    async def sample_task():
        return "final"

    job_id = await manager.create_job("scan", sample_task())
    await asyncio.sleep(0.1)

    result = await manager.get_result(job_id)
    assert result == "final"
