"""
Performance Manager for Vexa.

Handles dynamic configuration and resource management to meet strict performance requirements.
PRD Reference: Section 4.2 Performance Requirements
"""

import os
from pathlib import Path
from dataclasses import dataclass

from vexa.common.config import (
    SMALL_REPO_TIMEOUT,
    MEDIUM_REPO_TIMEOUT,
    LARGE_REPO_TIMEOUT,
)
from vexa.common.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ScanPerformanceConfig:
    """Performance configuration for a specific scan."""

    timeout_seconds: int
    repo_size_category: str
    file_count: int


class PerformanceManager:
    """
    Manages performance constraints and dynamic configuration.

    Implements:
    - PERF-001: Small repo (<100 files) -> < 3 mins
    - PERF-002: Medium repo (100-500 files) -> < 8 mins
    - PERF-003: Large repo (500-1000 files) -> < 15 mins
    """

    # Files to exclude from counting (noise)
    EXCLUDE_DIRS = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".tox",
        "dist",
        "build",
        "coverage",
        ".idea",
        ".vscode",
        "vexa_scan_reports",
    }

    @classmethod
    def analyze_repository(cls, path: Path) -> ScanPerformanceConfig:
        """
        Analyze repository size and determine performance constraints.

        Args:
            path: Target repository path

        Returns:
            ScanPerformanceConfig with appropriate timeouts
        """
        file_count = cls._count_files(path)

        if file_count < 100:
            category = "SMALL"
            target_timeout = SMALL_REPO_TIMEOUT
        elif file_count < 500:
            category = "MEDIUM"
            target_timeout = MEDIUM_REPO_TIMEOUT
        else:
            category = "LARGE"
            target_timeout = LARGE_REPO_TIMEOUT

        # Add 10% safety buffer to the PRD target for the execution timeout
        # to ensure we don't kill tools that are almost done exactly at the limit.
        timeout = int(target_timeout * 1.1)

        logger.info(
            f"Repository Analysis: {file_count} files detected ({category}). "
            f"PRD Target: {target_timeout}s, Execution Timeout (with buffer): {timeout}s"
        )

        return ScanPerformanceConfig(
            timeout_seconds=timeout, repo_size_category=category, file_count=file_count
        )

    @classmethod
    def _count_files(cls, path: Path) -> int:
        """Count relevant files in repository, skipping noise."""
        if not path.exists():
            return 0

        if path.is_file():
            return 1

        count = 0
        try:
            for root, dirs, files in os.walk(path, followlinks=True):
                # Modify dirs in-place to skip excluded directories
                dirs[:] = [d for d in dirs if d not in cls.EXCLUDE_DIRS]

                count += len(files)

                # Safety break for massive repos to avoid taking too long just to count
                if count > 2000:
                    return count

        except Exception as e:
            logger.warning(f"Failed to count files in {path}: {e}")
            return 0

        return count
