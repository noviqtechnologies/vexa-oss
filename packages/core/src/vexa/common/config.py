"""
Configuration settings for Vexa.

This module contains all configuration constants and settings.
"""

from pathlib import Path
from typing import Optional
import os
import tempfile


# Job Management Configuration - PERF-007, PERF-008
MAX_CONCURRENT_JOBS: int = 25  # PERF-007: Maximum concurrent jobs
JOB_TTL_HOURS: int = 24  # PERF-008: Job TTL for cleanup (hours)


# Storage Paths
def _get_default_home() -> Path:
    """Determine the default Vexa home directory with fallback for CI/Docker."""
    if os.environ.get("VEXA_HOME"):
        return Path(os.environ["VEXA_HOME"])

    # In CI environments, default to /tmp to avoid permission issues in /github/home
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        return Path(tempfile.gettempdir()) / ".vexa"

    try:
        return Path.home() / ".vexa"
    except Exception:
        # Fallback for environments without a defined home directory
        return Path(tempfile.gettempdir()) / ".vexa"


VEXA_HOME: Path = _get_default_home()
JOBS_STORAGE_PATH: Path = VEXA_HOME / "jobs"
SCANS_STORAGE_PATH: Path = VEXA_HOME / "scans"
REPORTS_STORAGE_PATH: Path = VEXA_HOME / "reports"
THREAT_MODELS_STORAGE_PATH: Path = VEXA_HOME / "threat_models"
LOGS_STORAGE_PATH: Path = VEXA_HOME / "logs"
CONFIG_FILE_PATH: Path = VEXA_HOME / "config.yaml"
TERMS_ACCEPTANCE_FILE: Path = VEXA_HOME / ".terms_accepted"

# Scanner Timeouts (seconds)
SCANNER_TIMEOUT: int = 480  # 8 minutes per scanner
AI_BATCH_TIMEOUT: int = 600  # 10 minutes per AI batch

# AI Configuration
AI_BATCH_SIZE: int = 10  # Findings per AI batch
FALSE_POSITIVE_THRESHOLD: float = 0.90  # 90% confidence for FP detection
AI_MAX_CONCURRENT_BATCHES: int = 3  # PERF-009: Max concurrent AI batches
AI_CACHE_FILE: Path = VEXA_HOME / "ai_cache.json"
AI_MIN_SEVERITY_THRESHOLD: str = "medium"  # Default min severity for AI enrichment

# Performance Targets - From TDD Section 10 & PRD Section 4.2
SMALL_REPO_TIMEOUT: int = 300  # 5 minutes
MEDIUM_REPO_TIMEOUT: int = 600  # 10 minutes
LARGE_REPO_TIMEOUT: int = 1200  # 20 minutes
THREAT_MODEL_TIMEOUT: int = 900  # PERF-004: 10-15 minutes

# Logging Configuration - REL-003, REL-004
LOG_RETENTION_DAYS: int = 30
LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
AUDIT_LOG_FORMAT: str = (
    '{"timestamp": "%(asctime)s", "event": "%(message)s", "level": "%(levelname)s"}'
)


def ensure_storage_dirs() -> None:
    """Create all required storage directories if they don't exist."""
    dirs = [
        VEXA_HOME,
        JOBS_STORAGE_PATH,
        SCANS_STORAGE_PATH,
        REPORTS_STORAGE_PATH,
        THREAT_MODELS_STORAGE_PATH,
        LOGS_STORAGE_PATH,
    ]
    for dir_path in dirs:
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            # Fail silently in restricted environments; logging will fallback to NullHandler
            pass


def get_env(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get environment variable with optional default."""
    return os.environ.get(key, default)


# Cloud Provider Defaults
DEFAULT_CLOUD_PROVIDER: str = get_env("VEXA_CLOUD_PROVIDER", "none")


def is_terms_accepted() -> bool:
    """Check if the user has accepted the terms.

    In CI environments (GitHub Actions, GitLab, etc.), terms are auto-accepted.
    """
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        return True
    return TERMS_ACCEPTANCE_FILE.exists()


def accept_terms() -> None:
    """Mark the terms as accepted."""
    ensure_storage_dirs()
    TERMS_ACCEPTANCE_FILE.touch()
