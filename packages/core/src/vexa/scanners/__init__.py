"""
Scanners Module for Vexa.

SS-001: Security scanning tool integration
SS-002: Local and container execution modes
SS-008: pip-audit integration
SS-009: pip-licenses integration
SS-014: Framework mapping
"""

from vexa.scanners.base import (
    BaseScanner,
    ScannerFinding,
    ScannerSeverity,
    Finding,         # Deprecated alias for ScannerFinding
    FindingSeverity,  # Deprecated alias for ScannerSeverity
    ScanMode,
    ScannerResult,
)
from vexa.scanners.engine import (
    ScannerEngine,
    ScanResult,
    get_scanner_engine,
)
from vexa.scanners.framework_mapper import (
    FrameworkMapper,
    get_framework_mapper,
)
from vexa.scanners.bandit import BanditScanner
from vexa.scanners.semgrep import SemgrepScanner
from vexa.scanners.checkov import CheckovScanner
from vexa.scanners.detect_secrets import DetectSecretsScanner
from vexa.scanners.npm_audit import NpmAuditScanner
from vexa.scanners.grype import GrypeScanner
from vexa.scanners.syft import SyftScanner
from vexa.scanners.pip_audit import PipAuditScanner
from vexa.scanners.pip_licenses import PipLicensesScanner

__all__ = [
    # Base classes
    "BaseScanner",
    "Finding",
    "FindingSeverity",
    "ScanMode",
    "ScannerResult",
    # Engine
    "ScannerEngine",
    "ScanResult",
    "get_scanner_engine",
    # Framework mapping
    "FrameworkMapper",
    "get_framework_mapper",
    # Scanners
    "BanditScanner",
    "SemgrepScanner",
    "CheckovScanner",
    "DetectSecretsScanner",
    "NpmAuditScanner",
    "GrypeScanner",
    "SyftScanner",
    "PipAuditScanner",
    "PipLicensesScanner",
]
