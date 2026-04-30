"""
Security Module for Vexa.

Provides security controls for input validation, subprocess execution,
and output sanitization.

Requirements:
- SEC-001: Path Traversal Prevention (CWE-22, CWE-23)
- SEC-002: Command Injection Prevention (CWE-77, CWE-78)
- SEC-003: XSS Prevention (CWE-79)
- SEC-004: Sanitize Log Messages (CWE-200)
- SEC-005: Block Access to System Directories
- SEC-006: Use shell=False in all subprocess calls
- SEC-007: Sanitize All User Inputs
- SEC-008: Privilege Isolation for Subprocesses
"""

from vexa.security.validators import (
    PathValidator,
    CommandSanitizer,
    SecurityError,
)
from vexa.security.subprocess_runner import (
    SecureSubprocessRunner,
    SubprocessResult,
    SubprocessTimeoutError,
)
from vexa.security.output_sanitizer import (
    OutputSanitizer,
    get_output_sanitizer,
)

__all__ = [
    # Validators
    "PathValidator",
    "CommandSanitizer",
    "SecurityError",
    # Subprocess
    "SecureSubprocessRunner",
    "SubprocessResult",
    "SubprocessTimeoutError",
    # Output
    "OutputSanitizer",
    "get_output_sanitizer",
]
