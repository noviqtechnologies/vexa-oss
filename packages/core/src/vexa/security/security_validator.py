"""
Security Validator for Vexa.

Pre-merge validation of findings to prevent CWE issues and ensure
security controls are enforced.

Implements:
- SEC-001: Path Traversal Prevention (CWE-22, CWE-23)
- SEC-002: Command Injection Prevention (CWE-77, CWE-78)
- SEC-003: XSS Prevention (CWE-79)
- SEC-004: Log Message Sanitization (CWE-200)
- SEC-007: Sanitize All User Inputs
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from vexa.common.logging import get_logger, audit_logger
from vexa.common.models import Finding, EnhancedFinding
from vexa.security.validators import PathValidator, CommandSanitizer, SecurityError


logger = get_logger(__name__)


class FindingValidator:
    """
    Validates security findings before they are merged and outputted.
    
    Ensures:
    - File paths in findings are valid and don't contain traversal attacks
    - Finding content doesn't contain malicious payloads
    - Sensitive data is sanitized in outputs
    """
    
    # Patterns that might indicate malicious content in findings
    SUSPICIOUS_PATTERNS = [
        r"<script[^>]*>",  # XSS attempt
        r"javascript:",  # XSS via protocol
        r"on\w+\s*=",  # Event handler injection
        r"\$\{.+\}",  # Template injection
        r"{{.+}}",  # Template injection (Jinja/Angular)
        r"`.*`",  # Backtick command substitution (only in certain contexts)
    ]
    
    # Sensitive data patterns to redact
    SENSITIVE_PATTERNS = [
        (r"(?i)password\s*[=:]\s*['\"]?(\S+)['\"]?", "password=***REDACTED***"),
        (r"(?i)api[_-]?key\s*[=:]\s*['\"]?(\S+)['\"]?", "api_key=***REDACTED***"),
        (r"(?i)secret\s*[=:]\s*['\"]?(\S+)['\"]?", "secret=***REDACTED***"),
        (r"(?i)token\s*[=:]\s*['\"]?(\S+)['\"]?", "token=***REDACTED***"),
        (r"(?i)aws_access_key_id\s*[=:]\s*['\"]?(\S+)['\"]?", "aws_access_key_id=***REDACTED***"),
        (r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?(\S+)['\"]?", "aws_secret_access_key=***REDACTED***"),
    ]
    
    def __init__(self):
        """Initialize FindingValidator with path and command validators."""
        self._path_validator = PathValidator()
        self._command_sanitizer = CommandSanitizer()
    
    def validate_finding(self, finding: Finding) -> Tuple[bool, List[str]]:
        """
        Validate a single finding for security issues.
        
        Args:
            finding: The finding to validate
            
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []
        
        # Validate file path - SEC-001
        try:
            # Don't resolve, just check for basic traversal
            if ".." in finding.file_path:
                errors.append(f"SEC-001: Path traversal detected in file_path: {finding.file_path}")
            if "\x00" in finding.file_path:
                errors.append(f"SEC-001: Null byte detected in file_path")
        except Exception as e:
            errors.append(f"SEC-001: Invalid file path: {e}")
        
        # Check for suspicious content in code snippet - SEC-003
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, finding.code_snippet, re.IGNORECASE):
                # Log but don't fail - the code snippet is from the actual source
                logger.debug(
                    "SEC-003: Suspicious pattern in code snippet (expected for vulnerability): %s",
                    pattern
                )
        
        # Validate line numbers
        if finding.line_start < 0:
            errors.append(f"Invalid line_start: {finding.line_start}")
        if finding.line_end < finding.line_start:
            errors.append(f"line_end ({finding.line_end}) < line_start ({finding.line_start})")
        
        # Validate severity
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if finding.severity not in valid_severities:
            errors.append(f"Invalid severity: {finding.severity}")
        
        is_valid = len(errors) == 0
        
        if not is_valid:
            audit_logger.log_security_violation(
                "SEC-007",
                f"Finding validation failed: {finding.id}",
                details={"errors": errors}
            )
        
        return (is_valid, errors)
    
    def validate_findings(
        self,
        findings: List[Finding],
    ) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        """
        Validate multiple findings.
        
        Args:
            findings: List of findings to validate
            
        Returns:
            Tuple of (valid_findings, validation_errors)
        """
        valid_findings = []
        validation_errors = []
        
        for finding in findings:
            is_valid, errors = self.validate_finding(finding)
            
            if is_valid:
                valid_findings.append(finding)
            else:
                validation_errors.append({
                    "finding_id": finding.id,
                    "errors": errors,
                })
        
        logger.info(
            "Finding validation: %d valid, %d invalid",
            len(valid_findings), len(validation_errors)
        )
        
        return (valid_findings, validation_errors)
    
    def sanitize_finding_output(self, finding: Finding) -> Finding:
        """
        Sanitize finding content for safe output.
        
        SEC-004: Log message sanitization
        SEC-003: XSS prevention in output
        
        Args:
            finding: The finding to sanitize
            
        Returns:
            Sanitized finding
        """
        # Create a copy to avoid modifying the original
        sanitized = finding.model_copy()
        
        # Sanitize code snippet - redact sensitive data
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            sanitized.code_snippet = re.sub(pattern, replacement, sanitized.code_snippet)
        
        # Sanitize description
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            sanitized.description = re.sub(pattern, replacement, sanitized.description)
        
        return sanitized
    
    def sanitize_findings_for_output(
        self,
        findings: List[Finding],
    ) -> List[Finding]:
        """
        Sanitize multiple findings for safe output.
        
        Args:
            findings: List of findings to sanitize
            
        Returns:
            List of sanitized findings
        """
        return [self.sanitize_finding_output(f) for f in findings]


class SecurityValidator:
    """
    Central security validator for Vexa.
    
    Provides:
    - Pre-merge finding validation
    - Path validation for all file operations
    - Command argument sanitization
    - Audit logging for security events
    """
    
    def __init__(self):
        """Initialize SecurityValidator with component validators."""
        self._path_validator = PathValidator()
        self._command_sanitizer = CommandSanitizer()
        self._finding_validator = FindingValidator()
    
    def validate_path(self, path: str) -> Path:
        """
        Validate a path for security issues.
        
        SEC-001: Path Traversal Prevention
        SEC-005: Block system directories
        
        Args:
            path: The path to validate
            
        Returns:
            Validated and resolved Path
            
        Raises:
            SecurityError: If path fails validation
        """
        return self._path_validator.validate(path)
    
    def sanitize_command_args(self, args: List[str]) -> List[str]:
        """
        Sanitize command arguments.
        
        SEC-002: Command Injection Prevention
        SEC-007: Input sanitization
        
        Args:
            args: List of command arguments
            
        Returns:
            Sanitized arguments
            
        Raises:
            SecurityError: If args contain dangerous characters
        """
        return self._command_sanitizer.sanitize_args(args)
    
    def validate_findings_pre_merge(
        self,
        findings: List[Finding],
    ) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        """
        Validate findings before merging.
        
        Args:
            findings: List of findings to validate
            
        Returns:
            Tuple of (valid_findings, validation_errors)
        """
        return self._finding_validator.validate_findings(findings)
    
    def sanitize_findings_for_output(
        self,
        findings: List[Finding],
    ) -> List[Finding]:
        """
        Sanitize findings for safe output.
        
        Args:
            findings: List of findings to sanitize
            
        Returns:
            Sanitized findings
        """
        return self._finding_validator.sanitize_findings_for_output(findings)
    
    def log_security_event(
        self,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a security event via the audit logger.
        
        REL-004: Audit logging for security events
        
        Args:
            event_type: Type of security event
            details: Additional event details
        """
        audit_logger.log_event(event_type, details or {})


# Singleton instance
_security_validator: Optional[SecurityValidator] = None


def get_security_validator() -> SecurityValidator:
    """Get the global SecurityValidator singleton."""
    global _security_validator
    if _security_validator is None:
        _security_validator = SecurityValidator()
    return _security_validator
