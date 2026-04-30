"""
Logging configuration for Vexa.

Implements REL-003: Comprehensive error handling with logging
Implements REL-004: Audit logging for security events
Implements SEC-004: Sanitize log messages
"""

import logging
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any, Dict

from vexa.common.config import LOGS_STORAGE_PATH, LOG_FORMAT, AUDIT_LOG_FORMAT


# Sensitive data patterns for sanitization - SEC-004
SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?[^\s"\']+'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(api_key|apikey|api-key)["\']?\s*[:=]\s*["\']?[^\s"\']+'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(secret|token)["\']?\s*[:=]\s*["\']?[^\s"\']+'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(auth|authorization)["\']?\s*[:=]\s*["\']?[^\s"\']+'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(aws_access_key|aws_secret)["\']?\s*[:=]\s*["\']?[^\s"\']+'), r'\1=***REDACTED***'),
]


def sanitize_log_message(message: str) -> str:
    """
    Sanitize log message by removing sensitive data - SEC-004.
    
    Args:
        message: The log message to sanitize
        
    Returns:
        Sanitized log message with sensitive data redacted
    """
    sanitized = message
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class SanitizingFilter(logging.Filter):
    """Log filter that sanitizes sensitive data - SEC-004."""
    
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_log_message(record.msg)
        if record.args:
            record.args = tuple(
                sanitize_log_message(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )
        return True


class AuditLogger:
    """
    Audit logger for security events - REL-004.
    
    Logs security-relevant events in a structured format for compliance
    and forensic analysis.
    """
    
    def __init__(self, name: str = "vexa.audit"):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.INFO)
        
        # Ensure logs directory exists and fallback to NullHandler if unwritable
        try:
            LOGS_STORAGE_PATH.mkdir(parents=True, exist_ok=True)
            audit_log_file = LOGS_STORAGE_PATH / "audit.log"
            file_handler = logging.FileHandler(audit_log_file)
        except (PermissionError, OSError):
            file_handler = logging.NullHandler()

        file_handler.setFormatter(logging.Formatter(AUDIT_LOG_FORMAT))
        file_handler.addFilter(SanitizingFilter())
        
        if not self._logger.handlers:
            self._logger.addHandler(file_handler)
    
    def log_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: str = "INFO"
    ) -> None:
        """
        Log a security audit event.
        
        Args:
            event_type: Type of security event (e.g., "SEC-001 violation")
            details: Additional event details
            severity: Event severity level
        """
        event_data = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
        }
        
        log_method = getattr(self._logger, severity.lower(), self._logger.info)
        log_method(json.dumps(event_data))
    
    def log_security_violation(
        self,
        control_id: str,
        description: str,
        source: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log a security control violation.
        
        Args:
            control_id: Security control ID (e.g., "SEC-001")
            description: Description of the violation
            source: Source of the violation (e.g., file path, user input)
            details: Additional details
        """
        event_details = {
            "control_id": control_id,
            "description": sanitize_log_message(description),
            "source": sanitize_log_message(source) if source else None,
            **(details or {}),
        }
        self.log_event(f"{control_id} violation", event_details, severity="WARNING")
    
    def log_job_event(
        self,
        job_id: str,
        event: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log a job lifecycle event.
        
        Args:
            job_id: The job ID
            event: Event type (created, started, completed, failed, cancelled)
            details: Additional details
        """
        event_details = {
            "job_id": job_id,
            "event": event,
            **(details or {}),
        }
        self.log_event(f"job_{event}", event_details)

    def log_security_event(
        self,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a security event (alias/helper).
        
        Args:
            event_type: Type of security event
            details: Additional event details
        """
        self.log_event(event_type, details or {})


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger instance - REL-003.
    
    Args:
        name: Logger name (typically module name)
        
    Returns:
        Configured logger instance with sanitization filter
    """
    logger = logging.getLogger(name)
    
    # Only configure if no handlers exist
    if not logger.handlers:
        import os
        import sys
        
        # Determine global log level - Default to INFO/WARNING for professional CLI experience
        debug_mode = os.environ.get("VEXA_DEBUG", "").lower() == "true"
        console_level = logging.DEBUG if debug_mode else logging.WARNING
        internal_level = logging.DEBUG if debug_mode else logging.INFO
        
        # Console handler - Use stderr to avoid corrupting MCP stdout
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(console_level)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        console_handler.addFilter(SanitizingFilter())
        logger.addHandler(console_handler)
        
        # Ensure logs directory exists and fallback to NullHandler if unwritable
        try:
            LOGS_STORAGE_PATH.mkdir(parents=True, exist_ok=True)
            log_file = LOGS_STORAGE_PATH / f"{name.replace('.', '_')}.log"
            file_handler = logging.FileHandler(log_file)
        except (PermissionError, OSError):
            file_handler = logging.NullHandler()
            
        file_handler.setLevel(internal_level)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        file_handler.addFilter(SanitizingFilter())
        logger.addHandler(file_handler)
        
        logger.setLevel(internal_level)
    
    return logger


# Global audit logger instance
audit_logger = AuditLogger()
