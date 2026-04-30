"""
Output Sanitizer for Vexa.

Implements:
- SEC-003: XSS Prevention (CWE-79)
- SEC-004: Sanitize Log Messages (CWE-200)
"""

import html
import re
from typing import List, Pattern, Tuple

from vexa.common.logging import get_logger


logger = get_logger(__name__)


class OutputSanitizer:
    """
    Sanitize output for safe display and logging.
    
    SEC-003: XSS Prevention - escape HTML content
    SEC-004: Log sanitization - remove sensitive data from logs
    
    Usage:
        sanitizer = OutputSanitizer()
        safe_html = sanitizer.escape_html("<script>alert(1)</script>")
        safe_log = sanitizer.sanitize_logs("password=secret123")
    """
    
    # Patterns for sensitive data - SEC-004
    # Each tuple is (pattern, replacement)
    SENSITIVE_PATTERNS: List[Tuple[Pattern, str]] = [
        # Passwords
        (
            re.compile(r'(?i)(password|passwd|pwd)(["\']?\s*[:=]\s*["\']?)([^\s"\']+)', re.IGNORECASE),
            r'\1\2***REDACTED***'
        ),
        # API Keys
        (
            re.compile(r'(?i)(api[_-]?key|apikey)(["\']?\s*[:=]\s*["\']?)([^\s"\']+)', re.IGNORECASE),
            r'\1\2***REDACTED***'
        ),
        # Tokens
        (
            re.compile(r'(?i)(token|bearer|jwt)(["\']?\s*[:=]\s*["\']?)([^\s"\']+)', re.IGNORECASE),
            r'\1\2***REDACTED***'
        ),
        # Secrets
        (
            re.compile(r'(?i)(secret|private[_-]?key)(["\']?\s*[:=]\s*["\']?)([^\s"\']+)', re.IGNORECASE),
            r'\1\2***REDACTED***'
        ),
        # AWS Credentials
        (
            re.compile(r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)(["\']?\s*[:=]\s*["\']?)([^\s"\']+)', re.IGNORECASE),
            r'\1\2***REDACTED***'
        ),
        # Authorization headers - match Bearer token and full header value
        (
            re.compile(r'(?i)(authorization|auth)(["\']?\s*[:=]\s*["\']?)(Bearer\s+)?([^\s"\']+(?:\.[^\s"\']+)*)', re.IGNORECASE),
            r'\1\2***REDACTED***'
        ),
        # Connection strings with passwords
        (
            re.compile(r'(?i)(mongodb|mysql|postgres|redis)://[^:]+:([^@]+)@', re.IGNORECASE),
            r'\1://***:***REDACTED***@'
        ),
    ]
    
    # Additional JSON-aware patterns
    JSON_SENSITIVE_PATTERNS: List[Tuple[Pattern, str]] = [
        # JSON: "password": "value"
        (
            re.compile(r'"(password|passwd|pwd|secret|api[_-]?key|token|auth)":\s*"([^"]+)"', re.IGNORECASE),
            r'"\1": "***REDACTED***"'
        ),
        # JSON: 'password': 'value'
        (
            re.compile(r"'(password|passwd|pwd|secret|api[_-]?key|token|auth)':\s*'([^']+)'", re.IGNORECASE),
            r"'\1': '***REDACTED***'"
        ),
    ]
    
    def escape_html(self, content: str) -> str:
        """
        Escape HTML special characters to prevent XSS.
        
        SEC-003: XSS Prevention (CWE-79)
        
        Args:
            content: The content to escape
            
        Returns:
            HTML-escaped content safe for display in HTML context
            
        Example:
            >>> sanitizer.escape_html("<script>alert(1)</script>")
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        """
        if not content:
            return content
        
        # Use Python's built-in html.escape which handles:
        # & -> &amp;
        # < -> &lt;
        # > -> &gt;
        # " -> &quot; (when quote=True)
        # ' -> &#x27; (when quote=True)
        return html.escape(content, quote=True)
    
    def sanitize_logs(self, message: str) -> str:
        """
        Remove sensitive information from log messages.
        
        SEC-004: Sanitize Log Messages (CWE-200)
        
        Args:
            message: The log message to sanitize
            
        Returns:
            Sanitized message with sensitive data redacted
            
        Example:
            >>> sanitizer.sanitize_logs("password=secret123")
            "password=***REDACTED***"
        """
        if not message:
            return message
        
        sanitized = message
        
        # Apply standard patterns
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        
        # Apply JSON patterns
        for pattern, replacement in self.JSON_SENSITIVE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        
        return sanitized
    
    def sanitize_all(self, content: str) -> str:
        """
        Apply both log sanitization and HTML escaping.
        
        Convenience method to prepare content for safe display in HTML
        while also removing sensitive data.
        
        Args:
            content: The content to sanitize
            
        Returns:
            Content safe for HTML display with sensitive data removed
        """
        if not content:
            return content
        
        # First sanitize sensitive data from logs
        sanitized = self.sanitize_logs(content)
        
        # Then escape for HTML
        escaped = self.escape_html(sanitized)
        
        return escaped
    
    def sanitize_finding_output(self, finding_output: str) -> str:
        """
        Sanitize scanner finding output for display.
        
        Specialized method for sanitizing security scanner output
        which may contain code snippets and paths.
        
        Args:
            finding_output: Raw output from security scanner
            
        Returns:
            Sanitized output safe for display
        """
        if not finding_output:
            return finding_output
        
        # First apply log sanitization
        sanitized = self.sanitize_logs(finding_output)
        
        # Escape HTML for safe display
        sanitized = self.escape_html(sanitized)
        
        return sanitized


# Global singleton instance
_output_sanitizer: OutputSanitizer = None


def get_output_sanitizer() -> OutputSanitizer:
    """Get the global OutputSanitizer singleton instance."""
    global _output_sanitizer
    if _output_sanitizer is None:
        _output_sanitizer = OutputSanitizer()
    return _output_sanitizer
