"""
Security Validators for Vexa.

Implements:
- SEC-001: Path Traversal Prevention (CWE-22, CWE-23)
- SEC-002: Command Injection Prevention (CWE-77, CWE-78)
- SEC-005: Block Access to System Directories
- SEC-007: Sanitize All User Inputs
"""

import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from vexa.common.logging import get_logger, audit_logger


logger = get_logger(__name__)


class SecurityError(Exception):
    """
    Security violation exception.
    
    Raised when a security control detects a violation.
    """
    
    def __init__(
        self,
        message: str,
        control_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.control_id = control_id or self._extract_control_id(message)
        self.details = details or {}
    
    def _extract_control_id(self, message: str) -> Optional[str]:
        """Extract SEC-XXX control ID from message."""
        match = re.search(r'SEC-\d{3}', message)
        return match.group(0) if match else None


class PathValidator:
    """
    Validate and sanitize file paths.
    
    SEC-001: Prevent path traversal attacks (CWE-22, CWE-23)
    SEC-005: Block access to system directories
    """
    
    # Maximum path length to prevent DoS
    MAX_PATH_LENGTH = 4096
    
    # System directories to block - SEC-005
    BLOCKED_PATHS_UNIX = [
        "/etc",
        "/var",
        "/usr",
        "/root",
        "/boot",
        "/sys",
        "/proc",
        "/dev",
        "/sbin",
        "/bin",
    ]
    
    BLOCKED_PATHS_WINDOWS = [
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\ProgramData",
        "C:\\System Volume Information",
    ]
    
    # Dangerous characters in paths
    DANGEROUS_CHARS = ["\x00"]  # Null byte
    
    def __init__(self):
        """Initialize PathValidator with platform-specific blocked paths."""
        if sys.platform == "win32":
            raw_paths = self.BLOCKED_PATHS_WINDOWS
        else:
            raw_paths = self.BLOCKED_PATHS_UNIX
            
        self.blocked_paths = []
        for p in raw_paths:
            self.blocked_paths.append(p)
            try:
                # Try to resolve blocked paths to handle system symlinks (like macOS /etc -> /private/etc)
                # We use resolve() to find the real path on the current system
                path_obj = Path(p)
                if path_obj.exists():
                    resolved = str(path_obj.resolve())
                    if resolved != p and resolved not in self.blocked_paths:
                        self.blocked_paths.append(resolved)
            except (OSError, ValueError):
                # If we can't resolve it (e.g. doesn't exist), just stick with the raw path
                pass
    
    def validate(self, path: str) -> Path:
        """
        Validate a path and return the resolved Path object.
        
        Args:
            path: The path to validate
            
        Returns:
            Resolved Path object
            
        Raises:
            SecurityError: If the path violates security controls
        """
        # Check for empty path
        if not path or not path.strip():
            audit_logger.log_security_violation(
                "SEC-001",
                "Empty path provided",
                source=path
            )
            raise SecurityError(
                "SEC-001: Empty path not allowed",
                control_id="SEC-001",
                details={"path": path}
            )
        
        path = path.strip()
        
        # Check path length
        if len(path) > self.MAX_PATH_LENGTH:
            audit_logger.log_security_violation(
                "SEC-001",
                f"Path exceeds maximum length ({len(path)} > {self.MAX_PATH_LENGTH})",
                source=path[:100]
            )
            raise SecurityError(
                f"SEC-001: Path exceeds maximum length of {self.MAX_PATH_LENGTH}",
                control_id="SEC-001",
                details={"length": len(path), "max": self.MAX_PATH_LENGTH}
            )
        
        # Check for null bytes - SEC-001
        for char in self.DANGEROUS_CHARS:
            if char in path:
                audit_logger.log_security_violation(
                    "SEC-001",
                    "Null byte in path detected",
                    source=repr(path)
                )
                raise SecurityError(
                    "SEC-001: Null byte in path detected",
                    control_id="SEC-001",
                    details={"path": repr(path)}
                )
        
        # Check for path traversal attempts - SEC-001
        if ".." in path:
            audit_logger.log_security_violation(
                "SEC-001",
                "Path traversal attempt detected",
                source=path
            )
            raise SecurityError(
                "SEC-001: Path traversal blocked - '..' not allowed",
                control_id="SEC-001",
                details={"path": path}
            )
        
        # Resolve the path
        try:
            resolved = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise SecurityError(
                f"SEC-001: Invalid path - {e}",
                control_id="SEC-001",
                details={"path": path, "error": str(e)}
            )
        
        # Check for symlinks to blocked paths - SEC-005
        resolved_str = str(resolved)
        
        # Get system temp dir and resolve it to handle its resolution of symlinks
        try:
            temp_dir = Path(tempfile.gettempdir()).resolve()
        except (OSError, ValueError):
            temp_dir = None
            
        for blocked in self.blocked_paths:
            blocked_normalized = blocked.lower() if sys.platform == "win32" else blocked
            resolved_normalized = resolved_str.lower() if sys.platform == "win32" else resolved_str
            
            if resolved_normalized.startswith(blocked_normalized):
                # Check if this is actually a child of the system's legitimate temp directory
                # We allow temp dir subtrees even if they are under blocked high-level paths like /var (macOS)
                if temp_dir and (resolved == temp_dir or temp_dir in resolved.parents):
                    continue
                
                audit_logger.log_security_violation(
                    "SEC-005",
                    f"Access to system directory blocked: {blocked}",
                    source=path,
                    details={"resolved": resolved_str, "blocked": blocked}
                )
                raise SecurityError(
                    f"SEC-005: Access to system directory blocked: {blocked}",
                    control_id="SEC-005",
                    details={"path": path, "resolved": resolved_str, "blocked": blocked}
                )
        
        logger.debug("Path validated: %s -> %s", path, resolved)
        return resolved


class CommandSanitizer:
    """
    Sanitize command arguments to prevent injection.
    
    SEC-002: Command Injection Prevention (CWE-77, CWE-78)
    SEC-007: Sanitize All User Inputs
    """
    
    # Shell metacharacters that could enable command injection
    DANGEROUS_CHARS = [
        ";",   # Command separator
        "|",   # Pipe
        "&",   # Background/AND operator
        "$",   # Variable/command substitution
        "`",   # Command substitution (backtick)
        "(",   # Subshell
        ")",   # Subshell
        "{",   # Brace expansion
        "}",   # Brace expansion
        "<",   # Input redirect
        ">",   # Output redirect
        "\n",  # Newline command injection
        "\r",  # Carriage return
        "!",   # History expansion (bash)
    ]
    
    def sanitize(self, arg: str) -> str:
        """
        Sanitize a single command argument.
        
        Args:
            arg: The argument to sanitize
            
        Returns:
            Sanitized argument (same as input if safe)
            
        Raises:
            SecurityError: If the argument contains dangerous characters
        """
        # Strip whitespace
        arg = arg.strip()
        
        # Empty strings are technically safe
        if not arg:
            return arg
        
        # Check for dangerous characters - SEC-002
        for char in self.DANGEROUS_CHARS:
            if char in arg:
                # Get readable representation of the character
                char_repr = repr(char) if not char.isprintable() else char
                
                audit_logger.log_security_violation(
                    "SEC-002",
                    f"Dangerous character in command argument: {char_repr}",
                    source=arg[:100],
                    details={"character": char_repr, "argument": arg[:100]}
                )
                raise SecurityError(
                    f"SEC-002: Dangerous character blocked: {char_repr}",
                    control_id="SEC-002",
                    details={"character": char_repr, "argument": arg}
                )
        
        logger.debug("Argument sanitized: %s", arg)
        return arg
    
    def sanitize_args(self, args: List[str]) -> List[str]:
        """
        Sanitize a list of command arguments.
        
        SEC-007: Sanitize all user inputs.
        
        Args:
            args: List of arguments to sanitize
            
        Returns:
            List of sanitized arguments
            
        Raises:
            SecurityError: If any argument contains dangerous characters
        """
        return [self.sanitize(arg) for arg in args]
