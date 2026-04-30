"""
Secure Subprocess Runner for Vexa.

Implements:
- SEC-006: Use shell=False in all subprocess calls
- SEC-008: Privilege isolation for subprocesses
- REL-001: Graceful timeout handling with recovery
"""

import asyncio
import os
import sys
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from vexa.security.validators import CommandSanitizer
from vexa.common.logging import get_logger, audit_logger


logger = get_logger(__name__)


@dataclass
class SubprocessResult:
    """Result from subprocess execution."""

    stdout: str
    stderr: str
    returncode: int
    command: List[str]
    duration: float = 0.0


class SubprocessTimeoutError(Exception):
    """Raised when a subprocess times out."""

    def __init__(self, message: str, timeout: int, command: List[str]):
        super().__init__(message)
        self.timeout = timeout
        self.command = command


class SecureSubprocessRunner:
    """
    Secure subprocess execution with shell=False enforcement.

    SEC-006: shell=False enforced in all subprocess calls
    SEC-008: Privilege isolation for subprocesses
    REL-001: Graceful timeout handling with recovery

    Usage:
        runner = SecureSubprocessRunner()
        result = await runner.run(["bandit", "-r", "."], cwd=Path("/project"))
    """

    # Default timeout in seconds - REL-001
    default_timeout: int = 300  # 5 minutes

    # Environment variables to exclude - SEC-008
    SENSITIVE_ENV_VARS = [
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "DATABASE_PASSWORD",
        "DB_PASSWORD",
        "PRIVATE_KEY",
        "API_SECRET",
    ]

    # Environment variables to always include (safe)
    SAFE_ENV_VARS = [
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "LC_ALL",
        "TERM",
        "PYTHONPATH",
        "NODE_PATH",
        "GOPATH",
        # Windows specific
        "SYSTEMROOT",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "ALLUSERSPROFILE",
        "PUBLIC",
        "COMPUTERNAME",
        "USERNAME",
        "OS",
    ]

    def __init__(self, sanitizer: Optional[CommandSanitizer] = None):
        """Initialize SecureSubprocessRunner."""
        self.sanitizer = sanitizer or CommandSanitizer()

    async def run(
        self,
        cmd: List[str],
        cwd: Path,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SubprocessResult:
        """
        Execute a command securely with shell=False.

        Args:
            cmd: Command and arguments as a list (NOT a string)
            cwd: Working directory for command execution
            timeout: Timeout in seconds (default: 300)
            env: Additional environment variables to include

        Returns:
            SubprocessResult with stdout, stderr, and return code

        Raises:
            TypeError: If cmd is not a list
            ValueError: If cmd is empty
            SubprocessTimeoutError: If command times out - REL-001
            FileNotFoundError: If command not found or cwd doesn't exist
            SecurityError: If command contains dangerous characters
        """
        import time

        # Validate command is a list - SEC-006
        if not isinstance(cmd, list):
            raise TypeError(
                f"SEC-006: Command must be a list, not {type(cmd).__name__}. "
                "This prevents shell=True from being used."
            )

        # Validate command is not empty
        if not cmd:
            raise ValueError("SEC-006: Command list cannot be empty")

        # Validate and sanitize all arguments - SEC-007
        cmd = self.sanitizer.sanitize_args(cmd)

        # Validate working directory exists
        if not cwd.exists():
            raise FileNotFoundError(f"Working directory does not exist: {cwd}")

        # Get restricted environment - SEC-008
        process_env = self._get_restricted_env(env)

        # Set timeout
        timeout = timeout or self.default_timeout

        logger.debug("Executing command: %s in %s (timeout: %ds)", cmd, cwd, timeout)

        start_time = time.time()

        # Resolve executable path - Handle Windows batch files and cross-platform issues
        path_env = process_env.get("PATH", "")
        executable = shutil.which(cmd[0], path=path_env)

        # Fallback to system PATH if not found in restricted PATH
        if not executable:
            executable = shutil.which(cmd[0])

        if not executable:
            logger.error("Command not found: %s. PATH=%s", cmd[0], path_env)
            raise FileNotFoundError(f"Command not found: {cmd[0]}")

        logger.debug("Resolved %s to %s", cmd[0], executable)

        # Update command with full path
        full_cmd = [executable] + cmd[1:]

        try:
            # SEC-006: CRITICAL - Never use shell=True
            # REL-001: Redirect stdin to DEVNULL to prevent scanners from hanging
            # waiting for input and deadlocking with the MCP server
            process = await asyncio.create_subprocess_exec(
                *full_cmd,
                cwd=str(cwd),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=process_env,
            )

            # REL-001: Apply timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                # Kill the process on timeout
                process.kill()
                try:
                    await process.wait()
                except Exception:
                    pass

                duration = time.time() - start_time

                audit_logger.log_event(
                    "subprocess_timeout",
                    {
                        "command": cmd,
                        "timeout": timeout,
                        "duration": duration,
                    },
                    severity="WARNING",
                )

                raise SubprocessTimeoutError(
                    f"REL-001: Command timed out after {timeout}s: {' '.join(cmd[:3])}...",
                    timeout=timeout,
                    command=cmd,
                )

            duration = time.time() - start_time

            result = SubprocessResult(
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                returncode=process.returncode,
                command=cmd,
                duration=duration,
            )

            logger.debug(
                "Command completed: returncode=%d, duration=%.2fs",
                result.returncode,
                duration,
            )

            return result

        except FileNotFoundError as e:
            logger.error("Command not found: %s", cmd[0])
            raise FileNotFoundError(f"Command not found: {cmd[0]}") from e

    def _get_restricted_env(
        self, additional_env: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Create a restricted environment for subprocess execution.

        SEC-008: Privilege isolation - only include safe environment variables.

        Args:
            additional_env: Additional environment variables to include

        Returns:
            Restricted environment dictionary
        """
        restricted = {}

        # Only include safe environment variables
        for var in self.SAFE_ENV_VARS:
            if var in os.environ:
                restricted[var] = os.environ[var]

        # Ensure the current Python environment's Scripts/bin dir is in PATH - SEC-008.1
        # This helps find sibling tools in the same virtual environment.
        py_bin_dir = str(Path(sys.executable).parent)
        current_path = restricted.get("PATH", "")
        if py_bin_dir not in current_path:
            restricted["PATH"] = f"{py_bin_dir}{os.pathsep}{current_path}"

        # Enforce UTF-8 for subprocesses - REL-002
        restricted["PYTHONIOENCODING"] = "utf-8"
        restricted["PYTHONUTF8"] = "1"

        # Add any additional environment variables
        if additional_env:
            for key, value in additional_env.items():
                # Check that additional vars are not in sensitive list
                if key.upper() not in [s.upper() for s in self.SENSITIVE_ENV_VARS]:
                    restricted[key] = value

        return restricted

    async def run_with_input(
        self,
        cmd: List[str],
        cwd: Path,
        stdin_data: str,
        timeout: Optional[int] = None,
    ) -> SubprocessResult:
        """
        Execute a command with stdin input.

        Args:
            cmd: Command and arguments as a list
            cwd: Working directory
            stdin_data: Data to send to stdin
            timeout: Timeout in seconds

        Returns:
            SubprocessResult with output
        """
        import time

        # Validate command is a list - SEC-006
        if not isinstance(cmd, list):
            raise TypeError(
                f"SEC-006: Command must be a list, not {type(cmd).__name__}"
            )

        if not cmd:
            raise ValueError("SEC-006: Command list cannot be empty")

        cmd = self.sanitizer.sanitize_args(cmd)

        if not cwd.exists():
            raise FileNotFoundError(f"Working directory does not exist: {cwd}")

        process_env = self._get_restricted_env()
        timeout = timeout or self.default_timeout

        start_time = time.time()

        executable = shutil.which(cmd[0], path=process_env.get("PATH"))
        if not executable:
            raise FileNotFoundError(f"Command not found: {cmd[0]}")

        full_cmd = [executable] + cmd[1:]

        try:
            process = await asyncio.create_subprocess_exec(
                *full_cmd,
                cwd=str(cwd),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=process_env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=stdin_data.encode("utf-8")),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                try:
                    await process.wait()
                except Exception:
                    pass

                raise SubprocessTimeoutError(
                    f"REL-001: Command timed out after {timeout}s",
                    timeout=timeout,
                    command=cmd,
                )

            duration = time.time() - start_time

            return SubprocessResult(
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                returncode=process.returncode,
                command=cmd,
                duration=duration,
            )

        except FileNotFoundError:
            raise FileNotFoundError(f"Command not found: {cmd[0]}")
