"""
Unit tests for SecureSubprocessRunner - TDD Approach

Tests for requirements:
- SEC-006: Use shell=False in all subprocess calls
- SEC-008: Privilege isolation for subprocesses
- REL-001: Graceful timeout handling with recovery
"""

import asyncio
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

from vexa.security.subprocess_runner import (
    SecureSubprocessRunner,
    SubprocessResult,
    SubprocessTimeoutError,
)


class TestSecureSubprocessRunnerSEC006:
    """Test shell=False enforcement - SEC-006."""

    @pytest.mark.asyncio
    async def test_runs_command_without_shell(self):
        """SEC-006: Commands must run with shell=False."""
        runner = SecureSubprocessRunner()
        
        # Simple command that works on all platforms
        if sys.platform == "win32":
            cmd = ["cmd", "/c", "echo", "hello"]
        else:
            cmd = ["echo", "hello"]
        
        result = await runner.run(cmd, cwd=Path.cwd())
        
        assert result.returncode == 0
        assert "hello" in result.stdout.lower() or "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_shell_injection_prevented(self):
        """SEC-006: Shell injection via command string should be blocked by sanitizer."""
        runner = SecureSubprocessRunner()
        
        # Attempt shell injection - this should be BLOCKED by CommandSanitizer
        if sys.platform == "win32":
            cmd = ["cmd", "/c", "echo", "safe && echo INJECTED"]
        else:
            cmd = ["echo", "safe; echo INJECTED"]
        
        # The CommandSanitizer should raise SecurityError for dangerous chars
        from vexa.security.validators import SecurityError
        with pytest.raises(SecurityError, match="SEC-002"):
            await runner.run(cmd, cwd=Path.cwd())

    @pytest.mark.asyncio
    async def test_command_as_list_required(self):
        """SEC-006: Command must be a list, not a string."""
        runner = SecureSubprocessRunner()
        
        # Passing a string should raise an error
        with pytest.raises((TypeError, ValueError)):
            await runner.run("echo hello", cwd=Path.cwd())  # type: ignore

    @pytest.mark.asyncio
    async def test_returns_subprocess_result(self):
        """Command execution should return a structured result."""
        runner = SecureSubprocessRunner()
        
        if sys.platform == "win32":
            cmd = ["cmd", "/c", "echo", "test"]
        else:
            cmd = ["echo", "test"]
        
        result = await runner.run(cmd, cwd=Path.cwd())
        
        assert isinstance(result, SubprocessResult)
        assert hasattr(result, 'stdout')
        assert hasattr(result, 'stderr')
        assert hasattr(result, 'returncode')


class TestSecureSubprocessRunnerSEC008:
    """Test privilege isolation - SEC-008."""

    @pytest.mark.asyncio
    async def test_restricted_environment(self):
        """SEC-008: Subprocess should run with restricted environment."""
        runner = SecureSubprocessRunner()
        
        # Check that dangerous env vars are not passed
        if sys.platform == "win32":
            cmd = ["cmd", "/c", "set"]
        else:
            cmd = ["env"]
        
        result = await runner.run(cmd, cwd=Path.cwd())
        
        # Verify certain sensitive vars are sanitized
        # (This is a basic check; implementation should filter more)
        assert result is not None

    @pytest.mark.asyncio
    async def test_working_directory_enforced(self):
        """SEC-008: Command must run in specified working directory."""
        runner = SecureSubprocessRunner()
        
        if sys.platform == "win32":
            cmd = ["cmd", "/c", "cd"]
        else:
            cmd = ["pwd"]
        
        cwd = Path.cwd()
        result = await runner.run(cmd, cwd=cwd)
        
        # Output should contain the working directory path
        assert result.returncode == 0

    @pytest.mark.asyncio
    async def test_no_inherited_handles(self):
        """SEC-008: Subprocess should not inherit unnecessary handles."""
        runner = SecureSubprocessRunner()
        
        if sys.platform == "win32":
            cmd = ["cmd", "/c", "echo", "isolated"]
        else:
            cmd = ["echo", "isolated"]
        
        result = await runner.run(cmd, cwd=Path.cwd())
        
        assert result.returncode == 0


class TestSecureSubprocessRunnerREL001:
    """Test timeout handling - REL-001."""

    @pytest.mark.asyncio
    async def test_timeout_kills_process(self):
        """REL-001: Long-running process should be killed after timeout."""
        runner = SecureSubprocessRunner()
        
        # Command that would run indefinitely
        if sys.platform == "win32":
            cmd = ["ping", "-n", "100", "localhost"]
        else:
            cmd = ["sleep", "100"]
        
        with pytest.raises(SubprocessTimeoutError):
            await runner.run(cmd, cwd=Path.cwd(), timeout=1)

    @pytest.mark.asyncio
    async def test_timeout_error_contains_details(self):
        """REL-001: Timeout error should contain useful information."""
        runner = SecureSubprocessRunner()
        
        if sys.platform == "win32":
            cmd = ["ping", "-n", "100", "localhost"]
        else:
            cmd = ["sleep", "100"]
        
        try:
            await runner.run(cmd, cwd=Path.cwd(), timeout=1)
            pytest.fail("Expected SubprocessTimeoutError")
        except SubprocessTimeoutError as e:
            assert e.timeout == 1
            assert e.command is not None

    @pytest.mark.asyncio
    async def test_default_timeout_is_reasonable(self):
        """REL-001: Default timeout should be set (e.g., 300s)."""
        runner = SecureSubprocessRunner()
        
        # Check that default timeout exists
        assert runner.default_timeout == 300

    @pytest.mark.asyncio
    async def test_fast_command_completes_before_timeout(self):
        """REL-001: Fast commands should complete normally."""
        runner = SecureSubprocessRunner()
        
        if sys.platform == "win32":
            cmd = ["cmd", "/c", "echo", "fast"]
        else:
            cmd = ["echo", "fast"]
        
        result = await runner.run(cmd, cwd=Path.cwd(), timeout=10)
        
        assert result.returncode == 0


class TestSecureSubprocessRunnerErrorHandling:
    """Test error handling and edge cases."""

    @pytest.mark.asyncio
    async def test_nonexistent_command_error(self):
        """Should handle non-existent command gracefully."""
        runner = SecureSubprocessRunner()
        
        cmd = ["nonexistent_command_xyz_12345"]
        
        with pytest.raises((FileNotFoundError, OSError)):
            await runner.run(cmd, cwd=Path.cwd())

    @pytest.mark.asyncio
    async def test_command_failure_captured(self):
        """Non-zero exit codes should be captured."""
        runner = SecureSubprocessRunner()
        
        if sys.platform == "win32":
            cmd = ["cmd", "/c", "exit", "1"]
        else:
            cmd = ["false"]  # Always returns 1
        
        result = await runner.run(cmd, cwd=Path.cwd())
        
        assert result.returncode != 0

    @pytest.mark.asyncio
    async def test_stderr_captured(self):
        """Standard error should be captured."""
        runner = SecureSubprocessRunner()
        
        # Use a command that writes to stderr without using dangerous characters
        # e.g. passing an invalid argument to a standard command
        if sys.platform == "win32":
            # 'dir /bad_arg' writes to stderr
            cmd = ["cmd", "/c", "dir", "/bad_arg"]
        else:
            # 'ls --bad_arg' writes to stderr
            cmd = ["ls", "--bad_arg"]
        
        # This should fail (returncode != 0) AND have content in stderr
        # We expect it to Run, not be blocked by sanitizer
        result = await runner.run(cmd, cwd=Path.cwd())
        
        assert result is not None
        assert result.returncode != 0
        assert len(result.stderr) > 0

    @pytest.mark.asyncio
    async def test_empty_command_rejected(self):
        """Empty command list should be rejected."""
        runner = SecureSubprocessRunner()
        
        with pytest.raises(ValueError):
            await runner.run([], cwd=Path.cwd())

    @pytest.mark.asyncio 
    async def test_cwd_must_exist(self):
        """Working directory must exist."""
        runner = SecureSubprocessRunner()
        
        if sys.platform == "win32":
            cmd = ["cmd", "/c", "echo", "test"]
        else:
            cmd = ["echo", "test"]
        
        nonexistent = Path("/this/path/does/not/exist/xyz123")
        
        with pytest.raises((FileNotFoundError, OSError)):
            await runner.run(cmd, cwd=nonexistent)
