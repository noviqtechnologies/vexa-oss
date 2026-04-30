"""
Unit tests for Security Validators - TDD Approach

Tests for requirements:
- SEC-001: Path Traversal Prevention (CWE-22, CWE-23)
- SEC-002: Command Injection Prevention (CWE-77, CWE-78)
- SEC-005: Block Access to System Directories
- SEC-007: Sanitize All User Inputs
"""

import pytest
import sys
from pathlib import Path

from vexa.security.validators import (
    PathValidator,
    CommandSanitizer,
    SecurityError,
)


class TestPathValidatorSEC001:
    """Test path traversal prevention - SEC-001 (CWE-22, CWE-23)."""

    def test_blocks_double_dot_path_traversal(self):
        """SEC-001: Blocks '../' path traversal attempts."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError, match="SEC-001"):
            validator.validate("../../../etc/passwd")

    def test_blocks_mixed_path_traversal(self):
        """SEC-001: Blocks mixed path traversal like 'foo/../../../etc'."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError, match="SEC-001"):
            validator.validate("project/foo/../../../etc/passwd")

    def test_blocks_encoded_path_traversal(self):
        """SEC-001: Blocks URL-encoded path traversal."""
        validator = PathValidator()
        
        # Even if decoded, should still catch '..'
        with pytest.raises(SecurityError, match="SEC-001"):
            validator.validate("..%2F..%2Fetc/passwd")

    def test_blocks_backslash_traversal_windows(self):
        """SEC-001: Blocks Windows-style path traversal."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError, match="SEC-001"):
            validator.validate("..\\..\\windows\\system32")

    def test_allows_path_without_traversal(self, tmp_path):
        """Valid paths without traversal should be allowed."""
        validator = PathValidator()
        
        # Create a test directory
        test_dir = tmp_path / "project"
        test_dir.mkdir()
        
        result = validator.validate(str(test_dir))
        
        assert result.exists()
        assert result.is_absolute()

    def test_allows_relative_path_within_working_dir(self, tmp_path, monkeypatch):
        """Relative paths that don't traverse should work."""
        validator = PathValidator()
        
        # Create test path
        test_file = tmp_path / "myfile.py"
        test_file.touch()
        
        # Validate the path
        result = validator.validate(str(test_file))
        
        assert result.exists()


class TestPathValidatorSEC005:
    """Test system directory blocking - SEC-005."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix paths")
    def test_blocks_etc_directory_unix(self):
        """SEC-005: Blocks access to /etc on Unix."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError, match="SEC-005"):
            validator.validate("/etc/passwd")

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix paths")
    def test_blocks_var_directory_unix(self):
        """SEC-005: Blocks access to /var on Unix."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError, match="SEC-005"):
            validator.validate("/var/log/messages")

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix paths")
    def test_blocks_root_directory_unix(self):
        """SEC-005: Blocks access to /root on Unix."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError, match="SEC-005"):
            validator.validate("/root/.bashrc")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows paths")
    def test_blocks_windows_system_directory(self):
        """SEC-005: Blocks access to C:\\Windows on Windows."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError, match="SEC-005"):
            validator.validate("C:\\Windows\\System32\\config")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows paths")
    def test_blocks_windows_program_files(self):
        """SEC-005: Blocks access to C:\\Program Files on Windows."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError, match="SEC-005"):
            validator.validate("C:\\Program Files\\SomeApp")

    def test_allows_non_system_directory(self, tmp_path):
        """Non-system directories should be allowed."""
        validator = PathValidator()
        
        # Create a user directory
        user_project = tmp_path / "my_project"
        user_project.mkdir()
        
        result = validator.validate(str(user_project))
        
        assert result.exists()

    def test_blocks_symlink_to_system_directory(self, tmp_path):
        """SEC-005: Blocks symlinks pointing to system directories."""
        validator = PathValidator()
        
        # Create a symlink to /etc (Unix) or C:\Windows (Windows)
        if sys.platform == "win32":
            # Skip symlink test on Windows as it requires admin privileges
            pytest.skip("Symlink test requires admin on Windows")
        
        symlink = tmp_path / "innocent_link"
        try:
            symlink.symlink_to("/etc")
        except OSError:
            pytest.skip("Unable to create symlink")
        
        with pytest.raises(SecurityError, match="SEC-005"):
            validator.validate(str(symlink))


class TestPathValidatorEdgeCases:
    """Edge case tests for PathValidator."""

    def test_empty_path_raises_error(self):
        """Empty paths should raise an error."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError):
            validator.validate("")

    def test_null_bytes_blocked(self):
        """SEC-001: Null bytes in path should be blocked."""
        validator = PathValidator()
        
        with pytest.raises(SecurityError):
            validator.validate("/valid/path\x00/etc/passwd")

    def test_very_long_path_handled(self):
        """Very long paths should be handled gracefully."""
        validator = PathValidator()
        
        long_path = "a" * 10000
        
        with pytest.raises(SecurityError):
            validator.validate(long_path)


class TestCommandSanitizerSEC002:
    """Test command injection prevention - SEC-002 (CWE-77, CWE-78)."""

    def test_blocks_semicolon(self):
        """SEC-002: Blocks semicolon command chaining."""
        sanitizer = CommandSanitizer()
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py; rm -rf /")

    def test_blocks_pipe(self):
        """SEC-002: Blocks pipe operator."""
        sanitizer = CommandSanitizer()
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py | cat /etc/passwd")

    def test_blocks_ampersand(self):
        """SEC-002: Blocks background/AND operator."""
        sanitizer = CommandSanitizer()
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py & malicious_command")

    def test_blocks_dollar_sign(self):
        """SEC-002: Blocks command/variable substitution."""
        sanitizer = CommandSanitizer()
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py $(cat /etc/passwd)")

    def test_blocks_backtick(self):
        """SEC-002: Blocks backtick command substitution."""
        sanitizer = CommandSanitizer()
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py `cat /etc/passwd`")

    def test_blocks_parentheses(self):
        """SEC-002: Blocks subshell execution."""
        sanitizer = CommandSanitizer()
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py (malicious)")

    def test_blocks_curly_braces(self):
        """SEC-002: Blocks brace expansion."""
        sanitizer = CommandSanitizer()
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py {a,b}")

    def test_blocks_redirect_operators(self):
        """SEC-002: Blocks redirect operators."""
        sanitizer = CommandSanitizer()
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py > /etc/passwd")
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py < /etc/passwd")

    def test_blocks_newline(self):
        """SEC-002: Blocks newline command injection."""
        sanitizer = CommandSanitizer()
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize("file.py\nmalicious_command")

    def test_allows_safe_arguments(self):
        """Safe arguments should pass through."""
        sanitizer = CommandSanitizer()
        
        # Safe file paths
        assert sanitizer.sanitize("myfile.py") == "myfile.py"
        assert sanitizer.sanitize("/path/to/file.py") == "/path/to/file.py"
        assert sanitizer.sanitize("C:\\path\\file.py") == "C:\\path\\file.py"
        
        # Safe arguments
        assert sanitizer.sanitize("--output=report.json") == "--output=report.json"
        assert sanitizer.sanitize("-v") == "-v"

    def test_allows_hyphens_underscores(self):
        """Hyphens and underscores should be allowed."""
        sanitizer = CommandSanitizer()
        
        assert sanitizer.sanitize("my-file_name.py") == "my-file_name.py"
        assert sanitizer.sanitize("--my-option") == "--my-option"


class TestCommandSanitizerSEC007:
    """Test input sanitization - SEC-007."""

    def test_sanitize_list_of_args(self):
        """SEC-007: Should be able to sanitize a list of arguments."""
        sanitizer = CommandSanitizer()
        
        safe_args = ["python", "-m", "bandit", "-r", "src/"]
        sanitized = sanitizer.sanitize_args(safe_args)
        
        assert sanitized == safe_args

    def test_sanitize_list_with_dangerous_arg(self):
        """SEC-007: Should raise on any dangerous arg in list."""
        sanitizer = CommandSanitizer()
        
        dangerous_args = ["python", "-c", "import os; os.system('rm -rf /')"]
        
        with pytest.raises(SecurityError, match="SEC-002"):
            sanitizer.sanitize_args(dangerous_args)

    def test_strips_whitespace(self):
        """SEC-007: Should strip leading/trailing whitespace."""
        sanitizer = CommandSanitizer()
        
        assert sanitizer.sanitize("  file.py  ") == "file.py"

    def test_empty_string_handling(self):
        """SEC-007: Empty strings should be handled."""
        sanitizer = CommandSanitizer()
        
        # Empty string is technically safe
        assert sanitizer.sanitize("") == ""


class TestSecurityErrorException:
    """Test SecurityError exception class."""

    def test_security_error_has_control_id(self):
        """SecurityError should contain the control ID."""
        try:
            raise SecurityError("SEC-001: Test error", control_id="SEC-001")
        except SecurityError as e:
            assert e.control_id == "SEC-001"
            assert "SEC-001" in str(e)

    def test_security_error_has_details(self):
        """SecurityError should contain detailed information."""
        try:
            raise SecurityError(
                "SEC-002: Dangerous character",
                control_id="SEC-002",
                details={"character": ";", "input": "file.py; rm -rf /"}
            )
        except SecurityError as e:
            assert e.details["character"] == ";"
