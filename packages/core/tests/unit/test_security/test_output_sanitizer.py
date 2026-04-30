"""
Unit tests for OutputSanitizer - TDD Approach

Tests for requirements:
- SEC-003: XSS Prevention (CWE-79)
- SEC-004: Sanitize Log Messages (CWE-200)
"""

import pytest

from vexa.security.output_sanitizer import OutputSanitizer


class TestOutputSanitizerSEC003:
    """Test XSS prevention in HTML output - SEC-003 (CWE-79)."""

    def test_escapes_script_tag(self):
        """SEC-003: Should escape <script> tags."""
        sanitizer = OutputSanitizer()
        
        malicious = "<script>alert('XSS')</script>"
        escaped = sanitizer.escape_html(malicious)
        
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped

    def test_escapes_less_than_greater_than(self):
        """SEC-003: Should escape < and > characters."""
        sanitizer = OutputSanitizer()
        
        content = "1 < 2 and 3 > 2"
        escaped = sanitizer.escape_html(content)
        
        assert "&lt;" in escaped
        assert "&gt;" in escaped
        assert "<" not in escaped.replace("&lt;", "").replace("&gt;", "")

    def test_escapes_ampersand(self):
        """SEC-003: Should escape & character."""
        sanitizer = OutputSanitizer()
        
        content = "Tom & Jerry"
        escaped = sanitizer.escape_html(content)
        
        assert "&amp;" in escaped

    def test_escapes_quotes(self):
        """SEC-003: Should escape quotes for attribute injection."""
        sanitizer = OutputSanitizer()
        
        # Double quotes
        content = 'value="malicious" onclick="alert(1)"'
        escaped = sanitizer.escape_html(content)
        
        assert '&quot;' in escaped or '"' not in escaped

    def test_escapes_event_handlers(self):
        """SEC-003: Should prevent event handler injection."""
        sanitizer = OutputSanitizer()
        
        malicious = '<img src="x" onerror="alert(1)">'
        escaped = sanitizer.escape_html(malicious)
        
        assert "<img" not in escaped
        assert "&lt;img" in escaped

    def test_escapes_svg_injection(self):
        """SEC-003: Should escape SVG-based XSS."""
        sanitizer = OutputSanitizer()
        
        malicious = '<svg onload="alert(1)">'
        escaped = sanitizer.escape_html(malicious)
        
        assert "<svg" not in escaped
        assert "&lt;svg" in escaped

    def test_leaves_safe_content_unchanged(self):
        """Safe content should remain readable after escaping."""
        sanitizer = OutputSanitizer()
        
        safe = "Hello World! This is a normal message."
        escaped = sanitizer.escape_html(safe)
        
        assert escaped == safe

    def test_handles_empty_string(self):
        """Empty string should return empty string."""
        sanitizer = OutputSanitizer()
        
        assert sanitizer.escape_html("") == ""

    def test_handles_unicode(self):
        """Unicode characters should be preserved."""
        sanitizer = OutputSanitizer()
        
        unicode_text = "Hello 世界 🌍 Привет"
        escaped = sanitizer.escape_html(unicode_text)
        
        assert "世界" in escaped
        assert "🌍" in escaped
        assert "Привет" in escaped


class TestOutputSanitizerSEC004:
    """Test log sanitization - SEC-004 (CWE-200)."""

    def test_sanitizes_password_in_logs(self):
        """SEC-004: Should sanitize password from logs."""
        sanitizer = OutputSanitizer()
        
        log = 'User login: password="secret123"'
        sanitized = sanitizer.sanitize_logs(log)
        
        assert "secret123" not in sanitized
        assert "password=" in sanitized.lower() or "***" in sanitized

    def test_sanitizes_api_key_in_logs(self):
        """SEC-004: Should sanitize API keys from logs."""
        sanitizer = OutputSanitizer()
        
        log = 'Request headers: api_key=sk-1234567890abcdef'
        sanitized = sanitizer.sanitize_logs(log)
        
        assert "sk-1234567890abcdef" not in sanitized
        assert "api_key=" in sanitized.lower() or "***" in sanitized

    def test_sanitizes_token_in_logs(self):
        """SEC-004: Should sanitize tokens from logs."""
        sanitizer = OutputSanitizer()
        
        log = 'Auth: token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."'
        sanitized = sanitizer.sanitize_logs(log)
        
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized

    def test_sanitizes_secret_in_logs(self):
        """SEC-004: Should sanitize secrets from logs."""
        sanitizer = OutputSanitizer()
        
        log = 'Config: secret=my_super_secret_value'
        sanitized = sanitizer.sanitize_logs(log)
        
        assert "my_super_secret_value" not in sanitized

    def test_sanitizes_aws_credentials(self):
        """SEC-004: Should sanitize AWS credentials from logs."""
        sanitizer = OutputSanitizer()
        
        log = 'AWS: aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        sanitized = sanitizer.sanitize_logs(log)
        
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "wJalrXUtnFEMI" not in sanitized

    def test_sanitizes_auth_header(self):
        """SEC-004: Should sanitize authorization headers from logs."""
        sanitizer = OutputSanitizer()
        
        log = 'Headers: authorization=Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ'
        sanitized = sanitizer.sanitize_logs(log)
        
        assert "eyJhbGciOiJIUzI1NiJ9" not in sanitized

    def test_preserves_non_sensitive_content(self):
        """Non-sensitive content should remain in logs."""
        sanitizer = OutputSanitizer()
        
        log = 'User john.doe@example.com logged in from 192.168.1.1'
        sanitized = sanitizer.sanitize_logs(log)
        
        assert "john.doe@example.com" in sanitized
        assert "192.168.1.1" in sanitized

    def test_handles_multiple_sensitive_items(self):
        """Should sanitize multiple sensitive items in one log."""
        sanitizer = OutputSanitizer()
        
        log = 'Config: password=pass123, api_key=key456, token=tok789'
        sanitized = sanitizer.sanitize_logs(log)
        
        assert "pass123" not in sanitized
        assert "key456" not in sanitized
        assert "tok789" not in sanitized

    def test_case_insensitive_matching(self):
        """Sensitive pattern matching should be case-insensitive."""
        sanitizer = OutputSanitizer()
        
        logs = [
            'PASSWORD=secret',
            'Password=secret',
            'API_KEY=secret',
            'Api-Key=secret',
        ]
        
        for log in logs:
            sanitized = sanitizer.sanitize_logs(log)
            assert "secret" not in sanitized

    def test_handles_json_format(self):
        """Should sanitize sensitive data in JSON format."""
        sanitizer = OutputSanitizer()
        
        log = '{"password": "secret123", "api_key": "key456"}'
        sanitized = sanitizer.sanitize_logs(log)
        
        assert "secret123" not in sanitized
        assert "key456" not in sanitized


class TestOutputSanitizerCombined:
    """Test combined HTML and log sanitization."""

    def test_sanitize_for_html_report(self):
        """Should safely include log output in HTML reports."""
        sanitizer = OutputSanitizer()
        
        # Log content that contains both sensitive data and HTML
        log = 'Error: <script>alert(1)</script> password=secret123'
        
        # First sanitize logs, then escape HTML
        log_sanitized = sanitizer.sanitize_logs(log)
        html_safe = sanitizer.escape_html(log_sanitized)
        
        # Should not have XSS
        assert "<script>" not in html_safe
        # Should not have sensitive data
        assert "secret123" not in html_safe

    def test_sanitize_all_method(self):
        """Should have a convenience method to sanitize everything."""
        sanitizer = OutputSanitizer()
        
        content = '<script>alert(1)</script> password=secret'
        safe = sanitizer.sanitize_all(content)
        
        assert "<script>" not in safe
        assert "secret" not in safe
