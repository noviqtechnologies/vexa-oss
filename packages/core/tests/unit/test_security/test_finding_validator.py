"""
Tests for FindingValidator.
"""

from vexa.security.security_validator import FindingValidator
from vexa.common.models import Finding


class TestFindingValidator:
    def test_validate_finding_path_traversal(self):
        """Should detect path traversal."""
        validator = FindingValidator()
        finding = Finding(
            id="1",
            scanner="test",
            title="t",
            description="d",
            severity="high",
            file_path="../etc/passwd",
            line_start=1,
            line_end=2,
        )
        is_valid, errors = validator.validate_finding(finding)
        assert not is_valid
        assert any("SEC-001" in e for e in errors)

    def test_validate_finding_valid(self):
        """Should accept valid finding."""
        validator = FindingValidator()
        finding = Finding(
            id="1",
            scanner="test",
            title="t",
            description="d",
            severity="high",
            file_path="src/main.py",
            line_start=1,
            line_end=2,
        )
        is_valid, errors = validator.validate_finding(finding)
        assert is_valid
        assert not errors

    def test_sanitize_finding_output(self):
        """Should redact sensitive data."""
        validator = FindingValidator()
        finding = Finding(
            id="1",
            scanner="test",
            title="t",
            description="password='secret'",
            severity="high",
            file_path="src/main.py",
            code_snippet="api_key='12345'",
            line_start=1,
            line_end=2,
        )
        sanitized = validator.sanitize_finding_output(finding)

        assert "***REDACTED***" in sanitized.description
        assert "secret" not in sanitized.description
        assert "***REDACTED***" in sanitized.code_snippet
        assert "12345" not in sanitized.code_snippet
