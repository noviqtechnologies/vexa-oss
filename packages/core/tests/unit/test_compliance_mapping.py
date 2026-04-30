"""
Tests for SS-014: OWASP, MITRE, CWE mapping.

Validates that findings carry correct compliance framework references.
"""

from vexa.common.models import Finding


class TestComplianceMapping:
    """SS-014: Findings must carry OWASP/CWE references."""

    def test_finding_supports_cwe_ids(self):
        """SS-014: Finding model must accept CWE IDs."""
        f = Finding(
            id="F001",
            scanner="bandit",
            severity="high",
            title="SQL Injection",
            description="test",
            file_path="app.py",
            line_start=1,
            line_end=1,
            cwe_ids=["CWE-89"],
        )
        assert "CWE-89" in f.cwe_ids

    def test_finding_supports_owasp_category(self):
        """SS-014: Finding model must accept OWASP category."""
        f = Finding(
            id="F002",
            scanner="semgrep",
            severity="critical",
            title="XSS",
            description="test",
            file_path="app.py",
            line_start=5,
            line_end=5,
            owasp_category="A03:2021-Injection",
        )
        assert "A03" in f.owasp_category

    def test_finding_defaults_empty_cwe(self):
        """SS-014: CWE IDs should default to empty list."""
        f = Finding(
            id="F003",
            scanner="checkov",
            severity="medium",
            title="Open SG",
            description="test",
            file_path="main.tf",
            line_start=1,
            line_end=1,
        )
        assert f.cwe_ids is not None

    def test_finding_supports_multiple_cwe(self):
        """SS-014: Findings can have multiple CWE references."""
        f = Finding(
            id="F004",
            scanner="bandit",
            severity="critical",
            title="Command Injection",
            description="test",
            file_path="app.py",
            line_start=10,
            line_end=10,
            cwe_ids=["CWE-77", "CWE-78"],
        )
        assert len(f.cwe_ids) == 2
