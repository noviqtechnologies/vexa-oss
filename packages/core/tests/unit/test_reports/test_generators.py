"""
Unit tests for Report Generators.
"""

import json
import pytest
import tempfile
from pathlib import Path

from vexa.reports import (
    ReportGenerator,
    ReportMetadata,
    JSONReportGenerator,
    HTMLReportGenerator,
    SARIFReportGenerator,
    MarkdownReportGenerator,
)
from vexa.common.models import Finding
from vexa.scanners.base import FindingSeverity
from vexa.scanners.engine import ScanResult, ScannerResult


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        Finding(
            id="test123",
            scanner="bandit",
            title="Hardcoded Password",
            description="Password is hardcoded in source code",
            severity="high",
            file_path="test.py",
            line_start=10,
            line_end=10,
            code_snippet="password = 'secret123'",
            cwe_ids=["CWE-259", "CWE-798"],
        ),
        Finding(
            id="test456",
            scanner="semgrep",
            title="SQL Injection",
            description="User input used in SQL query",
            severity="critical",
            file_path="db.py",
            line_start=25,
            line_end=27,
            code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
            cwe_ids=["CWE-89"],
        ),
        Finding(
            id="test789",
            scanner="checkov",
            title="S3 Bucket Public",
            description="S3 bucket allows public access",
            severity="medium",
            file_path="main.tf",
            line_start=42,
            line_end=42,
            cwe_ids=["CWE-732"],
        ),
    ]


@pytest.fixture
def sample_scan_result(sample_findings):
    """Create sample scan result for testing."""
    return ScanResult(
        job_id="test_job_123",
        success=True,
        findings=sample_findings,
        scanner_results={
            "bandit": ScannerResult(scanner_name="bandit", success=True, findings=[sample_findings[0]]),
            "semgrep": ScannerResult(scanner_name="semgrep", success=True, findings=[sample_findings[1]]),
            "checkov": ScannerResult(scanner_name="checkov", success=True, findings=[sample_findings[2]]),
        },
        duration_seconds=5.25,
    )


class TestReportGenerator:
    """Tests for ReportGenerator orchestrator."""
    
    def test_available_formats(self):
        """All four formats should be registered."""
        formats = ReportGenerator.get_available_formats()
        assert "json" in formats
        assert "html" in formats
        assert "sarif" in formats
        assert "markdown" in formats
    
    def test_invalid_format_raises_error(self, sample_scan_result):
        """Unknown format should raise ValueError."""
        generator = ReportGenerator()
        with pytest.raises(ValueError, match="Unsupported report format"):
            generator.generate(sample_scan_result, "invalid_format", Path("."))


class TestJSONReportGenerator:
    """Tests for JSONReportGenerator."""
    
    def test_generate_creates_file(self, sample_scan_result, tmp_path):
        """JSON generator should create a valid JSON file."""
        generator = JSONReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        assert output.exists()
        assert output.suffix == ".json"
    
    def test_json_structure(self, sample_scan_result, tmp_path):
        """JSON report should have expected structure."""
        generator = JSONReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        with open(output) as f:
            data = json.load(f)
        
        assert "metadata" in data
        assert "summary" in data
        assert "findings" in data
        assert data["summary"]["total_findings"] == 3
    
    def test_findings_content(self, sample_scan_result, tmp_path):
        """JSON findings should contain expected data."""
        generator = JSONReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        with open(output) as f:
            data = json.load(f)
        
        findings = data["findings"]
        assert len(findings) == 3
        assert any(f["title"] == "Hardcoded Password" for f in findings)


class TestHTMLReportGenerator:
    """Tests for HTMLReportGenerator."""
    
    def test_generate_creates_file(self, sample_scan_result, tmp_path):
        """HTML generator should create an HTML file."""
        generator = HTMLReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        assert output.exists()
        assert output.suffix == ".html"
    
    def test_html_contains_findings(self, sample_scan_result, tmp_path):
        """HTML report should contain finding titles."""
        generator = HTMLReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        content = output.read_text(encoding="utf-8")
        assert "Hardcoded Password" in content
        assert "SQL Injection" in content
    
    def test_html_escaping(self, sample_scan_result, tmp_path):
        """HTML report should escape special characters (SEC-003)."""
        # Add a finding with HTML characters
        sample_scan_result.findings.append(Finding(
            id="xss_test",
            scanner="test",
            title="<script>alert('xss')</script>",
            description="Test <b>injection</b>",
            severity="high",
            file_path="test.py",
            line_start=1,
            line_end=1,
        ))
        
        generator = HTMLReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        content = output.read_text(encoding="utf-8")
        # Should be escaped, not raw HTML
        assert "<script>" not in content
        assert "&lt;script&gt;" in content


class TestSARIFReportGenerator:
    """Tests for SARIFReportGenerator."""
    
    def test_generate_creates_file(self, sample_scan_result, tmp_path):
        """SARIF generator should create a .sarif file."""
        generator = SARIFReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        assert output.exists()
        assert output.suffix == ".sarif"
    
    def test_sarif_schema_version(self, sample_scan_result, tmp_path):
        """SARIF should use version 2.1.0."""
        generator = SARIFReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        with open(output, encoding="utf-8") as f:
            data = json.load(f)
        
        assert data["version"] == "2.1.0"
        assert "$schema" in data
    
    def test_sarif_runs_structure(self, sample_scan_result, tmp_path):
        """SARIF should have runs for each scanner."""
        generator = SARIFReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        with open(output, encoding="utf-8") as f:
            data = json.load(f)
        
        assert "runs" in data
        assert len(data["runs"]) == 3  # bandit, semgrep, checkov

    def test_sarif_ai_metadata(self, sample_scan_result, tmp_path):
        """SARIF should include AI markdown and properties if available."""
        # Add AI data to findings (bypass Pydantic strictness via __dict__)
        finding1 = sample_scan_result.findings[0]
        finding1.__dict__['is_false_positive'] = True
        finding1.__dict__['detailed_description'] = "AI determined this is safe."
        
        finding2 = sample_scan_result.findings[1]
        finding2.__dict__['remediation_code'] = "app.run(host='127.0.0.1')"
        finding2.__dict__['detailed_description'] = "Bind to localhost instead"
        
        generator = SARIFReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        with open(output, encoding="utf-8") as f:
            data = json.load(f)
            
        bandit_run = next(r for r in data["runs"] if r["tool"]["driver"]["name"] == "bandit")
        semgrep_run = next(r for r in data["runs"] if r["tool"]["driver"]["name"] == "semgrep")
        
        result1 = bandit_run["results"][0]
        assert "Likely False Positive" in result1["message"]["markdown"]
        assert result1["properties"]["vexa/ai_false_positive"] is True
        
        result2 = semgrep_run["results"][0]
        assert "Remediation Suggestion" in result2["message"]["markdown"]
        assert "app.run(host='127.0.0.1')" in result2["message"]["markdown"]
        assert result2["properties"]["vexa/ai_false_positive"] is False


class TestMarkdownReportGenerator:
    """Tests for MarkdownReportGenerator."""
    
    def test_generate_creates_file(self, sample_scan_result, tmp_path):
        """Markdown generator should create an .md file."""
        generator = MarkdownReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        assert output.exists()
        assert output.suffix == ".md"
    
    def test_markdown_contains_summary(self, sample_scan_result, tmp_path):
        """Markdown should contain summary section."""
        generator = MarkdownReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        content = output.read_text(encoding="utf-8")
        assert "## 📊 Summary" in content
        assert "Total Findings" in content
    
    def test_markdown_contains_findings(self, sample_scan_result, tmp_path):
        """Markdown should list all findings."""
        generator = MarkdownReportGenerator()
        output = generator.generate(sample_scan_result, tmp_path)
        
        content = output.read_text(encoding="utf-8")
        assert "Hardcoded Password" in content
        assert "SQL Injection" in content
        assert "CWE-89" in content
