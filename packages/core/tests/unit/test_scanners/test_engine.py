"""
Unit tests for BaseScanner and ScannerEngine.
"""

import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from vexa.scanners.base import (
    BaseScanner,
    Finding,
    FindingSeverity,
    ScanMode,
    ScannerResult,
)
from vexa.scanners.engine import ScannerEngine, ScanResult
from vexa.scanners.bandit import BanditScanner
from vexa.security.subprocess_runner import SubprocessResult


class TestScanMode:
    """Tests for ScanMode enum."""
    
    def test_local_mode(self):
        """ScanMode.LOCAL should have 'local' value."""
        assert ScanMode.LOCAL.value == "local"
    
    def test_container_mode(self):
        """ScanMode.CONTAINER should have 'container' value."""
        assert ScanMode.CONTAINER.value == "container"


class TestFindingSeverity:
    """Tests for FindingSeverity enum."""
    
    def test_severity_levels(self):
        """Test all severity levels exist."""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"


class TestFinding:
    """Tests for Finding dataclass."""
    
    def test_finding_creation(self):
        """Test creating a Finding."""
        finding = Finding(
            id="test123",
            scanner="bandit",
            title="Test Issue",
            description="A test issue",
            severity=FindingSeverity.HIGH,
            file_path="test.py",
            line_start=10,
        )
        assert finding.id == "test123"
        assert finding.scanner == "bandit"
        assert finding.severity == FindingSeverity.HIGH
    
    def test_finding_to_dict(self):
        """Test converting Finding to dict."""
        finding = Finding(
            id="test123",
            scanner="bandit",
            title="Test Issue",
            description="A test issue",
            severity=FindingSeverity.HIGH,
            file_path="test.py",
        )
        result = finding.to_dict()
        assert result["id"] == "test123"
        assert result["severity"] == "high"


class TestScannerResult:
    """Tests for ScannerResult dataclass."""
    
    def test_success_result(self):
        """Test successful scanner result."""
        result = ScannerResult(
            scanner_name="bandit",
            success=True,
            findings=[
                Finding(
                    id="1", scanner="bandit", title="Issue",
                    description="", severity=FindingSeverity.HIGH, file_path=""
                )
            ],
        )
        assert result.success
        assert result.finding_count == 1
        assert result.has_findings
    
    def test_failed_result(self):
        """Test failed scanner result."""
        result = ScannerResult(
            scanner_name="bandit",
            success=False,
            error="Scanner not found",
        )
        assert not result.success
        assert result.error == "Scanner not found"
        assert result.finding_count == 0


class TestBanditScanner:
    """Tests for BanditScanner."""
    
    def test_supported_modes(self):
        """Bandit supports both LOCAL and CONTAINER modes."""
        assert ScanMode.LOCAL in BanditScanner.supported_modes
        assert ScanMode.CONTAINER in BanditScanner.supported_modes
    
    def test_get_command(self):
        """Test command generation."""
        scanner = BanditScanner()
        cmd = scanner.get_command(Path("/test/project"))
        # Command should either start with bandit or sys.executable -m bandit
        assert "bandit" in cmd
        assert "-r" in cmd
        assert "-f" in cmd
        assert "json" in cmd
    
    def test_parse_output_empty(self):
        """Test parsing empty output."""
        scanner = BanditScanner()
        findings = scanner.parse_output("", Path("/test"))
        assert findings == []
    
    def test_parse_output_valid(self):
        """Test parsing valid Bandit JSON output."""
        scanner = BanditScanner()
        output = json.dumps({
            "results": [
                {
                    "test_id": "B105",
                    "test_name": "hardcoded_password_string",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "Possible hardcoded password",
                    "filename": "test.py",
                    "line_number": 10,
                    "code": "password = 'secret'",
                }
            ]
        })
        findings = scanner.parse_output(output, Path("/test"))
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH
        assert "CWE-259" in findings[0].cwe_ids


class TestScannerEngine:
    """Tests for ScannerEngine orchestrator."""
    
    def test_scanner_registry(self):
        """Engine should have all scanners registered."""
        engine = ScannerEngine()
        assert "bandit" in engine.SCANNERS
        assert "semgrep" in engine.SCANNERS
        assert "checkov" in engine.SCANNERS
        assert "detect-secrets" in engine.SCANNERS
        assert "npm-audit" in engine.SCANNERS
        assert "grype" in engine.SCANNERS
        assert "syft" in engine.SCANNERS
        assert "pip-audit" in engine.SCANNERS
        assert "pip-licenses" in engine.SCANNERS
    
    def test_get_available_scanners_local(self):
        """Get scanners available for local mode."""
        engine = ScannerEngine()
        local_scanners = engine.get_available_scanners(ScanMode.LOCAL)
        assert "bandit" in local_scanners
        assert "semgrep" in local_scanners
        # npm-audit, grype, and syft are now supported in local mode
        assert "npm-audit" in local_scanners
        assert "grype" in local_scanners
        assert "syft" in local_scanners
    
    def test_get_available_scanners_container(self):
        """Get scanners available for container mode."""
        engine = ScannerEngine()
        container_scanners = engine.get_available_scanners(ScanMode.CONTAINER)
        # All scanners should be available in container mode
        assert "bandit" in container_scanners
        assert "npm-audit" in container_scanners
        assert "grype" in container_scanners
    
    @pytest.mark.asyncio
    async def test_run_scan_unknown_scanner(self):
        """ZF-01: Running with unknown scanner should degrade gracefully with a warning."""
        engine = ScannerEngine()
        result = await engine.run_scan_with_progress(
            path=Path("."),
            job_id="test_job",
            scanners=["non-existent-scanner"],
            mode=ScanMode.LOCAL,
        )
        assert result.success is True
        assert len(result.errors) == 0
        assert any("non-existent-scanner" in w.lower() for w in getattr(result, "warnings", []))
    
    @pytest.mark.asyncio
    async def test_run_scan_with_progress(self):
        """Should invoke progress callback."""
        engine = ScannerEngine()
        
        # Mock scanner class and instance
        mock_result = ScannerResult("mock", True, [])
        mock_instance = AsyncMock(spec=BaseScanner)
        mock_instance.name = "mock"
        mock_instance.run.return_value = mock_result
        
        mock_cls = MagicMock(return_value=mock_instance)
        mock_cls.supported_modes = [ScanMode.LOCAL]
        
        with patch.dict(engine.SCANNERS, {"mock": mock_cls}, clear=True):
            callback_called = False
            async def progress_cb(pct, msg):
                nonlocal callback_called
                callback_called = True
                
            result = await engine.run_scan_with_progress(
                path=Path("."),
                job_id="test_job",
                scanners=["mock"],
                mode=ScanMode.LOCAL,
                progress_callback=progress_cb
            )
            
            assert callback_called
            assert result.success is True
            assert result.total_findings == 0


class TestScanResult:
    """Tests for aggregated ScanResult."""
    
    def test_findings_by_severity(self):
        """Test counting findings by severity."""
        result = ScanResult(
            job_id="test_job",
            success=True,
            findings=[
                {
                    "id": "1", "scanner": "a", "title": "t", "description": "d",
                    "severity": "high", "file_path": "f", "line_start": 0, "line_end": 0
                },
                {
                    "id": "2", "scanner": "a", "title": "t", "description": "d",
                    "severity": "high", "file_path": "f", "line_start": 0, "line_end": 0
                },
                {
                    "id": "3", "scanner": "a", "title": "t", "description": "d",
                    "severity": "medium", "file_path": "f", "line_start": 0, "line_end": 0
                },
            ],
        )
        counts = result.findings_by_severity
        assert counts["high"] == 2
        assert counts["medium"] == 1
    
    def test_findings_by_scanner(self):
        """Test counting findings by scanner."""
        result = ScanResult(
            job_id="test_job",
            success=True,
            findings=[
                {
                    "id": "1", "scanner": "bandit", "title": "t", "description": "d",
                    "severity": "high", "file_path": "f", "line_start": 0, "line_end": 0
                },
                {
                    "id": "2", "scanner": "semgrep", "title": "t", "description": "d",
                    "severity": "high", "file_path": "f", "line_start": 0, "line_end": 0
                },
                {
                    "id": "3", "scanner": "bandit", "title": "t", "description": "d",
                    "severity": "medium", "file_path": "f", "line_start": 0, "line_end": 0
                },
            ],
        )
        counts = result.findings_by_scanner
        assert counts["bandit"] == 2
        assert counts["semgrep"] == 1
