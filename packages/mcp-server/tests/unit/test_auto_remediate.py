import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock

# Attempt to import to verify syntax, assuming pytest-asyncio is available
from vexa_mcp.scanner.server import _auto_remediate_workspace_internal as auto_remediate_workspace
from vexa.common.models import EnhancedFinding, ScanResult


@pytest.mark.asyncio
async def test_auto_remediate_workspace_dry_run():
    """Test generating a Fix Plan without modifying files."""
    with (
        patch("vexa_mcp.scanner.server.get_scanner_engine") as mock_engine,
        patch("vexa_mcp.scanner.server.get_ai_manager") as mock_ai,
    ):
        # Mock the scan result
        mock_finding = EnhancedFinding(
            id="123",
            scanner="bandit",
            title="Hardcoded Secret",
            severity="critical",
            file_path="main.py",
            line_start=10,
            line_end=10,
            code_snippet="secret = '123456'",
            cwe_ids=["CWE-798"],
            description="Mock",
            remediation_code="secret = os.environ.get('SECRET')",
            remediation_guidance="Use environment variables.",
            is_false_positive=False,
            detailed_description="High risk.",
        )

        mock_result = ScanResult(
            job_id="test",
            status="completed",
            progress=100,
            findings=[mock_finding],
            duration_seconds=1.0,
            scanners_run=["bandit"],
        )

        engine_instance = mock_engine.return_value
        engine_instance.run_scan_with_progress = AsyncMock(return_value=mock_result)

        output = await auto_remediate_workspace(
            path=".", severity_threshold="medium", dry_run=True
        )

        assert "Vexa Autonomous Agency" in output
        assert "Mode: Dry Run" in output
        assert "+++ Fix: Hardcoded Secret" in output
        assert "secret = os.environ.get('SECRET')" in output


@pytest.mark.asyncio
async def test_auto_remediate_workspace_apply_fix():
    """Test snapshot creation and actual file modification."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = Path(temp_dir) / "vuln.py"
        test_file.write_text("secret = '12345'", encoding="utf-8")

        with (
            patch("vexa_mcp.scanner.server.get_scanner_engine") as mock_engine,
            patch("vexa_mcp.scanner.server.get_ai_manager") as mock_ai,
        ):
            mock_finding = EnhancedFinding(
                id="123",
                scanner="bandit",
                title="Hardcoded Secret",
                severity="critical",
                file_path=str(test_file),
                line_start=1,
                line_end=1,
                code_snippet="secret = '12345'",
                cwe_ids=["CWE-798"],
                description="Mock",
                remediation_code="secret = os.environ.get('SECRET')",
                is_false_positive=False,
                detailed_description="High risk.",
            )

            mock_result = ScanResult(
                job_id="test",
                status="completed",
                progress=100,
                findings=[mock_finding],
                duration_seconds=1.0,
                scanners_run=["bandit"],
            )

            engine_instance = mock_engine.return_value
            engine_instance.run_scan_with_progress = AsyncMock(return_value=mock_result)

            output = await auto_remediate_workspace(
                path=temp_dir, severity_threshold="medium", dry_run=False
            )

            assert "Applied 1 patches from 1 actionable findings" in output
            assert "Snapshot:" in output

            # Verify file was actually modified
            assert "os.environ.get('SECRET')" in test_file.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_auto_remediate_workspace_safe_failure():
    """Verify tool catches exceptions and prevents agent crash (Exit 0)."""
    with patch("vexa_mcp.scanner.server.get_scanner_engine") as mock_engine:
        engine_instance = mock_engine.return_value
        engine_instance.run_scan_with_progress.side_effect = Exception(
            "Docker not running"
        )

        output = await auto_remediate_workspace(path=".", dry_run=True)

        # Tool must swallow the error and return a string (not raise)
        assert "Scan failed \u2014 Docker not running" in output
