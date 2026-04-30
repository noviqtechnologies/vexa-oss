"""
Unit tests for CLI.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from click.testing import CliRunner

import vexa_cli.main as cli_module
from vexa.scanners.engine import ScanResult
from vexa.common.models import Finding
from vexa.scanners.base import ScanMode

import re


def strip_ansi(text):
    """Strip ANSI escape sequences from text."""
    ansi_escape = re.compile(r"\x1b\[([0-9,;]*[mGKH])")
    return ansi_escape.sub("", text)


@pytest.fixture
def mock_generator():
    """Mock ReportGenerator."""
    with patch("vexa_cli.commands.scan._generate_report") as mock:
        yield mock


@pytest.fixture
def mock_scan_result():
    """Mock ScanResult."""
    return ScanResult(
        job_id="test_job_cli",
        success=True,
        findings=[
            Finding(
                id="test1",
                scanner="test",
                title="Test Finding",
                description="Desc",
                severity="low",
                file_path="test.py",
                line_start=1,
                line_end=1,
            )
        ],
        scanner_results={},
        duration_seconds=1.0,
    )


def test_scan_command_success(mock_scan_result, mock_generator):
    """Test scan command success flow."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        # Create dummy target
        Path("target").mkdir()

        with (
            patch(
                "vexa_cli.commands.scan._run_scan", new_callable=AsyncMock
            ) as mock_run,
            patch("vexa.common.config.is_terms_accepted", return_value=True),
        ):
            mock_run.return_value = mock_scan_result

            result = runner.invoke(
                cli_module.scan, ["target", "--format", "html", "--ai-provider", "none"]
            )

            output = strip_ansi(result.output)
            assert result.exit_code == 0, f"Command failed with output: {output}"
            assert "Scan Summary" in output
            assert "Scan completed" in output
            assert "Provider: None" in output

            # Verify _run_scan call
            mock_run.assert_called_once()
            mock_generator.assert_called_once()


def test_scan_command_container_mode(mock_scan_result):
    """Test scan command with container mode."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("target").mkdir()

        with (
            patch(
                "vexa_cli.commands.scan._run_scan", new_callable=AsyncMock
            ) as mock_run,
            patch("vexa.common.config.is_terms_accepted", return_value=True),
        ):
            mock_run.return_value = mock_scan_result

            result = runner.invoke(
                cli_module.scan,
                ["target", "--mode", "container", "--ai-provider", "none"],
            )

            output = strip_ansi(result.output)
            assert result.exit_code == 0, f"Command failed with output: {output}"

            # Verify _run_scan call
            mock_run.assert_called_once()
            args = mock_run.call_args[0]
            assert args[2] == ScanMode.CONTAINER


def test_list_scanners():
    """Test list-scanners command."""
    runner = CliRunner()
    with patch("vexa.scanners.engine.get_scanner_engine") as mock_engine_factory:
        mock_engine = MagicMock()
        mock_engine.get_available_scanners.return_value = ["test-scanner"]
        mock_engine_factory.return_value = mock_engine

        result = runner.invoke(cli_module.list_scanners)

        assert result.exit_code == 0
        assert "Available Scanners" in result.output
        assert "test-scanner" in result.output


def test_not_implemented_commands():
    """Test placeholder commands."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("target").mkdir()

        # Threat Model
        result = runner.invoke(cli_module.threat_model, ["target"])
        assert "pending TM-001" in strip_ansi(result.output)

        # Validate
        result = runner.invoke(cli_module.validate, ["target"])
        assert "pending SV-001" in strip_ansi(result.output)
