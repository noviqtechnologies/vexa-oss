"""
Unified Configuration Manager for `.vexa.yml`

This module provides the central schema and loading mechanism for configuring
scanners, AI providers, and quality gates across the CLI and extensions.
"""

from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field
import yaml

from vexa.common.models import CloudProvider


class ScannersConfig(BaseModel):
    """Scanner configuration."""

    enabled: List[str] = Field(
        default=["semgrep", "bandit", "checkov", "detect-secrets", "pip-audit"],
        description="List of enabled scanners",
    )


class QualityGateConfig(BaseModel):
    """Quality gate thresholds."""

    fail_on: List[str] = Field(
        default=["critical", "high"],
        description="Severities that fail the quality gate",
    )
    max_total: int = Field(default=50, description="Maximum total allowed findings")
    new_only: bool = Field(
        default=False, description="Whether to fail only on new baseline findings"
    )
    baseline: Optional[str] = Field(
        default=".vexa-baseline.json", description="Path to the baseline file"
    )
    min_score: str = Field(default="C", description="Minimum letter grade score")


class AIConfig(BaseModel):
    """AI enrichment configuration."""

    enabled: bool = Field(
        default=True, description="Whether AI features are enabled globally"
    )
    provider: CloudProvider = Field(
        default=CloudProvider.NONE, description="Active AI Provider"
    )
    fp_detection: bool = Field(
        default=True, description="Whether False Positive detection is active"
    )
    remediation: bool = Field(
        default=True, description="Whether AI remediation is active"
    )
    # Ollama / Local LLM configuration (PRIV-01)
    model: str = Field(
        default="gemma4:26b", description="Model name for Ollama local LLM"
    )
    ollama_host: str = Field(default="localhost", description="Ollama server hostname")
    ollama_port: int = Field(default=11434, description="Ollama server port")


class ReportsConfig(BaseModel):
    """Report generation configuration."""

    formats: List[str] = Field(
        default=["sarif", "html", "json", "markdown"],
        description="Report formats to generate",
    )
    output_dir: str = Field(
        default="vexa_scan_reports",
        description="Directory where reports will be saved",
    )


class GuardrailsConfig(BaseModel):
    """Pre-commit guardrails configuration."""

    block_on: str = Field(
        default="critical",
        description="Minimum severity to block commits (critical, high, medium, low)",
    )


class VexaConfig(BaseModel):
    """Root configuration mapping to `.vexa.yml`."""

    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    quality_gate: QualityGateConfig = Field(default_factory=QualityGateConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)
    guardrails: GuardrailsConfig = Field(default_factory=GuardrailsConfig)
    ignore: List[str] = Field(
        default_factory=list, description="List of path patterns to ignore globally"
    )


def load_config(directory: Path | str) -> VexaConfig:
    """
    Search for a .vexa.yml or .vexa.yaml recursively up from `directory`.
    If found, parse and return the VexaConfig.
    If not found, return the default code configuration.
    """
    directory = Path(directory).resolve()
    
    # Load .env from the project directory if it exists
    from dotenv import load_dotenv
    env_path = directory / ".env"
    if env_path.is_file():
        load_dotenv(env_path)

    # Simple search upward up to 5 directories to find a config
    current_dir = directory
    for _ in range(5):
        for filename in [".vexa.yml", ".vexa.yaml"]:
            config_path = current_dir / filename
            if config_path.is_file():
                try:
                    with open(config_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                        return VexaConfig.model_validate(data)
                except Exception as e:
                    # Log error, but fail gracefully to default for now
                    print(f"[Warning] Failed to parse {config_path}: {e}")

        parent_dir = current_dir.parent
        if parent_dir == current_dir:
            break
        current_dir = parent_dir

    return VexaConfig()
