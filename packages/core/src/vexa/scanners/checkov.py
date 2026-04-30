"""
Checkov Scanner for IaC Security.

SS-001: Checkov - Infrastructure as Code security analysis
Modes: LOCAL, CONTAINER
"""

import json
from pathlib import Path
from typing import List, Any, Optional

from vexa.scanners.base import (
    BaseScanner,
    Finding,
    FindingSeverity,
    ScanMode,
)
from vexa.common.logging import get_logger


logger = get_logger(__name__)


class CheckovScanner(BaseScanner):
    """
    Checkov scanner for Infrastructure as Code security.

    Checkov scans Terraform, CloudFormation, Kubernetes, Helm,
    and other IaC frameworks for misconfigurations.
    """

    name = "checkov"
    supported_modes = [ScanMode.LOCAL, ScanMode.CONTAINER]
    timeout_multiplier = 2.0

    def get_command(
        self, path: Path, exclusions: Optional[List[str]] = None
    ) -> List[str]:
        """Build Checkov command."""

        cmd = [
            "checkov",
            "-d",
            str(path),
            "-o",
            "json",
            "--quiet",
            "--skip-download",
        ]

        if exclusions:
            cmd.extend(["--skip-path", ",".join(exclusions)])

        return cmd

    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """Parse Checkov JSON output into normalized findings."""
        findings = []

        if not output.strip():
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse Checkov JSON output: %s", e)
            return findings

        # Checkov output can be a list or dict depending on version
        if isinstance(data, list):
            check_results = data
        elif isinstance(data, dict):
            results_obj = data.get("results")
            if isinstance(results_obj, dict):
                check_results = results_obj.get("failed_checks", [])
            else:
                check_results = []
        else:
            return findings

        if not isinstance(check_results, list):
            return findings

        for item in check_results:
            if not isinstance(item, dict):
                continue

            # Checkov can return a list of framework results
            framework_results = item.get("results")
            if isinstance(framework_results, dict):
                failed_checks = framework_results.get("failed_checks")
                if isinstance(failed_checks, list):
                    for failed in failed_checks:
                        finding = self._parse_check(failed)
                        if finding:
                            findings.append(finding)

            # Check for failed_checks directly in item (common when data is a list of results)
            elif "failed_checks" in item:
                failed_checks = item.get("failed_checks")
                if isinstance(failed_checks, list):
                    for failed in failed_checks:
                        finding = self._parse_check(failed)
                        if finding:
                            findings.append(finding)

            # Item is itself a single check
            elif "check_id" in item:
                finding = self._parse_check(item)
                if finding:
                    findings.append(finding)

        return findings

    def _parse_check(self, check: dict) -> Finding:
        """Parse a single Checkov check result."""
        file_path = check.get("file_path") or ""
        # Remove leading / from file path if present
        if file_path.startswith("/"):
            file_path = file_path[1:]
        file_path = file_path.replace("\\", "/")

        line_range = check.get("file_line_range")
        if not isinstance(line_range, list) or not line_range:
            line_range = [0, 0]

        return Finding(
            id=self._generate_finding_id(
                self.name, file_path, line_range[0], check.get("check_id") or ""
            ),
            scanner=self.name,
            title=str(check.get("check_id") or "Unknown Check"),
            description=str(check.get("check_name") or ""),
            severity=self._map_severity(check.get("severity", "MEDIUM")),
            file_path=file_path,
            line_start=line_range[0],
            line_end=line_range[-1],
            code_snippet=self._format_code_block(check.get("code_block")),
            confidence="high",
            cwe_ids=self._extract_cwe(check),
            raw_data=check,
        )

    def _format_code_block(self, code_block: Any) -> str:
        """Format Checkov's code_block list into a readable string snippet."""
        if not isinstance(code_block, list):
            return str(code_block or "")

        lines = []
        for item in code_block:
            if isinstance(item, list) and len(item) >= 2:
                line_num, line_content = item[0], item[1]
                # Checkov line content usually ends with \n
                content = line_content.rstrip()
                lines.append(f"{line_num}: {content}")
            else:
                lines.append(str(item))

        return "\n".join(lines)

    def _map_severity(self, severity: str) -> FindingSeverity:
        """Map Checkov severity to normalized severity."""
        if severity is None:
            return FindingSeverity.MEDIUM

        mapping = {
            "CRITICAL": FindingSeverity.CRITICAL,
            "HIGH": FindingSeverity.HIGH,
            "MEDIUM": FindingSeverity.MEDIUM,
            "LOW": FindingSeverity.LOW,
            "INFO": FindingSeverity.INFO,
        }
        return mapping.get(severity.upper(), FindingSeverity.MEDIUM)

    def _extract_cwe(self, check: dict) -> List[str]:
        """Extract CWE IDs from Checkov check."""
        cwe_ids = []

        # Checkov includes CWE in guideline field sometimes
        guideline = check.get("guideline")
        if guideline and isinstance(guideline, str) and "CWE" in guideline:
            # Extract CWE-XXX patterns
            import re

            matches = re.findall(r"CWE-\d+", guideline)
            cwe_ids.extend(matches)

        # Common IaC CWE mappings
        check_id = check.get("check_id", "")
        iac_cwe_mapping = {
            "CKV_AWS_": ["CWE-284", "CWE-732"],  # AWS misconfigs -> access control
            "CKV_GCP_": ["CWE-284", "CWE-732"],  # GCP misconfigs
            "CKV_AZURE_": ["CWE-284", "CWE-732"],  # Azure misconfigs
            "CKV_K8S_": ["CWE-284"],  # Kubernetes misconfigs
        }

        for prefix, cwes in iac_cwe_mapping.items():
            if check_id.startswith(prefix):
                for cwe in cwes:
                    if cwe not in cwe_ids:
                        cwe_ids.append(cwe)

        return cwe_ids
