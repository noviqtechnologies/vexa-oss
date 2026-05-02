"""
Semgrep Scanner for Multi-Language SAST.

SS-001: Semgrep - Pattern-based vulnerability detection
Modes: LOCAL, CONTAINER
"""

import json
from pathlib import Path
from typing import List, Optional

from vexa.scanners.base import (
    BaseScanner,
    Finding,
    FindingSeverity,
    ScanMode,
)
from vexa.common.logging import get_logger


logger = get_logger(__name__)


class SemgrepScanner(BaseScanner):
    """
    Semgrep scanner for multi-language SAST analysis.

    Semgrep is a fast, open-source static analysis tool that detects
    bugs and enforces code standards using pattern matching.
    """

    name = "semgrep"
    executable = "semgrep"
    supported_modes = [ScanMode.LOCAL, ScanMode.CONTAINER]

    def get_command(
        self, path: Path, exclusions: Optional[List[str]] = None
    ) -> List[str]:
        """Build Semgrep command."""
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--config",
            "auto",  # Use auto config for common rules
        ]

        if exclusions:
            for ex in exclusions:
                cmd.extend(["--exclude", ex])

        cmd.append(str(path))
        return cmd

    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """Parse Semgrep JSON output into normalized findings."""
        findings = []

        if not output.strip():
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse Semgrep JSON output: %s", e)
            return findings

        results = data.get("results", [])

        for result in results:
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            # Get severity from metadata or extra
            severity_str = extra.get("severity", "WARNING")

            # Normalize path
            file_path = result.get("path", "").replace("\\", "/")

            finding = Finding(
                id=self._generate_finding_id(
                    self.name,
                    file_path,
                    result.get("start", {}).get("line", 0),
                    result.get("check_id", ""),
                ),
                scanner=self.name,
                title=result.get("check_id", "")
                .split(".")[-1]
                .replace("-", " ")
                .title(),
                description=extra.get("message", ""),
                severity=self._map_severity(severity_str),
                file_path=file_path,
                line_start=result.get("start", {}).get("line", 0),
                line_end=result.get("end", {}).get("line", 0),
                code_snippet=extra.get("lines", ""),
                confidence=metadata.get("confidence", "MEDIUM").lower(),
                cwe_ids=self._extract_cwe(metadata),
                owasp_category=metadata.get("owasp", [None])[0]
                if metadata.get("owasp")
                else None,
                raw_data=result,
            )
            findings.append(finding)

        return findings

    def _map_severity(self, severity: str) -> FindingSeverity:
        """Map Semgrep severity to normalized severity."""
        mapping = {
            "ERROR": FindingSeverity.HIGH,
            "WARNING": FindingSeverity.MEDIUM,
            "INFO": FindingSeverity.LOW,
        }
        return mapping.get(severity.upper(), FindingSeverity.MEDIUM)

    def _extract_cwe(self, metadata: dict) -> List[str]:
        """Extract CWE IDs from Semgrep metadata."""
        cwe_ids = []

        # Semgrep stores CWE in metadata.cwe field
        cwe_field = metadata.get("cwe", [])
        if isinstance(cwe_field, list):
            for cwe in cwe_field:
                if isinstance(cwe, str):
                    # Format: "CWE-79" or just "79"
                    if cwe.startswith("CWE-"):
                        cwe_ids.append(cwe)
                    else:
                        cwe_ids.append(f"CWE-{cwe}")
        elif isinstance(cwe_field, str):
            if cwe_field.startswith("CWE-"):
                cwe_ids.append(cwe_field)
            else:
                cwe_ids.append(f"CWE-{cwe_field}")

        return cwe_ids
