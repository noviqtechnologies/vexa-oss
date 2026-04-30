"""
Syft Scanner for SBOM Generation.

SS-001: Syft - Software Bill of Materials generation
Modes: CONTAINER only
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


class SyftScanner(BaseScanner):
    """
    Syft scanner for SBOM generation.

    Syft generates Software Bill of Materials from container images
    and filesystems. While not a vulnerability scanner itself,
    it provides inventory data useful for security analysis.

    Container only due to Syft installation requirements.
    """

    name = "syft"
    supported_modes = [ScanMode.LOCAL, ScanMode.CONTAINER]

    def get_command(
        self, path: Path, exclusions: Optional[List[str]] = None
    ) -> List[str]:
        """Build Syft command."""
        cmd = [
            "syft",
            str(path),
            "-o",
            "json",
            "--quiet",
        ]
        if exclusions:
            for ex in exclusions:
                cmd.extend(["--exclude", ex])
        return cmd

    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """
        Parse Syft JSON output.

        Note: Syft generates SBOM, not vulnerability findings.
        This returns informational findings about detected packages.
        For vulnerability scanning, use Grype with the SBOM.
        """
        findings = []

        if not output.strip():
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse Syft JSON output: %s", e)
            return findings

        # Syft output contains artifacts (packages)
        artifacts = data.get("artifacts", [])

        # We don't create findings for every package,
        # but we can flag packages with known license issues
        # or packages without version pinning

        license_concerns = ["GPL", "AGPL", "LGPL", "SSPL"]

        for artifact in artifacts:
            licenses = artifact.get("licenses", [])
            license_names = []

            for lic in licenses:
                if isinstance(lic, str):
                    license_names.append(lic)
                elif isinstance(lic, dict):
                    license_names.append(
                        lic.get("value", "") or lic.get("spdxExpression", "")
                    )

            # Flag restrictive licenses
            for lic_name in license_names:
                for concern in license_concerns:
                    if concern.lower() in lic_name.lower():
                        finding = Finding(
                            id=self._generate_finding_id(
                                self.name, artifact.get("name", ""), 0, lic_name
                            ),
                            scanner=self.name,
                            title=f"Restrictive License: {artifact.get('name', 'Unknown')}",
                            description=f"Package uses {lic_name} license which may have compliance implications",
                            severity=FindingSeverity.INFO,
                            file_path="",
                            line_start=0,
                            line_end=0,
                            code_snippet=f"{artifact.get('name', '')}@{artifact.get('version', '')}",
                            confidence="high",
                            cwe_ids=[],
                            raw_data=artifact,
                        )
                        findings.append(finding)
                        break

        return findings
