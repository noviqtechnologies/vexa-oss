"""
pip-licenses Scanner for License Compliance.

SS-009: pip-licenses - Python license compliance scanning
Modes: LOCAL, CONTAINER
"""

import json
from pathlib import Path
from typing import List, Set, Optional

from vexa.scanners.base import (
    BaseScanner,
    Finding,
    FindingSeverity,
    ScanMode,
)
from vexa.common.logging import get_logger


logger = get_logger(__name__)


class PipLicensesScanner(BaseScanner):
    """
    pip-licenses scanner for Python license compliance.
    
    SS-009: Scans Python dependencies for license information
    and flags restrictive or unknown licenses.
    """
    
    name = "pip-licenses"
    supported_modes = [ScanMode.LOCAL, ScanMode.CONTAINER]
    
    # Licenses that may require compliance attention
    RESTRICTIVE_LICENSES: Set[str] = {
        "GPL", "GPLv2", "GPLv3", "GPL-2.0", "GPL-3.0",
        "LGPL", "LGPLv2", "LGPLv3", "LGPL-2.0", "LGPL-3.0",
        "AGPL", "AGPLv3", "AGPL-3.0",
        "SSPL",
        "CC-BY-NC", "CC-BY-ND",
    }
    
    # Licenses that require review
    UNKNOWN_LICENSES: Set[str] = {
        "UNKNOWN", "Unknown", "unknown", "",
    }
    
    def get_command(self, path: Path, exclusions: Optional[List[str]] = None) -> List[str]:
        """Build pip-licenses command."""
        import sys
        return [
            "pip-licenses",
            "--format=json",
            "--with-urls",
        ]
    
    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """Parse pip-licenses JSON output into normalized findings."""
        findings = []
        
        if not output.strip():
            return findings
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse pip-licenses JSON output: %s", e)
            return findings
        
        for package in data:
            license_name = package.get("License", "UNKNOWN")
            pkg_name = package.get("Name", "unknown")
            
            # Check for restrictive licenses
            if self._is_restrictive(license_name):
                finding = Finding(
                    id=self._generate_finding_id(
                        self.name,
                        "",
                        0,
                        f"{pkg_name}-restrictive"
                    ),
                    scanner=self.name,
                    title=f"Restrictive License: {pkg_name}",
                    description=f"Package '{pkg_name}' uses {license_name} license which may have compliance implications",
                    severity=FindingSeverity.MEDIUM,
                    file_path="requirements.txt",
                    line_start=0,
                    line_end=0,
                    code_snippet=f"{pkg_name}=={package.get('Version', '')}",
                    confidence="high",
                    cwe_ids=[],
                    raw_data=package,
                )
                findings.append(finding)
            
            # Check for unknown licenses
            elif license_name in self.UNKNOWN_LICENSES:
                finding = Finding(
                    id=self._generate_finding_id(
                        self.name,
                        "",
                        0,
                        f"{pkg_name}-unknown"
                    ),
                    scanner=self.name,
                    title=f"Unknown License: {pkg_name}",
                    description=f"Package '{pkg_name}' has unknown or unspecified license",
                    severity=FindingSeverity.LOW,
                    file_path="requirements.txt",
                    line_start=0,
                    line_end=0,
                    code_snippet=f"{pkg_name}=={package.get('Version', '')}",
                    confidence="medium",
                    cwe_ids=[],
                    raw_data=package,
                )
                findings.append(finding)
        
        return findings
    
    def _is_restrictive(self, license_name: str) -> bool:
        """Check if license is restrictive."""
        license_upper = license_name.upper()
        for restrictive in self.RESTRICTIVE_LICENSES:
            if restrictive.upper() in license_upper:
                return True
        return False
