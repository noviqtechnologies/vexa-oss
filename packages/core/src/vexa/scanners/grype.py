"""
Grype Scanner for Container Vulnerabilities.

SS-001: Grype - Container/SBOM vulnerability scanning
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


class GrypeScanner(BaseScanner):
    """
    Grype scanner for container and SBOM vulnerabilities.
    
    Grype is a vulnerability scanner for container images and filesystems.
    Container only due to Grype installation requirements.
    """
    
    name = "grype"
    supported_modes = [ScanMode.LOCAL, ScanMode.CONTAINER]
    
    def get_command(self, path: Path, exclusions: Optional[List[str]] = None) -> List[str]:
        """Build Grype command."""
        cmd = [
            "grype",
            str(path),
            "-o", "json",
            "--quiet",
        ]
        if exclusions:
            for ex in exclusions:
                cmd.extend(["--exclude", ex])
        return cmd
    
    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """Parse Grype JSON output into normalized findings."""
        findings = []
        
        if not output.strip():
            return findings
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse Grype JSON output: %s", e)
            return findings
        
        matches = data.get("matches", [])
        
        for match in matches:
            artifact = match.get("artifact", {})
            vuln = match.get("vulnerability", {})
            related = match.get("relatedVulnerabilities", [])
            
            # Get the most specific CVE/vulnerability ID
            vuln_id = vuln.get("id", "unknown")
            
            finding = Finding(
                id=self._generate_finding_id(
                    self.name,
                    artifact.get("name", ""),
                    0,
                    vuln_id
                ),
                scanner=self.name,
                title=f"{vuln_id}: {artifact.get('name', 'Unknown Package')}",
                description=vuln.get("description", "") or self._get_description(related),
                severity=self._map_severity(vuln.get("severity", "Unknown")),
                file_path=artifact.get("locations", [{}])[0].get("path", "") if artifact.get("locations") else "",
                line_start=0,
                line_end=0,
                code_snippet=f"{artifact.get('name', '')}@{artifact.get('version', '')}",
                confidence="high",
                cwe_ids=self._extract_cwe(related),
                raw_data=match,
            )
            findings.append(finding)
        
        return findings
    
    def _get_description(self, related: list) -> str:
        """Get description from related vulnerabilities."""
        for r in related:
            desc = r.get("description", "")
            if desc:
                return desc
        return "Container vulnerability detected"
    
    def _map_severity(self, severity: str) -> FindingSeverity:
        """Map Grype severity to normalized severity."""
        mapping = {
            "Critical": FindingSeverity.CRITICAL,
            "High": FindingSeverity.HIGH,
            "Medium": FindingSeverity.MEDIUM,
            "Low": FindingSeverity.LOW,
            "Negligible": FindingSeverity.INFO,
            "Unknown": FindingSeverity.MEDIUM,
        }
        return mapping.get(severity, FindingSeverity.MEDIUM)
    
    def _extract_cwe(self, related: list) -> List[str]:
        """Extract CWE IDs from related vulnerabilities."""
        cwe_ids = []
        
        for r in related:
            cwes = r.get("cwes", [])
            for cwe in cwes:
                if isinstance(cwe, str):
                    cwe_ids.append(cwe if cwe.startswith("CWE-") else f"CWE-{cwe}")
                elif isinstance(cwe, dict):
                    cwe_id = cwe.get("id", "")
                    if cwe_id:
                        cwe_ids.append(f"CWE-{cwe_id}" if not str(cwe_id).startswith("CWE-") else str(cwe_id))
        
        return list(set(cwe_ids))  # Deduplicate
