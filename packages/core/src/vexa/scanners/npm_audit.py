"""
npm-audit Scanner for Node.js Dependency Vulnerabilities.

SS-001: npm-audit - JavaScript/Node.js dependency vulnerabilities
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


class NpmAuditScanner(BaseScanner):
    """
    npm audit scanner for Node.js dependency vulnerabilities.
    
    npm audit checks package.json dependencies for known vulnerabilities.
    Container only due to npm requirement.
    """
    
    name = "npm-audit"
    supported_modes = [ScanMode.LOCAL, ScanMode.CONTAINER]
    
    def get_command(self, path: Path, exclusions: Optional[List[str]] = None) -> List[str]:
        """Build npm audit command."""
        return [
            "npm",
            "audit",
            "--json",
        ]
    
    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """Parse npm audit JSON output into normalized findings."""
        findings = []
        
        if not output.strip():
            return findings
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse npm audit JSON output: %s", e)
            return findings
        
        # npm audit v7+ format
        vulnerabilities = data.get("vulnerabilities", {})
        
        for pkg_name, vuln_info in vulnerabilities.items():
            via = vuln_info.get("via", [])
            
            # 'via' can be a list of vulnerability details or strings
            for v in via:
                if isinstance(v, dict):
                    finding = Finding(
                        id=self._generate_finding_id(
                            self.name,
                            "package.json",
                            0,
                            str(v.get("source", pkg_name))
                        ),
                        scanner=self.name,
                        title=v.get("title", f"Vulnerability in {pkg_name}"),
                        description=v.get("url", ""),
                        severity=self._map_severity(v.get("severity", "moderate")),
                        file_path="package.json",
                        line_start=0,
                        line_end=0,
                        code_snippet=f"{pkg_name}@{vuln_info.get('range', 'unknown')}",
                        confidence="high",
                        cwe_ids=self._extract_cwe(v),
                        raw_data=v,
                    )
                    findings.append(finding)
        
        # Also handle older npm audit format
        if "advisories" in data:
            for advisory_id, advisory in data.get("advisories", {}).items():
                finding = Finding(
                    id=self._generate_finding_id(
                        self.name,
                        "package.json",
                        0,
                        str(advisory_id)
                    ),
                    scanner=self.name,
                    title=advisory.get("title", "npm vulnerability"),
                    description=advisory.get("overview", ""),
                    severity=self._map_severity(advisory.get("severity", "moderate")),
                    file_path="package.json",
                    line_start=0,
                    line_end=0,
                    code_snippet=advisory.get("module_name", ""),
                    confidence="high",
                    cwe_ids=self._extract_cwe(advisory),
                    raw_data=advisory,
                )
                findings.append(finding)
        
        return findings
    
    def _map_severity(self, severity: str) -> FindingSeverity:
        """Map npm audit severity to normalized severity."""
        mapping = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "moderate": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        return mapping.get(severity.lower(), FindingSeverity.MEDIUM)
    
    def _extract_cwe(self, advisory: dict) -> List[str]:
        """Extract CWE IDs from npm advisory."""
        cwe_ids = []
        
        # npm advisories include CWE in the response
        cwe_field = advisory.get("cwe", [])
        if isinstance(cwe_field, list):
            cwe_ids.extend(cwe_field)
        elif isinstance(cwe_field, str):
            cwe_ids.append(cwe_field)
        
        return cwe_ids
