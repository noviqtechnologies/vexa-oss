"""
pip-audit Scanner for Python Dependency Vulnerabilities.

SS-008: pip-audit - Python dependency vulnerability scanning
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


class PipAuditScanner(BaseScanner):
    """
    pip-audit scanner for Python dependency vulnerabilities.
    
    SS-008: Scans Python dependencies for known vulnerabilities
    using the PyPI vulnerability database.
    """
    
    name = "pip-audit"
    supported_modes = [ScanMode.LOCAL, ScanMode.CONTAINER]
    
    def get_command(self, path: Path, exclusions: Optional[List[str]] = None) -> List[str]:
        """Build pip-audit command."""
        import sys
        # Check for requirements.txt
        req_file = path / "requirements.txt" if path.is_dir() else path
        
        cmd = ["pip-audit", "-f", "json"]
        
        if req_file.exists() and req_file.name == "requirements.txt":
            cmd.extend(["-r", str(req_file)])
        
        return cmd
    
    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """Parse pip-audit JSON output into normalized findings."""
        findings = []
        
        if not output.strip():
            return findings
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse pip-audit JSON output: %s", e)
            return findings
        
        # pip-audit outputs a list of vulnerability records
        dependencies = data.get("dependencies", []) if isinstance(data, dict) else data
        
        for dep in dependencies:
            vulns = dep.get("vulns", [])
            
            for vuln in vulns:
                finding = Finding(
                    id=self._generate_finding_id(
                        self.name,
                        "requirements.txt",
                        0,
                        vuln.get("id", "")
                    ),
                    scanner=self.name,
                    title=f"{vuln.get('id', 'Unknown')}: {dep.get('name', 'Unknown Package')}",
                    description=self._clean_description(vuln.get("description", "Vulnerability in Python dependency")),
                    severity=self._map_severity(vuln),
                    file_path="requirements.txt",
                    line_start=0,
                    line_end=0,
                    code_snippet=f"{dep.get('name', '')}=={dep.get('version', '')}",
                    confidence="high",
                    cwe_ids=self._extract_cwe(vuln),
                    raw_data=vuln,
                )
                findings.append(finding)
        
        return findings
    
    def _map_severity(self, vuln: dict) -> FindingSeverity:
        """Map pip-audit vulnerability to severity."""
        # pip-audit doesn't always include severity
        # Use aliases to determine - CVE-* typically indicates real vuln
        vuln_id = vuln.get("id", "")
        
        if vuln_id.startswith("GHSA-"):
            # GitHub Security Advisory - usually higher severity
            return FindingSeverity.HIGH
        elif vuln_id.startswith("CVE-"):
            return FindingSeverity.HIGH
        elif vuln_id.startswith("PYSEC-"):
            return FindingSeverity.MEDIUM
        else:
            return FindingSeverity.MEDIUM
    
    def _clean_description(self, description: str) -> str:
        """Clean and format vulnerability description."""
        if not description:
            return ""
            
        import re
            
        # Ensure description handles newlines properly for markdown
        cleaned = description.replace("\r\n", "\n")
        
        # Add Markdown headers to common sections
        # Use regex to find these words when they start a line or sentence
        sections = ["Summary", "Details", "PoC", "Impact", "Recommendation", "Scenario", "Leak analysis"]
        pattern = r'(?:^|\n|\.\s+)(Summary|Details|PoC|Impact|Recommendation|Scenario|Leak analysis)[\s:]+'
        
        def replace_header(match):
            # \n\n#### Section\n
            return f"\n\n#### {match.group(1)}\n"
            
        cleaned = re.sub(pattern, replace_header, cleaned, flags=re.MULTILINE)
        
        # Fix code blocks that might be inline
        # Ensure ``` starts on a new line
        cleaned = re.sub(r'(?<!\n)```', r'\n```', cleaned)
        # Ensure ``` ends on a new line if followed by text
        cleaned = re.sub(r'```(?!\n)', r'```\n', cleaned)
        
        # Clean up excessive newlines
        cleaned = re.sub(r'\n{3,}', r'\n\n', cleaned)
                
        return cleaned.strip()

    def _extract_cwe(self, vuln: dict) -> List[str]:
        """Extract CWE IDs from pip-audit vulnerability."""
        cwe_ids = []
        
        # Check aliases for CWE references
        aliases = vuln.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CWE-"):
                cwe_ids.append(alias)
        
        return cwe_ids
