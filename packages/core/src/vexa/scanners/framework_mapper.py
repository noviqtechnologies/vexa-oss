"""
Framework Mapper for Security Findings.

SS-014: Map findings to security frameworks (CWE, OWASP, MITRE, NIST)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vexa.common.models import Finding
from vexa.common.logging import get_logger


logger = get_logger(__name__)


class FrameworkMapper:
    """
    SS-014: Map findings to security frameworks.
    
    Maps security findings to:
    - CWE (Common Weakness Enumeration)
    - OWASP Top 10 (2021)
    - MITRE ATT&CK
    - NIST 800-53 Controls
    """
    
    # CWE to vulnerability type mapping (used for scanners that don't provide CWE)
    CWE_MAPPINGS: Dict[str, List[str]] = {
        "hardcoded_password": ["CWE-259", "CWE-798"],
        "sql_injection": ["CWE-89"],
        "command_injection": ["CWE-77", "CWE-78"],
        "path_traversal": ["CWE-22", "CWE-23"],
        "xss": ["CWE-79"],
        "xxe": ["CWE-611"],
        "ssrf": ["CWE-918"],
        "insecure_deserialization": ["CWE-502"],
        "broken_auth": ["CWE-287", "CWE-306"],
        "sensitive_data_exposure": ["CWE-200", "CWE-312"],
        "security_misconfiguration": ["CWE-16", "CWE-732"],
        "insecure_crypto": ["CWE-327", "CWE-328"],
    }
    
    # OWASP Top 10 2021 mappings
    OWASP_MAPPINGS: Dict[str, str] = {
        "CWE-89": "A03:2021-Injection",
        "CWE-77": "A03:2021-Injection",
        "CWE-78": "A03:2021-Injection",
        "CWE-79": "A03:2021-Injection",
        "CWE-611": "A03:2021-Injection",
        "CWE-259": "A07:2021-Identification and Authentication Failures",
        "CWE-798": "A07:2021-Identification and Authentication Failures",
        "CWE-287": "A07:2021-Identification and Authentication Failures",
        "CWE-306": "A07:2021-Identification and Authentication Failures",
        "CWE-22": "A01:2021-Broken Access Control",
        "CWE-23": "A01:2021-Broken Access Control",
        "CWE-732": "A01:2021-Broken Access Control",
        "CWE-200": "A02:2021-Cryptographic Failures",
        "CWE-312": "A02:2021-Cryptographic Failures",
        "CWE-327": "A02:2021-Cryptographic Failures",
        "CWE-328": "A02:2021-Cryptographic Failures",
        "CWE-16": "A05:2021-Security Misconfiguration",
        "CWE-502": "A08:2021-Software and Data Integrity Failures",
        "CWE-918": "A10:2021-Server-Side Request Forgery",
    }
    
    # MITRE ATT&CK mappings
    MITRE_MAPPINGS: Dict[str, List[str]] = {
        "CWE-78": ["T1059-Command and Scripting Interpreter"],
        "CWE-77": ["T1059-Command and Scripting Interpreter"],
        "CWE-89": ["T1190-Exploit Public-Facing Application"],
        "CWE-798": ["T1552-Unsecured Credentials"],
        "CWE-259": ["T1552-Unsecured Credentials"],
        "CWE-22": ["T1083-File and Directory Discovery"],
        "CWE-502": ["T1055-Process Injection"],
    }
    
    # NIST 800-53 Control mappings
    NIST_MAPPINGS: Dict[str, List[str]] = {
        "CWE-78": ["SI-10", "SI-3"],
        "CWE-77": ["SI-10", "SI-3"],
        "CWE-89": ["SI-10", "SI-3"],
        "CWE-79": ["SI-10", "SI-3"],
        "CWE-798": ["IA-5", "SC-12"],
        "CWE-259": ["IA-5", "SC-12"],
        "CWE-22": ["AC-3", "AC-6"],
        "CWE-732": ["AC-3", "AC-6"],
        "CWE-327": ["SC-12", "SC-13"],
        "CWE-328": ["SC-12", "SC-13"],
        "CWE-200": ["SC-28", "SC-8"],
        "CWE-312": ["SC-28", "SC-8"],
    }
    
    def map_finding(self, finding: Finding) -> Finding:
        """
        Map a finding to security frameworks.
        
        Args:
            finding: The finding to enrich
            
        Returns:
            The modified Finding object with framework mappings
        """
        # Start with existing CWE IDs from the finding
        cwe_ids = list(finding.cwe_ids) if finding.cwe_ids else []
        
        # Get OWASP category
        if not finding.owasp_category:
            for cwe in cwe_ids:
                if cwe in self.OWASP_MAPPINGS:
                    finding.owasp_category = self.OWASP_MAPPINGS[cwe]
                    break
        
        # Get MITRE techniques (mapped to mitre_attack_id)
        if not finding.mitre_attack_id:
            for cwe in cwe_ids:
                if cwe in self.MITRE_MAPPINGS:
                    # Take the first one for simplicity as it's a single string field
                    finding.mitre_attack_id = self.MITRE_MAPPINGS[cwe][0]
                    break
        
        # Get NIST controls
        nist_controls = list(finding.nist_controls) if finding.nist_controls else []
        for cwe in cwe_ids:
            if cwe in self.NIST_MAPPINGS:
                for control in self.NIST_MAPPINGS[cwe]:
                    if control not in nist_controls:
                        nist_controls.append(control)
        
        finding.nist_controls = nist_controls
        
        return finding
    
    def map_findings(self, findings: List[Finding]) -> List[Finding]:
        """Map multiple findings to security frameworks."""
        for f in findings:
            self.map_finding(f)
        return findings
    
    def get_cwe_for_type(self, vulnerability_type: str) -> List[str]:
        """Get CWE IDs for a vulnerability type."""
        return self.CWE_MAPPINGS.get(vulnerability_type, [])
    
    def get_owasp_for_cwe(self, cwe_id: str) -> Optional[str]:
        """Get OWASP category for a CWE ID."""
        return self.OWASP_MAPPINGS.get(cwe_id)


# Singleton instance
_framework_mapper: Optional[FrameworkMapper] = None


def get_framework_mapper() -> FrameworkMapper:
    """Get the global FrameworkMapper singleton."""
    global _framework_mapper
    if _framework_mapper is None:
        _framework_mapper = FrameworkMapper()
    return _framework_mapper
