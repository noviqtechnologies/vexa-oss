"""
Data Merger for Vexa.

Consolidates and deduplicates findings from multiple security scanners.

Implements:
- SS-001: Orchestrates security tool execution (aggregation)
- SS-014: Map findings to OWASP, MITRE, NIST, CWE (enrichment)
"""

import hashlib
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from vexa.common.logging import get_logger, audit_logger
from vexa.common.models import Finding, EnhancedFinding
from vexa.security.security_validator import get_security_validator
from vexa.scanners.deduplication_engine import DeduplicationEngine


logger = get_logger(__name__)


class DataMerger:
    """
    Merges and deduplicates findings from multiple scanners.
    
    Features:
    - Finding deduplication based on file, line, and type
    - Severity consolidation for duplicate findings
    - Framework mapping enrichment (OWASP, CWE, MITRE)
    - Security validation before output
    """
    
    # Severity priority for deduplication (higher = more severe)
    SEVERITY_PRIORITY = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }
    
    def __init__(self, validate_findings: bool = True):
        """
        Initialize DataMerger.
        
        Args:
            validate_findings: Whether to validate findings before merging
        """
        self.logger = logger
        self._validate = validate_findings
        self._security_validator = get_security_validator()
        self._dedup_engine = DeduplicationEngine()
    
    def merge_findings(
        self,
        findings_by_scanner: Dict[str, List[Finding]],
    ) -> List[Finding]:
        """
        Merge findings from multiple scanners.
        
        Args:
            findings_by_scanner: Dictionary of scanner_name -> list of findings
            
        Returns:
            List of merged findings
        """
        all_findings = []
        
        for scanner_name, findings in findings_by_scanner.items():
            self.logger.info("Processing %d findings from %s", len(findings), scanner_name)
            all_findings.extend(findings)
        
        self.logger.info(
            "Merging %d findings from %d scanners: %s",
            len(all_findings), len(findings_by_scanner), list(findings_by_scanner.keys())
        )
        
        # Validate findings if enabled
        if self._validate:
            all_findings, validation_errors = self._security_validator.validate_findings_pre_merge(
                all_findings
            )
            if validation_errors:
                self.logger.warning(
                    "Removed %d invalid findings during merge: %s",
                    len(validation_errors), validation_errors
                )
        
        # Deduplicate
        input_count = len(all_findings)
        merged = self.deduplicate(all_findings)
        output_count = len(merged)
        
        self.logger.info(
            "Deduplication complete: %d -> %d findings (%d removed)",
            input_count, output_count, input_count - output_count
        )
        
        audit_logger.log_security_event(
            "findings_merged",
            {
                "input_count": input_count,
                "output_count": output_count,
                "scanners": list(findings_by_scanner.keys()),
            }
        )
        
        return merged
    
    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings using the advanced 3-stage engine.
        
        Args:
            findings: List of findings to deduplicate
            
        Returns:
            Deduplicated list of findings
        """
        return self._dedup_engine.deduplicate(findings)
    
    def _generate_dedup_key(self, finding: Finding) -> str:
        """
        Generate a deduplication key for a finding.
        
        Key is based on:
        - File path
        - Line range (start-end)
        - CWE IDs or title hash
        
        Args:
            finding: The finding to generate key for
            
        Returns:
            Deduplication key string
        """
        # Normalize file path
        file_path = finding.file_path.replace("\\", "/").lower()
        
        # Line range
        line_range = f"{finding.line_start}-{finding.line_end}"
        
        # Vulnerability identifier (prefer CWE, fall back to title hash)
        if finding.cwe_ids:
            vuln_id = ",".join(sorted(finding.cwe_ids))
        else:
            # Hash of title for consistent dedup
            vuln_id = hashlib.md5(finding.title.lower().encode()).hexdigest()[:8]
        
        return f"{file_path}:{line_range}:{vuln_id}"
    
    def _merge_duplicate_info(
        self,
        primary: Finding,
        duplicates: List[Finding],
    ) -> Finding:
        """
        Merge additional information from duplicate findings into primary.
        Delegates to DeduplicationEngine.
        """
        return self._dedup_engine.merge_duplicate_info(primary, duplicates)
    
    def sort_by_severity(
        self,
        findings: List[Finding],
        descending: bool = True,
    ) -> List[Finding]:
        """
        Sort findings by severity.
        
        Args:
            findings: List of findings to sort
            descending: If True, critical first; if False, info first
            
        Returns:
            Sorted list of findings
        """
        return sorted(
            findings,
            key=lambda f: self.SEVERITY_PRIORITY.get(f.severity, 0),
            reverse=descending
        )
    
    def group_by_file(
        self,
        findings: List[Finding],
    ) -> Dict[str, List[Finding]]:
        """
        Group findings by file path.
        
        Args:
            findings: List of findings to group
            
        Returns:
            Dictionary of file_path -> findings
        """
        grouped: Dict[str, List[Finding]] = defaultdict(list)
        
        for finding in findings:
            grouped[finding.file_path].append(finding)
        
        # Sort findings within each file by line number
        for file_path in grouped:
            grouped[file_path].sort(key=lambda f: f.line_start)
        
        return dict(grouped)
    
    def group_by_severity(
        self,
        findings: List[Finding],
    ) -> Dict[str, List[Finding]]:
        """
        Group findings by severity level.
        
        Args:
            findings: List of findings to group
            
        Returns:
            Dictionary of severity -> findings
        """
        grouped: Dict[str, List[Finding]] = defaultdict(list)
        
        for finding in findings:
            grouped[finding.severity].append(finding)
        
        return dict(grouped)
    
    def get_summary_stats(
        self,
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """
        Get summary statistics for findings.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary with summary statistics
        """
        by_severity = self.group_by_severity(findings)
        by_scanner = defaultdict(int)
        files_affected = set()
        
        for finding in findings:
            by_scanner[finding.scanner] += 1
            files_affected.add(finding.file_path)
        
        return {
            "total_findings": len(findings),
            "by_severity": {sev: len(f) for sev, f in by_severity.items()},
            "by_scanner": dict(by_scanner),
            "files_affected": len(files_affected),
            "critical_count": len(by_severity.get("critical", [])),
            "high_count": len(by_severity.get("high", [])),
        }


# Singleton instance
_data_merger: Optional[DataMerger] = None


def get_data_merger() -> DataMerger:
    """Get the global DataMerger singleton."""
    global _data_merger
    if _data_merger is None:
        _data_merger = DataMerger()
    return _data_merger
