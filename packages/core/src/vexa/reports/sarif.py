"""
SARIF Report Generator for Vexa.

SS-006: SARIF 2.1.0 compliant output for IDE integration.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from vexa.reports.generator import BaseReportGenerator, ReportGenerator, ReportMetadata
from vexa.scanners.base import Finding, FindingSeverity
from vexa.scanners.engine import ScanResult
from vexa.common.logging import get_logger


logger = get_logger(__name__)


class SARIFReportGenerator(BaseReportGenerator):
    """
    SS-006: SARIF 2.1.0 report generator for IDE integration.
    
    Produces SARIF output compatible with:
    - VS Code SARIF Viewer
    - GitHub Code Scanning
    - Azure DevOps
    - Other SARIF-compliant tools
    """
    
    format_name = "sarif"
    file_extension = ".sarif"
    
    # SARIF schema version
    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    # Severity to SARIF level mapping
    SEVERITY_TO_LEVEL = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    
    def generate(
        self,
        result: ScanResult,
        output_path: Path,
        metadata: Optional[ReportMetadata] = None,
    ) -> Path:
        """Generate SARIF report."""
        output_path = self._prepare_output_path(output_path)
        metadata = metadata or ReportMetadata()
        
        sarif = self._build_sarif(result, metadata)
        
        # Save output directory as a property for internal path resolution
        self._current_metadata = metadata
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, default=str)
        
        return output_path
    
    def _build_sarif(self, result: ScanResult, metadata: ReportMetadata) -> Dict[str, Any]:
        """Build SARIF 2.1.0 compliant structure."""
        # Group findings by scanner for tool runs
        findings_by_scanner: Dict[str, List[Finding]] = {}
        for finding in result.findings:
            if finding.scanner not in findings_by_scanner:
                findings_by_scanner[finding.scanner] = []
            findings_by_scanner[finding.scanner].append(finding)
        
        runs = []
        for scanner_name, findings in findings_by_scanner.items():
            runs.append(self._build_run(scanner_name, findings, metadata))
        
        # If no findings, create an empty run for Vexa
        if not runs:
            runs.append({
                "tool": {
                    "driver": {
                        "name": "Vexa",
                        "version": metadata.tool_version,
                        "informationUri": "https://github.com/vexa",
                    }
                },
                "results": [],
            })
        
        return {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": runs,
        }
    
    def _build_run(
        self,
        scanner_name: str,
        findings: List[Finding],
        metadata: ReportMetadata,
    ) -> Dict[str, Any]:
        """Build a SARIF run for a scanner."""
        # Collect unique rules
        rules = {}
        for finding in findings:
            rule_id = finding.id[:12]  # Use truncated ID as rule ID
            if rule_id not in rules:
                rules[rule_id] = self._build_rule(finding)
        
        # Ensure timestamp is clean (e.g. 2026-03-23T15:39:24Z)
        end_time = metadata.generated_at.isoformat()
        if "+" in end_time:
            end_time = end_time.split("+")[0]
        if not end_time.endswith("Z"):
            end_time += "Z"

        return {
            "tool": {
                "driver": {
                    "name": scanner_name,
                    "version": metadata.tool_version,
                    "rules": list(rules.values()),
                }
            },
            "results": [self._build_result(f) for f in findings],
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": end_time,
                "properties": {
                    "jobId": metadata.job_id
                }
            }],
            "automationDetails": {
                "id": f"vexa/{scanner_name}/{metadata.job_id or 'local'}"
            },
        }
    
    def _build_rule(self, finding: Finding) -> Dict[str, Any]:
        """Build a SARIF rule definition."""
        rule = {
            "id": finding.id[:12],
            "name": finding.title,
            "shortDescription": {
                "text": finding.title,
            },
            "fullDescription": {
                "text": finding.description or finding.title,
            },
            "defaultConfiguration": {
                "level": self.SEVERITY_TO_LEVEL.get(
                    finding.severity.value if hasattr(finding.severity, 'value') else finding.severity, 
                    "warning"
                ),
            },
        }
        
        # Add CWE relationships
        if finding.cwe_ids:
            rule["relationships"] = [
                {
                    "target": {
                        "id": cwe,
                        "toolComponent": {"name": "CWE"},
                    },
                    "kinds": ["superset"],
                }
                for cwe in finding.cwe_ids
            ]
        
        return rule
    
    def _build_result(self, finding: Finding) -> Dict[str, Any]:
        """Build a SARIF result from a finding."""
        # Resolve relative path for GitHub/IDE compatibility (SS-006)
        file_uri = finding.file_path.replace("\\", "/")
        
        # 1. Strip common Docker workspace prefix if present
        if file_uri.startswith("/workspace/"):
            file_uri = file_uri[11:]
        elif file_uri.startswith("/workspace"):
             file_uri = file_uri[10:].lstrip("/")

        # 2. Try generic resolution against scan_target metadata
        if hasattr(self, "_current_metadata") and self._current_metadata and self._current_metadata.scan_target:
            try:
                # Use str-based manipulation for Docker paths to avoid resolve() ambiguities
                target_str = str(self._current_metadata.scan_target).replace("\\", "/").rstrip("/")
                if file_uri.startswith(target_str):
                    file_uri = file_uri[len(target_str):].lstrip("/")
                
                # Double-check with Path.resolve() if still absolute
                if Path(file_uri).is_absolute():
                    base_path = Path(self._current_metadata.scan_target).resolve()
                    abs_file_path = Path(finding.file_path).resolve()
                    if abs_file_path.is_relative_to(base_path):
                        file_uri = str(abs_file_path.relative_to(base_path)).replace("\\", "/")
            except Exception:
                pass
        
        # 3. Ensure no leading slashes remain (GitHub requires relative paths)
        file_uri = file_uri.lstrip("/")
        
        # 4. Handle common relative path prefixes
        if file_uri.startswith("./"):
            file_uri = file_uri[2:]

        message = {
            "text": finding.description or finding.title,
        }
        
        # Build markdown with AI context if available
        markdown_text = finding.description or finding.title
        has_ai_context = False
        
        if getattr(finding, "is_false_positive", False):
            markdown_text += "\n\n### 🤖 Vexa AI Analyst\n**Status:** ❌ Likely False Positive\n"
            if getattr(finding, "detailed_description", ""):
                markdown_text += f"**Reason:** {finding.detailed_description}\n"
            has_ai_context = True
        elif getattr(finding, "remediation_code", "") or getattr(finding, "detailed_description", ""):
            if not getattr(finding, "is_false_positive", False):
                markdown_text += "\n\n### 🤖 Vexa AI Analyst\n"
                if getattr(finding, "detailed_description", ""):
                    markdown_text += f"**Analysis:** {finding.detailed_description}\n\n"
                if getattr(finding, "remediation_code", ""):
                    markdown_text += f"**Remediation Suggestion:**\n```\n{finding.remediation_code}\n```\n"
                has_ai_context = True
            
        if has_ai_context:
            message["markdown"] = markdown_text

        result = {
            "ruleId": finding.id[:12],
            "level": self.SEVERITY_TO_LEVEL.get(
                finding.severity.value if hasattr(finding.severity, 'value') else finding.severity, 
                "warning"
            ),
            "message": message,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_uri,
                        },
                        "region": {
                            "startLine": max(1, finding.line_start),
                            "endLine": max(1, finding.line_end or finding.line_start),
                        },
                    }
                }
            ],
        }
        
        # Add code snippet if available
        if finding.code_snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.code_snippet,
            }
        
        # Add fingerprint for deduplication
        result["fingerprints"] = {
            "primaryLocationLineHash": finding.id,
        }
        
        # Add AI enhancements to properties
        if hasattr(finding, "detailed_description"):
            result["properties"] = {
                "vexa/ai_false_positive": getattr(finding, "is_false_positive", False),
                "detailedDescription": getattr(finding, "detailed_description", ""),
                "attackScenario": getattr(finding, "attack_scenario", ""),
                "exploitability": getattr(finding, "exploitability", ""),
                "remediationCode": getattr(finding, "remediation_code", ""),
                "owaspCategory": getattr(finding, "owasp_category", ""),
                "mitreAttackId": getattr(finding, "mitre_attack_id", ""),
                "nistControls": getattr(finding, "nist_controls", []),
            }
        
        return result


# Register with ReportGenerator
ReportGenerator.register(SARIFReportGenerator)
