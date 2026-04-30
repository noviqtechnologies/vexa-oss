"""
JSON Report Generator for Vexa.

SS-006: Native JSON report output for API/automation.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from vexa.reports.generator import BaseReportGenerator, ReportGenerator, ReportMetadata
from vexa.scanners.base import Finding
from vexa.scanners.engine import ScanResult
from vexa.common.logging import get_logger


logger = get_logger(__name__)


class JSONReportGenerator(BaseReportGenerator):
    """
    SS-006: JSON report generator for API/automation.

    Produces structured JSON output suitable for:
    - API responses
    - CI/CD pipeline consumption
    - Data analysis tools
    """

    format_name = "json"
    file_extension = ".json"

    def generate(
        self,
        result: ScanResult,
        output_path: Path,
        metadata: Optional[ReportMetadata] = None,
    ) -> Path:
        """Generate JSON report."""
        output_path = self._prepare_output_path(output_path)
        metadata = metadata or ReportMetadata()

        report = self._build_report(result, metadata)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return output_path

    def _build_report(
        self, result: ScanResult, metadata: ReportMetadata
    ) -> Dict[str, Any]:
        """Build the JSON report structure."""
        return {
            "metadata": {
                "title": metadata.title,
                "generated_at": metadata.generated_at.isoformat(),
                "scan_target": metadata.scan_target,
                "scan_duration_seconds": metadata.scan_duration
                or result.duration_seconds,
                "tool_version": metadata.tool_version,
                "job_id": metadata.job_id,
            },
            "summary": {
                "total_findings": result.total_findings,
                "success": result.success,
                "by_severity": self._get_severity_counts(result.findings),
                "by_scanner": self._get_scanner_counts(result.findings),
            },
            "scanners": self._build_scanner_summary(result),
            "findings": [self._finding_to_dict(f) for f in result.findings],
            "errors": result.errors,
        }

    def _build_scanner_summary(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Build scanner execution summary."""
        summaries = []
        for name, sr in result.scanner_results.items():
            # sr is a dict when coming from Pydantic/MCP
            is_dict = isinstance(sr, dict)
            summaries.append(
                {
                    "name": name,
                    "success": sr.get("success") if is_dict else sr.success,
                    "finding_count": sr.get("finding_count")
                    if is_dict
                    else sr.finding_count,
                    "execution_time_seconds": sr.get("execution_time")
                    if is_dict
                    else sr.execution_time,
                    "error": sr.get("error") if is_dict else sr.error,
                }
            )
        return summaries

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary with all 11 required AI fields."""
        severity = (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else finding.severity
        )

        # Base finding data
        data = {
            "id": finding.id,
            "scanner": finding.scanner,
            "title": finding.title,
            "description": finding.description,
            "severity": severity,
            "location": {
                "file": finding.file_path,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
            },
            # Top-level line info for easier consumption
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "code_snippet": finding.code_snippet,
            "code_snippet_before": getattr(
                finding, "code_snippet_before", finding.code_snippet
            ),
            "cwe_ids": finding.cwe_ids,
            "owasp_category": finding.owasp_category,
            "mitre_attack_id": finding.mitre_attack_id,
            "nist_controls": finding.nist_controls,
        }

        # AI-enhanced fields (Required: 11 fields total)
        # We ensure these keys are ALWAYS present if they are requested for professionalism
        ai_fields = {
            "detailed_description": getattr(finding, "detailed_description", ""),
            "attack_scenario": getattr(finding, "attack_scenario", ""),
            "business_impact": getattr(finding, "business_impact", ""),
            "exploitability": getattr(finding, "exploitability", "unknown"),
            "remediation_code": getattr(finding, "remediation_code", ""),
            "remediation_guidance": getattr(finding, "remediation_guidance", ""),
            "implementation_steps": getattr(finding, "implementation_steps", []),
            "google_cloud_recommendation": getattr(
                finding, "google_cloud_recommendation", ""
            ),
            "google_cloud_doc_links": getattr(finding, "google_cloud_doc_links", []),
            "aws_recommendation": getattr(finding, "aws_recommendation", ""),
            "aws_well_architected_pillar": getattr(
                finding, "aws_well_architected_pillar", ""
            ),
            "aws_doc_links": getattr(finding, "aws_doc_links", []),
            "test_cases": getattr(finding, "test_cases", []),
        }

        data.update(ai_fields)

        # Add FP analysis if available
        if hasattr(finding, "false_positive_confidence"):
            data.update(
                {
                    "false_positive_confidence": finding.false_positive_confidence,
                    "is_false_positive": finding.is_false_positive,
                    "fp_explanation": finding.fp_explanation,
                }
            )

        return data


# Register with ReportGenerator
ReportGenerator.register(JSONReportGenerator)
