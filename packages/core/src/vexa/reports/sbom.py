"""
SBOM Report Generator for Vexa.

SS-001: Exports Software Bill of Materials (SBOM) in JSON/SPDX format.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from vexa.scanners.engine import ScanResult
from vexa.reports.generator import BaseReportGenerator, ReportGenerator, ReportMetadata


class SBOMReportGenerator(BaseReportGenerator):
    """
    Generator for SBOM reports.
    
    KF-012: Extracts raw SBOM data from the 'syft' scanner results.
    """
    
    format_name = "sbom"
    file_extension = ".json"
    
    def generate(
        self,
        result: ScanResult,
        output_path: Path,
        metadata: Optional[ReportMetadata] = None,
    ) -> Path:
        """
        Generate an SBOM report.
        
        Args:
            result: ScanResult containing data from syft scanner
            output_path: Directory or file path for output
            metadata: Optional report metadata
            
        Returns:
            Path to the generated SBOM file
        """
        target_path = self._prepare_output_path(output_path)
        
        # Find syft scanner result
        syft_result = None
        for scanner_name, res in result.scanners_run.items():
            if scanner_name == "syft":
                syft_result = res
                break
        
        if not syft_result:
            # Fallback: create a minimal SBOM from scanned packages in core findings
            # but usually we want the full Syft output
            gen_at = metadata.generated_at if metadata else datetime.now()
            sbom_data = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "metadata": {
                    "timestamp": gen_at.isoformat(),
                    "tool": {
                        "vendor": "Vexa",
                        "name": "Vexa Core",
                        "version": "1.0.20"
                    }
                },
                "components": []
            }
            
            # Extract basic package info from syft informant findings if available
            for finding in result.findings:
                if finding.scanner == "syft":
                    if finding.raw_data:
                        sbom_data["components"].append(finding.raw_data)
        else:
            # Try to use raw output if it was captured
            try:
                # Syft raw output is already JSON
                sbom_data = json.loads(syft_result.raw_output)
            except Exception:
                # Fallback to findings raw_data
                sbom_data = {"components": []}
                for f in syft_result.findings:
                    if f.raw_data:
                        sbom_data["components"].append(f.raw_data)
        
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2)
            
        return target_path


# Register the generator
ReportGenerator.register(SBOMReportGenerator)
