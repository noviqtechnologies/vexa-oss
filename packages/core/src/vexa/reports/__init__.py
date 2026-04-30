"""
Reports Module for Vexa.

SS-006: Multi-format report generation
TM-008: Threat model report generation
"""

from vexa.reports.generator import (
    BaseReportGenerator,
    ReportGenerator,
    ReportMetadata,
    get_report_generator,
)

# Import generators to register them
from vexa.reports.json import JSONReportGenerator
from vexa.reports.html import HTMLReportGenerator
from vexa.reports.sarif import SARIFReportGenerator
from vexa.reports.markdown import MarkdownReportGenerator
from vexa.reports.sbom import SBOMReportGenerator

__all__ = [
    # Base classes
    "BaseReportGenerator",
    "ReportGenerator",
    "ReportMetadata",
    "get_report_generator",
    # Format generators
    "JSONReportGenerator",
    "HTMLReportGenerator",
    "SARIFReportGenerator",
    "MarkdownReportGenerator",
    "SBOMReportGenerator",
]
