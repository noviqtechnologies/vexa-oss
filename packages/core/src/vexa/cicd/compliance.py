"""
Compliance Mapping for Vexa CI/CD.

CI-FR-052: Group and report findings by compliance frameworks (OWASP, NIST, etc).
"""

from dataclasses import dataclass, field
from typing import Dict, List

from vexa.common.models import ScanResult


@dataclass
class ComplianceMetric:
    """Metrics for a specific compliance framework category."""
    name: str
    finding_count: int = 0
    severity_distribution: Dict[str, int] = field(default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    passed: bool = True


@dataclass
class ComplianceReport:
    """Consolidated compliance report across multiple frameworks."""
    frameworks: Dict[str, List[ComplianceMetric]] = field(default_factory=dict)
    total_non_compliant: int = 0

    @property
    def summary(self) -> str:
        """Return a human-readable summary of the compliance status."""
        if self.total_non_compliant == 0:
            return "✅ Compliance: 100% compliant with tracked controls"
        return f"⚠️ Compliance: {self.total_non_compliant} findings map to regulatory controls"


class ComplianceAnalyzer:
    """
    Analyzes scan results to produce compliance-specific views.
    
    KF-052: Maps findings to OWASP, NIST, and other frameworks for auditing.
    """

    def analyze(self, result: ScanResult) -> ComplianceReport:
        """
        Analyze scan results for compliance metrics.
        
        Args:
            result: The completed scan result
            
        Returns:
            ComplianceReport grouped by framework
        """
        report = ComplianceReport()
        owasp_metrics: Dict[str, ComplianceMetric] = {}
        nist_metrics: Dict[str, ComplianceMetric] = {}
        
        for finding in result.findings:
            # 1. OWASP Mapping
            if finding.owasp_category:
                cat = str(finding.owasp_category)
                if cat not in owasp_metrics:
                    owasp_metrics[cat] = ComplianceMetric(name=cat)
                
                owasp_metrics[cat].finding_count += 1
                sev = str(finding.severity.lower()) if hasattr(finding.severity, "lower") else str(finding.severity).lower()
                owasp_metrics[cat].severity_distribution[sev] = owasp_metrics[cat].severity_distribution.get(sev, 0) + 1
                owasp_metrics[cat].passed = False
                report.total_non_compliant += 1
                
            # 2. NIST Mapping
            if finding.nist_controls:
                for control in finding.nist_controls:
                    c_name = str(control)
                    if c_name not in nist_metrics:
                        nist_metrics[c_name] = ComplianceMetric(name=c_name)
                    
                    nist_metrics[c_name].finding_count += 1
                    sev = str(finding.severity.lower()) if hasattr(finding.severity, "lower") else str(finding.severity).lower()
                    nist_metrics[c_name].severity_distribution[sev] = nist_metrics[c_name].severity_distribution.get(sev, 0) + 1
                    nist_metrics[c_name].passed = False

        report.frameworks["OWASP Top 10"] = sorted(owasp_metrics.values(), key=lambda x: x.name)
        report.frameworks["NIST 800-53"] = sorted(nist_metrics.values(), key=lambda x: x.name)
        
        return report
