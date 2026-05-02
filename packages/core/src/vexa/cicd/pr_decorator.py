"""
PR Decoration / Comment Generator for CI/CD Pipelines.

CI-FR-061: Summary comment with score, severity counts, quality gate status.
CI-FR-062: Inline annotations on specific lines.
CI-FR-063: Collapsible finding table in PR comment.
CI-FR-065: Update existing comment (not post new one).
CI-FR-066: Show resolved badge when quality gate passes.
"""

from typing import Dict, List, Optional

from vexa.common.models import ScanResult, Finding
from .baseline import BaselineDiff
from .quality_gate import QualityGateResult
from .security_score import SecurityScore
from .trend import TrendReport
from .compliance import ComplianceReport


class PRDecorator:
    """
    Generates markdown content for PR/MR comments and inline annotations.

    Supports GitHub PR comments, GitLab MR notes, and Azure DevOps PR threads.
    """

    SEVERITY_ICONS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    def generate_summary_comment(
        self,
        scan_result: ScanResult,
        gate_result: QualityGateResult,
        score: SecurityScore,
        diff: Optional[BaselineDiff] = None,
        trend: Optional[TrendReport] = None,
        compliance: Optional[ComplianceReport] = None,
    ) -> str:
        """
        Generate a full PR summary comment in markdown.

        Args:
            scan_result: Completed scan result
            gate_result: Quality gate evaluation result
            score: Security score
            diff: Optional baseline diff
            trend: Optional trend report
            compliance: Optional compliance report

        Returns:
            Markdown string for the PR comment
        """
        lines: List[str] = []
        sections: List[str] = []

        # Header
        lines.append("## 🔒 Vexa Security Scan Report")
        lines.append("")

        # Quality Gate Status
        if gate_result.passed:
            lines.append("### ✅ Quality Gate: **PASSED**")
        else:
            lines.append("### ❌ Quality Gate: **FAILED**")
        lines.append("")

        # Security Score
        lines.append(f"**{score.display}**")
        lines.append("")

        # Summary Table
        lines.append("| Metric | Value |")
        lines.append("|:---|:---|")
        lines.append(f"| Total Findings | {scan_result.total_findings} |")
        lines.append(f"| Scanners Run | {len(scan_result.scanners_run)} |")
        lines.append(f"| Duration | {scan_result.duration_seconds:.1f}s |")
        lines.append(f"| Files Scanned | {scan_result.scanned_files} |")

        lines.append("")

        if diff:
            sections.append(self._generate_diff_section(diff))

        if trend:
            sections.append(self._generate_trend_section(trend))

        # Severity Breakdown
        severity_counts = scan_result.findings_by_severity
        if severity_counts:
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|:---|:---|")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    icon = self.SEVERITY_ICONS.get(sev, "")
                    lines.append(f"| {icon} {sev.upper()} | {count} |")
            lines.append("")

        # Quality Gate Details (if failed)
        if not gate_result.passed and gate_result.reasons:
            lines.append("### Quality Gate Failures")
            lines.append("")
            for reason in gate_result.reasons:
                lines.append(f"- ❌ {reason}")
            lines.append("")

        # Finding Details (collapsible with diffs)
        findings = diff.new_findings if diff else scan_result.findings
        if findings:
            lines.append(f"## Vexa found {len(findings)} new security issue{'s' if len(findings) != 1 else ''} in this pull request. Here are the fixes:")
            lines.append("")
            
            for i, finding in enumerate(findings[:30], 1):  # Cap at 30 to avoid huge PR comments
                icon = self.SEVERITY_ICONS.get(finding.severity, "")
                file_short = self._shorten_path(finding.file_path)
                
                # Use plain English title instead of any technical ID
                title = getattr(finding, "title", "Security Issue")
                
                lines.append(f"<details><summary>{icon} <b>{finding.severity.upper()}</b> | {title} in <code>{file_short}</code></summary>")
                lines.append("")
                
                # Description
                description = getattr(finding, "description", "")
                if description:
                    lines.append(f"> {description}")
                    lines.append("")
                
                # Add AI-suggested fixed code diff if available
                remediation = getattr(finding, "remediation_code", "")
                snippet = getattr(finding, "code_snippet", "")
                
                if remediation and snippet:
                    lines.append("**Suggested Fix:**")
                    lines.append("```diff")
                    lines.append(f"- {snippet.strip()}")
                    lines.append(f"+ {remediation.strip()}")
                    lines.append("```")
                    lines.append("")
                elif remediation:
                    lines.append("**Suggested Fix:**")
                    lines.append("```python")
                    lines.append(f"{remediation.strip()}")
                    lines.append("```")
                    lines.append("")
                
                lines.append("</details>")
                
            if len(findings) > 30:
                lines.append("")
                lines.append(f"*...and {len(findings) - 30} more findings. Check the local CLI scan for the full list.*")
                
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("*Generated by Vexa — Security Autopilot*")

        if trend:
            sections.append(self._generate_trend_section(trend))

        if compliance:
            sections.append(self._generate_compliance_section(compliance))

        return "\n".join(lines + sections)

    def generate_inline_annotations(
        self, findings: List[Finding]
    ) -> List[Dict]:
        """
        Generate inline review annotations for per-line PR comments.

        Args:
            findings: List of findings to annotate

        Returns:
            List of annotation dicts with path, line, body fields
        """
        annotations = []
        for finding in findings:
            icon = self.SEVERITY_ICONS.get(finding.severity, "⚠️")
            body = (
                f"{icon} **Vexa: {finding.severity.upper()}** — "
                f"{finding.title}\n\n"
                f"**Description:** {finding.description}\n"
            )

            annotations.append({
                "path": finding.file_path,
                "line": finding.line_start,
                "body": body,
                "severity": finding.severity,
            })

        return annotations

    def _generate_diff_section(self, diff: BaselineDiff) -> str:
        """Generate baseline diff section."""
        return (
            "### Baseline Changes\n\n"
            "| Metric | Value |\n"
            "|:---|:---|\n"
            f"| New Findings | {diff.new_count} |\n"
            f"| Fixed Findings | {diff.fixed_count} |\n"
        )

    def _generate_trend_section(self, trend: TrendReport) -> str:
        """Generate trend analysis section."""
        icon = "📈" if trend.is_improving else "📉"
        status = "**Improving**" if trend.is_improving else "**Attention Needed**"
        
        delta_text = ""
        if trend.delta_total != 0:
            dir_text = "reduced by" if trend.delta_total < 0 else "increased by"
            delta_text = f" (Findings {dir_text} {abs(trend.delta_total)})"

        return (
            f"### {icon} Security Trend\n"
            f"Overall health is {status}.{delta_text}\n"
        )

    def _generate_compliance_section(self, compliance: ComplianceReport) -> str:
        """Generate compliance reporting section."""
        if compliance.total_non_compliant == 0:
            return "### ✅ Compliance Status\nAudit reveals 100% compliance across tracked frameworks.\n"
        
        lines = ["### 📜 Compliance Mapping", "Non-compliant findings detected in regulatory frameworks.\n"]
        for framework, metrics in compliance.frameworks.items():
            if metrics:
                lines.append(f"#### {framework}")
                lines.append("| Category | Findings | Status |")
                lines.append("|:---|:---|:---|")
                for m in metrics[:5]: # Cap at 5 for PR brevity
                    status = "🔴 Non-compliant" if m.finding_count > 0 else "🟢 Compliant"
                    lines.append(f"| {m.name} | {m.finding_count} | {status} |")
                lines.append("")
        
        return "\n".join(lines)

    def generate_resolved_badge(self) -> str:
        """Generate a resolved/passing badge comment."""
        return (
            "## 🔒 Vexa Security Scan Report\n\n"
            "### ✅ All findings resolved\n\n"
            "No security issues detected. Quality gate passed.\n\n"
            "---\n"
            "*Generated by [Vexa](https://vexasec.io)*"
        )

    @staticmethod
    def _shorten_path(path: str, max_parts: int = 3) -> str:
        """Shorten a file path for display."""
        parts = path.replace("\\", "/").split("/")
        if len(parts) <= max_parts:
            return path
        return ".../" + "/".join(parts[-max_parts:])
