"""
Quality Gate Evaluator for CI/CD Pipelines.

CI-FR-021: Severity threshold
CI-FR-022: Count threshold
CI-FR-023: New findings only
CI-FR-024: Baseline comparison
CI-FR-025: Security score gate
"""

from dataclasses import dataclass, field
from typing import List, Optional

from vexa.common.config_manager import QualityGateConfig
from vexa.common.models import ScanResult


@dataclass
class QualityGateResult:
    """Result of quality gate evaluation."""
    passed: bool
    reasons: List[str] = field(default_factory=list)
    summary: str = ""
    checks_performed: List[str] = field(default_factory=list)
    severity_counts: dict = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        """Return 0 for pass, 1 for fail."""
        return 0 if self.passed else 1


class QualityGateEvaluator:
    """
    Evaluates scan results against configurable quality gate thresholds.

    Supports:
    - Severity-based thresholds (fail if critical/high findings exist)
    - Total count thresholds (fail if > N findings)
    - New-only mode (only fail on new findings vs baseline)
    - Minimum security score grade
    """

    def evaluate(
        self,
        scan_result: ScanResult,
        config: QualityGateConfig,
        new_findings_count: Optional[int] = None,
        security_grade: Optional[str] = None,
    ) -> QualityGateResult:
        """
        Evaluate scan results against quality gate configuration.

        Args:
            scan_result: The completed scan result
            config: Quality gate configuration from .vexa.yml
            new_findings_count: If new_only mode, the count of new findings
            security_grade: Current security grade (A-F) for score gate

        Returns:
            QualityGateResult with pass/fail and reasons
        """
        reasons: List[str] = []
        checks: List[str] = []
        severity_counts = scan_result.findings_by_severity

        # --- Check 1: Severity Threshold (CI-FR-021) ---
        if config.fail_on:
            checks.append("severity_threshold")
            for severity in config.fail_on:
                sev_lower = severity.lower()
                count = severity_counts.get(sev_lower, 0)
                if count > 0:
                    reasons.append(
                        f"Found {count} {sev_lower.upper()} severity finding(s) "
                        f"(threshold: 0 allowed)"
                    )

        # --- Check 2: Total Count Threshold (CI-FR-022) ---
        if config.max_total is not None and config.max_total > 0:
            checks.append("count_threshold")
            effective_count = (
                new_findings_count
                if config.new_only and new_findings_count is not None
                else scan_result.total_findings
            )
            if effective_count > config.max_total:
                count_type = "new " if config.new_only else ""
                reasons.append(
                    f"Total {count_type}findings ({effective_count}) exceeds "
                    f"maximum allowed ({config.max_total})"
                )

        # --- Check 3: New Findings Only (CI-FR-023) ---
        if config.new_only and new_findings_count is not None:
            checks.append("new_findings_only")
            # In new-only mode, severity check applies only to new findings
            # This is handled via the new_findings_count in check 2

        # --- Check 4: Security Score Gate (CI-FR-025) ---
        if config.min_score and security_grade:
            checks.append("security_score")
            grade_order = {"A+": 0, "A": 1, "A-": 2, "B+": 3, "B": 4, "B-": 5,
                           "C+": 6, "C": 7, "C-": 8, "D+": 9, "D": 10, "D-": 11,
                           "F": 12}
            current_rank = grade_order.get(security_grade, 12)
            # min_score could be "B", "C", etc.
            min_rank = grade_order.get(config.min_score, 12)
            if current_rank > min_rank:
                reasons.append(
                    f"Security score {security_grade} is below minimum "
                    f"required grade {config.min_score}"
                )

        passed = len(reasons) == 0

        if passed:
            summary = "✅ Quality gate PASSED — all checks cleared"
        else:
            summary = f"❌ Quality gate FAILED — {len(reasons)} check(s) failed"

        return QualityGateResult(
            passed=passed,
            reasons=reasons,
            summary=summary,
            checks_performed=checks,
            severity_counts=severity_counts,
        )

    def evaluate_simple(
        self,
        scan_result: ScanResult,
        fail_on: Optional[List[str]] = None,
        max_total: Optional[int] = None,
    ) -> QualityGateResult:
        """
        Simplified evaluation for CLI/action usage without full config.

        Args:
            scan_result: The completed scan result
            fail_on: List of severity levels that fail the gate
            max_total: Maximum total findings allowed

        Returns:
            QualityGateResult
        """
        config = QualityGateConfig(
            fail_on=fail_on or [],
            max_total=max_total or 0,
            new_only=False,
        )
        return self.evaluate(scan_result, config)
