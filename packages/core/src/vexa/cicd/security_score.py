"""
Security Score Calculator for CI/CD Pipelines.

CI-FR-031: Calculate A–F score based on severity-weighted finding count.
CI-FR-032: Display score in PR comments.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional

from vexa.common.models import ScanResult


# Severity weights — how much each finding type deducts from the perfect score
SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.0,
}

# Grade thresholds — minimum numeric score for each grade
GRADE_THRESHOLDS = [
    (97, "A+"),
    (93, "A"),
    (90, "A-"),
    (87, "B+"),
    (83, "B"),
    (80, "B-"),
    (77, "C+"),
    (73, "C"),
    (70, "C-"),
    (67, "D+"),
    (63, "D"),
    (60, "D-"),
    (0, "F"),
]


@dataclass
class SecurityScore:
    """Security score result."""
    numeric_score: float
    grade: str
    breakdown: Dict[str, int] = field(default_factory=dict)
    total_deductions: float = 0.0
    max_score: float = 100.0
    scanner_coverage: int = 0

    @property
    def color(self) -> str:
        """Return rich text color for the grade."""
        if self.grade.startswith("A"):
            return "spring_green3"
        elif self.grade.startswith("B"):
            return "deep_sky_blue1"
        elif self.grade.startswith("C"):
            return "gold1"
        elif self.grade.startswith("D"):
            return "orange_red1"
        return "red"

    @property
    def grade_emoji(self) -> str:
        """Return emoji indicator for the grade."""
        if self.grade.startswith("A"):
            return "🟢"
        elif self.grade.startswith("B"):
            return "🔵"
        elif self.grade.startswith("C"):
            return "🟡"
        elif self.grade.startswith("D"):
            return "🟠"
        return "🔴"

    @property
    def display(self) -> str:
        """Formatted display string for PR comments."""
        return f"{self.grade_emoji} Security Score: **{self.grade}** ({self.numeric_score:.0f}/100)"


class SecurityScorer:
    """
    Calculates a security score (A+ to F) based on scan results.

    Scoring methodology:
    - Start from 100 points
    - Deduct points per finding based on severity weights
    - Map final score to letter grade
    - Factor in scanner coverage as a bonus/penalty
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        base_score: float = 100.0,
    ):
        """
        Initialize scorer with optional custom weights.

        Args:
            weights: Custom severity weights (default: SEVERITY_WEIGHTS)
            base_score: Starting score (default: 100)
        """
        self.weights = weights or SEVERITY_WEIGHTS
        self.base_score = base_score

    def calculate(self, scan_result: ScanResult) -> SecurityScore:
        """
        Calculate security score from scan results.

        Args:
            scan_result: The completed scan result

        Returns:
            SecurityScore with numeric score and letter grade
        """
        severity_counts = scan_result.findings_by_severity

        # Calculate total deductions
        total_deductions = 0.0
        for severity, count in severity_counts.items():
            weight = self.weights.get(severity.lower(), 0.0)
            total_deductions += weight * count

        # Calculate raw score (floor at 0)
        raw_score = max(0.0, self.base_score - total_deductions)

        # Determine grade
        grade = "F"
        for threshold, letter in GRADE_THRESHOLDS:
            if raw_score >= threshold:
                grade = letter
                break

        return SecurityScore(
            numeric_score=round(raw_score, 1),
            grade=grade,
            breakdown=severity_counts,
            total_deductions=round(total_deductions, 1),
            max_score=self.base_score,
            scanner_coverage=len(scan_result.scanners_run),
        )

    def compare(
        self,
        current: SecurityScore,
        previous_grade: Optional[str] = None,
    ) -> str:
        """
        Generate a comparison string showing score trend.

        Args:
            current: Current security score
            previous_grade: Previous grade for delta display

        Returns:
            Formatted trend string (e.g., "B+ (↑ from C)")
        """
        if not previous_grade:
            return current.display

        grade_values = {g: i for i, (_, g) in enumerate(GRADE_THRESHOLDS)}
        current_val = grade_values.get(current.grade, 12)
        previous_val = grade_values.get(previous_grade, 12)

        if current_val < previous_val:
            arrow = "↑"
        elif current_val > previous_val:
            arrow = "↓"
        else:
            arrow = "→"

        return (
            f"{current.grade_emoji} Security Score: **{current.grade}** "
            f"({arrow} from {previous_grade})"
        )
