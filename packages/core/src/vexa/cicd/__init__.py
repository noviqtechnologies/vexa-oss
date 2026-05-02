"""
Vexa CI/CD Integration Module.

Provides quality gate evaluation, baseline comparison, security scoring,
PR decoration, and headless CI runner for pipeline integration.
"""

from .quality_gate import QualityGateEvaluator, QualityGateResult
from .baseline import BaselineManager, BaselineDiff
from .security_score import SecurityScorer, SecurityScore
from .pr_decorator import PRDecorator
from .runner import CICDRunner, CICDResult

__all__ = [
    "QualityGateEvaluator",
    "QualityGateResult",
    "BaselineManager",
    "BaselineDiff",
    "SecurityScorer",
    "SecurityScore",
    "PRDecorator",
    "CICDRunner",
    "CICDResult",
]
