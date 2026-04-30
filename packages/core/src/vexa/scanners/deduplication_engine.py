"""
Advanced Deduplication Engine for Vexa.

Implements a 3-stage deduplication pipeline:
1. Exact Match: Hash-based identification.
2. Fuzzy Match: Token similarity and line tolerance.
3. Semantic Match: Heuristic-based grouping by category, severity, and proximity.
"""

import hashlib
import difflib
from typing import Any, Dict, List, Set, Tuple, Optional
from pathlib import Path

from vexa.common.logging import get_logger
from vexa.common.models import Finding

logger = get_logger(__name__)


class DeduplicationEngine:
    """
    Orchestrates advanced deduplication of security findings.
    """

    def __init__(
        self,
        fuzzy_threshold: float = 0.85,
        semantic_title_threshold: float = 0.75,
        semantic_line_tolerance: int = 15,
        line_tolerance_fuzzy: int = 2,
    ):
        self.fuzzy_threshold = fuzzy_threshold
        self.semantic_title_threshold = semantic_title_threshold
        self.semantic_line_tolerance = semantic_line_tolerance
        self.line_tolerance_fuzzy = line_tolerance_fuzzy

        # Severity priority (same as DataMerger)
        self.SEVERITY_PRIORITY = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Run the 3-stage deduplication pipeline.
        
        Args:
            findings: List of findings to deduplicate.
            
        Returns:
            Deduplicated list of findings.
        """
        if not findings:
            return []

        logger.debug("Starting deduplication on %d findings", len(findings))

        # Stage 1: Exact Match (Hash-based)
        exact_groups = self._stage1_exact_match(findings)
        
        # Select best from exact groups to feed into stage 2
        stage2_input = [self._select_best(group) for group in exact_groups]
        
        # Stage 2: Fuzzy Match
        fuzzy_groups = self._stage2_fuzzy_match(stage2_input)
        
        # Select best from fuzzy groups to feed into stage 3
        stage3_input = [self._select_best(group) for group in fuzzy_groups]
        
        # Stage 3: Semantic Match
        semantic_groups = self._stage3_semantic_match(stage3_input)
        
        # Final selection
        results = [self._select_best(group) for group in semantic_groups]

        logger.info(
            "Advanced Deduplication completed: %d -> %d findings",
            len(findings), len(results)
        )
        return results

    def _stage1_exact_match(self, findings: List[Finding]) -> List[List[Finding]]:
        """Stage 1: Strict equality check."""
        groups: Dict[str, List[Finding]] = {}
        
        for f in findings:
            # Key: normalized file, start line, end line, scanner, rule id (if any), title hash
            file_norm = f.file_path.replace("\\", "/").lower()
            key = f"{file_norm}:{f.line_start}:{f.line_end}:{f.title.lower()}"
            
            if key not in groups:
                groups[key] = []
            groups[key].append(f)
            
        return list(groups.values())

    def _group_by_predicate(self, findings: List[Finding], predicate) -> List[List[Finding]]:
        """Group findings using a pairwise predicate function."""
        processed_indices: Set[int] = set()
        groups: List[List[Finding]] = []

        for i in range(len(findings)):
            if i in processed_indices:
                continue

            current_group = [findings[i]]
            processed_indices.add(i)

            for j in range(i + 1, len(findings)):
                if j in processed_indices:
                    continue

                if predicate(findings[i], findings[j]):
                    current_group.append(findings[j])
                    processed_indices.add(j)

            groups.append(current_group)

        return groups

    def _stage2_fuzzy_match(self, findings: List[Finding]) -> List[List[Finding]]:
        """Stage 2: Code similarity and slight line drift."""
        return self._group_by_predicate(findings, self._is_fuzzy_match)

    def _is_fuzzy_match(self, f1: Finding, f2: Finding) -> bool:
        """Check if two findings are fuzzy matches."""
        # Must have same severity
        if f1.severity != f2.severity:
            return False
            
        # Must be in same file
        if f1.file_path.replace("\\", "/").lower() != f2.file_path.replace("\\", "/").lower():
            return False
        
        # Line tolerance
        if abs(f1.line_start - f2.line_start) > self.line_tolerance_fuzzy:
            return False
            
        # Code similarity
        if f1.code_snippet and f2.code_snippet:
            similarity = difflib.SequenceMatcher(None, f1.code_snippet, f2.code_snippet).ratio()
            if similarity >= self.fuzzy_threshold:
                return True
        elif f1.title.lower() == f2.title.lower():
            # If no code snippets, fallback to exact title match at this stage
            return True
            
        return False

    def _stage3_semantic_match(self, findings: List[Finding]) -> List[List[Finding]]:
        """Stage 3: Heuristic-based semantic grouping."""
        return self._group_by_predicate(findings, self._is_semantic_match)

    def _is_semantic_match(self, f1: Finding, f2: Finding) -> bool:
        """Check if two findings are semantic matches based on user criteria."""
        # 1. Severity must match
        if f1.severity != f2.severity:
            return False
            
        # 2. Category must match (OWASP or CWE)
        cat_match = False
        if f1.owasp_category and f2.owasp_category and f1.owasp_category == f2.owasp_category:
            cat_match = True
        elif f1.cwe_ids and f2.cwe_ids:
            if set(f1.cwe_ids).intersection(set(f2.cwe_ids)):
                cat_match = True
        
        if not cat_match:
            return False
            
        # 3. Scope: Same File OR Same Parent Directory
        p1 = Path(f1.file_path.replace("\\", "/").lower())
        p2 = Path(f2.file_path.replace("\\", "/").lower())
        
        if p1 == p2:
            scope_match = True
        elif p1.parent == p2.parent and p1.parent != Path("."):
            scope_match = True
        else:
            scope_match = False
            
        if not scope_match:
            return False
            
        # 4. Location: Line difference <= 15
        if abs(f1.line_start - f2.line_start) > self.semantic_line_tolerance:
            return False
            
        # 5. Title Similarity >= 75%
        title_sim = difflib.SequenceMatcher(None, f1.title.lower(), f2.title.lower()).ratio()
        if title_sim < self.semantic_title_threshold:
            return False
            
        return True

    def _select_best(self, group: List[Finding]) -> Finding:
        """Select the best finding from a group and merge metadata."""
        if len(group) == 1:
            return group[0]
            
        # Sort by severity priority (descending)
        sorted_group = sorted(
            group,
            key=lambda f: self.SEVERITY_PRIORITY.get(f.severity, 0),
            reverse=True
        )
        
        primary = sorted_group[0]
        duplicates = sorted_group[1:]
        
        return self.merge_duplicate_info(primary, duplicates)

    def merge_duplicate_info(
        self,
        primary: Finding,
        duplicates: List[Finding],
    ) -> Finding:
        """
        Merge additional information from duplicate findings into primary.
        """
        # Create a copy to avoid modifying the original
        merged = primary.model_copy()
        
        # Collect all CWE IDs
        all_cwes: Set[str] = set(merged.cwe_ids)
        for dup in duplicates:
            all_cwes.update(dup.cwe_ids)
        merged.cwe_ids = sorted(list(all_cwes))
        
        # Collect all NIST controls
        all_nist: Set[str] = set(merged.nist_controls)
        for dup in duplicates:
            all_nist.update(dup.nist_controls)
        merged.nist_controls = sorted(list(all_nist))
        
        # Use best OWASP category (prefer non-None)
        if not merged.owasp_category:
            for dup in duplicates:
                if dup.owasp_category:
                    merged.owasp_category = dup.owasp_category
                    break
        
        # Use best MITRE ID (prefer non-None)
        if not merged.mitre_attack_id:
            for dup in duplicates:
                if dup.mitre_attack_id:
                    merged.mitre_attack_id = dup.mitre_attack_id
                    break
        
        # Note which scanners found this issue
        scanners = {merged.scanner}
        for dup in duplicates:
            scanners.add(dup.scanner)
        
        if len(scanners) > 1:
            if "\n\n[Also detected by:" not in merged.description:
                merged.description += f"\n\n[Also detected by: {', '.join(sorted(scanners))}]"
            else:
                # Avoid redundant appending if already merged in a previous stage
                pass
        
        return merged
