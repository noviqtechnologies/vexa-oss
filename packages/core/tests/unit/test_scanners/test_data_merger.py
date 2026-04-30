"""
Tests for DataMerger.
"""
import pytest
from vexa.scanners.data_merger import DataMerger
from vexa.common.models import Finding

class TestDataMerger:
    
    def test_deduplicate_findings(self):
        """Should merge duplicate findings and keep highest severity."""
        merger = DataMerger()
        
        f1 = Finding(
            id="1", scanner="bandit", title="Weak Hash", description="MD5", 
            severity="medium", file_path="app.py", line_start=10, line_end=15
        )
        # Duplicate but higher severity (simulated scenario)
        f2 = Finding(
            id="2", scanner="semgrep", title="Weak Hash", description="MD5 used", 
            severity="high", file_path="app.py", line_start=10, line_end=15
        )
        
        merged = merger.deduplicate([f1, f2])
        
        assert len(merged) == 1
        assert merged[0].severity == "high"
        # Check if scanner info is merged if implemented
        
    def test_merge_findings(self):
        """Should merge findings from dict."""
        merger = DataMerger()
        
        input_map = {
            "bandit": [
                Finding(id="1", scanner="bandit", title="A", description="A", severity="low", file_path="a.py", line_start=1, line_end=2)
            ],
            "semgrep": [
                Finding(id="2", scanner="semgrep", title="B", description="B", severity="low", file_path="b.py", line_start=1, line_end=2)
            ]
        }
        
        result = merger.merge_findings(input_map)
        assert len(result) == 2
