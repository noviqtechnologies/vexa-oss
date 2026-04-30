import fnmatch
from pathlib import Path
from typing import List, Optional


class PathFilter:
    """Centralized Exclusion Engine for Vexa."""

    DEFAULT_EXCLUSIONS = {
        ".git",
        "node_modules",
        "test",
        "tests",
        "unit_test",
        "vexa_scan_reports",
        ".vexa",
        ".vexa-baseline.json",
        "vexa-baseline.json",
        "venv",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        ".pytest_cache",
        ".tox",
    }

    def __init__(
        self,
        workspace_root: Path,
        user_config_ignores: Optional[List[str]] = None,
        cli_excludes: Optional[List[str]] = None,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.user_config_ignores = set(user_config_ignores or [])
        self.cli_excludes = set(cli_excludes or [])
        self.gitignore_patterns = self._load_gitignore()

        # Combine all exclusions for easy access
        self.all_ignores = self.DEFAULT_EXCLUSIONS.union(
            self.user_config_ignores
        ).union(self.cli_excludes)

    def _load_gitignore(self) -> List[str]:
        gitignore_path = self.workspace_root / ".gitignore"
        patterns = []
        if gitignore_path.exists():
            with open(gitignore_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
        return patterns

    def is_excluded(self, path: Path) -> bool:
        """Check if a path should be excluded based on the priority logic."""
        try:
            rel_path = path.resolve().relative_to(self.workspace_root)
        except ValueError:
            # If path is outside workspace, we just check its parts
            rel_path = path

        path_str = str(rel_path).replace("\\", "/")
        parts = path.parts

        # 1. Check CLI Excludes & Default Exclusions & User Config (Exact directory/file match)
        for ignore_item in self.all_ignores:
            if ignore_item in parts:
                return True
            if fnmatch.fnmatch(path_str, ignore_item) or fnmatch.fnmatch(
                path.name, ignore_item
            ):
                return True

        # 2. Check .gitignore patterns
        for pattern in self.gitignore_patterns:
            if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(
                path.name, pattern
            ):
                return True
            # naive directory glob fallback
            if pattern.endswith("/") and pattern[:-1] in parts:
                return True

        return False

    def get_scanner_exclusion_list(self) -> List[str]:
        """Returns a flat list of items to pass to CLI scanners (like bandit/checkov)."""
        return list(self.all_ignores)
