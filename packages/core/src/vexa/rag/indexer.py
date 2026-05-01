"""
AST-based workspace indexer for Vexa RAG.

Walks the workspace, parses Python files into AST nodes, and extracts
function signatures, class hierarchies, imports, and call-site relationships.
All processing is strictly local — no data leaves the developer's machine.
"""

import ast
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from vexa.common.logging import get_logger

logger = get_logger(__name__)


class ASTNode:
    """Represents an extracted AST element (function, class, import)."""

    def __init__(
        self,
        node_type: str,
        name: str,
        file_path: str,
        line_start: int,
        line_end: int,
        parent: Optional[str] = None,
        signature: str = "",
        docstring: str = "",
        calls: Optional[List[str]] = None,
        decorators: Optional[List[str]] = None,
    ):
        self.node_type = node_type  # "function" | "class" | "import" | "method"
        self.name = name
        self.file_path = file_path
        self.line_start = line_start
        self.line_end = line_end
        self.parent = parent
        self.signature = signature
        self.docstring = docstring
        self.calls = calls or []
        self.decorators = decorators or []

    def to_context_string(self) -> str:
        """Produce a compact, LLM-readable context string."""
        parts = [f"{self.node_type} `{self.name}`"]
        if self.parent:
            parts.append(f"(inside {self.parent})")
        parts.append(f"at {self.file_path}:{self.line_start}")
        if self.signature:
            parts.append(f"sig: {self.signature}")
        if self.decorators:
            parts.append(f"decorators: {', '.join(self.decorators)}")
        if self.calls:
            parts.append(f"calls: {', '.join(self.calls[:10])}")
        return " | ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": self.node_type,
            "name": self.name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "parent": self.parent,
            "signature": self.signature,
            "docstring": self.docstring[:200] if self.docstring else "",
            "calls": self.calls,
            "decorators": self.decorators,
        }


class WorkspaceIndexer:
    """
    Indexes a workspace by walking Python files and extracting AST metadata.

    Features:
    - Extracts functions, methods, classes, and imports.
    - Captures call-site relationships for data-flow context.
    - Fully offline — no network calls.
    """

    # Directories to always skip
    SKIP_DIRS: Set[str] = {
        "__pycache__",
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".eggs",
        "*.egg-info",
        "vexa_scan_reports",
    }

    MAX_FILE_SIZE_BYTES = 512_000  # Skip files larger than 500KB

    def __init__(self, workspace_path: Path):
        self.workspace_path = workspace_path.resolve()
        self.nodes: List[ASTNode] = []
        self._file_count = 0

    def index(self) -> int:
        """Walk the workspace and index all Python files. Returns node count."""
        self.nodes.clear()
        self._file_count = 0

        for root, dirs, files in os.walk(self.workspace_path):
            # Prune skippable directories in-place
            dirs[:] = [
                d
                for d in dirs
                if d not in self.SKIP_DIRS and not d.endswith(".egg-info")
            ]

            for f in files:
                if not f.endswith(".py"):
                    continue
                fpath = Path(root) / f
                if fpath.stat().st_size > self.MAX_FILE_SIZE_BYTES:
                    continue
                self._index_file(fpath)

        logger.info(
            "Workspace indexed: %d files, %d AST nodes extracted.",
            self._file_count,
            len(self.nodes),
        )
        return len(self.nodes)

    def _index_file(self, file_path: Path) -> None:
        """Parse a single Python file and extract AST nodes."""
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, UnicodeDecodeError) as e:
            logger.debug("Skipping %s: %s", file_path, e)
            return

        self._file_count += 1
        rel_path = str(file_path.relative_to(self.workspace_path))

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(
                node, ast.AsyncFunctionDef
            ):
                self._extract_function(node, rel_path)
            elif isinstance(node, ast.ClassDef):
                self._extract_class(node, rel_path)

    def _extract_function(
        self, node: ast.FunctionDef, rel_path: str, parent: Optional[str] = None
    ) -> None:
        """Extract function/method metadata."""
        # Build signature
        args = []
        for arg in node.args.args:
            args.append(arg.arg)
        sig = f"{node.name}({', '.join(args)})"

        # Collect decorators
        decorators = []
        for d in node.decorator_list:
            if isinstance(d, ast.Name):
                decorators.append(d.id)
            elif isinstance(d, ast.Attribute):
                decorators.append(f"{ast.dump(d)[:30]}")

        # Collect function calls within the body
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    calls.append(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    calls.append(child.func.attr)

        docstring = ast.get_docstring(node) or ""

        self.nodes.append(
            ASTNode(
                node_type="method" if parent else "function",
                name=node.name,
                file_path=rel_path,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                parent=parent,
                signature=sig,
                docstring=docstring,
                calls=calls,
                decorators=decorators,
            )
        )

    def _extract_class(self, node: ast.ClassDef, rel_path: str) -> None:
        """Extract class metadata and its methods."""
        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                bases.append(base.attr)

        docstring = ast.get_docstring(node) or ""

        self.nodes.append(
            ASTNode(
                node_type="class",
                name=node.name,
                file_path=rel_path,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                signature=f"class {node.name}({', '.join(bases)})"
                if bases
                else f"class {node.name}",
                docstring=docstring,
            )
        )

        # Extract methods within the class
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._extract_function(item, rel_path, parent=node.name)

    def get_nodes_for_file(self, file_path: str) -> List[ASTNode]:
        """Get all indexed nodes for a specific file."""
        return [n for n in self.nodes if n.file_path == file_path]

    def get_nodes_at_line(self, file_path: str, line: int) -> List[ASTNode]:
        """Get nodes that contain the specified line."""
        return [
            n
            for n in self.nodes
            if n.file_path == file_path and n.line_start <= line <= n.line_end
        ]

    def get_callers_of(self, function_name: str) -> List[ASTNode]:
        """Find all nodes that call the given function."""
        return [n for n in self.nodes if function_name in n.calls]

    def is_test_file(self, file_path: str) -> bool:
        """Check if a file is likely a test file."""
        lower = file_path.lower()
        return (
            "test" in lower
            or lower.startswith("tests/")
            or lower.startswith("test_")
            or "/tests/" in lower
        )
