"""
RAG Context Builder for Vexa.

Given a security finding, queries the local AST index and vector store
to build rich semantic context that reduces false positives in AI enrichment.

Example context: "This eval() call is inside test_helpers.py which is a test
file, and the input comes from a hardcoded fixture — likely a false positive."
"""

from pathlib import Path
from typing import Any, Dict

from vexa.common.logging import get_logger
from vexa.rag.indexer import WorkspaceIndexer
from vexa.rag.vector_store import LocalVectorStore

logger = get_logger(__name__)


class RAGContextBuilder:
    """
    Builds semantic context for security findings using local workspace data.

    Flow:
    1. Index the workspace AST (once per scan).
    2. For each finding, retrieve relevant AST nodes and similar code patterns.
    3. Produce a compact context string for the AI enrichment prompt.
    """

    # Maximum context tokens to inject into the AI prompt
    MAX_CONTEXT_CHARS = 2000

    def __init__(self, workspace_path: Path):
        self.workspace_path = workspace_path.resolve()
        self.indexer = WorkspaceIndexer(self.workspace_path)
        self.vector_store = LocalVectorStore()
        self._indexed = False

    def build_index(self) -> int:
        """Index the workspace. Returns the number of AST nodes extracted."""
        node_count = self.indexer.index()

        # Populate vector store with node context strings
        for i, node in enumerate(self.indexer.nodes):
            doc_text = (
                f"{node.name} {node.signature} {node.docstring} {' '.join(node.calls)}"
            )
            self.vector_store.add_document(
                doc_id=f"node_{i}",
                text=doc_text,
                metadata=node.to_dict(),
            )

        self.vector_store.build_index()
        self._indexed = True
        logger.info(
            "RAG index built: %d nodes, %d vector documents.",
            node_count,
            self.vector_store.document_count,
        )
        return node_count

    def get_context(self, finding: Any) -> str:
        """
        Build a context string for a single finding.

        Args:
            finding: A Finding object with file_path, line_start, code_snippet, title.

        Returns:
            A compact, LLM-readable context string.
        """
        if not self._indexed:
            self.build_index()

        file_path = str(getattr(finding, "file_path", ""))
        line_start = int(getattr(finding, "line_start", 0))
        code_snippet = str(getattr(finding, "code_snippet", ""))
        title = str(getattr(finding, "title", ""))

        context_parts = []

        # 1. File-level context
        try:
            rel_path = str(Path(file_path).relative_to(self.workspace_path))
        except (ValueError, TypeError):
            rel_path = file_path

        if self.indexer.is_test_file(rel_path):
            context_parts.append(
                f"[TEST FILE] {rel_path} is a test file. Findings in test code are more likely false positives."
            )

        # 2. Enclosing scope context (which function/class contains this line?)
        enclosing = self.indexer.get_nodes_at_line(rel_path, line_start)
        for node in enclosing:
            context_parts.append(f"[SCOPE] {node.to_context_string()}")

        # 3. Caller/callee relationships
        # If the finding is about a function, find who calls it
        for node in enclosing:
            if node.node_type in ("function", "method"):
                callers = self.indexer.get_callers_of(node.name)
                if callers:
                    caller_names = [f"{c.name} ({c.file_path})" for c in callers[:5]]
                    context_parts.append(
                        f"[CALLERS] {node.name} is called by: {', '.join(caller_names)}"
                    )

        # 4. Semantic similarity search
        query = f"{title} {code_snippet}"
        similar = self.vector_store.search(query, top_k=3)
        for doc_id, score, meta in similar:
            if score > 0.15:  # Only include reasonably similar results
                context_parts.append(
                    f"[SIMILAR] {meta.get('node_type', '')} `{meta.get('name', '')}` "
                    f"in {meta.get('file_path', '')}:{meta.get('line_start', '')} (relevance: {score:.2f})"
                )

        # 5. Truncate to budget
        context = "\n".join(context_parts)
        if len(context) > self.MAX_CONTEXT_CHARS:
            context = context[: self.MAX_CONTEXT_CHARS] + "\n[... context truncated]"

        return context

    def get_batch_contexts(self, findings: list) -> Dict[str, str]:
        """
        Build context for a batch of findings.

        Returns:
            Dict mapping finding_id -> context_string.
        """
        if not self._indexed:
            self.build_index()

        contexts = {}
        for finding in findings:
            finding_id = str(getattr(finding, "id", ""))
            if finding_id:
                contexts[finding_id] = self.get_context(finding)
        return contexts
