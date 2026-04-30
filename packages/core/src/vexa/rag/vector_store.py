"""
Lightweight local vector store for Vexa RAG.

Uses TF-IDF with cosine similarity for zero-dependency, fully offline
semantic search. No external vector database or cloud API required.

Implements the Zero-Telemetry Local RAG Context strategy.
"""

import math
import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple


class LocalVectorStore:
    """
    A minimal TF-IDF vector store operating entirely in-memory.

    Features:
    - Zero external dependencies (no numpy, no FAISS).
    - Fully offline and privacy-preserving.
    - Suitable for workspace-scale indexing (up to ~50K documents).
    """

    def __init__(self):
        self._documents: List[str] = []
        self._doc_ids: List[str] = []
        self._doc_metadata: List[dict] = []
        self._idf: Dict[str, float] = {}
        self._tfidf_vectors: List[Dict[str, float]] = []
        self._is_built = False

    def add_document(
        self, doc_id: str, text: str, metadata: Optional[dict] = None
    ) -> None:
        """Add a document to the store."""
        self._documents.append(text)
        self._doc_ids.append(doc_id)
        self._doc_metadata.append(metadata or {})
        self._is_built = False

    def build_index(self) -> None:
        """Compute TF-IDF vectors for all documents."""
        if not self._documents:
            return

        # Tokenize all documents
        tokenized = [self._tokenize(doc) for doc in self._documents]

        # Compute IDF
        doc_count = len(tokenized)
        df: Dict[str, int] = defaultdict(int)
        for tokens in tokenized:
            unique_tokens = set(tokens)
            for token in unique_tokens:
                df[token] += 1

        self._idf = {
            token: math.log((doc_count + 1) / (count + 1)) + 1
            for token, count in df.items()
        }

        # Compute TF-IDF vectors
        self._tfidf_vectors = []
        for tokens in tokenized:
            tf = Counter(tokens)
            total = len(tokens) or 1
            vector = {
                token: (count / total) * self._idf.get(token, 1.0)
                for token, count in tf.items()
            }
            self._tfidf_vectors.append(vector)

        self._is_built = True

    def search(self, query: str, top_k: int = 5) -> List[Tuple[str, float, dict]]:
        """
        Search for the most similar documents to the query.

        Returns:
            List of (doc_id, similarity_score, metadata) tuples.
        """
        if not self._is_built or not self._documents:
            return []

        query_tokens = self._tokenize(query)
        query_tf = Counter(query_tokens)
        total = len(query_tokens) or 1
        query_vector = {
            token: (count / total) * self._idf.get(token, 1.0)
            for token, count in query_tf.items()
        }

        # Cosine similarity
        results = []
        for i, doc_vector in enumerate(self._tfidf_vectors):
            sim = self._cosine_similarity(query_vector, doc_vector)
            if sim > 0:
                results.append((self._doc_ids[i], sim, self._doc_metadata[i]))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Simple tokenizer: lowercase, split on non-alphanumeric, filter short tokens."""
        tokens = re.findall(r"[a-z_][a-z0-9_]*", text.lower())
        return [t for t in tokens if len(t) > 1]

    @staticmethod
    def _cosine_similarity(vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
        """Compute cosine similarity between two sparse vectors."""
        common_keys = set(vec_a.keys()) & set(vec_b.keys())
        if not common_keys:
            return 0.0

        dot_product = sum(vec_a[k] * vec_b[k] for k in common_keys)
        mag_a = math.sqrt(sum(v**2 for v in vec_a.values()))
        mag_b = math.sqrt(sum(v**2 for v in vec_b.values()))

        if mag_a == 0 or mag_b == 0:
            return 0.0

        return dot_product / (mag_a * mag_b)

    @property
    def document_count(self) -> int:
        return len(self._documents)
