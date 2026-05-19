# retriever.py — Query and retrieve chunks from Pinecone hybrid document index.
#
# Uses Pinecone SDK 8+ document API (pc.preview) for hybrid search.
# Two scoring strategies available per query:
#   dense_vector  — semantic embedding similarity (cosine)
#   text (BM25)   — lexical token matching for exact identifiers (function names, struct names)
#
# Hybrid pattern: run dense_vector search with $match_phrase filter for BM25 pre-filter,
# or run BM25-primary search for exact-identifier lookups.
#
# Query text is NEVER flattened — raw LLM queries may contain code-like patterns
# (e.g. "void *memcpy(void *dst, ...)") where stripping * or ( would degrade precision.
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from typing import Any, Dict, List, Optional

from config import (
    EMBEDDING_MODEL,
    PINECONE_API_KEY,
    PINECONE_INDEX_NAME,
    PINECONE_NAMESPACE,
    apply_embeddings_env,
)
from ingestion.embedder import Embedder

os.environ.setdefault("PINECONE_API_KEY", PINECONE_API_KEY)
apply_embeddings_env()

# Fields to return in every documents.search() response.
_INCLUDE_FIELDS = [
    "chunk_text", "parent_id", "sibling_index", "n_siblings",
    "type", "source", "file_name",
    "function_name", "section", "doc_id", "page", "origin",
    "doc_title", "toc_section", "entry_id",
]

# Fields fetched when reconstructing sibling chunks.
_SIBLING_FIELDS = ["chunk_text", "sibling_index"]

# Only these doc types reconstruct the full parent section at retrieval time.
# Code chunks need complete function bodies for accurate vulnerability reasoning.
# Documentation chunks (reference_document) return only the matched child — the
# section heading path already provides navigation context, and full reconstruction
# would inflate token consumption significantly for large documentation sections.
_RECONSTRUCT_TYPES = frozenset({"decompiled", "c_function"})


class DocumentRetriever:
    """Hybrid search interface over the Pinecone document-schema index."""

    def __init__(self, index_name: str = PINECONE_INDEX_NAME):
        if not PINECONE_API_KEY:
            raise ValueError("PINECONE_API_KEY not set. Check your .env file.")
        self._index_name = index_name
        self._namespace = PINECONE_NAMESPACE
        self._embedder = Embedder()

    def _preview_index(self):
        from pinecone import Pinecone
        return Pinecone(api_key=PINECONE_API_KEY).preview.index(name=self._index_name)

    def _dense_query(
        self,
        query: str,
        k: int,
        filter: Optional[Dict] = None,
    ) -> List[Any]:
        """Dense semantic search. Used for concept/vulnerability lookups."""
        dense_vec = self._embedder.embed_query(query)
        score_by = [{"type": "dense_vector", "field": "embedding", "values": dense_vec}]
        resp = self._preview_index().documents.search(
            namespace=self._namespace,
            top_k=k,
            score_by=score_by,
            filter=filter,
            include_fields=_INCLUDE_FIELDS,
        )
        return resp.matches

    def _bm25_query(
        self,
        query: str,
        k: int,
        filter: Optional[Dict] = None,
    ) -> List[Any]:
        """BM25 lexical search. Used for exact identifier lookups (function/struct names)."""
        score_by = [{"type": "text", "field": "text", "query": query}]
        resp = self._preview_index().documents.search(
            namespace=self._namespace,
            top_k=k,
            score_by=score_by,
            filter=filter,
            include_fields=_INCLUDE_FIELDS,
        )
        return resp.matches

    def _hybrid_query(
        self,
        query: str,
        k: int,
        filter: Optional[Dict] = None,
    ) -> List[Any]:
        """
        True hybrid via Reciprocal Rank Fusion (RRF).

        Both dense and BM25 fetch 2k candidates independently; results are merged
        by RRF score (1 / (60 + rank)) so each leg contributes to the final ranking.
        Documents appearing in both legs get a score boost automatically.
        """
        dense_matches = self._dense_query(query, k=k * 2, filter=filter)
        bm25_matches = self._bm25_query(query, k=k * 2, filter=filter)

        K_RRF = 60
        rrf: Dict[str, float] = {}
        id_to_match: Dict[str, Any] = {}

        for rank, match in enumerate(dense_matches, 1):
            mid = match._id
            rrf[mid] = rrf.get(mid, 0.0) + 1.0 / (K_RRF + rank)
            id_to_match[mid] = match

        for rank, match in enumerate(bm25_matches, 1):
            mid = match._id
            rrf[mid] = rrf.get(mid, 0.0) + 1.0 / (K_RRF + rank)
            id_to_match.setdefault(mid, match)

        sorted_ids = sorted(rrf, key=rrf.__getitem__, reverse=True)
        return [id_to_match[mid] for mid in sorted_ids[:k]]

    @staticmethod
    def _match_to_dict(match: Any, rank: int, score: Optional[float] = None) -> Dict[str, str]:
        """
        Serialize a retrieved document match to a flat dict for MCP JSON transport.

        Fields:
            content     — the matched chunk text (precise search target).
            context     — full reconstructed parent section (set by _format_results).
            section     — Markdown heading path e.g. "IVC Architecture > Configuration".
            source      — canonical source path.
            source_file — file basename for readability.
            page        — page number (PDF) or pattern index (JSON).
            type        — doc type (c_function, vulnerability_pattern, reference_document, ...).
            doc_id      — pattern card ID when type=vulnerability_pattern, else "".
            function_name — decompiled function name, populated for c_function chunks.
        """
        def _field(name: str) -> str:
            return str(getattr(match, name, "") or "")

        source_path = _field("source") or "unknown"
        source_file = _field("file_name") or os.path.basename(source_path) or "unknown"
        result: Dict[str, str] = {
            "rank": str(rank),
            "content": _field("chunk_text"),
            "context": "",  # filled in by _format_results after sibling reconstruction
            "section": _field("section"),
            "source": source_path,
            "source_file": source_file,
            "page": _field("page"),
            "type": _field("type"),
            "doc_id": _field("doc_id"),
            "origin": _field("origin"),
            "function_name": _field("function_name"),
            "doc_title": _field("doc_title"),
            "toc_section": _field("toc_section"),
        }
        effective_score = score if score is not None else getattr(match, "_score", None)
        if effective_score is not None:
            result["score"] = f"{float(effective_score):.4f}"
        return result

    def _fetch_siblings(self, parent_id: str) -> List[Any]:
        """
        Fetch all chunks belonging to parent_id from Pinecone using a metadata filter.
        Uses wildcard text search (same pattern as _delete_by_source) — not vector search.
        Returns raw match objects sorted by sibling_index.
        """
        try:
            resp = self._preview_index().documents.search(
                namespace=self._namespace,
                top_k=200,
                score_by=[{"type": "query_string", "query": "*"}],
                filter={"parent_id": {"$eq": parent_id}},
                include_fields=_SIBLING_FIELDS,
            )
            return resp.matches
        except Exception as e:
            _log(f"[WARN] _fetch_siblings failed for parent_id={parent_id!r}: {e}")
            return []

    def _reconstruct_context(self, parent_id: str, already_retrieved: List[Any]) -> str:
        """
        Reconstruct the full parent section from sibling chunks.

        Uses already-retrieved matches first (no extra Pinecone call if we have all
        siblings). Fetches missing siblings only when needed.
        Joins chunks in sibling_index order with blank-line separators.
        """
        n_siblings = int(getattr(already_retrieved[0], "n_siblings", 0) or 0)
        known: Dict[int, str] = {
            int(getattr(m, "sibling_index", 0) or 0): str(getattr(m, "chunk_text", "") or "")
            for m in already_retrieved
        }

        if len(known) < n_siblings:
            for m in self._fetch_siblings(parent_id):
                idx = int(getattr(m, "sibling_index", 0) or 0)
                if idx not in known:
                    known[idx] = str(getattr(m, "chunk_text", "") or "")

        if not known:
            return ""
        return "\n\n".join(known[i] for i in sorted(known))

    def _format_results(
        self,
        matches: List[Any],
        scores: Optional[List[float]] = None,
    ) -> List[Dict[str, str]]:
        """
        Convert raw Pinecone matches to result dicts with type-aware context.

        Standalone chunks (no parent_id): context = content.
        Child chunks sharing a parent_id: merged into one result (best rank wins).
          - type in _RECONSTRUCT_TYPES (decompiled, c_function): context = full
            reconstructed parent section (all siblings joined in order). Necessary
            because a partial function body cannot be reasoned about for security analysis.
          - all other types: context = content (matched chunk only). The section
            heading path provides navigation context without inflating token cost.
        """
        parent_groups: Dict[str, List[tuple]] = {}  # parent_id -> [(rank, match, score)]
        standalone: List[tuple] = []

        for i, match in enumerate(matches):
            rank = i + 1
            score = scores[i] if scores is not None else None
            pid = str(getattr(match, "parent_id", "") or "")
            if pid:
                parent_groups.setdefault(pid, []).append((rank, match, score))
            else:
                standalone.append((rank, match, score))

        output: List[tuple] = []  # (rank, result_dict)

        for rank, match, score in standalone:
            r = self._match_to_dict(match, rank, score)
            r["context"] = r["content"]
            output.append((rank, r))

        for pid, group in parent_groups.items():
            best_rank, best_match, best_score = min(group, key=lambda t: t[0])
            r = self._match_to_dict(best_match, best_rank, best_score)
            doc_type = str(getattr(best_match, "type", "") or "")
            if doc_type in _RECONSTRUCT_TYPES:
                r["context"] = self._reconstruct_context(pid, [m for _, m, _ in group])
            else:
                r["context"] = r["content"]
            output.append((best_rank, r))

        output.sort(key=lambda t: t[0])
        return [r for _, r in output]

    def query(
        self,
        query: str,
        k: int = 5,
        filter: Optional[Dict] = None,
        min_score: Optional[float] = None,
    ) -> List[Dict[str, str]]:
        """Return the k most relevant chunks for query (no scores)."""
        matches = self._hybrid_query(query, k=k, filter=filter)
        if min_score is not None and min_score > 0:
            matches = [m for m in matches if float(getattr(m, "_score", 0.0) or 0.0) >= min_score]
        return self._format_results(matches)

    def query_with_scores(
        self,
        query: str,
        k: int = 5,
        filter: Optional[Dict] = None,
        min_score: Optional[float] = None,
    ) -> List[Dict[str, str]]:
        """Same as query() but includes similarity scores."""
        matches = self._hybrid_query(query, k=k, filter=filter)
        scores = [float(getattr(m, "_score", 0.0) or 0.0) for m in matches]
        if min_score is not None and min_score > 0:
            matches, scores = zip(
                *[(m, s) for m, s in zip(matches, scores) if s >= min_score]
            ) if matches else ([], [])
            matches, scores = list(matches), list(scores)
        return self._format_results(matches, scores=scores)

    def query_by_function_name(
        self,
        function_name: str,
        binary_name: str = "",
        k: int = 10,
    ) -> List[Dict[str, str]]:
        """Metadata-filtered lookup for all chunks from a named decompiled function."""
        f: Dict = {"function_name": {"$eq": function_name}}
        query_str = f"{function_name} {binary_name}".strip()
        matches = self._bm25_query(query_str, k=k, filter=f)
        if not matches:
            matches = self._dense_query(function_name, k=k, filter=f)
        scores = [float(getattr(m, "_score", 0.0) or 0.0) for m in matches]
        return self._format_results(matches, scores=scores)

    def get_db_info(self) -> Dict[str, str]:
        """Return connection status and index metadata."""
        try:
            from pinecone import Pinecone
            pc = Pinecone(api_key=PINECONE_API_KEY)
            desc = pc.preview.indexes.describe(name=self._index_name)
            return {
                "status": "connected",
                "index_name": self._index_name,
                "namespace": self._namespace,
                "embedding_model": EMBEDDING_MODEL,
                "index_status": str(getattr(getattr(desc, "status", {}), "state", "unknown")),
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}


# Module-level singleton — shared across all MCP tool calls
_retriever: Optional[DocumentRetriever] = None


def get_retriever() -> DocumentRetriever:
    """Return the module-level DocumentRetriever singleton."""
    global _retriever
    if _retriever is None:
        _retriever = DocumentRetriever()
    return _retriever


if __name__ == "__main__":
    retriever = DocumentRetriever()
    query = "buffer overflow memcpy guest-controlled length"
    print(f"Query: {query}\n")
    for result in retriever.query_with_scores(query, k=3):
        print(f"\n--- Rank {result['rank']} | Score {result.get('score', '?')} | {result['source']} ---")
        print(result["content"][:300] + "...")
