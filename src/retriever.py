# retriever.py - Query and retrieve chunks from Pinecone vector database
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from typing import Any, Dict, List, Optional

from langchain_openai import OpenAIEmbeddings
from langchain_pinecone import PineconeVectorStore

from config import (
    EMBEDDING_MODEL,
    OPENAI_API_KEY,
    PINECONE_API_KEY,
    PINECONE_INDEX_NAME,
)

# Ensure LangChain picks up the keys
os.environ.setdefault("PINECONE_API_KEY", PINECONE_API_KEY)
os.environ.setdefault("OPENAI_API_KEY", OPENAI_API_KEY)


class DocumentRetriever:
    """Similarity-search interface over the Pinecone vector store."""

    def __init__(self, index_name: str = PINECONE_INDEX_NAME):
        if not PINECONE_API_KEY:
            raise ValueError("PINECONE_API_KEY not set. Check your .env file.")
        if not OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY not set. Check your .env file.")

        self.index_name = index_name
        self.embeddings = OpenAIEmbeddings(
            model=EMBEDDING_MODEL,
            openai_api_key=OPENAI_API_KEY,
        )
        self._vectorstore: Optional[PineconeVectorStore] = None

    @property
    def vectorstore(self) -> PineconeVectorStore:
        """Lazy-initialize Pinecone connection on first access."""
        if self._vectorstore is None:
            self._vectorstore = PineconeVectorStore(
                index_name=self.index_name,
                embedding=self.embeddings,
            )
        return self._vectorstore

    @staticmethod
    def _format(doc: Any, rank: int, score: Optional[float] = None) -> Dict[str, str]:
        """
        Serialize a retrieved Document to a flat dict for MCP JSON transport.

                Fields:
                    content     — the matched child chunk (precise search target).
                    context     — full parent section containing this chunk.
                                                Equals content when the chunk was not child-split
                                                (small sections and pattern cards).
                    section     — Markdown heading path e.g. "IVC Architecture > Configuration".
                    source      — canonical source path (unique; can disambiguate same filenames).
                    source_file — file basename for readability (may be duplicated).
                    page        — page number (PDF) or pattern index (JSON).
                    type        — "vulnerability_pattern" | "reference_document" | "analysis_result".
                    doc_id      — pattern card ID when type=vulnerability_pattern, else "".
        """
        meta = doc.metadata
        source_path = str(meta.get("source", "unknown"))
        source_file = str(meta.get("file_name", os.path.basename(source_path) or "unknown"))
        result: Dict[str, str] = {
            "rank": str(rank),
            "content": doc.page_content,
            "context": meta.get("parent_content", doc.page_content),
            "section": meta.get("section", ""),
                        "source": source_path,
                        "source_file": source_file,
            "page": str(meta.get("page", "?")),
            "type": str(meta.get("type", "")),
            "doc_id": str(meta.get("doc_id", "")),
        }
        if score is not None:
            result["score"] = f"{score:.4f}"
        return result

    @staticmethod
    def _dedup_contexts(results: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Suppress duplicate parent_content across results from the same section.

        Multiple child chunks from the same parent section all carry identical
        `context` (up to 2000 chars). Keeping them wastes context window and
        triggers lost-in-the-middle degradation. For each duplicate, we blank
        `context` and note which rank already contains the full section so the
        LLM still knows it is available.
        """
        seen: dict = {}  # context_text -> first rank that showed it
        for r in results:
            ctx = r.get("context", "")
            content = r.get("content", "")
            # Only deduplicate when context != content (i.e., it IS a parent section)
            if ctx and ctx != content:
                rank = r["rank"]
                if ctx in seen:
                    r["context"] = f"[same section as rank {seen[ctx]} — omitted to save context]"
                else:
                    seen[ctx] = rank
        return results

    def query(
        self,
        query: str,
        k: int = 5,
        filter: Optional[Dict] = None,
        min_score: Optional[float] = None,
    ) -> List[Dict[str, str]]:
        """
        Return the k most relevant chunks for query.
        Optionally filter by metadata fields (e.g. filter={"type": "vulnerability_pattern"}).
        """
        kwargs: Dict = {"k": k}
        if filter:
            kwargs["filter"] = filter
        if min_score is not None and min_score > 0:
            scored_results = self.vectorstore.similarity_search_with_score(query, **kwargs)
            scored_results = [(doc, score) for doc, score in scored_results if score >= min_score]
            return self._dedup_contexts(
                [self._format(doc, i + 1) for i, (doc, _) in enumerate(scored_results)]
            )

        results = self.vectorstore.similarity_search(query, **kwargs)
        return self._dedup_contexts([self._format(doc, i + 1) for i, doc in enumerate(results)])

    def query_with_scores(
        self,
        query: str,
        k: int = 5,
        filter: Optional[Dict] = None,
        min_score: Optional[float] = None,
    ) -> List[Dict[str, str]]:
        """Same as query() but includes cosine similarity scores (higher = more relevant)."""
        kwargs: Dict = {"k": k}
        if filter:
            kwargs["filter"] = filter
        results = self.vectorstore.similarity_search_with_score(query, **kwargs)
        if min_score is not None and min_score > 0:
            results = [(doc, score) for doc, score in results if score >= min_score]
        return self._dedup_contexts(
            [self._format(doc, i + 1, score) for i, (doc, score) in enumerate(results)]
        )

    def get_db_info(self) -> Dict[str, str]:
        """Return connection status and index metadata."""
        try:
            _ = self.vectorstore  # trigger lazy connect
            return {
                "status": "connected",
                "index_name": self.index_name,
                "embedding_model": EMBEDDING_MODEL,
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
        print(f"\n--- Rank {result['rank']} | Score {result['score']} | {result['source']} (p{result['page']}) ---")
        print(result["content"][:300] + "...")
