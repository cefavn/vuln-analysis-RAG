# store/pinecone_client.py — Pinecone vector store: embed, upsert, incremental update.
#
# Uses Pinecone SDK 8+ document API (pc.preview) for hybrid search:
#   embedding    — dense semantic vector (1536 dims, cosine)
#   text         — BM25 full-text field (FTS-indexed; use for lexical recall)
#   chunk_text   — stored copy of text, returned in search results
#
# Schema: vuln-analysis-rag-v2 (document-schema index created via pc.preview)
#   dense_vector: embedding (1536d, cosine)
#   string FTS:   text (BM25, language=en)
#   string:       chunk_text, parent_id, type, source, file_name,
#                 function_name, section, doc_id, origin, doc_title, toc_section, entry_id
#   integer:      sibling_index, n_siblings
#
# Responsibilities:
#   - Generate stable document IDs from content hashes.
#   - Detect which sources have changed and delete stale docs before re-upserting.
#   - Provide upsert_chunks() for runtime ingestion (add_knowledge_text MCP tool).
import hashlib
import os
import sys
from typing import Dict, List, Set, Tuple

from langchain_core.documents import Document

from config import (
    PINECONE_API_KEY,
    PINECONE_INDEX_NAME,
    PINECONE_NAMESPACE,
    apply_embeddings_env,
)
from ingestion.embedder import Embedder, text_for_dense_embedding

os.environ.setdefault("PINECONE_API_KEY", PINECONE_API_KEY)
apply_embeddings_env()


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _normalize_ws(text: str) -> str:
    return " ".join((text or "").split())


def _content_hash(text: str) -> str:
    return hashlib.sha256(_normalize_ws(text).encode()).hexdigest()


# Embedding input size limits (chars). C code tokenizes ~2x denser than prose.
MAX_EMBEDDING_CHARS = 25000       # prose/text docs (~6 250 tokens)
MAX_EMBEDDING_CHARS_CODE = 15000  # C code/config (conservative, avoids token overflow)

# Size limit for chunk_text stored field.
# Pinecone metadata cap ~40 KB/vector; 20 000 chars is a safe ceiling.
MAX_CHUNK_TEXT_METADATA = 20000

# Types where a metadata overflow is a pipeline bug, not a truncation candidate.
_CODE_TYPES = frozenset({
    "decompiled",
    "build_config",
})


def _batched(items: List, batch_size: int) -> List[List]:
    if batch_size <= 0:
        return [items]
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]


def _guard_sizes(docs: List[Document]) -> None:
    """Raise if any chunk exceeds the embedding model token limit."""
    for doc in docs:
        limit = (
            MAX_EMBEDDING_CHARS_CODE
            if doc.metadata.get("type", "") in _CODE_TYPES
            else MAX_EMBEDDING_CHARS
        )
        if len(doc.page_content) > limit:
            raise ValueError(
                f"Chunk exceeds embedding limit ({len(doc.page_content)} > {limit} chars): "
                f"source={doc.metadata.get('source', '?')} "
                f"type={doc.metadata.get('type', '?')} — "
                f"review Chunker CHILD_CHUNK_SIZE config."
            )


def _guard_metadata_size(records: List[Dict]) -> None:
    """Raise if any chunk_text field exceeds Pinecone's stored field size limit."""
    for r in records:
        ct = r.get("chunk_text", "")
        if len(ct) > MAX_CHUNK_TEXT_METADATA:
            raise ValueError(
                f"chunk_text exceeds Pinecone metadata limit ({len(ct)} > {MAX_CHUNK_TEXT_METADATA} chars): "
                f"type={r.get('type', '?')} source={r.get('source', '?')} "
                f"function={r.get('function_name', '?')} — "
                f"review Chunker CHILD_CHUNK_SIZE config."
            )


def make_vector_id(doc: Document) -> str:
    """Stable document ID derived from key metadata fields and normalized content hash."""
    meta = doc.metadata or {}
    key = "|".join([
        str(meta.get("source", "unknown")),
        str(meta.get("page", 0)),
        str(meta.get("type", "unknown")),
        str(meta.get("section", "")),
        str(meta.get("doc_id", "")),
        str(
            meta.get("function_name") or meta.get("struct_name")
            or meta.get("block_name") or meta.get("section_name") or ""
        ),
        str(meta.get("entry_id", "")),
        _content_hash(doc.page_content or ""),
    ])
    return hashlib.sha256(key.encode()).hexdigest()


class VectorStore:
    """Pinecone embed + upsert with incremental update logic (document schema API)."""

    def __init__(self, index_name: str = PINECONE_INDEX_NAME):
        if not PINECONE_API_KEY:
            raise ValueError("PINECONE_API_KEY not set. Check your .env file.")
        self.index_name = index_name
        self._namespace = PINECONE_NAMESPACE
        self._embedder = Embedder()

    def _preview_index(self):
        from pinecone import Pinecone
        return Pinecone(api_key=PINECONE_API_KEY).preview.index(name=self.index_name)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def _upsert(self, docs: List[Document], ids: List[str]) -> None:
        _guard_sizes(docs)
        idx = self._preview_index()
        ok = fail = 0
        for id_, doc in zip(ids, docs):
            meta = {k: v for k, v in doc.metadata.items() if v is not None and v != ""}
            record = {
                "_id": id_,
                "embedding": self._embedder.embed_documents([
                    text_for_dense_embedding(doc.page_content, doc.metadata.get("type", ""))
                ])[0],
                "text": doc.page_content,
                "chunk_text": doc.page_content,
                **meta,
            }
            _guard_metadata_size([record])
            try:
                idx.documents.batch_upsert(
                    namespace=self._namespace,
                    documents=[record],
                    batch_size=1,
                )
                ok += 1
                if ok % 50 == 0:
                    _log(f"  [{ok + fail}] {ok} ok, {fail} fail")
            except Exception as e:
                fail += 1
                _log(f"  [WARN] Upsert failed for {id_[:8]}… ({doc.metadata.get('source', '?')}): {e}")
        _log(f"  Upsert complete: {ok} ok, {fail} failed")

    def _delete_by_source(self, source: str) -> None:
        """
        Delete all documents for a given source.
        The document API only supports delete-by-id or delete_all — no filter delete.
        Fetch matching IDs via query_string wildcard search with source filter, then delete.
        """
        try:
            idx = self._preview_index()
            resp = idx.documents.search(
                namespace=self._namespace,
                top_k=10000,
                score_by=[{"type": "query_string", "query": "*"}],
                filter={"source": {"$eq": source}},
                include_fields=[],
            )
            ids_to_delete = [m._id for m in resp.matches]
            if ids_to_delete:
                for batch in _batched(ids_to_delete, 1000):
                    idx.documents.delete(namespace=self._namespace, ids=batch)
                _log(f"  Deleted {len(ids_to_delete)} doc(s) for source '{source}'")
        except Exception as e:
            if "Namespace not found" not in str(e) and "no documents" not in str(e).lower():
                _log(f"  [WARN] Could not delete docs for '{source}': {e}")

    def _fetch_existing_ids(self, ids: List[str], batch_size: int = 200) -> Set[str]:
        if not ids:
            return set()
        try:
            idx = self._preview_index()
            existing: Set[str] = set()
            for batch in _batched(ids, batch_size):
                response = idx.documents.fetch(
                    namespace=self._namespace,
                    ids=batch,
                    include_fields=[],
                )
                for doc_id in response.documents:
                    existing.add(doc_id)
            return existing
        except Exception as e:
            _log(f"  [WARN] Could not fetch existing IDs: {e}")
            return set()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def upsert_incremental(
        self,
        docs: List[Document],
        append_only: bool = False,
    ) -> Tuple[int, int]:
        """
        Embed and upsert documents with change detection.

        append_only=True: skip existence checks and source deletion (faster, no dedup).
        Returns (n_upserted, n_skipped).
        """
        ids = [make_vector_id(doc) for doc in docs]

        if append_only:
            _log(f"\n[3/3] Append-only: upserting {len(docs)} chunk(s)...")
            self._upsert(docs, ids)
            return len(docs), 0

        source_map: Dict[str, List[Tuple[Document, str]]] = {}
        for doc, doc_id in zip(docs, ids):
            src = str(doc.metadata.get("source", "")).strip() or "unknown"
            source_map.setdefault(src, []).append((doc, doc_id))

        all_ids = [doc_id for items in source_map.values() for _, doc_id in items]
        _log(f"  Checking {len(all_ids)} chunk(s) against existing index...")
        existing_ids = self._fetch_existing_ids(all_ids)
        _log(f"  Existing vectors: {len(existing_ids)}")

        forced = {s.strip() for s in os.getenv("FORCE_REFRESH_SOURCES", "").split(",") if s.strip()}

        changed_sources, n_unchanged = [], 0
        for src, items in source_map.items():
            if src == "unknown" or src in forced:
                changed_sources.append(src)
            elif all(doc_id in existing_ids for _, doc_id in items):
                n_unchanged += 1
            else:
                changed_sources.append(src)

        if changed_sources:
            for src in changed_sources:
                if src != "unknown":
                    self._delete_by_source(src)
            _log(f"  Refreshed {len(changed_sources)} changed/new source(s)")

        docs_to_upsert = [
            doc for src in changed_sources for doc, _ in source_map.get(src, [])
        ]
        ids_to_upsert = [
            doc_id for src in changed_sources for _, doc_id in source_map.get(src, [])
        ]
        n_skipped = len(docs) - len(docs_to_upsert)

        _log(
            f"\n[3/3] Upsert: {len(docs_to_upsert)} new/changed, "
            f"{n_skipped} skipped ({n_unchanged} unchanged source(s))"
        )
        if docs_to_upsert:
            _log("  Embedding + upsert in progress...")
            self._upsert(docs_to_upsert, ids_to_upsert)
            _log("  Done.")
        else:
            _log("  Index is already up to date.")

        return len(docs_to_upsert), n_skipped

    def upsert_chunks(self, chunks: List[Document]) -> Dict[str, str]:
        """Embed and add pre-chunked documents; returns a status dict."""
        if not chunks:
            return {"status": "error", "message": "No chunks provided."}
        ids = [make_vector_id(c) for c in chunks]
        self._upsert(chunks, ids)
        return {
            "status": "success",
            "message": f"Added {len(chunks)} chunk(s)",
            "chunks_added": str(len(chunks)),
            "source": str(chunks[0].metadata.get("source", "unknown")),
            "entry_id": str(chunks[0].metadata.get("entry_id", "")),
        }
