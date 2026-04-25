# builder.py — Load (L) stage of the ETL pipeline: chunk + embed + upsert.
#
# Architecture
# ============
# The ingestion pipeline is now split into two stages:
#
#   [Extract & Transform]  src/converters/
#     pdf_converter.py     PDF (PyMuPDF + Tesseract OCR) → Markdown
#     c_converter.py       Decompiled C (regex + brace scanning) → Markdown
#     json_converter.py    Vulnerability pattern JSON → Markdown
#     build_converter.py   QNX .build + .sh → Markdown
#
#   [Load]  src/builder.py  (this file)
#     1. Orchestrate converters based on file extension.
#     2. Parse YAML frontmatter from each converter output into Document.metadata.
#     3. Route Documents to Atomic or Parent-Child chunking by `type`.
#     4. Embed + upsert to Pinecone.
#
# Standard intermediate format (converter output):
#   ---
#   source: rag_docs/decompiled-code/qvm.c
#   type: c_function
#   file_name: qvm.c
#   section: function/handle_write
#   page: 0
#   ---
#
#   ## Function: handle_write ...
#
# Chunking strategy (UNCHANGED — do not modify):
#   Atomic types  → kept as single vectors (no further splitting)
#     vulnerability_pattern, c_overview, c_constants, c_struct,
#     build_config, build_image, build_script
#   Parent-Child  → MarkdownHeaderSplit → child-split if section > CHILD_CHUNK_SIZE
#     reference_document, c_function, c_section,
#     build_section, build_suid, build_hypervisor, analysis_result
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hashlib
import yaml
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings
from langchain_pinecone import PineconeVectorStore
from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter

from config import (
    CHILD_CHUNK_OVERLAP,
    CHILD_CHUNK_SIZE,
    CHUNK_OVERLAP,
    CHUNK_SIZE,
    DOCS_DIR,
    EMBEDDING_MODEL,
    OPENAI_API_KEY,
    PARENT_CONTENT_MAX,
    PINECONE_API_KEY,
    PINECONE_INDEX_NAME,
    TESSERACT_PATH,
)
from converters import convert_pdf, convert_c, convert_json, convert_build, convert_sh
from converters.utils import make_frontmatter

os.environ.setdefault("PINECONE_API_KEY", PINECONE_API_KEY)
os.environ.setdefault("OPENAI_API_KEY", OPENAI_API_KEY)

_HEADER_SPLIT_ON = [("#", "h1"), ("##", "h2"), ("###", "h3")]

# Document types kept atomic (not further child-split).
# build_script covers both [+script] blocks AND standalone .sh files.
_ATOMIC_TYPES = frozenset({
    "vulnerability_pattern",
    "c_overview", "c_constants", "c_struct",
    "build_config", "build_image", "build_script",
})

# ---------------------------------------------------------------------------
# Shared utility helpers (used by DocumentBuilder internals)
# ---------------------------------------------------------------------------

def _normalize_ws(text: str) -> str:
    return " ".join((text or "").split())


def _content_hash(text: str) -> str:
    return hashlib.sha256(_normalize_ws(text).encode()).hexdigest()


def _canonical_source(path: str) -> str:
    """
    Build a stable, Docker-agnostic source identifier.
    Files under DOCS_DIR are stored as rag_docs/<relative_path>.
    """
    if not path:
        return "unknown"
    abs_path = os.path.abspath(path)
    docs_root = os.path.abspath(DOCS_DIR)
    try:
        rel_path = os.path.relpath(abs_path, docs_root)
    except Exception:
        rel_path = abs_path
    if rel_path and rel_path != "." and not rel_path.startswith(".."):
        return os.path.join("rag_docs", rel_path).replace("\\", "/")
    return abs_path.replace("\\", "/")


def _make_vector_id(doc: Document) -> str:
    """Stable vector ID from semantic metadata + normalized content hash."""
    meta = doc.metadata or {}
    source   = str(meta.get("source", "unknown"))
    page     = str(meta.get("page", 0))
    doc_type = str(meta.get("type", "unknown"))
    section  = str(meta.get("section", ""))
    doc_id   = str(meta.get("doc_id", ""))
    symbol   = str(
        meta.get("function_name")
        or meta.get("struct_name")
        or meta.get("block_name")
        or meta.get("section_name")
        or ""
    )
    entry_id = str(meta.get("entry_id", ""))
    content  = _content_hash(doc.page_content or "")
    key = "|".join([source, page, doc_type, section, doc_id, symbol, entry_id, content])
    return hashlib.sha256(key.encode()).hexdigest()


def _batched(items: List[str], batch_size: int) -> List[List[str]]:
    if batch_size <= 0:
        return [items]
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]


def _section_path(meta: Dict) -> str:
    """Human-readable heading path from h1/h2/h3 splitter metadata."""
    return " > ".join(meta[k] for k in ("h1", "h2", "h3") if meta.get(k))


def _frontmatter_to_doc(text: str) -> Optional[Document]:
    """
    Parse a YAML-frontmatter Markdown string into a LangChain Document.

    The frontmatter block (---...---) is parsed by yaml.safe_load into
    Document.metadata.  The remainder becomes Document.page_content.
    Returns None if parsing fails or produces empty content.
    """
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            try:
                meta: Dict = yaml.safe_load(text[4:end]) or {}
            except Exception:
                meta = {}
            content = text[end + 5:].strip()
            if content:
                return Document(page_content=content, metadata=meta)
            return None
    # No frontmatter — treat whole text as content with empty metadata
    stripped = text.strip()
    return Document(page_content=stripped, metadata={}) if stripped else None


# ---------------------------------------------------------------------------
# DocumentBuilder — Load + Chunk + Upsert
# ---------------------------------------------------------------------------

class DocumentBuilder:
    """Pipeline orchestrator: route files → converters → chunk → embed → upsert."""

    def __init__(
        self,
        document_paths: Optional[List[str]] = None,
        index_name: str = PINECONE_INDEX_NAME,
    ):
        if not PINECONE_API_KEY:
            raise ValueError("PINECONE_API_KEY not set. Check your .env file.")
        if not OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY not set. Check your .env file.")

        self.index_name = index_name
        self.embeddings = OpenAIEmbeddings(
            model=EMBEDDING_MODEL,
            openai_api_key=OPENAI_API_KEY,
        )
        self._header_splitter = MarkdownHeaderTextSplitter(
            headers_to_split_on=_HEADER_SPLIT_ON,
            strip_headers=False,
        )
        self._child_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHILD_CHUNK_SIZE,
            chunk_overlap=CHILD_CHUNK_OVERLAP,
            separators=["\n\n", "\n", ". ", " ", ""],
        )
        self._fallback_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE,
            chunk_overlap=CHUNK_OVERLAP,
            separators=["\n\n", "\n", ". ", " ", ""],
        )
        self.document_paths = document_paths if document_paths is not None else self._discover_documents()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discover_documents(self) -> List[str]:
        if not os.path.exists(DOCS_DIR):
            print(f"Warning: DOCS_DIR not found: {DOCS_DIR}")
            return []
        paths = []
        for root, dirs, files in os.walk(DOCS_DIR):
            for f in files:
                if f.lower().endswith((".pdf", ".txt", ".json", ".md", ".c", ".build", ".sh")):
                    paths.append(os.path.join(root, f))
        paths.sort()
        print(f"Discovered {len(paths)} document(s) in {DOCS_DIR} and its subdirectories")
        return paths

    # ------------------------------------------------------------------
    # Step 1: Orchestrate converters → parse frontmatter → Documents
    # ------------------------------------------------------------------

    def load_documents(self) -> List[Document]:
        """
        Route each file to its converter, parse the YAML-frontmatter output,
        and return a flat list of LangChain Documents ready for chunking.
        """
        all_docs: List[Document] = []
        print(f"Loading {len(self.document_paths)} document(s)...")

        for path in self.document_paths:
            if not os.path.exists(path):
                print(f"  [SKIP] Not found: {path}")
                continue
            try:
                ext = os.path.splitext(path)[1].lower()
                source = _canonical_source(path)
                file_name = os.path.basename(path)

                if ext == ".pdf":
                    md_strings = convert_pdf(path, source, tesseract_path=TESSERACT_PATH)

                elif ext == ".c":
                    md_strings = convert_c(path, source)
                    print(f"  Extracted {len(md_strings)} chunk(s) from {file_name}")

                elif ext == ".json":
                    md_strings = convert_json(path, source)
                    print(f"  Loaded {len(md_strings)} pattern(s) from {file_name}")

                elif ext == ".build":
                    md_strings = convert_build(path, source)
                    print(f"  Extracted {len(md_strings)} chunk(s) from {file_name}")

                elif ext == ".sh":
                    md_strings = convert_sh(path, source)
                    print(f"  Loaded {len(md_strings)} script(s) from {file_name}")

                elif ext in (".txt", ".md"):
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                    if text.strip():
                        meta: Dict[str, Any] = {
                            "source": source,
                            "file_name": file_name,
                            "type": "reference_document",
                            "page": 0,
                        }
                        md_strings = [make_frontmatter(meta, text)]
                    else:
                        md_strings = []

                else:
                    print(f"  [SKIP] Unsupported type: {path}")
                    continue

                docs = [d for s in md_strings if (d := _frontmatter_to_doc(s)) is not None]
                if not docs:
                    print(f"  [SKIP] No content: {path}")
                    continue

                all_docs.extend(docs)

            except Exception as e:
                print(f"  [ERROR] {os.path.basename(path)}: {e}")

        if not all_docs:
            raise ValueError(f"No documents loaded from {DOCS_DIR}")
        return all_docs

    # ------------------------------------------------------------------
    # Steps 2 & 3: Smart-chunk (Parent-Child) — DO NOT MODIFY
    # ------------------------------------------------------------------

    def _split_section_into_children(
        self,
        section_text: str,
        base_meta: Dict,
        section_meta: Dict,
    ) -> List[Document]:
        """
        Split one large Markdown section into child chunks.
        Each child stores the full parent section text for context retrieval.
        """
        parent_seed = (
            f"{base_meta.get('source', '')}|{base_meta.get('page', 0)}|"
            f"{section_meta.get('section', '')}"
        )
        parent_id = hashlib.sha256(parent_seed.encode()).hexdigest()
        parent_stored = section_text[:PARENT_CONTENT_MAX]

        children = self._child_splitter.split_text(section_text)
        docs: List[Document] = []
        for child_text in children:
            if not child_text.strip():
                continue
            docs.append(Document(
                page_content=child_text,
                metadata={
                    **section_meta,
                    "parent_id": parent_id,
                    "parent_content": parent_stored,
                },
            ))
        return docs

    def _chunk_document(self, doc: Document) -> List[Document]:
        """
        Apply the full Parent-Child chunking strategy to one Document.

        1. MarkdownHeaderTextSplitter → semantic parent sections.
        2. If section <= CHILD_CHUNK_SIZE → keep as single chunk.
        3. If section > CHILD_CHUNK_SIZE → child-split, store parent_content.
        4. If no heading structure found → fallback to RecursiveCharacterTextSplitter.
        """
        base_meta = doc.metadata
        results: List[Document] = []

        try:
            sections = self._header_splitter.split_text(doc.page_content)
        except Exception:
            sections = []

        if not sections:
            for chunk in self._fallback_splitter.split_text(doc.page_content):
                if chunk.strip():
                    results.append(Document(page_content=chunk, metadata=base_meta.copy()))
            return results

        for section in sections:
            section_text = section.page_content.strip()
            if not section_text:
                continue

            section_meta = {
                **base_meta,
                "section": _section_path(section.metadata),
                **{k: v for k, v in section.metadata.items() if k in ("h1", "h2", "h3")},
            }

            if len(section_text) <= CHILD_CHUNK_SIZE:
                results.append(Document(page_content=section_text, metadata=section_meta))
            else:
                results.extend(
                    self._split_section_into_children(section_text, base_meta, section_meta)
                )

        return results

    def _chunk_all_documents(self, documents: List[Document]) -> List[Document]:
        """
        Route documents through the correct chunking strategy:

        Atomic types (kept as-is, no further splitting):
          vulnerability_pattern, c_overview, c_constants, c_struct,
          build_config, build_image, build_script

        Parent-Child pipeline (large docs split into child chunks):
          reference_document, c_function, c_section,
          build_section, build_suid, build_hypervisor, analysis_result
        """
        atomic = [d for d in documents if d.metadata.get("type") in _ATOMIC_TYPES]
        large  = [d for d in documents if d.metadata.get("type") not in _ATOMIC_TYPES]

        result: List[Document] = list(atomic)
        for doc in large:
            result.extend(self._chunk_document(doc))

        for i, doc in enumerate(result):
            doc.metadata["chunk_id"] = i
            doc.metadata.setdefault("text_length", len(doc.page_content))

        n_atomic   = len(atomic)
        n_children = sum(1 for d in result if "parent_id" in d.metadata)
        n_sections = len(result) - n_atomic - n_children
        print(f"  Chunks: {len(result)} total "
              f"({n_atomic} atomic | {n_sections} section chunks | {n_children} child chunks)")
        return result

    def _fetch_existing_ids(self, ids: List[str], batch_size: int = 200) -> Set[str]:
        """
        Return the subset of IDs that already exist in Pinecone.
        If fetch fails, return empty set so pipeline falls back to regular upsert.
        """
        if not ids:
            return set()

        try:
            from pinecone import Pinecone

            pc = Pinecone(api_key=PINECONE_API_KEY)
            index = pc.Index(self.index_name)
            existing: Set[str] = set()

            for batch in _batched(ids, batch_size):
                response = index.fetch(ids=batch)
                vectors = getattr(response, "vectors", None)
                if vectors is None and isinstance(response, dict):
                    vectors = response.get("vectors", {})
                if isinstance(vectors, dict):
                    existing.update(vectors.keys())

            return existing
        except Exception as e:
            print(f"  [WARN] Could not fetch existing IDs from Pinecone: {e}")
            return set()

    # ------------------------------------------------------------------
    # Steps 4 & 5: Embed + Upsert — DO NOT MODIFY
    # ------------------------------------------------------------------

    def build_and_upsert(self) -> PineconeVectorStore:
        """Full pipeline: load → Markdown → smart-chunk → embed → upsert."""
        print("=" * 60)
        print("Starting document ingestion pipeline...")
        print("=" * 60)

        print("\n[1/3] Loading & standardizing documents to Markdown...")
        all_docs = self.load_documents()
        print(f"  Total pages/docs loaded: {len(all_docs)}")

        print("\n[2/3] Smart-chunking (MarkdownHeader + Parent-Child)...")
        splits = self._chunk_all_documents(all_docs)
        if not splits:
            raise ValueError("No chunks produced from documents.")

        source_to_items: Dict[str, List[Tuple[Document, str]]] = {}
        all_ids: List[str] = []
        for doc in splits:
            source = str(doc.metadata.get("source", "")).strip() or "unknown"
            doc_id = _make_vector_id(doc)
            all_ids.append(doc_id)
            source_to_items.setdefault(source, []).append((doc, doc_id))

        existing_ids = self._fetch_existing_ids(all_ids)

        forced_refresh_sources = {
            s.strip()
            for s in os.getenv("FORCE_REFRESH_SOURCES", "").split(",")
            if s.strip()
        }
        if forced_refresh_sources:
            print(f"  Force refresh sources: {len(forced_refresh_sources)}")

        changed_sources: List[str] = []
        unchanged_sources = 0
        for source, items in source_to_items.items():
            if source == "unknown":
                changed_sources.append(source)
                continue
            if source in forced_refresh_sources:
                changed_sources.append(source)
                continue

            source_ids = [item_id for _, item_id in items]
            if source_ids and all(item_id in existing_ids for item_id in source_ids):
                unchanged_sources += 1
            else:
                changed_sources.append(source)

        for source in forced_refresh_sources:
            if source not in changed_sources:
                changed_sources.append(source)

        docs_to_upsert: List[Document] = []
        ids_to_upsert: List[str] = []

        if changed_sources:
            cleaner = PineconeVectorStore(index_name=self.index_name, embedding=self.embeddings)
            refreshed = 0
            for source in changed_sources:
                if source == "unknown":
                    continue
                try:
                    cleaner.delete(filter={"source": {"$eq": source}})
                    refreshed += 1
                except Exception as e:
                    if "Namespace not found" not in str(e):
                        print(f"  [WARN] Could not clear old vectors for source '{source}': {e}")

            if refreshed:
                print(f"  Refreshed {refreshed} changed/new source(s) before upsert")

            for source in changed_sources:
                for doc, doc_id in source_to_items.get(source, []):
                    docs_to_upsert.append(doc)
                    ids_to_upsert.append(doc_id)

        print(
            f"\n[3/3] Incremental upsert: {len(docs_to_upsert)} changed/new chunks, "
            f"{len(splits) - len(docs_to_upsert)} unchanged chunks skipped "
            f"across {unchanged_sources} unchanged source(s)."
        )

        if docs_to_upsert:
            vectorstore = PineconeVectorStore.from_documents(
                documents=docs_to_upsert,
                embedding=self.embeddings,
                ids=ids_to_upsert,
                index_name=self.index_name,
            )
        else:
            vectorstore = PineconeVectorStore(index_name=self.index_name, embedding=self.embeddings)
            print("  Nothing new to embed. Index is already up to date for discovered sources.")

        print("\n" + "=" * 60)
        print("Vector database built successfully.")
        print(f"  Index : {self.index_name}")
        print(f"  Chunks discovered: {len(splits)}")
        print(f"  Chunks embedded  : {len(docs_to_upsert)}")
        print("=" * 60)
        return vectorstore

    def add_text_to_db(
        self,
        text_content: str,
        source_name: str = "analysis_result",
        metadata: Optional[Dict] = None,
    ) -> Dict[str, str]:
        """Add analysis conclusions or notes to the vector store at runtime."""
        if not text_content or not text_content.strip():
            return {"status": "error", "message": "Text content is empty."}
        try:
            entry_id = str((metadata or {}).get("entry_id") or uuid4().hex)
            base_meta = {
                "source": source_name,
                "file_name": source_name,
                "type": "analysis_result",
                "page": 0,
                "entry_id": entry_id,
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
            }
            if metadata:
                base_meta.update(metadata)

            doc = Document(page_content=text_content, metadata=base_meta)
            chunks = self._chunk_document(doc) if len(text_content) > CHILD_CHUNK_SIZE else [doc]

            for i, chunk in enumerate(chunks):
                chunk.metadata.setdefault("chunk_id", i)
                chunk.metadata.setdefault("text_length", len(chunk.page_content))

            ids = [_make_vector_id(chunk) for chunk in chunks]

            vectorstore = PineconeVectorStore(
                index_name=self.index_name,
                embedding=self.embeddings,
            )
            vectorstore.add_documents(chunks, ids=ids)

            return {
                "status": "success",
                "message": f"Added {len(chunks)} chunk(s) from '{source_name}'",
                "chunks_added": str(len(chunks)),
                "source": source_name,
                "entry_id": entry_id,
            }
        except Exception as e:
            return {"status": "error", "message": f"Failed to add: {e}"}


if __name__ == "__main__":
    builder = DocumentBuilder()
    builder.build_and_upsert()
    print("Done.")
