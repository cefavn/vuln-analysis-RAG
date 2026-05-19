# pipeline.py — Document ingestion pipeline orchestrator + CLI entry point.
#
# Chains the three stages:
#   [1] Load   — discover files, route through converters → LangChain Documents
#   [2] Chunk  — parent-child chunking by document type
#   [3] Store  — embed + upsert to Pinecone (incremental or append-only)
#
# Also exposes add_text() for runtime ingestion of LLM-generated findings
# (used by the MCP server tool add_knowledge_text).
#
# Optional: save converted YAML-frontmatter Markdown to converted_docs/ for inspection.
import argparse
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langchain_core.documents import Document

from config import CHILD_CHUNK_SIZE, DOCS_DIR, PINECONE_INDEX_NAME
from ingestion.chunker import Chunker
from ingestion.loader import discover_documents, expand_paths, load_documents
from converters.utils import make_frontmatter
from ingestion.router import canonical_source, convert_file
from store.pinecone_client import VectorStore


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _save_converted_docs(docs: List[Document], output_dir: str = "converted_docs") -> None:
    """
    Serialize already-loaded Documents to YAML-frontmatter Markdown and save,
    organized by source file mirroring rag_docs/ structure.
    """
    out_root = Path(output_dir)
    out_root.mkdir(exist_ok=True)

    by_source: Dict[str, List[Document]] = defaultdict(list)
    for doc in docs:
        by_source[doc.metadata.get("source", "unknown")].append(doc)

    saved_count = 0
    total_sources = len(by_source)
    _log(f"\n[Converting] Saving converted docs to {output_dir}/...")

    for idx, (source, source_docs) in enumerate(by_source.items(), 1):
        try:
            rel_str = source.removeprefix("rag_docs/")
            out_path = out_root / f"{rel_str}.md"
            out_path.parent.mkdir(parents=True, exist_ok=True)

            separator = "\n\n" + "=" * 80 + "\n\n"
            combined = separator.join(
                make_frontmatter(doc.metadata, doc.page_content) for doc in source_docs
            )
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(combined)

            saved_count += 1
            n = len(source_docs)
            _log(f"  [{idx}/{total_sources}] ✓ {rel_str} ({n} doc{'s' if n != 1 else ''})")

        except Exception as e:
            _log(f"  [{idx}/{total_sources}] ERROR: {source} - {e}")

    _log(f"  Saved: {saved_count}/{total_sources} files to {output_dir}/")


class DocumentPipeline:
    """Thin orchestrator: chains ingestion (load + chunk) and vector store stages."""

    def __init__(
        self,
        document_paths: Optional[List[str]] = None,
        index_name: str = PINECONE_INDEX_NAME,
        save_converted: bool = False,
    ):
        self._document_paths = document_paths
        self._chunker = Chunker()
        self._store = VectorStore(index_name=index_name)
        self._save_converted = save_converted
        if document_paths is not None:
            _log(f"Using explicit document paths: {len(document_paths)} file(s)")
        if save_converted:
            _log(f"Will save converted docs to converted_docs/")

    def run(self, append_only: bool = False) -> None:
        """Full ETL: discover → load → chunk → embed → upsert."""
        t0 = time.perf_counter()
        _log("=" * 60)
        _log("Starting document ingestion pipeline...")
        _log(f"Mode: {'append-only' if append_only else 'incremental'}")
        _log("=" * 60)

        _log("\n[1/3] Discovering and loading documents...")
        file_paths = self._document_paths or discover_documents()
        t_load = time.perf_counter()
        docs = load_documents(file_paths)
        _log(f"  Total docs loaded: {len(docs)}  ({time.perf_counter() - t_load:.2f}s)")

        # Optional: save converted YAML-frontmatter Markdown for inspection
        if self._save_converted:
            _save_converted_docs(docs)
            _log("\n" + "=" * 60)
            _log("✓ Converted docs saved to converted_docs/")
            _log("  Inspect the files, then press ENTER to continue chunking...")
            _log("=" * 60)
            input()  # Pause until user presses Enter

        _log("\n[2/3] Chunking (MarkdownHeader + Parent-Child)...")
        t_chunk = time.perf_counter()
        chunks = self._chunker.chunk_all(docs)
        if not chunks:
            raise ValueError("No chunks produced from documents.")
        _log(f"  Chunk duration: {time.perf_counter() - t_chunk:.2f}s")

        n_upserted, n_skipped = self._store.upsert_incremental(chunks, append_only=append_only)

        _log("\n" + "=" * 60)
        _log(f"  Chunks embedded : {n_upserted}")
        _log(f"  Chunks skipped  : {n_skipped}")
        _log(f"  Total duration  : {time.perf_counter() - t0:.2f}s")
        _log("=" * 60)

    def add_text(
        self,
        text_content: str,
        source_name: str = "analysis_result",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """
        Ingest LLM-generated text into the knowledge base at runtime.

        Pattern cards (text starting with 'PATTERN CARD:') are stored atomically.
        Other text is child-split only when it exceeds CHILD_CHUNK_SIZE.
        """
        if not text_content or not text_content.strip():
            return {"status": "error", "message": "Text content is empty."}
        try:
            entry_id = str((metadata or {}).get("entry_id") or uuid4().hex)
            is_pattern = text_content.lstrip().startswith("PATTERN CARD:")
            base_meta: Dict[str, Any] = {
                "source": source_name,
                "file_name": source_name,
                "type": "vulnerability_pattern" if is_pattern else "analysis_result",
                "page": 0,
                "entry_id": entry_id,
                "origin": "llm_generated",
            }
            if metadata:
                base_meta.update(metadata)

            doc = Document(page_content=text_content, metadata=base_meta)
            if is_pattern or len(text_content) <= CHILD_CHUNK_SIZE:
                chunks = [doc]
            else:
                chunks = self._chunker._chunk_document(doc)

            return self._store.upsert_chunks(chunks)
        except Exception as e:
            return {"status": "error", "message": f"Failed to add: {e}"}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest documents from rag_docs into Pinecone")
    parser.add_argument(
        "--paths",
        action="append",
        default=[],
        help=(
            "File or directory under rag_docs to ingest (repeatable or comma-separated). "
            "Omit to process all files in rag_docs."
        ),
    )
    parser.add_argument(
        "--append-only",
        action="store_true",
        help="Skip existence checks and source deletion — always upsert selected docs.",
    )
    parser.add_argument(
        "--save-converted",
        action="store_true",
        help="Save converted YAML-frontmatter Markdown to converted_docs/ for inspection.",
    )
    args = parser.parse_args()

    paths = expand_paths(args.paths) if args.paths else None
    if args.paths:
        _log(f"Selected: {', '.join(args.paths)}")

    DocumentPipeline(document_paths=paths, save_converted=args.save_converted).run(append_only=args.append_only)
    _log("Done.")
