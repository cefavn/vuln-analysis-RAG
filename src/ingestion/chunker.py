# ingestion/chunker.py — Document chunking strategies.
#
# Atomic types  → kept as single vectors (small, self-contained units whose
#                  coherence would break if split further).
# Parent-Child  → MarkdownHeaderTextSplitter produces semantic parent sections;
#                  sections exceeding CHILD_CHUNK_SIZE are further child-split.
#                  Each child stores parent_id + sibling_index + n_siblings so
#                  the retriever can reconstruct the full section on the fly via
#                  Pinecone fetch — no parent_content duplication in metadata.
#
# Two child splitters are maintained:
#   _child_splitter      — prose/text documents (separator priority: blank-line → line)
#   _code_child_splitter — C code/config (regex, matches closing braces at any indent
#                          level since IDA/Ghidra always outputs indented code)
import hashlib
import sys
from typing import Dict, List

from langchain_core.documents import Document
from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter

from config import CHILD_CHUNK_OVERLAP, CHILD_CHUNK_SIZE, CHUNK_OVERLAP, CHUNK_SIZE

_HEADER_SPLIT_ON = [("#", "h1"), ("##", "h2"), ("###", "h3")]

# Types using code-aware separators (closing braces, semicolons) for child splitting.
_CODE_CHILD_TYPES = frozenset({
    "decompiled",
    "c_function",
})

# Regex separators for decompiled C code and build config sections.
# \n\s*}\n  — closing brace at any indent level (IDA/Ghidra always indents)
# ;\n        — end of C statement
# \n\n       — blank line between logical blocks
# \n         — line boundary (last-resort fallback)
_CODE_SEPARATORS = [r"\n\s*\}\n", r";\n", r"\n\n", r"\n", r""]


def _parent_id(source: str, section: str) -> str:
    """Stable ID for a parent section — used to group sibling chunks in Pinecone."""
    return hashlib.sha256(f"{source}::{section}".encode()).hexdigest()[:16]


def _section_path(meta: Dict) -> str:
    """Human-readable heading path from MarkdownHeaderTextSplitter metadata."""
    return " > ".join(meta[k] for k in ("h1", "h2", "h3") if meta.get(k))


class Chunker:
    """Routes documents through the parent-child chunking pipeline by doc type."""

    def __init__(self) -> None:
        self._header_splitter = MarkdownHeaderTextSplitter(
            headers_to_split_on=_HEADER_SPLIT_ON,
            strip_headers=False,
        )
        self._child_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHILD_CHUNK_SIZE,
            chunk_overlap=CHILD_CHUNK_OVERLAP,
            separators=["\n\n", "\n", ". ", " ", ""],
        )
        self._code_child_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHILD_CHUNK_SIZE,
            chunk_overlap=0,
            separators=_CODE_SEPARATORS,
            is_separator_regex=True,
        )
        self._fallback_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE,
            chunk_overlap=CHUNK_OVERLAP,
            separators=["\n\n", "\n", ". ", " ", ""],
        )

    def chunk_all(self, documents: List[Document]) -> List[Document]:
        """Split all documents through the parent-child pipeline."""
        result: List[Document] = []
        for doc in documents:
            result.extend(self._chunk_document(doc))

        n_children = sum(1 for d in result if "parent_id" in d.metadata)
        print(
            f"  Chunks: {len(result)} total ({len(result) - n_children} single | {n_children} child)",
            file=sys.stderr,
        )
        return result

    def _chunk_document(self, doc: Document) -> List[Document]:
        """
        1. MarkdownHeaderTextSplitter → semantic parent sections.
        2. Section ≤ CHILD_CHUNK_SIZE → kept as one chunk.
        3. Section > CHILD_CHUNK_SIZE → child-split with parent_id/sibling metadata.
        4. No heading structure found → RecursiveCharacterTextSplitter fallback.
        """
        base_meta = doc.metadata
        try:
            sections = self._header_splitter.split_text(doc.page_content)
        except Exception:
            sections = []

        if not sections:
            return [
                Document(page_content=chunk, metadata=base_meta.copy())
                for chunk in self._fallback_splitter.split_text(doc.page_content)
                if chunk.strip()
            ]

        results: List[Document] = []
        for section in sections:
            text = section.page_content.strip()
            if not text:
                continue
            meta = {**base_meta, "section": base_meta.get("section") or _section_path(section.metadata)}
            if len(text) <= CHILD_CHUNK_SIZE:
                results.append(Document(page_content=text, metadata=meta))
            else:
                results.extend(self._split_into_children(text, meta))
        return results

    def _split_into_children(self, section_text: str, section_meta: Dict) -> List[Document]:
        """
        Child-split an oversized section.

        Each child carries:
          parent_id     — stable sha256[:16] of source::section, used to fetch
                          siblings from Pinecone at retrieval time.
          sibling_index — position in the ordered sequence (0-based).
          n_siblings    — total number of children for this parent.

        The retriever uses these three fields to reconstruct the full section
        without storing any parent text in metadata.
        """
        doc_type = section_meta.get("type", "")
        splitter = (
            self._code_child_splitter if doc_type in _CODE_CHILD_TYPES
            else self._child_splitter
        )

        chunks = [c for c in splitter.split_text(section_text) if c.strip()]
        if not chunks:
            return []

        pid = _parent_id(
            str(section_meta.get("source", "")),
            str(section_meta.get("section", "")),
        )
        n = len(chunks)

        return [
            Document(
                page_content=chunk,
                metadata={**section_meta, "parent_id": pid, "sibling_index": i, "n_siblings": n},
            )
            for i, chunk in enumerate(chunks)
        ]
