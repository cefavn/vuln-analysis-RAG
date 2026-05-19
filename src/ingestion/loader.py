# ingestion/loader.py — File discovery and document loading.
#
# Discovers files from rag_docs/, routes each through the appropriate converter,
# and parses YAML-frontmatter output into LangChain Documents ready for chunking.
import os
import sys
from typing import Dict, List, Set

from langchain_core.documents import Document

from config import DOCS_DIR
from ingestion.router import (
    SUPPORTED_EXTS, canonical_source, convert_file, frontmatter_to_doc, get_doc_dir, is_supported,
)

# Directories whose content is pre-processed (LLM-refactored or script-converted)
# before placement in rag_docs/. All other dirs are treated as unprocessed.
_PROCESSED_DIRS = frozenset({"decompiled", "vuln-pattern", "qnx-doc", "build-config"})


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def discover_documents(docs_dir: str = DOCS_DIR) -> List[str]:
    """Walk docs_dir recursively and return all supported file paths, sorted."""
    if not os.path.exists(docs_dir):
        _log(f"[WARN] DOCS_DIR not found: {docs_dir}")
        return []
    paths = [
        os.path.join(root, f)
        for root, _, files in os.walk(docs_dir)
        for f in files
        if is_supported(f) and f != "SPEC.md"
    ]
    paths.sort()
    _log(f"Discovered {len(paths)} document(s) in {docs_dir}")
    return paths


def expand_paths(path_specs: List[str], docs_dir: str = DOCS_DIR) -> List[str]:
    """
    Resolve file/directory specs (relative to docs_dir or absolute) to concrete paths.
    Specs can be comma-separated within a single string.
    """
    docs_root = os.path.abspath(docs_dir)
    expanded: List[str] = []

    for spec in path_specs:
        for raw in spec.split(","):
            item = raw.strip()
            if not item:
                continue
            candidate = item if os.path.isabs(item) else os.path.join(docs_root, item)
            if os.path.isdir(candidate):
                for root, _, files in os.walk(candidate):
                    for f in files:
                        if is_supported(f) and f != "SPEC.md":
                            expanded.append(os.path.join(root, f))
            elif os.path.isfile(candidate):
                if is_supported(candidate):
                    expanded.append(candidate)
                else:
                    _log(f"  [SKIP] Unsupported type: {candidate}")
            else:
                _log(f"  [SKIP] Not found: {candidate}")

    seen: Set[str] = set()
    unique = [p for p in expanded if not (p in seen or seen.add(p))]
    _log(f"Resolved {len(unique)} document(s) from {len(path_specs)} path spec(s)")
    return unique


def load_documents(file_paths: List[str]) -> List[Document]:
    """
    Convert each file through the appropriate converter, parse YAML frontmatter,
    and return a flat list of LangChain Documents ready for chunking.
    """
    all_docs: List[Document] = []
    _log(f"Loading {len(file_paths)} file(s)...")

    for path in file_paths:
        if not os.path.exists(path):
            _log(f"  [SKIP] Not found: {path}")
            continue
        try:
            source = canonical_source(path)
            origin = "processed" if get_doc_dir(path) in _PROCESSED_DIRS else "unprocessed"
            md_strings = convert_file(path, source)
            docs = [d for s in md_strings if (d := frontmatter_to_doc(s)) is not None]
            for doc in docs:
                doc.metadata.setdefault("origin", origin)
            if not docs:
                _log(f"  [SKIP] No content: {path}")
            all_docs.extend(docs)
        except Exception as e:
            _log(f"  [ERROR] {os.path.basename(path)}: {e}")

    if not all_docs:
        raise ValueError(f"No documents loaded from {len(file_paths)} path(s).")

    type_counts: Dict[str, int] = {}
    for doc in all_docs:
        t = str(doc.metadata.get("type", "unknown"))
        type_counts[t] = type_counts.get(t, 0) + 1
    top = ", ".join(
        f"{k}={v}"
        for k, v in sorted(type_counts.items(), key=lambda kv: kv[1], reverse=True)[:6]
    )
    _log(f"  Document types (top 6): {top}")
    return all_docs
