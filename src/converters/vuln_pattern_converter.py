# converters/vuln_pattern_converter.py — Hand-written .md vulnerability pattern converter.
#
# Handles vuln-pattern/*.md files where each file has YAML frontmatter (doc_id, vuln_type,
# and optional fields) followed by Markdown content (description, apply_when, code patterns).
#
# Uses frontmatter_to_doc() for YAML parsing — enforces yaml.safe_load (no arbitrary
# Python object deserialization). Pattern cards are stored atomically (one vector per file).
import os
import sys
from typing import List

from converters.utils import make_frontmatter

_REQUIRED_FIELDS = frozenset({"doc_id", "vuln_type"})


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def convert_vuln_pattern(file_path: str, source: str) -> List[str]:
    """
    Parse a hand-written .md vulnerability pattern file into a single
    YAML-frontmatter Markdown string, ready for atomic ingestion.

    Structural validation: warns if required fields (doc_id, vuln_type) are missing,
    but ingests the file anyway to avoid silently dropping partial patterns.
    """
    from ingestion.router import frontmatter_to_doc  # uses yaml.safe_load internally

    file_name = os.path.basename(file_path)
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        _log(f"  [ERROR] Cannot read {file_name}: {e}")
        return []

    doc = frontmatter_to_doc(text)
    if doc is None:
        _log(f"  [WARN] {file_name}: no content after frontmatter parsing — skipped")
        return []

    meta = doc.metadata
    missing = _REQUIRED_FIELDS - set(meta.keys())
    if missing:
        _log(f"  [WARN] {file_name}: missing required fields {missing} — ingesting anyway")

    meta.setdefault("type", "vulnerability_pattern")
    meta["source"] = source
    meta["file_name"] = file_name
    meta.setdefault("page", 0)

    return [make_frontmatter(meta, doc.page_content)]
