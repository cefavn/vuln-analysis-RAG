# builder.py - Build vector database from documents (PDF, TXT, JSON, C, .build)
#
# Pipeline:
#   1. Standardize  → convert all sources to Markdown
#   2. Smart-chunk  → MarkdownHeaderTextSplitter at heading boundaries (parent sections)
#   3. Child-split  → RecursiveCharacterTextSplitter for precise embedding (child chunks)
#   4. Metadata     → wrap with source, page, section path, parent_content
#   5. Upsert       → embed + push to Pinecone
#
# Document types produced:
#   vulnerability_pattern  JSON vuln cards         → atomic
#   reference_document     PDF / TXT / MD           → Parent-Child
#   c_overview             decompiled C file header → atomic
#   c_constants            #define groups           → atomic
#   c_struct               typedef struct blocks    → atomic
#   c_function             function + comment       → Parent-Child if large
#   c_section              other C sections         → Parent-Child if large
#   build_config           .build global params     → atomic
#   build_image            [virtual=...] blocks     → atomic
#   build_script           [+script] blocks         → atomic
#   build_section          ### Section ### blocks   → Parent-Child if large
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import re
import hashlib
from statistics import median
from typing import Any, Dict, List, Optional, Tuple

import fitz  # PyMuPDF
import pytesseract
from PIL import Image

from langchain_community.document_loaders import TextLoader
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

pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

os.environ.setdefault("PINECONE_API_KEY", PINECONE_API_KEY)
os.environ.setdefault("OPENAI_API_KEY", OPENAI_API_KEY)

_HEADER_SPLIT_ON = [("#", "h1"), ("##", "h2"), ("###", "h3")]

# Document types kept atomic (not further child-split)
_ATOMIC_TYPES = frozenset({
    "vulnerability_pattern",
    "c_overview", "c_constants", "c_struct",
    "build_config", "build_image", "build_script",
})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_id(source: str, page: int, chunk_id: int) -> str:
    """Deterministic, collision-resistant chunk ID."""
    return hashlib.sha256(f"{source}-{page}-{chunk_id}".encode()).hexdigest()


def _section_path(meta: Dict) -> str:
    """Build a human-readable heading path from h1/h2/h3 metadata."""
    return " > ".join(meta[k] for k in ("h1", "h2", "h3") if meta.get(k))


# ---------------------------------------------------------------------------
# Step 1a: PDF → Markdown  (layout-aware heading detection)
# ---------------------------------------------------------------------------

def _pdf_page_to_markdown(page: fitz.Page) -> str:
    """
    Convert one PDF page to Markdown using font-size heading detection.

    Algorithm:
    - Extract all text spans with font size and bold flag.
    - Calculate body font size = median of all span sizes on the page.
    - Lines whose max span size >= 1.4× body → ## heading.
    - Lines whose max span size >= 1.15× body OR bold → ### heading.
    - Everything else → plain paragraph text.

    This preserves semantic structure for MarkdownHeaderTextSplitter.
    """
    try:
        blocks = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)["blocks"]
    except Exception:
        return page.get_text()  # fallback to raw text

    # Collect font sizes for body-size estimation
    sizes: List[float] = [
        span["size"]
        for block in blocks if block.get("type") == 0
        for line in block.get("lines", [])
        for span in line.get("spans", [])
        if span.get("text", "").strip()
    ]
    if not sizes:
        return ""

    body_size = median(sizes)

    output_blocks: List[str] = []
    for block in blocks:
        if block.get("type") != 0:  # skip image blocks
            continue

        block_lines: List[str] = []
        for line in block.get("lines", []):
            text_parts: List[str] = []
            max_size = 0.0
            is_bold = False

            for span in line.get("spans", []):
                t = span.get("text", "")
                if not t.strip():
                    continue
                text_parts.append(t)
                max_size = max(max_size, span.get("size", 12.0))
                font = span.get("font", "").lower()
                if "bold" in font or "heavy" in font or "black" in font:
                    is_bold = True

            line_text = "".join(text_parts).strip()
            if not line_text:
                continue

            ratio = max_size / body_size if body_size > 0 else 1.0
            if ratio >= 1.4:
                block_lines.append(f"## {line_text}")
            elif ratio >= 1.15 or is_bold:
                block_lines.append(f"### {line_text}")
            else:
                block_lines.append(line_text)

        if block_lines:
            output_blocks.append("\n".join(block_lines))

    return "\n\n".join(output_blocks)


# ---------------------------------------------------------------------------
# Step 1b: JSON vulnerability pattern card → Markdown
# ---------------------------------------------------------------------------

def _pattern_to_markdown(pattern: Dict[str, Any]) -> str:
    """
    Convert a structured vulnerability pattern card to well-formed Markdown.

    Using proper #/##/### headings allows MarkdownHeaderTextSplitter to
    split large patterns (root_cause.json variants) at semantic boundaries
    while keeping small patterns (buffer_overflow.json) atomic.
    """
    lines: List[str] = []

    name = pattern.get("pattern_name", pattern.get("name", "Unknown Pattern"))
    doc_id = pattern.get("doc_id", "")
    severity = pattern.get("severity", "")
    cwes = ", ".join(pattern.get("cwe", []))
    tags = ", ".join(pattern.get("tags", []))

    lines.append(f"# {name}")
    meta_parts = [p for p in [
        f"**ID:** {doc_id}" if doc_id else "",
        f"**Severity:** {severity}" if severity else "",
        f"**CWE:** {cwes}" if cwes else "",
    ] if p]
    if meta_parts:
        lines.append(" | ".join(meta_parts))
    if tags:
        lines.append(f"**Tags:** {tags}")
    lines.append("")

    if pattern.get("root_cause_class"):
        lines += ["## Root Cause", pattern["root_cause_class"], ""]

    if pattern.get("description"):
        lines += ["## Description", pattern["description"], ""]

    if pattern.get("apply_when"):
        lines += ["## Apply When", pattern["apply_when"], ""]

    if pattern.get("not_this_pattern"):
        lines += ["## Not This Pattern", pattern["not_this_pattern"], ""]

    # Subtypes (buffer_overflow / integer_overflow style)
    if pattern.get("subtypes"):
        lines.append("## Subtypes")
        for st in pattern["subtypes"]:
            lines.append(f"### {st.get('name', 'Subtype')}")
            if st.get("trigger"):
                lines.append(f"**Trigger:** {st['trigger']}")
            lines.append("")

    # Variants (root_cause.json style)
    if pattern.get("variants"):
        lines.append("## Variants")
        for v in pattern["variants"]:
            vid = v.get("id", "")
            vname = v.get("name", "")
            lines.append(f"### {vid}: {vname}")
            if v.get("root_cause"):
                lines.append(f"**Root cause:** {v['root_cause']}")
            if v.get("dangerous_pattern"):
                lines.append(f"**Pattern:** `{v['dangerous_pattern']}`")
            if v.get("trigger"):
                lines.append(f"**Trigger:** {v['trigger']}")
            if v.get("note"):
                lines.append(f"*{v['note']}*")
            lines.append("")

    # CVE evidence
    if pattern.get("cve_evidence"):
        lines.append("## CVE Evidence")
        for cve in pattern["cve_evidence"]:
            cve_id = cve.get("cve", "")
            cvss = cve.get("cvss", "")
            product = cve.get("product", "")
            desc = cve.get("root_cause", cve.get("one_line", ""))
            lesson = cve.get("key_lesson", cve.get("root_cause_match", ""))
            lines.append(f"### {cve_id}")
            detail_parts = [p for p in [
                f"**CVSS:** {cvss}" if cvss else "",
                f"**Product:** {product}" if product else "",
            ] if p]
            if detail_parts:
                lines.append(" | ".join(detail_parts))
            if desc:
                lines.append(f"**Root cause:** {desc}")
            if lesson:
                lines.append(f"**Key lesson:** {lesson}")
            lines.append("")

    # Binary indicators
    if pattern.get("binary_indicators"):
        lines.append("## Binary Indicators")
        for ind in pattern["binary_indicators"]:
            lines.append(f"- {ind}")
        lines.append("")

    return "\n".join(lines)


def _load_json_pattern_file(json_path: str) -> List[Document]:
    """
    Load a vulnerability pattern JSON file as Markdown Documents.
    Single-object files → 1 document.
    Array files (root_cause.json) → N documents, one per pattern.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    patterns = data if isinstance(data, list) else [data]
    file_name = os.path.basename(json_path)
    documents: List[Document] = []

    for i, pattern in enumerate(patterns):
        text = _pattern_to_markdown(pattern)
        if not text.strip():
            continue
        documents.append(Document(
            page_content=text,
            metadata={
                "source": json_path,
                "file_name": file_name,
                "type": "vulnerability_pattern",
                "doc_id": pattern.get("doc_id", f"{file_name}-{i}"),
                "severity": pattern.get("severity", ""),
                "tags": ", ".join(pattern.get("tags", [])),
                "page": i,
            }
        ))

    return documents


# ---------------------------------------------------------------------------
# Step 1c: Decompiled C source → Markdown Documents
# ---------------------------------------------------------------------------

# Matches /* ====...==== */ style section dividers.
# The closing */ may appear on the same line as the last ==== OR several
# description lines later (e.g. SECTION 2 adds extra context after the ====).
# We only require ====...==== at the opening; anything up to the next */ is consumed.
_C_SECTION_DIV_RE = re.compile(r"/\*\s*={10,}.*?\*/", re.DOTALL)

# Extract the section title: the first `* TEXT` line right after the opening ====
_C_SECTION_TITLE_RE = re.compile(
    r"/\*\s*={10,}\s*\n"
    r"\s*\*\s*(.+?)\s*\n"   # title line (captured)
    r".*?\*/",               # rest of the comment until */
    re.DOTALL,
)

# Top-level (unindented) block comment
_C_TOP_COMMENT_RE = re.compile(r"^/\*.*?\*/", re.MULTILINE | re.DOTALL)

# typedef struct ... } name; (handles one level of nested braces)
_C_STRUCT_RE = re.compile(
    r"typedef\s+struct\s+\w*\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}\s*(\w+)\s*;",
    re.DOTALL,
)


def _scan_balanced_braces(text: str, pos: int) -> int:
    """Return the index after the `}` that closes the `{` at pos."""
    depth = 0
    i = pos
    in_block = in_line = in_str = False
    sc = ""
    while i < len(text):
        c = text[i]
        if in_block:
            if c == "*" and i + 1 < len(text) and text[i + 1] == "/":
                in_block = False
                i += 2
                continue
        elif in_line:
            if c == "\n":
                in_line = False
        elif in_str:
            if c == "\\" and i + 1 < len(text):
                i += 2
                continue
            if c == sc:
                in_str = False
        else:
            if c == "/" and i + 1 < len(text):
                if text[i + 1] == "*":
                    in_block = True
                    i += 2
                    continue
                elif text[i + 1] == "/":
                    in_line = True
            elif c in ('"', "'"):
                in_str = True
                sc = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return len(text)


def _clean_block_comment(s: str) -> str:
    """Strip /* */ markers and leading `*` from a C block comment."""
    out = []
    for line in s.split("\n"):
        line = line.strip()
        if line.startswith("/*"):
            line = line[2:].strip()
        if line.endswith("*/"):
            line = line[:-2].strip()
        if line.startswith("*"):
            line = line[1:].strip()
        if re.match(r"^[=\- ]+$", line):
            continue
        if line:
            out.append(line)
    return "\n".join(out)


def _c_binary_meta(text: str) -> Dict[str, str]:
    """Pull SHA256, MD5, and binary name from the file header comment."""
    meta: Dict[str, str] = {}
    m = re.search(r"SHA256:\s*([0-9a-f]{64})", text, re.IGNORECASE)
    if m:
        meta["binary_sha256"] = m.group(1)
    m = re.search(r"(?:MD5|Binary MD5):\s*([0-9a-f]{32})", text, re.IGNORECASE)
    if m:
        meta["binary_md5"] = m.group(1)
    m = re.search(r"^\s*\*?\s*Binary:\s*(.+?)(?:\s*\(|\s*$)", text, re.MULTILINE)
    if m:
        meta["binary_name"] = m.group(1).strip()
    return meta


def _c_extract_functions(section_text: str) -> List[Tuple[str, str, str]]:
    """
    Extract (func_name, clean_comment, full_source) for each function in a C section.

    Looks for unindented block comments immediately followed by a function
    signature (return_type name(params)) and opening brace, then uses a
    brace-balanced scanner to capture the complete function body.
    """
    results: List[Tuple[str, str, str]] = []
    seen: set = set()

    # Function signature regex — matched against text right after a block comment
    _SIG_RE = re.compile(
        r"\s*\n"
        r"((?:static\s+)?"
        r"(?:(?:const|unsigned|signed|long|short|inline)\s+)*"
        r"(?:void|int|char|size_t|ssize_t|u?int\d+_t|[\w_]+)\s*\**\s*"
        r"(\w+)\s*"
        r"\([^;{}]*?\))"          # (params) — no semicolons or braces
        r"(?:\s*\n\s*|\s*)\{",    # optional whitespace then opening brace
        re.DOTALL,
    )

    for cm in _C_TOP_COMMENT_RE.finditer(section_text):
        # Only match comments starting at column 0 (preceded by \n or start)
        start = cm.start()
        if start > 0 and section_text[start - 1] != "\n":
            continue

        rest = section_text[cm.end():]
        sm = _SIG_RE.match(rest)
        if not sm:
            continue

        func_name = sm.group(2)
        full_sig = sm.group(1)

        # Reject non-functions
        if any(kw in full_sig for kw in ("typedef", "extern", "struct ")):
            continue
        if func_name in seen:
            continue
        seen.add(func_name)

        # Locate the opening brace in the original text and scan for its match
        brace_pos = section_text.find("{", cm.end())
        if brace_pos == -1 or brace_pos - cm.end() > 400:
            continue

        end = _scan_balanced_braces(section_text, brace_pos)
        results.append((
            func_name,
            _clean_block_comment(cm.group(0)),
            section_text[cm.start():end],
        ))

    return results


def _c_to_markdown_docs(c_path: str) -> List[Document]:
    """
    Convert a decompiled C source file to structured Markdown Documents.

    Produces one document per logical unit:
      - c_overview  : file-level comment (architecture, trust boundary, binary hash)
      - c_constants : groups of related #define constants
      - c_struct    : each typedef struct with its security annotation comment
      - c_function  : each function with its audit comment and full source
      - c_section   : any other named sections (forward decls, globals)
    """
    with open(c_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    fname = os.path.basename(c_path)
    bmeta = _c_binary_meta(text)
    base: Dict[str, Any] = {
        "source": c_path, "file_name": fname,
        "type": "decompiled_c", "page": 0,
        **bmeta,
    }
    docs: List[Document] = []

    # ── 1. File overview: leading block comment ──────────────────────────────
    m = re.match(r"\s*(/\*.*?\*/)", text, re.DOTALL)
    if m:
        clean = _clean_block_comment(m.group(1))
        lines = [f"# {fname}"]
        if bmeta.get("binary_name"):
            lines.append(f"**Binary:** {bmeta['binary_name']}")
        if bmeta.get("binary_sha256"):
            lines.append(f"**SHA256:** `{bmeta['binary_sha256']}`")
        lines.extend(["", clean])
        docs.append(Document(
            page_content="\n".join(lines),
            metadata={**base, "type": "c_overview", "section": "overview"},
        ))

    # ── 2. Split into sections on /* ====...==== */ dividers ─────────────────
    section_parts = _C_SECTION_DIV_RE.split(text)
    section_titles = [
        m2.group(1).strip() for m2 in _C_SECTION_TITLE_RE.finditer(text)
    ]

    # section_parts[0] = preamble; section_parts[i+1] = content of section i
    for title, content in zip(section_titles, section_parts[1:]):
        title_up = title.upper()

        # ── Constants: group #define lines by preceding comment labels ────
        if "CONSTANT" in title_up or "#DEFINE" in title_up:
            current_group, lines_buf = "General", []

            def _flush_group(gname: str, lbuf: List[str]) -> None:
                body = "\n".join(lbuf).strip()
                if body:
                    docs.append(Document(
                        page_content=f"## Constants: {gname}\n\n```c\n{body}\n```",
                        metadata={**base, "type": "c_constants",
                                  "section": f"constants/{gname}"},
                    ))

            for line in content.split("\n"):
                s = line.strip()
                # Single-line comment used as group label
                if re.match(r"^/\*.*\*/$", s) and "define" not in s.lower():
                    label = re.sub(r"^/\*+|\*+/$", "", s).strip().strip("=- \t")
                    if label:
                        _flush_group(current_group, lines_buf)
                        lines_buf = []
                        current_group = label
                elif s.startswith("#define"):
                    lines_buf.append(line)
            _flush_group(current_group, lines_buf)

        # ── Data structures: one chunk per typedef struct ─────────────────
        elif "DATA STRUCT" in title_up or title_up.startswith("STRUCT"):
            # Include nested-brace structs (vionet_hdr has uint32_t lengths[128])
            struct_re = re.compile(
                r"(/\*.*?\*/\s*)?"
                r"typedef\s+struct\s+[\w_]*\s*\{.*?\}\s*([\w_]+)\s*;",
                re.DOTALL,
            )
            for sm in struct_re.finditer(content):
                sname = sm.group(2)
                comment = _clean_block_comment(sm.group(1) or "")
                stext = sm.group(0)
                body = f"## Struct: {sname}\n\n{comment}\n\n```c\n{stext}\n```" \
                       if comment else f"## Struct: {sname}\n\n```c\n{stext}\n```"
                docs.append(Document(
                    page_content=body,
                    metadata={**base, "type": "c_struct",
                              "section": f"struct/{sname}", "struct_name": sname},
                ))

        # ── Function sections (SECTION N: ...): one chunk per function ────
        elif re.match(r"SECTION\s+\d+", title_up) or "FUNCTION" in title_up:
            for fn, comment, source in _c_extract_functions(content):
                md_parts = [f"## Function: {fn}  [{title}]"]
                if comment:
                    md_parts.extend(["", comment, ""])
                md_parts.append(f"```c\n{source}\n```")
                docs.append(Document(
                    page_content="\n".join(md_parts),
                    metadata={
                        **base, "type": "c_function",
                        "section": f"function/{fn}",
                        "func_name": fn, "c_section": title,
                    },
                ))

        # ── Everything else: keep as a labelled section ───────────────────
        else:
            body = content.strip()
            if body:
                docs.append(Document(
                    page_content=f"## {title}\n\n```c\n{body}\n```",
                    metadata={**base, "type": "c_section", "section": title},
                ))

    # ── Also scan the preamble for any functions (uncommon but possible) ──────
    seen_in_sections = {d.metadata.get("func_name") for d in docs if d.metadata.get("func_name")}
    for fn, comment, source in _c_extract_functions(section_parts[0]):
        if fn not in seen_in_sections:
            md_parts = [f"## Function: {fn}"]
            if comment:
                md_parts.extend(["", comment, ""])
            md_parts.append(f"```c\n{source}\n```")
            docs.append(Document(
                page_content="\n".join(md_parts),
                metadata={**base, "type": "c_function",
                          "section": f"function/{fn}", "func_name": fn},
            ))

    if not docs:
        docs.append(Document(page_content=text, metadata=base))

    return docs


# ---------------------------------------------------------------------------
# Step 1d: QNX .build image configuration file → Markdown Documents
# ---------------------------------------------------------------------------

# ### Section Name ### delimited by lines of # characters
_BUILD_SECT_RE = re.compile(
    r"^#{20,}\n"
    r"#{0,3}[ \t]*(.+?)[ \t]*#{0,3}?\n"
    r"#{20,}",
    re.MULTILINE,
)

# [optional attrs] name = { content \n}  or  name { content \n}
_BUILD_BLOCK_RE = re.compile(
    r"(?:(\[[^\]]*\])\s+)?"     # optional [attr=val ...]
    r"([\w./\-]+)\s*=?\s*\{\n"  # name = {\n  or  name {\n
    r"(.*?)\n\}",               # content \n}
    re.DOTALL,
)


def _build_to_markdown_docs(build_path: str) -> List[Document]:
    """
    Convert a QNX .build image configuration file to structured Markdown Documents.

    Produces:
      - build_config  : global image parameters (num_inodes, search paths)
      - build_image   : [virtual=...] boot image blocks
      - build_script  : [+script] startup script blocks
      - build_section : content between ### Section Name ### headers
                        (file mappings + inline embedded configs)

    This allows targeted retrieval for questions like:
      "What suid binaries are in the image?"
      "What is the boot startup sequence?"
      "Which hypervisor vdevs are loaded?"
      "What PAM config is used for SSH?"
    """
    with open(build_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    fname = os.path.basename(build_path)
    base: Dict[str, Any] = {
        "source": build_path, "file_name": fname,
        "type": "build_config", "page": 0,
    }
    docs: List[Document] = []

    # ── 1. Global config: image parameter lines ───────────────────────────────
    first_special = min(
        (m.start() for m in [
            _BUILD_SECT_RE.search(text),
            _BUILD_BLOCK_RE.search(text),
        ] if m),
        default=len(text),
    )
    config_lines = [
        line.strip()
        for line in text[:first_special].split("\n")
        if line.strip().startswith("[") and any(
            k in line for k in ("num_inodes", "num_sectors", "search", "image=", "prefix=")
        )
    ]
    if config_lines:
        md = (
            f"# {fname} — Image Configuration\n\n"
            "## Global Parameters\n\n"
            + "\n".join(f"- `{l}`" for l in config_lines)
        )
        docs.append(Document(
            page_content=md,
            metadata={**base, "type": "build_config", "section": "global_config"},
        ))

    # ── 2. Special blocks: [virtual=...] boot images and [+script] scripts ───
    for bm in _BUILD_BLOCK_RE.finditer(text):
        attrs = bm.group(1) or ""
        name = bm.group(2)
        content = bm.group(3)

        if "virtual=" in attrs:
            md = (
                f"# {fname} — Boot Image: {name}\n\n"
                f"**Attributes:** `{attrs}`\n\n"
                f"```\n{attrs} {name} = {{\n{content}\n}}\n```"
            )
            docs.append(Document(
                page_content=md,
                metadata={**base, "type": "build_image",
                          "section": f"boot_image/{name}", "block_name": name},
            ))
        elif "+script" in attrs:
            md = (
                f"# {fname} — Startup Script: {name}\n\n"
                f"```sh\n{content}\n```"
            )
            docs.append(Document(
                page_content=md,
                metadata={**base, "type": "build_script",
                          "section": f"startup_script/{name}", "block_name": name},
            ))

    # ── 3. Sections: ### Section Name ### delimited blocks ───────────────────
    section_matches = list(_BUILD_SECT_RE.finditer(text))
    for idx, sm in enumerate(section_matches):
        section_name = sm.group(1).strip()
        sec_start = sm.end()
        sec_end = section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(text)
        section_content = text[sec_start:sec_end]

        if not section_content.strip():
            continue

        md_lines = [f"# {fname} — {section_name}", ""]

        # Extract named inline content blocks (embedded file contents)
        inline_spans: List[Tuple[int, int]] = []
        for ib in _BUILD_BLOCK_RE.finditer(section_content):
            attrs = ib.group(1) or ""
            # Skip virtual/script blocks already handled above
            if "virtual=" in attrs or "+script" in attrs:
                continue
            iname = ib.group(2)
            icontent = ib.group(3)
            inline_spans.append((ib.start(), ib.end()))

            md_lines.append(f"### Embedded: {iname}")
            if attrs:
                md_lines.append(f"**Attrs:** `{attrs}`")
            md_lines.append(f"```\n{icontent}\n```")
            md_lines.append("")

        # File mapping lines (target=source entries outside inline blocks)
        mapping_lines: List[str] = []
        in_inline = False
        for line in section_content.split("\n"):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            # Skip lines that open/close inline blocks
            if re.search(r"=\s*\{$|\{$", s):
                in_inline = True
                continue
            if s == "}":
                in_inline = False
                continue
            if in_inline:
                continue
            # Include file mapping lines: contain = but not block content
            if "=" in s and "{" not in s:
                mapping_lines.append(s)
            elif s.startswith("[") and "{" not in s:
                mapping_lines.append(s)

        if mapping_lines:
            md_lines.append("### File Mappings")
            md_lines.append("```")
            md_lines.extend(mapping_lines)
            md_lines.append("```")

        # Infer document type for security-relevant sections
        sname_lower = section_name.lower()
        if "suid" in sname_lower:
            doc_type = "build_suid"
        elif "hypervisor" in sname_lower or "qvm" in sname_lower:
            doc_type = "build_hypervisor"
        else:
            doc_type = "build_section"

        docs.append(Document(
            page_content="\n".join(md_lines),
            metadata={
                **base, "type": doc_type,
                "section": f"section/{section_name}",
                "section_name": section_name,
            },
        ))

    if not docs:
        docs.append(Document(page_content=text, metadata=base))

    return docs


# ---------------------------------------------------------------------------
# DocumentBuilder
# ---------------------------------------------------------------------------

class DocumentBuilder:
    """Load → Markdown → Smart-chunk (Parent-Child) → Embed → Upsert."""

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
        # Reused across all chunking calls
        self._header_splitter = MarkdownHeaderTextSplitter(
            headers_to_split_on=_HEADER_SPLIT_ON,
            strip_headers=False,  # keep heading text in chunk content for richer embeddings
        )
        self._child_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHILD_CHUNK_SIZE,
            chunk_overlap=CHILD_CHUNK_OVERLAP,
            separators=["\n\n", "\n", ". ", " ", ""],
        )
        # Fallback splitter for oversized content with no headings
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
        paths = [
            os.path.join(DOCS_DIR, f)
            for f in sorted(os.listdir(DOCS_DIR))
            if f.lower().endswith((".pdf", ".txt", ".json", ".md", ".c", ".build"))
        ]
        print(f"Discovered {len(paths)} document(s) in {DOCS_DIR}")
        return paths

    # ------------------------------------------------------------------
    # Step 1: Load & standardize to Markdown Documents
    # ------------------------------------------------------------------

    def _extract_pdf(self, pdf_path: str) -> List[Document]:
        """
        Extract PDF as Markdown Documents (one Document per page).
        Text-based pages → font-size heading detection → Markdown.
        Image/scanned pages → Tesseract OCR → plain text fallback.
        """
        pdf = fitz.open(pdf_path)
        total = len(pdf)
        file_name = os.path.basename(pdf_path)
        print(f"  Processing {total} pages: {file_name}")

        documents: List[Document] = []
        for page_num in range(total):
            page = pdf[page_num]
            raw_text = page.get_text()

            if len(raw_text.strip()) < 100:
                # Scanned image page — use OCR, result is plain text
                mat = fitz.Matrix(2.0, 2.0)
                pix = page.get_pixmap(matrix=mat)
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                try:
                    md_text = pytesseract.image_to_string(img, lang="eng")
                except Exception as e:
                    print(f"    OCR failed page {page_num}: {e}")
                    md_text = ""
            else:
                # Text-based page — convert to Markdown with heading detection
                md_text = _pdf_page_to_markdown(page)
                if not md_text.strip():
                    md_text = raw_text  # final fallback

            if md_text.strip():
                documents.append(Document(
                    page_content=md_text,
                    metadata={
                        "source": pdf_path,
                        "file_name": file_name,
                        "type": "reference_document",
                        "page": page_num,
                    }
                ))

        pdf.close()
        print(f"  Extracted {len(documents)} pages with content")
        return documents

    def load_documents(self) -> List[Document]:
        """Load all configured documents and normalize to Markdown."""
        all_docs: List[Document] = []
        print(f"Loading {len(self.document_paths)} document(s)...")

        for path in self.document_paths:
            if not os.path.exists(path):
                print(f"  [SKIP] Not found: {path}")
                continue
            try:
                ext = os.path.splitext(path)[1].lower()
                if ext == ".pdf":
                    docs = self._extract_pdf(path)
                elif ext == ".txt":
                    loader = TextLoader(path, encoding="utf-8")
                    docs = loader.load()
                    for d in docs:
                        d.metadata.setdefault("type", "reference_document")
                        d.metadata.setdefault("file_name", os.path.basename(path))
                        d.metadata.setdefault("source", path)
                elif ext == ".md":
                    with open(path, "r", encoding="utf-8") as f:
                        text = f.read()
                    docs = [Document(
                        page_content=text,
                        metadata={
                            "source": path,
                            "file_name": os.path.basename(path),
                            "type": "reference_document",
                            "page": 0,
                        }
                    )]
                elif ext == ".json":
                    docs = _load_json_pattern_file(path)
                    print(f"  Loaded {len(docs)} pattern(s) from {os.path.basename(path)}")
                elif ext == ".c":
                    docs = _c_to_markdown_docs(path)
                    print(f"  Extracted {len(docs)} chunk(s) from {os.path.basename(path)}")
                elif ext == ".build":
                    docs = _build_to_markdown_docs(path)
                    print(f"  Extracted {len(docs)} chunk(s) from {os.path.basename(path)}")
                else:
                    print(f"  [SKIP] Unsupported type: {path}")
                    continue

                if not any(d.page_content.strip() for d in docs):
                    print(f"  [SKIP] No content: {path}")
                    continue

                all_docs.extend(docs)
            except Exception as e:
                print(f"  [ERROR] {os.path.basename(path)}: {e}")

        if not all_docs:
            raise ValueError(f"No documents loaded from {DOCS_DIR}")
        return all_docs

    # ------------------------------------------------------------------
    # Steps 2 & 3: Smart-chunk (Parent-Child)
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
        parent_id = _make_id(
            base_meta.get("source", ""),
            base_meta.get("page", 0),
            abs(hash(section_meta.get("section", "") + str(base_meta.get("page", 0)))) % 1_000_000,
        )
        # Truncate to Pinecone metadata limit (40 KB total per vector; conservative cap)
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
            # No heading structure — use fallback splitter directly
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
                # Section fits in one chunk — parent == child, no redundancy
                results.append(Document(page_content=section_text, metadata=section_meta))
            else:
                # Section is large — child-split and embed parent context
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

        # Assign sequential chunk_ids and text_length
        for i, doc in enumerate(result):
            doc.metadata["chunk_id"] = i
            doc.metadata.setdefault("text_length", len(doc.page_content))

        n_atomic   = len(atomic)
        n_children = sum(1 for d in result if "parent_id" in d.metadata)
        n_sections = len(result) - n_atomic - n_children
        print(f"  Chunks: {len(result)} total "
              f"({n_atomic} atomic | {n_sections} section chunks | {n_children} child chunks)")
        return result

    # ------------------------------------------------------------------
    # Steps 4 & 5: Embed + Upsert
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

        print(f"\n[3/3] Embedding and upserting {len(splits)} chunks to '{self.index_name}'...")
        ids = [
            _make_id(
                doc.metadata.get("source", "unknown"),
                doc.metadata.get("page", 0),
                doc.metadata.get("chunk_id", i),
            )
            for i, doc in enumerate(splits)
        ]

        vectorstore = PineconeVectorStore.from_documents(
            documents=splits,
            embedding=self.embeddings,
            ids=ids,
            index_name=self.index_name,
        )

        print("\n" + "=" * 60)
        print("Vector database built successfully.")
        print(f"  Index : {self.index_name}")
        print(f"  Chunks: {len(splits)}")
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
            base_meta = {
                "source": source_name,
                "file_name": source_name,
                "type": "analysis_result",
                "page": 0,
            }
            if metadata:
                base_meta.update(metadata)

            doc = Document(page_content=text_content, metadata=base_meta)
            chunks = self._chunk_document(doc) if len(text_content) > CHILD_CHUNK_SIZE else [doc]

            for i, chunk in enumerate(chunks):
                chunk.metadata.setdefault("chunk_id", i)
                chunk.metadata.setdefault("text_length", len(chunk.page_content))

            ids = [
                _make_id(
                    chunk.metadata.get("source", source_name),
                    chunk.metadata.get("page", 0),
                    chunk.metadata.get("chunk_id", i),
                )
                for i, chunk in enumerate(chunks)
            ]

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
            }
        except Exception as e:
            return {"status": "error", "message": f"Failed to add: {e}"}


if __name__ == "__main__":
    builder = DocumentBuilder()
    builder.build_and_upsert()
    print("Done.")
