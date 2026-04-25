# converters/c_converter.py — Decompiled C source → Markdown+frontmatter converter.
#
# Parses the structured comment/section layout used in QNX decompiled binaries:
#   /* ====================
#    * SECTION TITLE
#    * ==================== */
#
# Produces one frontmatter-wrapped Markdown string per logical unit:
#   c_overview   — file-level header comment (binary hash, architecture notes)
#   c_constants  — groups of #define constants (one group per comment label)
#   c_struct     — each typedef struct (balanced-brace scanner handles any nesting depth)
#   c_function   — each function with its audit comment and full source
#   c_section    — any other named section (forward decls, globals)
import os
import re
from typing import Any, Dict, List, Tuple

from converters.utils import make_frontmatter

# ---------------------------------------------------------------------------
# Section-level regexes
# ---------------------------------------------------------------------------

# Matches /* ====...==== */ style section dividers (opening ==== required;
# the rest of the comment up to the closing */ is consumed).
_C_SECTION_DIV_RE = re.compile(r"/\*\s*={10,}.*?\*/", re.DOTALL)

# Captures the section title: the first `* TEXT` line right after ====
_C_SECTION_TITLE_RE = re.compile(
    r"/\*\s*={10,}\s*\n"
    r"\s*\*\s*(.+?)\s*\n"
    r".*?\*/",
    re.DOTALL,
)

# Top-level (column-0) block comment used as function/struct preamble
_C_TOP_COMMENT_RE = re.compile(r"^/\*.*?\*/", re.MULTILINE | re.DOTALL)

# Matches the opening of a typedef struct (optional leading block comment consumed)
_TYPEDEF_OPEN_RE = re.compile(
    r"(/\*.*?\*/\s*)?typedef\s+struct\s+[\w_]*\s*\{",
    re.DOTALL,
)

# Function signature right after a block comment
_SIG_RE = re.compile(
    r"\s*\n"
    r"((?:static\s+)?"
    r"(?:(?:const|unsigned|signed|long|short|inline)\s+)*"
    r"(?:void|int|char|size_t|ssize_t|u?int\d+_t|[\w_]+)\s*\**\s*"
    r"(\w+)\s*"
    r"\([^;{}]*?\))"
    r"(?:\s*\n\s*|\s*)\{",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def convert_c(file_path: str, source: str) -> List[str]:
    """
    Convert a decompiled C source file to a list of Markdown+frontmatter strings.

    Args:
        file_path: Absolute path to the .c file.
        source:    Canonical source identifier.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    fname = os.path.basename(file_path)
    bmeta = _binary_meta(text)
    base: Dict[str, Any] = {
        "source": source,
        "file_name": fname,
        "type": "decompiled_c",
        "page": 0,
        **bmeta,
    }

    results: List[str] = []

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
        meta = {**base, "type": "c_overview", "section": "overview"}
        results.append(make_frontmatter(meta, "\n".join(lines)))

    # ── 2. Split into sections on /* ====...==== */ dividers ─────────────────
    section_parts = _C_SECTION_DIV_RE.split(text)
    section_titles = [
        m2.group(1).strip() for m2 in _C_SECTION_TITLE_RE.finditer(text)
    ]

    seen_funcs: set = set()

    for title, content in zip(section_titles, section_parts[1:]):
        title_up = title.upper()

        if "CONSTANT" in title_up or "#DEFINE" in title_up:
            for group_meta, group_content in _parse_constants(content):
                meta = {**base, "type": "c_constants", "section": f"constants/{group_meta}"}
                body = f"## Constants: {group_meta}\n\n```c\n{group_content}\n```"
                results.append(make_frontmatter(meta, body))

        elif "DATA STRUCT" in title_up or title_up.startswith("STRUCT"):
            for sname, comment, stext in _parse_structs(content):
                meta = {**base, "type": "c_struct", "section": f"struct/{sname}", "struct_name": sname}
                body = (
                    f"## Struct: {sname}\n\n{comment}\n\n```c\n{stext}\n```"
                    if comment
                    else f"## Struct: {sname}\n\n```c\n{stext}\n```"
                )
                results.append(make_frontmatter(meta, body))

        elif re.match(r"SECTION\s+\d+", title_up) or "FUNCTION" in title_up:
            for fn, comment, fsource in _extract_functions(content):
                seen_funcs.add(fn)
                md_parts = [f"## Function: {fn}  [{title}]"]
                if comment:
                    md_parts.extend(["", comment, ""])
                md_parts.append(f"```c\n{fsource}\n```")
                meta = {
                    **base,
                    "type": "c_function",
                    "section": f"function/{fn}",
                    "func_name": fn,
                    "c_section": title,
                }
                results.append(make_frontmatter(meta, "\n".join(md_parts)))

        else:
            body = content.strip()
            if body:
                meta = {**base, "type": "c_section", "section": title}
                results.append(make_frontmatter(meta, f"## {title}\n\n```c\n{body}\n```"))

    # ── 3. Preamble scan: block-commented functions before the first divider ───
    # When no section dividers exist, section_parts[0] IS the full file text,
    # so this scan covers the entire file for the common case.
    for fn, comment, fsource in _extract_functions(section_parts[0]):
        if fn not in seen_funcs:
            seen_funcs.add(fn)
            md_parts = [f"## Function: {fn}"]
            if comment:
                md_parts.extend(["", comment, ""])
            md_parts.append(f"```c\n{fsource}\n```")
            meta = {**base, "type": "c_function", "section": f"function/{fn}", "func_name": fn}
            results.append(make_frontmatter(meta, "\n".join(md_parts)))

    # ── 4. Bare-function fallback: runs only when no functions found yet ──────
    # Handles decompiler outputs that omit block comments entirely (e.g. some
    # Ghidra exports) or use // ===== dividers that our section regex misses.
    # Uses a signature-only scanner — no preceding comment required.
    if not any("c_function" in r for r in results):
        for fn, fsource in _extract_bare_functions(text, seen_funcs):
            md_parts = [f"## Function: {fn}", "", f"```c\n{fsource}\n```"]
            meta = {**base, "type": "c_function", "section": f"function/{fn}", "func_name": fn}
            results.append(make_frontmatter(meta, "\n".join(md_parts)))

    # ── Fallback: if nothing at all was extracted, emit raw text ─────────────
    if not results:
        meta = {**base, "type": "c_section", "section": "raw"}
        results.append(make_frontmatter(meta, text))

    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

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


def _binary_meta(text: str) -> Dict[str, str]:
    """Extract SHA256, MD5, and binary name from the file header comment."""
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


def _parse_constants(content: str) -> List[Tuple[str, str]]:
    """
    Group #define lines by preceding single-line comment labels.
    Returns list of (group_name, joined_define_lines).
    """
    results: List[Tuple[str, str]] = []
    current_group = "General"
    lines_buf: List[str] = []

    def _flush() -> None:
        body = "\n".join(lines_buf).strip()
        if body:
            results.append((current_group, body))

    for line in content.split("\n"):
        s = line.strip()
        if re.match(r"^/\*.*\*/$", s) and "define" not in s.lower():
            label = re.sub(r"^/\*+|\*+/$", "", s).strip().strip("=- \t")
            if label:
                _flush()
                lines_buf.clear()
                current_group = label
        elif s.startswith("#define"):
            lines_buf.append(line)

    _flush()
    return results


def _parse_structs(content: str) -> List[Tuple[str, str, str]]:
    """
    Extract typedef structs using balanced-brace scanning (handles any nesting depth).
    Returns list of (struct_name, cleaned_comment, full_source_text).
    """
    results: List[Tuple[str, str, str]] = []
    for tm in _TYPEDEF_OPEN_RE.finditer(content):
        # tm.end() - 1 is the position of the `{` consumed by the pattern
        brace_end = _scan_balanced_braces(content, tm.end() - 1)
        suffix_m = re.match(r"\s*([\w_]+)\s*;", content[brace_end:])
        if not suffix_m:
            continue
        sname = suffix_m.group(1)
        stext = content[tm.start() : brace_end + suffix_m.end()]
        comment = _clean_block_comment(tm.group(1) or "")
        results.append((sname, comment, stext))
    return results


def _extract_functions(section_text: str) -> List[Tuple[str, str, str]]:
    """
    Extract (func_name, clean_comment, full_source) for each function.

    Looks for column-0 block comments immediately followed by a function
    signature, then uses balanced-brace scanning for the complete body.
    """
    results: List[Tuple[str, str, str]] = []
    seen: set = set()

    for cm in _C_TOP_COMMENT_RE.finditer(section_text):
        start = cm.start()
        if start > 0 and section_text[start - 1] != "\n":
            continue

        rest = section_text[cm.end():]
        sm = _SIG_RE.match(rest)
        if not sm:
            continue

        func_name = sm.group(2)
        full_sig = sm.group(1)

        if any(kw in full_sig for kw in ("typedef", "extern", "struct ")):
            continue
        if func_name in seen:
            continue
        seen.add(func_name)

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


# Matches top-level (column-0) function definitions without requiring a
# preceding block comment. Used as a last-resort fallback only.
_BARE_SIG_RE = re.compile(
    r"^(?:static\s+)?(?:(?:const|unsigned|signed|long|short|inline)\s+)*"
    r"(?:void|int|char|size_t|ssize_t|u?int\d+_t|[\w_]+)\s*\**\s*"
    r"(\w+)\s*\([^;{}\n]*?\)\s*\{",
    re.MULTILINE,
)
_C_KEYWORDS = frozenset({"if", "for", "while", "switch", "do", "else", "return"})


def _extract_bare_functions(text: str, exclude: set) -> List[Tuple[str, str]]:
    """
    Find functions by signature alone — no preceding block comment needed.

    This is a deliberately conservative fallback: it only runs when the primary
    block-comment scanner found zero functions, and it anchors to column-0
    signatures to avoid matching nested function-like patterns.

    Returns list of (func_name, full_source_text). No comment field.
    """
    results: List[Tuple[str, str]] = []
    seen: set = set()

    for m in _BARE_SIG_RE.finditer(text):
        fn = m.group(1)
        if fn in exclude or fn in seen or fn in _C_KEYWORDS:
            continue
        seen.add(fn)

        # The `{` was consumed by _BARE_SIG_RE; it's the last char of the match
        brace_pos = m.end() - 1
        end = _scan_balanced_braces(text, brace_pos)
        results.append((fn, text[m.start():end]))

    return results
