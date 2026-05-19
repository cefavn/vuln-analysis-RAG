# converters/c_converter.py — C source → Markdown+frontmatter converter.
#
# Two public entry points, one per source directory:
#
#   convert_decompiled()  — rag_docs/decompiled/
#     Regex-based extraction driven by /* ====...==== */ section dividers
#     as described in the decompiled/ SPEC.md. Handles c_overview (binary
#     hash + arch notes), c_constants, c_struct, c_function, c_section.
#
#   convert_c()           — rag_docs/other/
#     Tree-sitter AST path when tree-sitter + tree-sitter-c are installed,
#     with a block-comment scanner → bare-function regex fallback otherwise.
#
# Both paths inject a compact "file context" prefix (includes, macros,
# global variable declarations) into every c_function chunk so that the
# embedding vector captures the type environment even when the function
# body is child-split across multiple child chunks.
#
# Produces one frontmatter-wrapped Markdown string per logical unit:
#   c_overview   — file-level header comment (binary hash, architecture notes)
#   c_constants  — groups of #define constants
#   c_struct     — each typedef struct
#   c_function   — each function with audit comment, file context, and source
#   c_section    — any other named section (forward decls, globals)
import os
import re
from typing import Any, Dict, List, Tuple

from converters.utils import make_frontmatter

# ---------------------------------------------------------------------------
# Tree-sitter lazy loader (soft dependency — falls back to regex if absent)
# ---------------------------------------------------------------------------

_TS_PARSER = None
_TS_CHECKED = False


def _get_ts_parser():
    """Return a cached tree-sitter C Parser, or None if the package is missing."""
    global _TS_PARSER, _TS_CHECKED
    if _TS_CHECKED:
        return _TS_PARSER
    _TS_CHECKED = True
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_c as tsc
        _TS_PARSER = Parser(Language(tsc.language()))
    except Exception:
        pass
    return _TS_PARSER


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
# File-context extraction (used by both regex and tree-sitter paths)
# ---------------------------------------------------------------------------

def _extract_file_context(text: str, max_chars: int = 600) -> str:
    """
    Build a compact "file context" string from the preamble of a C file:
    global variable declarations, #define macros, and #include directives
    (in that priority order so the most semantically dense content survives
    the char cap).

    This string is prepended to every c_function chunk's page_content so
    that the embedding vector captures the type environment even after the
    function body is child-split.
    """
    first_func = _BARE_SIG_RE.search(text)
    preamble = text[: first_func.start()] if first_func else text[:4000]

    includes: List[str] = []
    defines: List[str] = []
    globals_: List[str] = []
    seen: set = set()

    for line in preamble.splitlines():
        s = line.strip()
        if not s or s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            continue

        if s.startswith("#include"):
            if s not in seen:
                seen.add(s)
                includes.append(s)

        elif s.startswith("#define") and not re.match(r"#define\s+_", s):
            name = s.split()[1] if len(s.split()) > 1 else ""
            if name and name not in seen:
                seen.add(name)
                defines.append(s)

        elif (s.endswith(";") and "typedef" not in s and "(" not in s
              and not s.startswith("#") and not s.startswith("}")):
            # Heuristic for global variable declaration: type [*]name [= value];
            decl_part = s.split("=")[0].strip().rstrip(";")
            tokens = decl_part.split()
            if len(tokens) >= 2 and tokens[-1].strip("*").isidentifier():
                if s not in seen:
                    seen.add(s)
                    globals_.append(s)

    # Priority: globals (type context) → defines (constants) → includes
    result = "\n".join(globals_ + defines + includes)
    return result[:max_chars]


# ---------------------------------------------------------------------------
# Tree-sitter helpers (original-source path)
# ---------------------------------------------------------------------------

def _ts_func_name(func_node, src: bytes) -> str:
    """Recursively find the function name identifier inside a function_definition."""
    def _find(node) -> str:
        if node.type == "identifier":
            return src[node.start_byte:node.end_byte].decode(errors="replace")
        for child in node.children:
            if child.type in (
                "function_declarator", "pointer_declarator",
                "parenthesized_declarator", "identifier",
            ):
                name = _find(child)
                if name:
                    return name
        return ""

    for child in func_node.children:
        if child.type in ("function_declarator", "pointer_declarator"):
            name = _find(child)
            if name:
                return name
    return "unknown"


def _ts_preceding_comment(func_node, named_siblings: list, src: bytes) -> str:
    """
    Return the cleaned block comment that is the IMMEDIATE preceding named
    sibling of func_node.  Strict adjacency prevents attaching a distant
    file-header comment to an unrelated function.
    """
    try:
        idx = named_siblings.index(func_node)
    except ValueError:
        return ""
    if idx > 0:
        prev = named_siblings[idx - 1]
        if prev.type == "comment":
            raw = src[prev.start_byte:prev.end_byte].decode(errors="replace")
            if raw.startswith("/*"):
                return _clean_block_comment(raw)
    return ""


def _ts_convert(
    text: str,
    fname: str,
    base: Dict[str, Any],
    file_ctx: str,
) -> List[str]:
    """
    Convert an original-source C file using tree-sitter AST.
    Called only when _get_ts_parser() returns non-None and the file has no
    /* ====...==== */ section dividers.

    Produces:
      c_overview   — block comments before the first declaration / function
      c_constants  — top-level #define / #define-function macros
      c_section    — global variable declarations (section="globals")
      c_function   — each function definition with file context injected
    """
    parser = _get_ts_parser()
    src = text.encode("utf-8")
    root = parser.parse(src).root_node
    named = [c for c in root.children if c.is_named]
    results: List[str] = []

    # ── 1. File overview: block comments before any declaration / function ──
    first_code_idx = next(
        (i for i, n in enumerate(named)
         if n.type in ("declaration", "function_definition")),
        len(named),
    )
    top_comments = [
        n for n in named[:first_code_idx]
        if n.type == "comment"
        and src[n.start_byte: n.start_byte + 2] == b"/*"
    ]
    if top_comments:
        cleaned = [
            _clean_block_comment(src[n.start_byte:n.end_byte].decode(errors="replace"))
            for n in top_comments
        ]
        body = f"# {fname}\n\n" + "\n\n---\n\n".join(c for c in cleaned if c)
        meta = {**base, "type": "c_overview", "section": "overview"}
        results.append(make_frontmatter(meta, body))

    # ── 2. Top-level #define macros → c_constants ──────────────────────────
    define_nodes = [
        n for n in named
        if n.type in ("preproc_def", "preproc_function_def")
    ]
    if define_nodes:
        defines_text = "\n".join(
            src[n.start_byte:n.end_byte].decode(errors="replace").strip()
            for n in define_nodes
        )
        meta = {**base, "type": "c_constants", "section": "constants/Defines"}
        body = f"## Constants: Defines\n\n```c\n{defines_text}\n```"
        results.append(make_frontmatter(meta, body))

    # ── 3. Global variable declarations → c_section(globals) ───────────────
    # Exclude function prototypes (declarations that contain a parenthesis).
    decl_nodes = [
        n for n in named
        if n.type == "declaration"
        and b"(" not in src[n.start_byte:n.end_byte]
    ]
    if decl_nodes:
        globals_text = "\n".join(
            src[n.start_byte:n.end_byte].decode(errors="replace").strip()
            for n in decl_nodes
        )
        meta = {**base, "type": "c_section", "section": "globals"}
        body = f"## Global Declarations\n\n```c\n{globals_text}\n```"
        results.append(make_frontmatter(meta, body))

    # ── 4. Function definitions → c_function ───────────────────────────────
    seen_funcs: set = set()
    for func_node in (n for n in named if n.type == "function_definition"):
        func_name = _ts_func_name(func_node, src)
        if func_name in seen_funcs:
            continue
        seen_funcs.add(func_name)

        func_text = src[func_node.start_byte:func_node.end_byte].decode(errors="replace")
        comment = _ts_preceding_comment(func_node, named, src)

        md_parts = [f"## Function: {func_name}"]
        if file_ctx:
            md_parts.append(f"\n*File context:*\n```c\n{file_ctx}\n```")
        if comment:
            md_parts.extend(["", comment, ""])
        md_parts.append(f"```c\n{func_text}\n```")

        meta = {
            **base,
            "type": "c_function",
            "section": f"function/{func_name}",
            "function_name": func_name,
        }
        results.append(make_frontmatter(meta, "\n".join(md_parts)))

    if not results:
        meta = {**base, "type": "c_section", "section": "raw"}
        results.append(make_frontmatter(meta, text))

    return results


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def convert_decompiled(file_path: str, source: str) -> List[str]:
    """
    Convert a decompiled C file (rag_docs/decompiled/) to Markdown+frontmatter strings.

    Expects the /* ====...==== */ section-divider structure defined in decompiled/SPEC.md.
    Produces type=decompiled chunks distinguished by section prefix:
    overview, constants/<group>, struct/<name>, function/<name>, or raw section title.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    fname = os.path.basename(file_path)
    bmeta = _binary_meta(text)
    base: Dict[str, Any] = {"source": source, "file_name": fname, "page": 0}
    results: List[str] = []

    def _build_func_md(fn: str, comment: str, fsource: str, title: str = "") -> str:
        heading = f"## Function: {fn}  [{title}]" if title else f"## Function: {fn}"
        parts = [heading]
        if comment:
            parts.extend(["", comment, ""])
        parts.append(f"```c\n{fsource}\n```")
        return "\n".join(parts)

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
        meta = {**base, "type": "decompiled", "section": "overview"}
        results.append(make_frontmatter(meta, "\n".join(lines)))

    # ── 2. Split on /* ====...==== */ section dividers ──────────────────────
    section_parts = _C_SECTION_DIV_RE.split(text)
    section_titles = [m2.group(1).strip() for m2 in _C_SECTION_TITLE_RE.finditer(text)]

    for title, content in zip(section_titles, section_parts[1:]):
        title_up = title.upper()

        if "CONSTANT" in title_up or "#DEFINE" in title_up:
            for group_meta, group_content in _parse_constants(content):
                meta = {**base, "type": "decompiled", "section": f"constants/{group_meta}"}
                body = f"## Constants: {group_meta}\n\n```c\n{group_content}\n```"
                results.append(make_frontmatter(meta, body))

        elif "DATA STRUCT" in title_up or title_up.startswith("STRUCT"):
            for sname, comment, stext in _parse_structs(content):
                meta = {**base, "type": "decompiled", "section": f"struct", "struct_name": sname}
                body = (
                    f"## Struct: {sname}\n\n{comment}\n\n```c\n{stext}\n```"
                    if comment
                    else f"## Struct: {sname}\n\n```c\n{stext}\n```"
                )
                results.append(make_frontmatter(meta, body))

        elif re.match(r"SECTION\s+\d+", title_up) or "FUNCTION" in title_up:
            for fn, comment, fsource in _extract_functions(content):
                meta = {**base, "type": "decompiled", "section": f"function", "function_name": fn}
                results.append(make_frontmatter(meta, _build_func_md(fn, comment, fsource, title)))

        else:
            body = content.strip()
            if body:
                meta = {**base, "type": "decompiled", "section": title}
                results.append(make_frontmatter(meta, f"## {title}\n\n```c\n{body}\n```"))

    return results


def convert_c(file_path: str, source: str) -> List[str]:
    """
    Convert an original C source file (rag_docs/other/) to Markdown+frontmatter strings.

    Uses tree-sitter AST when available. Falls back to block-comment function
    scanner then bare-function regex when tree-sitter is not installed.
    For decompiled C files, use convert_decompiled() instead.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    fname = os.path.basename(file_path)
    base: Dict[str, Any] = {"source": source, "file_name": fname, "page": 0}
    file_ctx = _extract_file_context(text)

    if _get_ts_parser() is not None:
        ts_results = _ts_convert(text, fname, base, file_ctx)
        if ts_results:
            return ts_results

    # ── Fallback: block-comment scanner → bare-function scanner ──────────────
    results: List[str] = []
    seen_funcs: set = set()

    def _build_func_md(fn: str, comment: str, fsource: str) -> str:
        parts = [f"## Function: {fn}"]
        if file_ctx:
            parts.append(f"\n*File context:*\n```c\n{file_ctx}\n```")
        if comment:
            parts.extend(["", comment, ""])
        parts.append(f"```c\n{fsource}\n```")
        return "\n".join(parts)

    for fn, comment, fsource in _extract_functions(text):
        seen_funcs.add(fn)
        meta = {**base, "type": "c_function", "section": f"function/{fn}", "function_name": fn}
        results.append(make_frontmatter(meta, _build_func_md(fn, comment, fsource)))

    if not results:
        for fn, fsource in _extract_bare_functions(text, seen_funcs):
            meta = {**base, "type": "c_function", "section": f"function/{fn}", "function_name": fn}
            results.append(make_frontmatter(meta, _build_func_md(fn, "", fsource)))

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
    full_source_text starts at 'typedef' — the preamble block comment is separate in
    cleaned_comment to avoid duplication in the assembled chunk body.
    """
    results: List[Tuple[str, str, str]] = []
    for tm in _TYPEDEF_OPEN_RE.finditer(content):
        # tm.end() - 1 is the position of the `{` consumed by the pattern
        brace_end = _scan_balanced_braces(content, tm.end() - 1)
        suffix_m = re.match(r"\s*([\w_]+)\s*;", content[brace_end:])
        if not suffix_m:
            continue
        sname = suffix_m.group(1)
        comment = _clean_block_comment(tm.group(1) or "")
        # Start stext at 'typedef', not at '/*', so the code fence never
        # duplicates the prose already present in the comment field above it.
        typedef_start = tm.start() + len(tm.group(1)) if tm.group(1) else tm.start()
        stext = content[typedef_start : brace_end + suffix_m.end()].lstrip("\n")
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
        # fsource starts after the block comment so the code fence never
        # duplicates the prose already output in the comment field above it.
        results.append((
            func_name,
            _clean_block_comment(cm.group(0)),
            section_text[cm.end():end].lstrip("\n"),
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
