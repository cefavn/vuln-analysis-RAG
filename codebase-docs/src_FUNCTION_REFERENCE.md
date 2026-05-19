# src/ Module: Complete Function Reference & Call Flow

**Purpose:** Single-source lookup for all functions, parameters, return types, logic steps, and call graph for tracing RAG execution from ingestion to retrieval.

**Organization:** By flow stage (Ingestion → Transform → Store → Retrieval → MCP)

**Architecture:** Native hybrid (Pinecone SDK 8+, `pc.preview` document API).
Index: `vuln-analysis-rag` — dense_vector (1536d cosine) + FTS/BM25 string field.
Embedder: type-aware flattening (prose flattened, code kept raw).
Retriever: **Reciprocal Rank Fusion (RRF)** — dense + BM25 fetch 2k candidates independently, merged by `1/(60+rank)`.
Context: sibling-based reconstruction via `parent_id`/`sibling_index`/`n_siblings` — no `parent_content` stored.

---

## LEGEND

```
┌─ ENTRY POINT ─────────────────────────────────┐
│ Function: name(params) → ReturnType           │
├────────────────────────────────────────────────┤
│ Purpose: One-line description                 │
├────────────────────────────────────────────────┤
│ Logic Steps:                                  │
│   1. ...step 1...                             │
│   2. ...step 2...                             │
├────────────────────────────────────────────────┤
│ Callers: func_a(), func_b()                   │
│ Callees: func_x(), func_y()                   │
├────────────────────────────────────────────────┤
│ Returns: Description of return value          │
│ Raises: Exception types (if any)              │
│ Config: Config vars used (if any)             │
└────────────────────────────────────────────────┘
```

---

# SECTION 1: ENTRY POINTS

## 1.1 CLI Entry Point (pipeline.py)

```
Entry: python -m src.pipeline [--paths <paths>] [--append-only] [--save-converted]
```

**Function: `__main__` (pipeline.py)**
- Purpose: CLI entry point for batch ingestion
- Logic Steps:
  1. Parse arguments (--paths, --append-only, --save-converted)
  2. Expand path specs via expand_paths() (if --paths given)
  3. Create DocumentPipeline(document_paths=paths, save_converted=...)
  4. Call run(append_only=args.append_only)
- Callers: Shell / Python -m
- Callees: expand_paths(), DocumentPipeline.run()
- Config: Reads DOCS_DIR from config

---

## 1.2 MCP Server Entry Point (main.py)

```
Entry: mcp.run()  (FastMCP server)
```

**Function: `__main__` (main.py)**
- Purpose: Start MCP JSON-RPC server on stdio
- Logic Steps:
  1. Log server start with RETRIEVAL_MIN_SCORE
  2. Call mcp.run() (FastMCP blocking loop)
- Callers: Docker container / local execution
- Callees: log_server_start(), mcp.run()
- Config: RETRIEVAL_MIN_SCORE

---

# SECTION 2: INGESTION FLOW (Files → LangChain Documents)

## 2.1 Discovery Phase

### Function: `discover_documents(docs_dir=DOCS_DIR) → List[str]`

**Module:** `src/ingestion/loader.py`

**Purpose:** Recursively find all supported files in rag_docs/ directory

**Logic Steps:**
1. Check if docs_dir exists; return [] and log warning if not
2. Walk docs_dir recursively (os.walk)
3. Filter files: `is_supported(f)` and `f != "SPEC.md"`
4. Sort paths alphabetically
5. Log count to stderr

**Parameters:**
- `docs_dir: str = DOCS_DIR` — Directory to scan (default from config)

**Returns:** `List[str]` — Sorted absolute file paths

**Callers:** DocumentPipeline.run()

**Callees:** is_supported()

**Config:** SUPPORTED_EXTS (from router.py), DOCS_DIR

---

### Function: `expand_paths(path_specs, docs_dir=DOCS_DIR) → List[str]`

**Module:** `src/ingestion/loader.py`

**Purpose:** Resolve file/directory path specs to concrete file list

**Logic Steps:**
1. For each spec: split on comma, resolve absolute or relative path
2. If dir: walk and filter with is_supported + SPEC.md exclusion
3. If file: add if is_supported, else log [SKIP]
4. Deduplicate paths (preserve first occurrence via seen set)
5. Log resolution summary

**Parameters:**
- `path_specs: List[str]` — Comma-separated or space-separated specs
- `docs_dir: str = DOCS_DIR` — Root for relative resolution

**Returns:** `List[str]` — Deduplicated absolute file paths

**Callers:** CLI argument parser

**Callees:** is_supported()

**Config:** DOCS_DIR, SUPPORTED_EXTS

---

## 2.2 Routing & Conversion Phase

### Function: `convert_file(file_path, source) → List[str]`

**Module:** `src/ingestion/router.py`

**Purpose:** Dispatch file to appropriate converter; return YAML-frontmatter Markdown strings

**Logic Steps:**
1. Extract file extension, basename, top-level directory via get_doc_dir()
2. **Primary dispatch** by doc_dir:
   - `"vuln-pattern"` + `.md` → `convert_vuln_pattern()`
   - `"vuln-pattern"` + other → `[SKIP]` (log and return [])
   - `"build-config"` + {.build, .sh, .layout} → `convert_build_config()`
   - `"build-config"` + other → `[SKIP]`
   - `"decompiled"` + {.c, .h} → `convert_decompiled()`
   - `"decompiled"` + other → `[SKIP]`
   - `"qnx-doc"` + `.html` → `_convert_html()`
   - `"qnx-doc"` + other → `[SKIP]`
3. **Fallback by extension** (unrecognized directories):
   - .pdf → `convert_pdf()`
   - .c/.h → `convert_c()`
   - .txt/.md → `_load_md_file()`
   - other → `[SKIP]`
4. Return [] for unsupported/error files

**Note:** `.json`, `.build`, `.sh`, `.layout` extension-based fallbacks are disabled (commented out). Only `vuln-pattern/*.md`, `build-config/{.build,.sh,.layout}`, `decompiled/{.c,.h}`, `qnx-doc/*.html` are active directory routes.

**Returns:** `List[str]` — List of YAML-frontmatter Markdown strings (0 or more)

**Callers:** load_documents()

**Config:** TESSERACT_PATH

---

### Function: `_convert_html(html_path, source) → List[str]`

**Module:** `src/ingestion/router.py`

**Purpose:** Convert a single QNX HTML documentation file to YAML-frontmatter Markdown

**Logic Steps:**
1. Soft-import bs4 (BeautifulSoup) and markdownify; return [] if unavailable
2. Walk upward from html file's directory until a directory containing main.xml is found (plugin_dir)
3. Compute rel_path within plugin_dir; call `_load_toc_map(plugin_dir)` to get hierarchy
4. Read HTML bytes; parse with BeautifulSoup("html.parser")
5. Decompose nav, script, style, footer, header, meta, link tags
6. Locate main content: `div.class=body` → `body` → entire soup (fallback chain)
7. Replace `<img>` tags with `> [IMAGE: src | alt]` blockquote placeholders
8. Convert to Markdown via `markdownify(..., heading_style="ATX", autolinks=False)`
9. Build metadata: type="reference_document", source, file_name, page=0
10. From hierarchy: doc_title=hierarchy[0], toc_page=hierarchy[-1], toc_section=" > ".join(hierarchy[1:-1])
11. If no hierarchy: toc_page = soup.title.string or file_name
12. Return [make_frontmatter(meta, content)] or [] if content empty

**Parameters:**
- `html_path: str` — Absolute path to .html file
- `source: str` — Canonical source

**Returns:** `List[str]` — [frontmatter_string] or []

**Callers:** convert_file() when doc_dir="qnx-doc" and ext=".html"

**Callees:** _load_toc_map(), markdownify(), BeautifulSoup(), make_frontmatter()

**Document Type:** `reference_document`

---

### Function: `_load_toc_map(plugin_dir) → Dict[str, List[str]]`

**Module:** `src/ingestion/router.py`

**Purpose:** Parse main.xml in a QNX plugin directory to build TOC hierarchy map

**Logic Steps:**
1. Check cache (`_toc_map_cache`); return cached result if present
2. Locate `main.xml` in plugin_dir; return {} if not found
3. Parse XML with ElementTree; call `_traverse(root, [])` recursively
4. `_traverse`: extract label, build breadcrumb path; record `{rel_path: [title, section..., page_label]}` for `topic`/`href` link attributes (splitting on `#`)
5. Cache and return

**Parameters:**
- `plugin_dir: str` — Directory containing main.xml

**Returns:** `Dict[str, List[str]]` — Map of `{rel_html_path: [breadcrumb, ...]}` (cached per directory)

---

### Function: `convert_vuln_pattern(file_path, source) → List[str]`

**Module:** `src/converters/vuln_pattern_converter.py`

**Purpose:** Parse hand-written .md vulnerability pattern file → single atomic YAML-frontmatter string

**Logic Steps:**
1. Read file as UTF-8 (errors="replace")
2. Call `frontmatter_to_doc(text)` (uses yaml.safe_load — no arbitrary deserialization)
3. Warn if required fields (`doc_id`, `vuln_type`) are missing; ingest anyway
4. Set `type: "vulnerability_pattern"` (setdefault), inject `source`, `file_name`, set `page: 0` (setdefault)
5. Return [make_frontmatter(meta, doc.page_content)]

**Parameters:**
- `file_path: str` — Path to .md pattern file
- `source: str` — Canonical source

**Returns:** `List[str]` — Single-element list [frontmatter_string] or []

**Required frontmatter fields:** `doc_id`, `vuln_type`

**Optional fields:** `sink`, `component`, `severity`, `cwe`, `binary_indicators`, `tags`

**Document Type:** `vulnerability_pattern` (atomic — never split)

**Callers:** convert_file() when doc_dir="vuln-pattern" and ext=".md"

**Callees:** frontmatter_to_doc(), make_frontmatter()

**Notes:**
- yaml.safe_load enforced via frontmatter_to_doc() reuse
- Legacy .json files in vuln-pattern/ are now skipped (not routed to convert_json)

---

### Function: `get_doc_dir(file_path) → str`

**Module:** `src/ingestion/router.py`

**Purpose:** Extract top-level directory name from file path relative to DOCS_DIR

**Returns:** `str` — Top-level dir name (e.g., "decompiled", "vuln-pattern") or ""

---

### Function: `canonical_source(file_path) → str`

**Module:** `src/ingestion/router.py`

**Purpose:** Generate stable, Docker-agnostic source identifier ("rag_docs/<rel_path>")

---

### Function: `is_supported(file_path) → bool`

**Module:** `src/ingestion/router.py`

**Purpose:** Check if file extension is in SUPPORTED_EXTS

**Config:** `SUPPORTED_EXTS = (".pdf", ".txt", ".json", ".md", ".c", ".h", ".build", ".sh", ".layout", ".html")`

---

### Function: `_load_md_file(path, source, file_name) → List[str]`

**Module:** `src/ingestion/router.py`

**Purpose:** Load .md/.txt file; preserve existing YAML frontmatter or wrap with defaults

**Logic Steps:**
1. Read file as UTF-8; return [] if empty
2. If starts with "---\n": parse via frontmatter_to_doc(); inject/overwrite source, file_name; setdefault type="reference_document", page=0
3. Else: wrap with default reference_document metadata

---

### Function: `frontmatter_to_doc(text) → Optional[Document]`

**Module:** `src/ingestion/router.py`

**Purpose:** Parse YAML-frontmatter Markdown string → LangChain Document using yaml.safe_load

**Logic:**
1. If starts with "---\n": find closing "\n---\n"; parse YAML; extract content
2. Return Document if content non-empty, else None
3. Fallback: return Document(stripped text, metadata={}) for plain text

---

### Function: `make_frontmatter(meta, content) → str`

**Module:** `src/converters/utils.py`

**Purpose:** Wrap metadata dict + Markdown content with YAML frontmatter ("---\n{yaml}\n---\n\n{content}")

---

## 2.2b Converter Functions (File-Type Specific)

All converters:
- **Input:** `file_path: str`, `source: str`
- **Output:** `List[str]` — YAML-frontmatter Markdown strings
- **Format:** `"---\n{meta_yaml}\n---\n\n{markdown_content}"`

| Converter | Module | Doc Types Produced |
|---|---|---|
| `convert_vuln_pattern()` | vuln_pattern_converter.py | vulnerability_pattern (atomic) |
| `convert_decompiled()` | c_converter.py | c_overview, c_constants, c_struct, c_function, c_section |
| `convert_c()` | c_converter.py | c_overview, c_constants, c_section, c_function |
| `convert_pdf()` | pdf_converter.py | reference_document |
| `convert_build_config()` | build_converter.py | build_config (all subtypes) |

**Note:** `convert_json()` is imported in `__init__.py` but not actively routed from `convert_file()` (vuln-pattern .json fallback is disabled).

---

### Function: `convert_decompiled(file_path, source) → List[str]`

**Module:** `src/converters/c_converter.py`

**Purpose:** Convert a decompiled C file (`rag_docs/decompiled/`) into typed semantic units using regex-based section parsing driven by `/* ====...==== */` dividers as defined in `decompiled/SPEC.md`.

**Logic Steps:**
1. Read file as UTF-8; parse `_binary_meta()` (SHA256, MD5, binary name from header comment)
2. Extract `file_ctx = _extract_file_context(text)` — prepended to all c_function chunks
3. **c_overview:** Match leading block comment → emit with binary SHA256/name metadata
4. **Split on `/* ====...==== */` dividers** via `_C_SECTION_DIV_RE` + `_C_SECTION_TITLE_RE`; for each section by title:
   - `CONSTANT` / `#DEFINE` → `_parse_constants()` → one `c_constants` doc per group
   - `DATA STRUCT` / `STRUCT` → `_parse_structs()` → one `c_struct` doc per typedef
   - `SECTION N` / `FUNCTION` → `_extract_functions()` → one `c_function` doc per function
   - other → `c_section` doc (raw content)
5. **Preamble scan:** run `_extract_functions()` on text before the first divider (catches functions without section markers)
6. **Bare-function fallback:** if no c_function found yet, `_extract_bare_functions()` by regex signature alone
7. Final fallback: emit entire file as `c_section` type="raw"

**Doc types produced:** `c_overview`, `c_constants`, `c_struct`, `c_function`, `c_section`

**Each c_function chunk format:**
```
## Function: func_name  [Section Title]
*File context:*
```c
<globals + defines + includes>
```
<cleaned block comment>
```c
<full function source>
```
```

**Callers:** `convert_file()` when doc_dir="decompiled" and ext in (.c, .h)

---

### Function: `convert_c(file_path, source) → List[str]`

**Module:** `src/converters/c_converter.py`

**Purpose:** Convert an original C source file (`rag_docs/other/`) using tree-sitter AST when available, with fallback to block-comment scanner then bare-function regex.

**Logic Steps:**
1. Read file; extract `file_ctx = _extract_file_context(text)`
2. **Tree-sitter path** (if `_get_ts_parser()` returns non-None): call `_ts_convert()`:
   - c_overview: block comments before first declaration/function
   - c_constants: top-level `#define` / `preproc_function_def` nodes
   - c_section (globals): non-prototype `declaration` nodes
   - c_function: each `function_definition` node with preceding comment + file_ctx
3. **Fallback — block-comment scanner:** `_extract_functions()` → c_function per function
4. **Fallback — bare-function regex:** `_extract_bare_functions()` if block scanner found nothing
5. Final fallback: emit as `c_section` type="raw"

**Doc types produced:** `c_overview`, `c_constants`, `c_section`, `c_function`

**Callers:** `convert_file()` extension fallback for .c/.h in unrecognized directories

---

### Function: `convert_build_config(file_path, source) → List[str]`

**Module:** `src/converters/build_converter.py`

**Purpose:** Convert QNX build-config files (.build, .sh, .layout) to typed Markdown docs. All output has `type=build_config`.

**Logic Steps:**
1. Read file; skip if empty
2. **`.sh` / `.layout`:** emit single atomic doc with the full file content in a fenced code block; `section=fname`
3. **`.build` without `### Section ###` delimiters:** emit single atomic doc as code block; `section="full"`
4. **`.build` with sections** (matched by `_BUILD_SECT_RE` — 20+ `#` characters per delimiter):
   - Preamble (text before first delimiter) → doc with `section="preamble"` if non-empty
   - Each named section → doc with `section="section/{name}"`, `page=idx+1`
5. Fallback: emit raw text as `section="raw"` if all sections were empty

**Section delimiter format:**
```
####################
### Section Name ###
####################
```

**Doc types produced:** `build_config` (for all subtypes)

**Callers:** `convert_file()` when doc_dir="build-config" and ext in (.build, .sh, .layout)

---

### Function: `convert_pdf(file_path, source, tesseract_path) → List[str]`

**Module:** `src/converters/pdf_converter.py`

**Purpose:** Convert a PDF file to one `reference_document` per page with content.

**Logic Steps:**
1. Open PDF via `fitz.open()`; build `page_headings: Dict[int, (level, title)]` from embedded TOC (`pdf.get_toc()`)
2. Compute `ocr_threshold = max(50, median(first_5_page_lengths) * 0.15)`
3. For each page:
   - If `len(raw_text) < ocr_threshold`: rasterize at 2x via `fitz.Matrix(2,2)` → OCR via pytesseract
   - Else: `_page_to_markdown(page)` (font-size heading detection); fallback to raw `get_text()` if empty
   - If TOC heading available for this page: prepend as `## heading` (max h3)
4. Emit frontmatter doc: `{source, file_name, type="reference_document", page=page_num}`

**Doc types produced:** `reference_document`

**Callers:** `convert_file()` extension fallback for .pdf

---

### Helper: `_extract_file_context(text, max_chars=600) → str`

**Module:** `src/converters/c_converter.py`

**Purpose:** Build a compact file-context string (globals → defines → includes) prepended to every `c_function` chunk so the embedding captures the type environment even after child-splitting.

**Logic:**
1. Scan preamble (text before first function signature, max 4000 chars)
2. Collect lines by type: `#include` → includes; `#define` (non-underscore names) → defines; `type name;` patterns → globals
3. Priority: `globals + defines + includes` joined; truncate to `max_chars`

---

### Helper: `_ts_convert(text, fname, base, file_ctx) → List[str]`

**Module:** `src/converters/c_converter.py`

**Purpose:** Tree-sitter AST-based conversion for original C source files. Produces c_overview, c_constants, c_section(globals), c_function chunks using precise AST node types.

**Called by:** `convert_c()` when tree-sitter package is available

---

### Helper: `_parse_constants(content) → List[Tuple[str, str]]`

**Module:** `src/converters/c_converter.py`

**Purpose:** Group `#define` lines by preceding single-line comment labels. Returns list of `(group_name, joined_lines)`.

---

### Helper: `_parse_structs(content) → List[Tuple[str, str, str]]`

**Module:** `src/converters/c_converter.py`

**Purpose:** Extract `typedef struct` blocks using `_scan_balanced_braces()`. Returns `(struct_name, cleaned_comment, source_text)` per struct.

---

### Helper: `_extract_functions(section_text) → List[Tuple[str, str, str]]`

**Module:** `src/converters/c_converter.py`

**Purpose:** Find functions by locating column-0 block comments followed by a function signature, then scanning for balanced braces. Returns `(func_name, cleaned_comment, source_text)`. Strict adjacency (comment must immediately precede signature within 400 chars) prevents false positives.

---

### Helper: `_extract_bare_functions(text, exclude) → List[Tuple[str, str]]`

**Module:** `src/converters/c_converter.py`

**Purpose:** Last-resort fallback — find functions by `_BARE_SIG_RE` (column-0 signature, no preceding comment required). Only runs when `_extract_functions()` found nothing. Returns `(func_name, full_source)`.

---

### Helper: `_scan_balanced_braces(text, pos) → int`

**Module:** `src/converters/c_converter.py`

**Purpose:** Return the index after the `}` that closes the `{` at `pos`. Handles nested braces, block comments, line comments, and string literals to avoid false matches.

---

### Helper: `_page_to_markdown(page) → str`

**Module:** `src/converters/pdf_converter.py`

**Purpose:** Convert one PDF page to Markdown using font-size heading detection.

**Algorithm:**
- Extract all text spans with font size and bold flag via `page.get_text("dict")`
- body_size = median of all span sizes on the page
- `max_size >= 1.4x body` → `## heading`
- `max_size >= 1.15x body` OR bold → `### heading`
- else → plain paragraph text

---

## 2.3 Document Loading Phase

### Function: `load_documents(file_paths) → List[Document]`

**Module:** `src/ingestion/loader.py`

**Purpose:** Convert files via converters, parse frontmatter, return flat list of Documents

**Logic Steps:**
1. For each file_path: check exists (skip if not)
2. Compute canonical_source(), determine origin from get_doc_dir()
3. Call convert_file() → List[str] (YAML-frontmatter Markdown)
4. Parse each string via frontmatter_to_doc() → Document
5. Set `doc.metadata.setdefault("origin", origin)` for each doc
6. Log skipped (no content) files
7. Raise ValueError if no docs loaded at all
8. Log top-6 type breakdown; return all_docs

**`origin` values:**
- `"processed"` — doc_dir in `_PROCESSED_DIRS = {"decompiled", "vuln-pattern", "qnx-doc", "build-config"}`
- `"unprocessed"` — generic parsing (best-effort, lower trust level for LLM)

---

# SECTION 3: TRANSFORM FLOW (Documents → Chunks)

## 3.1 Embedder Module

### Module: `src/ingestion/embedder.py`

**Purpose:** Type-aware text normalization for dense embedding + OpenAI embedding client.

Dense embedding quality depends on input type:
- Text docs (prose): Markdown syntax is noise → flatten to plain prose
- Code docs: syntax characters `{`, `}`, `*`, `&` carry semantic meaning → keep raw
- Query strings: NEVER flattened (LLM may query with code-like patterns)

---

### Constant: `TEXT_TYPES`

```python
TEXT_TYPES = frozenset({
    "reference_document",
    "analysis_result",
    "vulnerability_pattern",
})
```

**Purpose:** Doc types that receive Markdown-to-prose flattening before dense embedding.
All other types (c_function, c_struct, build_*, etc.) use raw text.

---

### Function: `flatten_for_embedding(text) → str`

**Module:** `src/ingestion/embedder.py`

**Purpose:** Convert Markdown syntax to plain prose for dense embedding quality

**Transforms (4 regex passes):**
1. `## Section Title` → `Section Title:` (ATX headers stripped, colon appended)
2. `**Field:** value` or `**Field**: value` → `Field: value` (bold markers removed)
3. ` ```lang\ncode\n``` ` → `code` (code fences stripped, inner content kept)
4. `- bullet` or `* bullet` → `bullet` (list markers stripped)
5. Collapse 3+ blank lines → 2 blank lines; strip

**Parameters:**
- `text: str` — Markdown text

**Returns:** `str` — Plain prose, Markdown syntax removed

**Callers:** text_for_dense_embedding() (only for TEXT_TYPES)

**Notes:**
- NEVER applied to query strings (queries may contain code-like patterns)
- NEVER applied to code doc types

---

### Function: `text_for_dense_embedding(text, doc_type) → str`

**Module:** `src/ingestion/embedder.py`

**Purpose:** Route text to flatten (text types) or raw (code/config types)

**Logic:**
```python
return flatten_for_embedding(text) if doc_type in TEXT_TYPES else text
```

**Parameters:**
- `text: str` — Document page_content
- `doc_type: str` — metadata["type"] of the document

**Returns:** `str` — Text ready for dense embedding

**Callers:** VectorStore._upsert()

---

### Class: `Embedder`

**Module:** `src/ingestion/embedder.py`

**Purpose:** Wraps OpenAIEmbeddings; shared by VectorStore (upsert) and DocumentRetriever (query)

**Constructor:** Imports OpenAIEmbeddings, calls embeddings_client_kwargs() from config (passes model, api_key, chunk_size, request_timeout, optionally api_base)

**Methods:**
- `embed_documents(texts: List[str]) → List[List[float]]` — Batch embedding for upsert
- `embed_query(text: str) → List[float]` — Single embedding for query (raw, no flattening)

**Callers:** VectorStore.__init__(), DocumentRetriever.__init__()

---

## 3.2 Chunker Class & Methods

### Class: `Chunker`

**Module:** `src/ingestion/chunker.py`

**Constructor: `__init__()`** — Initializes 4 splitters:
- `_header_splitter`: MarkdownHeaderTextSplitter (headers #, ##, ###; `strip_headers=False`)
- `_child_splitter`: RecursiveCharacterTextSplitter (CHILD_CHUNK_SIZE, CHILD_CHUNK_OVERLAP, prose separators `["\n\n", "\n", ". ", " ", ""]`)
- `_code_child_splitter`: RecursiveCharacterTextSplitter (CHILD_CHUNK_SIZE, CHILD_CHUNK_OVERLAP, `_CODE_SEPARATORS`, `is_separator_regex=True`)
- `_fallback_splitter`: RecursiveCharacterTextSplitter (CHUNK_SIZE, CHUNK_OVERLAP, same prose separators)

---

### Constant: `_CODE_SEPARATORS`

```python
_CODE_SEPARATORS = [r"\n\s*\}\n", r";\n", r"\n\n", r"\n", r""]
```

**Purpose:** Regex-aware separators for C code child splitting.

- `r"\n\s*\}\n"` — closing brace at any indent level (IDA/Ghidra always indents: `    }\n`)
- `r";\n"` — end of statement
- `r"\n\n"` — blank line
- `r"\n"` — line boundary fallback

**`is_separator_regex=True`** required so `\s*` expands correctly.

**Why not `"\n}\n"`:** IDA/Ghidra output is always indented — a literal `"\n}\n"` would miss 90% of block boundaries.

---

### Constant: `_CODE_CHILD_TYPES`

```python
_CODE_CHILD_TYPES = frozenset({
    "c_function", "c_section",
})
```

**Purpose:** Types that use `_code_child_splitter` instead of `_child_splitter`.
Note: `build_section`, `build_suid`, `build_hypervisor` are NOT in this set.

---

### Constant: `ATOMIC_TYPES`

```python
ATOMIC_TYPES = frozenset({
    "vulnerability_pattern",
    "c_overview", "c_constants", "c_struct",
    "build_config",
})
```

**Note:** `build_image` and `build_script` are NOT atomic — they will be chunked if large.

---

### Helper: `_parent_id(source, section) → str`

**Purpose:** SHA256[:16] of `"{source}::{section}"` — stable ID for grouping sibling chunks in Pinecone.

---

### Helper: `_section_path(meta) → str`

**Purpose:** Human-readable heading path from MarkdownHeaderTextSplitter metadata (joins h1, h2, h3 with " > ").

---

### Method: `chunk_all(documents) → List[Document]`

**Purpose:** Split all documents according to type-based strategy

**Logic:**
- Atomic docs (ATOMIC_TYPES) pass through unchanged
- All others processed via `_chunk_document()`
- Logs summary: `Chunks: N total (A atomic | S section | C child)`

**Config:** ATOMIC_TYPES

---

### Method: `_chunk_document(doc) → List[Document]`

**Purpose:** Apply parent-child chunking strategy to a single document

**Logic Steps:**
1. Try MarkdownHeaderTextSplitter.split_text() on page_content
2. If no sections: apply `_fallback_splitter` (CHUNK_SIZE/CHUNK_OVERLAP) directly → return as flat chunks with base_meta
3. For each non-empty section:
   - Build `meta = {**base_meta, "section": _section_path(section.metadata)}`
   - If `len(text) <= CHILD_CHUNK_SIZE`: keep as one Document
   - Else: call `_split_into_children(text, meta)`

---

### Method: `_split_into_children(section_text, section_meta) → List[Document]`

**Purpose:** Child-split an oversized section; attach sibling linkage metadata for context reconstruction at retrieval time.

**Logic Steps:**
1. Choose splitter: `_code_child_splitter` if `doc_type in _CODE_CHILD_TYPES`, else `_child_splitter`
2. Split section_text → chunks (filter empty)
3. Compute `pid = _parent_id(source, section)`
4. Return Documents with metadata: `{**section_meta, "parent_id": pid, "sibling_index": i, "n_siblings": n}`

**Each child carries:**
- `parent_id` — stable SHA256[:16] linking siblings (used to fetch all siblings at retrieval time)
- `sibling_index` — 0-based position in the ordered sequence
- `n_siblings` — total count for this parent

**No parent_content stored in metadata.** Full context is reconstructed at retrieval time by fetching siblings via Pinecone query_string wildcard.

**Config:** `CHILD_CHUNK_SIZE`, `CHILD_CHUNK_OVERLAP`

---

# SECTION 4: STORE FLOW (Chunks → Pinecone Documents)

## 4.1 Pinecone Index Architecture

**Index:** `vuln-analysis-rag` (default; configurable via PINECONE_INDEX_NAME env var; Pinecone SDK 8+, `pc.preview` document API)

**Schema:**
| Field | Type | Purpose |
|---|---|---|
| `embedding` | dense_vector (1536d, cosine) | Dense semantic search |
| `text` | string + full_text_search (BM25, language=en) | Lexical identifier search |
| `chunk_text` | string (stored) | Returned in search results (same content as `text`) |
| `parent_id` | string (filterable) | SHA256[:16] linking sibling chunks for context reconstruction |
| `sibling_index` | integer | 0-based position within parent section |
| `n_siblings` | integer | Total sibling count for this parent |
| `type`, `source`, `file_name` | string (filterable) | Metadata filtering |
| `function_name`, `section`, `doc_id` | string (filterable) | Precise scoping |
| `origin`, `doc_title`, `toc_section`, `entry_id` | string (filterable) | Metadata filtering |

**Key constraints:**
- `text` field is BM25-indexed + stored; `chunk_text` is an explicit stored copy for clarity
- `parent_content` is NOT stored — context is reconstructed from siblings at retrieval time
- FTS fields are NOT subject to the 40KB metadata limit

**SDK API used:**
- Upsert: `pc.preview.index(name).documents.batch_upsert(namespace, documents=[record], batch_size=1)` (one record at a time, with per-record error handling)
- Query (dense): `pc.preview.index(name).documents.search(namespace, score_by=[{type: dense_vector, ...}], filter)`
- Query (BM25): `pc.preview.index(name).documents.search(namespace, score_by=[{type: text, field, query}], filter)`
- Query (wildcard): `pc.preview.index(name).documents.search(namespace, score_by=[{type: query_string, query: "*"}], filter)` — used for delete and sibling fetch
- Delete: `pc.preview.index(name).documents.delete(namespace, ids)`
- Fetch: `pc.preview.index(name).documents.fetch(namespace, ids)`

---

## 4.2 Size Guards

### Constant: `MAX_EMBEDDING_CHARS = 25000`
Prose/text docs — ~6250 tokens, safely below text-embedding-3-small's 8191 limit.

### Constant: `MAX_EMBEDDING_CHARS_CODE = 15000`
C code/config docs — conservative; C code tokenizes ~2x denser than prose.

### Constant: `MAX_CHUNK_TEXT_METADATA = 20000`
Safety ceiling for `chunk_text` stored field. Pinecone metadata limit ~40KB/doc.

### Constant: `_CODE_TYPES`
```python
_CODE_TYPES = frozenset({
    "c_function", "c_struct", "c_constants", "c_section", "c_overview",
    "build_config",
})
```
Used to select embedding char limit (code=15k, others=25k).

---

### Function: `_guard_sizes(docs) → None`

**Module:** `src/store/pinecone_client.py`

**Purpose:** Raise ValueError if any chunk exceeds the embedding model token limit.

**Logic:**
- `doc_type in _CODE_TYPES` → limit = `MAX_EMBEDDING_CHARS_CODE` (15000)
- else → limit = `MAX_EMBEDDING_CHARS` (25000)
- If exceeded: raises `ValueError` with source, type, and guidance to review Chunker config

**Note:** Raises for ALL types (not truncate-and-warn). Caller must ensure chunks are within limits.

**Callers:** VectorStore._upsert()

---

### Function: `_guard_metadata_size(records) → None`

**Module:** `src/store/pinecone_client.py`

**Purpose:** Raise ValueError if any chunk_text field exceeds Pinecone's stored field size limit.

**Logic:**
- `len(chunk_text) > MAX_CHUNK_TEXT_METADATA` → raises `ValueError` for ALL types with source, type, function_name info

**Note:** No truncation path — raises for both code and text types.

**Callers:** VectorStore._upsert()

---

## 4.3 VectorStore Class & Methods

### Class: `VectorStore`

**Module:** `src/store/pinecone_client.py`

**Purpose:** Embed, upsert, and incrementally update documents in the Pinecone document-schema index.

**Constructor: `__init__(index_name=PINECONE_INDEX_NAME)`**
- Validate PINECONE_API_KEY
- Store `self.index_name`, `self._namespace = PINECONE_NAMESPACE`
- Initialize `self._embedder = Embedder()`

**Attributes:**
- `index_name: str` — Index name from config
- `_namespace: str` — Pinecone namespace from config (default "default")
- `_embedder: Embedder` — Embedding client

---

### Method: `_preview_index() → pc.preview.Index`

**Purpose:** Get Pinecone preview index instance (per-call, not cached)

**Logic:** `Pinecone(api_key=...).preview.index(name=self.index_name)`

---

### Method: `_upsert(docs, ids) → None`

**Purpose:** Embed and upsert documents one-at-a-time with per-record error handling

**Logic Steps:**
1. `_guard_sizes(docs)` — raises if any chunk exceeds embedding limit
2. For each (id_, doc):
   a. Build `record = {"_id": id_, "embedding": embed(...), "text": content, "chunk_text": content, **meta}` (skip None/"" meta values)
   b. `_guard_metadata_size([record])` — raises if chunk_text too large
   c. `idx.documents.batch_upsert(namespace, documents=[record], batch_size=1)` — one record per call
   d. Track ok/fail counts; log progress every 50 ok
3. Log "Upsert complete: N ok, M failed"

**Key:** Each record is upserted individually (not batched). A failed record logs [WARN] and continues; other records still upsert.

---

### Method: `_delete_by_source(source) → None`

**Purpose:** Delete all documents for a given source path before re-upserting

**Logic Steps:**
1. `idx.documents.search(namespace, top_k=10000, score_by=[{type: "query_string", query: "*"}], filter={"source": {"$eq": source}}, include_fields=[])`
2. Collect `[m._id for m in resp.matches]`
3. Batch-delete IDs in batches of 1000 via `idx.documents.delete(namespace, ids=batch)`
4. Silently ignore "Namespace not found" / "no documents" errors

---

### Method: `_fetch_existing_ids(ids, batch_size=200) → Set[str]`

**Purpose:** Check which document IDs already exist (for incremental update dedup)

**Logic:** `idx.documents.fetch(namespace, ids=batch, include_fields=[])` → iterate `response.documents` dict keys → return set of existing IDs

---

### Method: `upsert_incremental(docs, append_only=False) → Tuple[int, int]`

**Purpose:** Embed and upsert with intelligent change detection

**If append_only=True:** Skip existence checks; upsert all; return (n, 0)

**If append_only=False:**
1. Generate IDs, group docs by source
2. `_fetch_existing_ids(all_ids)` → set of existing IDs
3. Check `FORCE_REFRESH_SOURCES` env var (comma-separated sources to force refresh)
4. For each source: if all IDs exist → unchanged; if any missing OR in forced → changed
5. `_delete_by_source()` for changed sources (skips "unknown" source)
6. `_upsert()` changed docs only
7. Return (n_upserted, n_skipped)

---

### Method: `upsert_chunks(chunks) → Dict[str, str]`

**Purpose:** Embed and add pre-chunked documents (used by `add_knowledge_text` MCP tool)

**Returns:** `{"status": "success", "message": "Added N chunk(s)", "chunks_added": "N", "source": ..., "entry_id": ...}`
or `{"status": "error", "message": "No chunks provided."}`

---

### Function: `make_vector_id(doc) → str`

**Module:** `src/store/pinecone_client.py`

**Purpose:** Generate stable, content-aware document ID for deduplication

**Key fields:** `source | page | type | section | doc_id | (function_name or struct_name or block_name or section_name) | entry_id | SHA256(whitespace-normalized content)`

**Returns:** SHA256(key) — 64-char hex

---

# SECTION 5: RETRIEVAL FLOW (Query → Results)

## 5.1 Hybrid Query Architecture

The retriever uses **Reciprocal Rank Fusion (RRF)** — not a pre-filter approach:

```
Query string (raw, never flattened)
  ├─ embed_query() → dense_vec (1536d)
  └─ raw string → BM25 token matching

RRF strategy (primary path for all query/query_with_scores calls):
  1. Dense search: fetch k*2 candidates by cosine similarity
  2. BM25 search:  fetch k*2 candidates by lexical token match
  3. Merge by RRF score: score(doc) = Σ 1/(60 + rank) across legs
     - Documents appearing in both legs get a combined score boost
  4. Return top-k by RRF score

Special case (query_by_function_name):
  → BM25-primary with function_name metadata filter (exact identifier lookup)
  → Falls back to dense if BM25 returns nothing
```

**Why raw query:** LLM may query with code patterns like `"void *memcpy(void *dst, ...)"` — flattening would strip `*`, `(`, `)` and degrade both BM25 and dense precision.

**Context reconstruction:**
- Child chunks carry `parent_id`, `sibling_index`, `n_siblings`
- At retrieval time, `_format_results()` groups children by `parent_id`
- Sibling chunks are fetched from Pinecone if needed to fill gaps
- Full parent section is reconstructed by joining all siblings in order

---

## 5.2 DocumentRetriever Class & Methods

### Class: `DocumentRetriever`

**Module:** `src/retriever.py`

**Constructor: `__init__(index_name=PINECONE_INDEX_NAME)`**
- Validate PINECONE_API_KEY
- Store `self._index_name`, `self._namespace = PINECONE_NAMESPACE`
- Initialize `self._embedder = Embedder()`

---

### Constant: `_INCLUDE_FIELDS`

```python
_INCLUDE_FIELDS = [
    "chunk_text", "parent_id", "sibling_index", "n_siblings",
    "type", "source", "file_name",
    "function_name", "section", "doc_id", "page", "origin",
    "doc_title", "toc_section", "entry_id",
]
```

Fields returned in every document search response. Includes sibling linkage fields; does NOT include `parent_content`.

---

### Constant: `_SIBLING_FIELDS`

```python
_SIBLING_FIELDS = ["chunk_text", "sibling_index"]
```

Fields fetched when reconstructing sibling context (minimal payload).

---

### Method: `_preview_index() → pc.preview.Index`

**Purpose:** Get Pinecone preview index instance (lazy, per-call)

---

### Method: `_dense_query(query, k, filter=None) → List[match]`

**Purpose:** Pure dense semantic search. For concept/vulnerability lookups.

**Logic:**
```python
dense_vec = self._embedder.embed_query(query)
score_by = [{"type": "dense_vector", "field": "embedding", "values": dense_vec}]
resp = idx.documents.search(namespace, top_k=k, score_by=score_by, filter=filter, include_fields=_INCLUDE_FIELDS)
```

---

### Method: `_bm25_query(query, k, filter=None) → List[match]`

**Purpose:** BM25 lexical search. For exact identifier lookups (function names, struct names, CVE IDs).

**Logic:**
```python
score_by = [{"type": "text", "field": "text", "query": query}]
resp = idx.documents.search(namespace, top_k=k, score_by=score_by, filter=filter, include_fields=_INCLUDE_FIELDS)
```

---

### Method: `_hybrid_query(query, k, filter=None) → List[match]`

**Purpose:** True hybrid via Reciprocal Rank Fusion (RRF). Primary search path for all query/query_with_scores calls.

**Logic Steps:**
1. `dense_matches = _dense_query(query, k=k*2, filter=filter)`
2. `bm25_matches = _bm25_query(query, k=k*2, filter=filter)`
3. For each leg: `rrf[id] += 1.0 / (60 + rank)` (K_RRF=60)
4. Track `id_to_match` (dense results take priority for match object if ID appears in both)
5. Sort all IDs by rrf score descending; return top-k match objects

**Note:** `$match_any` pre-filter is NOT used. Both legs run independently; documents appearing in both legs receive a score boost automatically through RRF addition.

---

### Static Method: `_match_to_dict(match, rank, score=None) → Dict[str, str]`

**Purpose:** Serialize a retrieved document match to flat dict for MCP JSON transport

**Input:** Pinecone preview match object (fields as attributes)

**Output fields:**
- `rank`, `content` (chunk_text), `context` (initially "", filled by `_format_results()`), `section`
- `source`, `source_file` (file_name), `page`, `type`, `doc_id`, `origin`
- `function_name`, `doc_title`, `toc_section`
- `score` (from `match._score`, formatted "%.4f") — only included if score is available

**Notes:**
- `context` is always "" from this method; set by `_format_results()` after reconstruction
- Score from `match._score` (Pinecone document API uses `_score` to avoid collision with user fields named `score`)

---

### Method: `_fetch_siblings(parent_id) → List[Any]`

**Purpose:** Fetch all chunks belonging to parent_id from Pinecone (for context reconstruction)

**Logic:**
```python
resp = idx.documents.search(
    namespace, top_k=200,
    score_by=[{"type": "query_string", "query": "*"}],
    filter={"parent_id": {"$eq": parent_id}},
    include_fields=_SIBLING_FIELDS,
)
```
Returns raw match objects. Logs [WARN] on failure, returns [].

**Callers:** `_reconstruct_context()` (only when already-retrieved siblings are incomplete)

---

### Method: `_reconstruct_context(parent_id, already_retrieved) → str`

**Purpose:** Reconstruct the full parent section from sibling chunks.

**Logic Steps:**
1. Read `n_siblings` from first match in `already_retrieved`
2. Build `known: Dict[int, str]` from already-retrieved matches (sibling_index → chunk_text)
3. If `len(known) < n_siblings`: call `_fetch_siblings(parent_id)` to fill gaps
4. Join all known chunks in sibling_index order with "\n\n" separators

**Optimization:** Uses already-retrieved matches first; avoids extra Pinecone call when all siblings were already returned in the search results.

---

### Method: `_format_results(matches, scores=None) → List[Dict[str, str]]`

**Purpose:** Convert raw Pinecone matches to result dicts with reconstructed sibling context.

**Logic Steps:**
1. Partition matches into `standalone` (no parent_id) and `parent_groups` (keyed by parent_id)
2. Standalone: `context = content` (self-contained)
3. For each parent group:
   - Pick best_rank (minimum rank) match as representative
   - `context = _reconstruct_context(pid, all_matches_in_group)`
4. Sort output by rank; return list of dicts

**Effect:** Multiple child chunks from same parent are merged into ONE result entry (best rank wins). Context holds the full reconstructed parent section, not just the matched chunk.

---

### Method: `query(query, k=5, filter=None, min_score=None) → List[Dict[str, str]]`

**Purpose:** Hybrid search, no scores in output

**Logic:** `_hybrid_query()` → min_score filter (on `_score`) → `_format_results()`

---

### Method: `query_with_scores(query, k=5, filter=None, min_score=None) → List[Dict[str, str]]`

**Purpose:** Same as query() but includes similarity scores

**Logic:** `_hybrid_query()` → extract scores → min_score filter → `_format_results(matches, scores)`

**Notes:** Score from RRF-merged results (effectively RRF score, not raw cosine)

---

### Method: `query_by_function_name(function_name, binary_name="", k=10) → List[Dict[str, str]]`

**Purpose:** Exact metadata lookup for all indexed chunks from a named decompiled function

**Logic Steps:**
1. Build filter: `{"function_name": {"$eq": function_name}}`
2. Query string: `f"{function_name} {binary_name}".strip()`
3. `_bm25_query(query_str, k=k, filter=f)` — BM25-primary (exact token match)
4. Fall back to `_dense_query(function_name, k=k, filter=f)` if BM25 returns nothing
5. Extract scores; call `_format_results(matches, scores)`

**Notes:**
- BM25-primary because function names are exact tokens (deterministic recall)
- Dense fallback handles BM25 indexing lag (~15s after upsert)

---

### Method: `get_db_info() → Dict[str, str]`

**Purpose:** Check database connection and return metadata

**Logic:** `pc.preview.indexes.describe(name=self._index_name)` → extract status.state

**Returns:** `{"status": "connected", "index_name", "namespace", "embedding_model", "index_status"}` or `{"status": "error", "message": ...}`

---

### Function: `get_retriever() → DocumentRetriever`

**Module:** `src/retriever.py`

**Purpose:** Module-level singleton DocumentRetriever — shared across all MCP tool calls

---

# SECTION 6: MCP TOOLS (Query Interface)

## 6.1 RAG Query Tools

### MCP Tool: `query_knowledge(query, k=5) → List[Dict]`

General-purpose hybrid search over entire knowledge base.

**Implementation:** `retriever.query(query, k=k, min_score=RETRIEVAL_MIN_SCORE)`

**k range:** 1–20

---

### MCP Tool: `search_vulnerability_patterns(vuln_type, code_context="", k=5, filter=None) → List[Dict]`

Phase B — search vulnerability pattern cards for a specific bug class.

**Implementation:**
1. Combine vuln_type + code_context into query
2. `effective_filter = filter if filter is not None else {"type": {"$eq": "vulnerability_pattern"}}`
3. `retriever.query_with_scores(combined, k=k, filter=effective_filter, min_score=RETRIEVAL_MIN_SCORE)`

**k range:** 1–10

**Filter override:** Pass custom filter to narrow beyond type (e.g., add tag or severity filter)

---

### MCP Tool: `search_component_context(component_name, extra_context="", k=7, filter=None) → List[Dict]`

Phase A — retrieve architecture context, excluding vulnerability pattern cards.

**Implementation:**
1. Combine component_name + extra_context
2. `effective_filter = filter if filter is not None else {"type": {"$ne": "vulnerability_pattern"}}`
3. `retriever.query_with_scores(combined, k=k, filter=effective_filter, min_score=RETRIEVAL_MIN_SCORE)`

**k range:** 1–15

**Filter examples:**
```python
{"type": {"$eq": "c_function"}}                          # only decompiled functions
{"source": {"$eq": "rag_docs/decompiled/qvm.c"}}         # only from one file
{"function_name": {"$in": ["parse_packet", "handle_input"]}}
{"$and": [{"type": {"$eq": "c_function"}}, {"source": ...}]}
```

---

### MCP Tool: `search_by_function(function_name, binary_name="", filter=None) → List[Dict]`

Exact metadata lookup for all indexed chunks from a specific decompiled function.

**Implementation:** `retriever.query_by_function_name(function_name, binary_name)`

**Note:** `filter` param is accepted but not currently passed to `query_by_function_name()` — the filter in that method is always `{"function_name": {"$eq": function_name}}`.

---

### MCP Tool: `query_knowledge_with_scores(query, k=5) → List[Dict]`

Same as query_knowledge but includes similarity scores for retrieval confidence assessment.

**k range:** 1–20

---

## 6.2 Knowledge Base Write Tool

### MCP Tool: `add_knowledge_text(text, source_name="analysis_result") → Dict`

**Implementation:**
1. `_get_pipeline().add_text(text_content=text, source_name=source_name)`
2. Detects "PATTERN CARD:" prefix → type="vulnerability_pattern"; else type="analysis_result"
3. Generates entry_id (UUID hex)
4. Sets `origin="llm_generated"` in base_meta
5. If pattern or text <= CHILD_CHUNK_SIZE → `chunks = [doc]` (atomic); else → `_chunk_document(doc)`
6. `VectorStore.upsert_chunks(chunks)`

**Returns:** `{"status", "message", "chunks_added", "source", "entry_id"}`

---

## 6.3 Knowledge Base Info Tool

### MCP Tool: `get_knowledge_info() → Dict`

**Returns:** `{"status", "index_name", "namespace", "embedding_model", "retrieval_min_score", "index_status"}`

---

## 6.4 MCP Prompts (Workflow Templates)

The server registers `@mcp.prompt()` decorators — LLM-facing workflow templates. Implemented in `src/prompts.py`.

| Prompt | Purpose |
|---|---|
| `analyze_current_function` | Full 6-step vulnerability analysis on current decompiled function |
| `triage_module` | Fast attack-surface scan; classify all functions by role |
| `trace_data_flow` | Trace guest-controlled value across multi-function call chain |
| `refactor_current_function` | Rename function/vars with IVC-semantic names; insert security comments |
| `generate_poc` | Write minimal QNX guest-side PoC for MEDIUM/HIGH hypotheses |
| `map_attack_surface` | Synthesize findings into Mermaid diagram + attack surface table |
| `identify_fuzzing_targets` | Convert hypotheses into fuzzing specs with mutation strategy |
| `benchmark_analysis` | Full workflow on known-vulnerable function to validate RAG performance |

---

# SECTION 7: UTILITY FUNCTIONS & HELPERS

## 7.1 Configuration (config.py)

```python
PINECONE_API_KEY: str                                    # required
PINECONE_INDEX_NAME: str = "vuln-analysis-rag"           # default (no -v2 suffix)
PINECONE_NAMESPACE: str = "default"                      # partition (from env)
RETRIEVAL_MIN_SCORE: float = 0.0                         # 0.0 = disabled

EMBEDDING_MODEL: str = ""                                # must be set via env var
EMBEDDINGS_PROVIDER: str = "openai" | "third_party" | "proxy"
EMBEDDINGS_API_BASE: str = ""                            # required for third_party/proxy
EMBEDDINGS_API_KEY: str = ""                             # required
EMBEDDINGS_CHUNK_SIZE: int = 5 (third_party) | 100 (openai)  # texts per embedding API call
EMBEDDINGS_TIMEOUT: float = 60                           # seconds for embedding API call

CHUNK_SIZE: int = 1000            # fallback splitter chunk size
CHUNK_OVERLAP: int = 200
CHILD_CHUNK_SIZE: int = 1500      # child chunk max size (also section split threshold)
CHILD_CHUNK_OVERLAP: int = 200
PARENT_CONTENT_MAX: int = 3000    # in config but unused by current chunker

DOCS_DIR: str                     # auto-resolved from src/ location
TESSERACT_PATH: str = ""          # optional OCR
```

**Functions:**
- `embeddings_client_kwargs() → Dict` — builds kwargs for OpenAIEmbeddings (model, api_key, chunk_size, timeout, optionally api_base)
- `apply_embeddings_env() → None` — sets OPENAI_API_KEY/BASE env vars (for SDK compatibility)

---

## 7.2 Logging (logger.py)

### Function: `log_call(tool, args, *, ok, ms, extra=None) → None`
Logs MCP tool invocation to stderr + JSONL file. All MCP tools call this.

### Function: `log_server_start(min_score) → None`
Logs server startup event.

---

## 7.3 JSON Serialization (main.py)

### Function: `_ensure_json_serializable(value) → Any`
Guards against non-serializable types leaking into MCP responses. Tries json.dumps; on failure for str uses round-trip loads; otherwise returns error dict.

### Function: `_no_evidence(query, min_score) → List[Dict]`
Returns `[{"status": "no_evidence", "query": ..., "message": ...}]` when retrieval finds no matches above threshold.

---

## 7.4 Singleton Factories (main.py / pipeline.py)

### Function: `_get_pipeline() → DocumentPipeline`
Module-level singleton DocumentPipeline (reuses Chunker + VectorStore).

### Function: `_save_converted_docs(docs, output_dir="converted_docs") → None`
Optional: serialize loaded Documents to YAML-frontmatter Markdown files mirroring rag_docs/ structure. Used with `--save-converted` flag.

---

# SECTION 8: CALL FLOW DIAGRAMS

## Flow 1: CLI Ingestion

```
python -m src.pipeline [--paths ...] [--append-only] [--save-converted]
│
├─ expand_paths()
├─ DocumentPipeline(paths, save_converted=...)
│  └─ __init__(): create Chunker, VectorStore
└─ .run(append_only=...)
   ├─ [1/3] discover_documents() → List[str]
   ├─ load_documents(file_paths) → List[Document]
   │  ├─ canonical_source()
   │  ├─ convert_file(path, source)
   │  │  ├─ [vuln-pattern/*.md]         → convert_vuln_pattern()
   │  │  ├─ [vuln-pattern/other]        → [SKIP]
   │  │  ├─ [build-config/*.build|sh|layout] → convert_build_config()
   │  │  ├─ [decompiled/*.c|h]          → convert_decompiled()
   │  │  ├─ [qnx-doc/*.html]            → _convert_html()
   │  │  ├─ [qnx-doc/other]             → [SKIP]
   │  │  └─ [other dir] by ext: .pdf → convert_pdf(); .c/.h → convert_c(); .txt/.md → _load_md_file()
   │  └─ frontmatter_to_doc() → Document
   │
   ├─ [optional] _save_converted_docs() → converted_docs/
   │
   ├─ [2/3] chunker.chunk_all(docs) → List[Document]
   │  ├─ Atomic types → pass through unchanged
   │  └─ Others → _chunk_document()
   │     ├─ MarkdownHeaderTextSplitter → sections
   │     └─ [oversized section] → _split_into_children(text, meta)
   │        ├─ code types (c_function, c_section) → _code_child_splitter (regex)
   │        └─ other types → _child_splitter (prose)
   │        └─ metadata: {parent_id, sibling_index, n_siblings}
   │
   └─ [3/3] store.upsert_incremental(chunks, append_only=...)
      ├─ make_vector_id(chunk)
      ├─ [incremental] _fetch_existing_ids() via documents.fetch()
      ├─ [incremental] _delete_by_source() via query_string * + delete()
      └─ _upsert(changed_docs, ids)
         ├─ _guard_sizes(docs)  [raises if exceeded]
         ├─ per record: embed → build record → _guard_metadata_size → batch_upsert(batch_size=1)
         └─ Embedder.embed_documents([text_for_dense_embedding(...)])
            └─ flatten_for_embedding() for TEXT_TYPES, raw for code/config types
```

## Flow 2: MCP Query (search_component_context — Phase A)

```
MCP Client
│
├─ search_component_context(component_name, extra_context, k=7)
│  ├─ effective_filter = {"type": {"$ne": "vulnerability_pattern"}}
│  ├─ get_retriever() [singleton]
│  ├─ retriever.query_with_scores(combined, k=7, filter=effective_filter)
│  │  └─ _hybrid_query(query, k=7, filter)  [RRF]
│  │     ├─ _dense_query(query, k=14, filter) → dense_matches
│  │     ├─ _bm25_query(query, k=14, filter)  → bm25_matches
│  │     ├─ RRF merge: score[id] += 1/(60+rank) for each leg
│  │     └─ return top-7 by RRF score
│  ├─ _format_results(matches, scores)
│  │  ├─ Partition: standalone vs parent_groups
│  │  ├─ Standalone: context = content
│  │  └─ Parent group: _reconstruct_context(pid, group_matches)
│  │     ├─ Fill from already-retrieved siblings
│  │     └─ [gaps] _fetch_siblings(pid) via query_string * + parent_id filter
│  │        └─ join in sibling_index order → full parent section
│  └─ return sorted by rank
│
└─ [Result: List[Dict] — content, context (full parent), function_name, doc_title, score, ...]
```

## Flow 3: MCP Query (search_by_function — exact lookup)

```
MCP Client
│
├─ search_by_function("vdshmem_vwrite", binary_name="vdev-shmem")
│  ├─ retriever.query_by_function_name("vdshmem_vwrite", "vdev-shmem")
│  │  ├─ filter = {"function_name": {"$eq": "vdshmem_vwrite"}}
│  │  ├─ _bm25_query("vdshmem_vwrite vdev-shmem", k=10, filter)
│  │  └─ [0 BM25 hits] → _dense_query("vdshmem_vwrite", k=10, filter)
│  └─ _format_results(matches, scores)  [with sibling reconstruction]
│
└─ [Result: all indexed chunks from that function, with reconstructed context]
```

## Flow 4: MCP Add Knowledge (add_knowledge_text)

```
MCP Client
│
├─ add_knowledge_text("PATTERN CARD: ...", source_name="vdev-shmem-toctou")
│  ├─ _get_pipeline().add_text(text, source_name)
│  │  ├─ Detect "PATTERN CARD:" → type="vulnerability_pattern", atomic
│  │  ├─ base_meta: {source, file_name, type, page, entry_id, origin="llm_generated"}
│  │  ├─ [pattern or short] → chunks = [Document(...)]
│  │  └─ [long non-pattern] → chunker._chunk_document(doc) → chunks
│  ├─ store.upsert_chunks(chunks)
│  │  ├─ make_vector_id(chunk)
│  │  └─ _upsert(chunks, ids)
│  │     ├─ flatten_for_embedding("vulnerability_pattern") → dense embed
│  │     └─ idx.documents.batch_upsert(namespace, [record], batch_size=1)
│  └─ return {"status": "success", "chunks_added": "1", "entry_id": ...}
│
└─ [Result: Dict]
```

---

# SECTION 9: QUICK LOOKUP TABLE

| Function | Module | Purpose | Notes |
|---|---|---|---|
| `discover_documents()` | loader | Find all files in rag_docs | — |
| `expand_paths()` | loader | Resolve path specs | — |
| `load_documents()` | loader | Convert files → Documents | — |
| `convert_file()` | router | Route file to converter | json/build/sh/layout fallbacks disabled |
| `_convert_html()` | router | Convert QNX HTML to Markdown | tries div.body → body → soup |
| `_load_toc_map()` | router | Parse main.xml for TOC hierarchy | — |
| `convert_vuln_pattern()` | vuln_pattern_converter | .md vuln pattern → atomic doc | — |
| `convert_c()` | c_converter | C source → semantic units | — |
| `convert_decompiled()` | c_converter | Decompiled C → semantic units | — |
| `convert_pdf()` | pdf_converter | PDF pages → docs | — |
| `convert_build_config()` | build_converter | Build config files | — |
| `get_doc_dir()` | router | Extract top-level dir | — |
| `canonical_source()` | router | Generate stable source ID | — |
| `frontmatter_to_doc()` | router | Parse YAML frontmatter (safe_load) | — |
| `make_frontmatter()` | utils | Wrap with YAML metadata | — |
| `flatten_for_embedding()` | embedder | Markdown → plain prose | — |
| `text_for_dense_embedding()` | embedder | Route flatten vs raw by type | — |
| `Embedder` | embedder | OpenAI embedding client | chunk_size, timeout configurable |
| `TEXT_TYPES` | embedder | Types that get flattened | — |
| `_parent_id()` | chunker | SHA256[:16] for sibling linkage | — |
| `_section_path()` | chunker | h1 > h2 > h3 breadcrumb | — |
| `Chunker.chunk_all()` | chunker | Route to chunking strategy | — |
| `Chunker._chunk_document()` | chunker | Apply parent-child split | — |
| `Chunker._split_into_children()` | chunker | Recursive child split; attach parent_id/sibling_index/n_siblings | no parent_content stored |
| `_code_child_splitter` | chunker | Regex-aware C code splitter | — |
| `_CODE_SEPARATORS` | chunker | `\n\s*}\n`, `;\n` regex patterns | — |
| `_CODE_CHILD_TYPES` | chunker | {c_function, c_section} — use code splitter | build_section etc. NOT included |
| `ATOMIC_TYPES` | chunker | {vulnerability_pattern, c_overview, c_constants, c_struct, build_config} | build_image/script NOT atomic |
| `make_vector_id()` | pinecone_client | Stable document ID | includes struct_name/block_name fallbacks |
| `VectorStore._upsert()` | pinecone_client | Embed + upsert one-at-a-time with error recovery | not batch-100 |
| `VectorStore._delete_by_source()` | pinecone_client | query_string * → delete IDs in 1000-batches | — |
| `VectorStore._fetch_existing_ids()` | pinecone_client | documents.fetch() in 200-batches | — |
| `VectorStore.upsert_incremental()` | pinecone_client | Smart upsert with change detect | FORCE_REFRESH_SOURCES env var |
| `VectorStore.upsert_chunks()` | pinecone_client | Runtime upsert | — |
| `_guard_sizes()` | pinecone_client | Size check → raises ValueError | no truncation |
| `_guard_metadata_size()` | pinecone_client | chunk_text limit → raises ValueError | no truncation for any type |
| `_CODE_TYPES` | pinecone_client | Types with code embedding limit (15k) | build_image/script/section/suid/hypervisor NOT included |
| `DocumentRetriever._hybrid_query()` | retriever | RRF: dense + BM25, k*2 each, merge by 1/(60+rank) | NOT $match_any pre-filter |
| `DocumentRetriever._dense_query()` | retriever | Pure dense semantic search | — |
| `DocumentRetriever._bm25_query()` | retriever | BM25 lexical search | — |
| `DocumentRetriever._fetch_siblings()` | retriever | Wildcard query by parent_id filter → sibling chunks | — |
| `DocumentRetriever._reconstruct_context()` | retriever | Join siblings in order → full parent section | uses already-retrieved first |
| `DocumentRetriever._format_results()` | retriever | Group by parent_id; one result per parent; context = reconstructed section | replaces _dedup_contexts |
| `DocumentRetriever.query()` | retriever | Hybrid search, no scores | — |
| `DocumentRetriever.query_with_scores()` | retriever | Hybrid search with scores | — |
| `DocumentRetriever.query_by_function_name()` | retriever | BM25-primary exact lookup | — |
| `DocumentRetriever._match_to_dict()` | retriever | Serialize preview match object; context="" initially | — |
| `DocumentRetriever.get_db_info()` | retriever | Connection check | — |
| `get_retriever()` | retriever | Singleton factory | — |
| `query_knowledge()` | main | MCP: generic hybrid search | k 1-20 |
| `search_vulnerability_patterns()` | main | MCP: Phase B — pattern search | k 1-10 |
| `search_component_context()` | main | MCP: Phase A — component search | k 1-15 |
| `search_by_function()` | main | MCP: exact function lookup | filter param not forwarded |
| `query_knowledge_with_scores()` | main | MCP: search with scores | k 1-20 |
| `add_knowledge_text()` | main | MCP: add finding to KB | sets origin=llm_generated |
| `get_knowledge_info()` | main | MCP: connection check | — |

---

# SECTION 10: KEY ARCHITECTURAL DECISIONS

| Decision | Rationale |
|---|---|
| Pinecone `pc.preview` document API (SDK 8+) | Only API supporting native BM25 FTS + dense vector in same index. `search_records` (integrated inference) requires Pinecone-hosted model — incompatible with OpenAI embeddings. |
| RRF fusion (not $match_any pre-filter) | Dense + BM25 run independently with k*2 candidates each; RRF score `1/(60+rank)` merges legs so documents appearing in both get a boost. More robust than pre-filter: never drops semantic-only or identifier-only queries. |
| Sibling-based context reconstruction (parent_id/sibling_index/n_siblings) | Storing `parent_content` in every child metadata would hit Pinecone's ~40KB/doc limit for large functions. Sibling IDs allow on-demand reconstruction by fetching only the needed chunks. |
| `_format_results()` merges parent group → one result | Multiple child chunks from same parent are coalesced into one result entry (best rank wins); context holds the full reconstructed section. Prevents LLM from seeing the same function in multiple fragmented results. |
| Per-record upsert (batch_size=1) | Isolates upsert failures to individual records; a malformed embedding or record doesn't abort the entire batch. Trade-off: more API calls, but full error visibility. |
| Separate `embedding` (dense) + `text` (FTS) fields | BM25 indexed on `text`; dense vector on `embedding`. `chunk_text` is a stored copy returned in results for readability. |
| Type-aware flattening (TEXT_TYPES only) | Flattening C code destroys `{`, `}`, `*`, `&` — ~50% of program semantics. Prose Markdown headers/bold are noise for embedding. |
| Never flatten query strings | LLM queries may contain `"void *memcpy(void *dst, ...)"` — stripping `*`/`(` degrades both BM25 and dense precision. |
| `MAX_EMBEDDING_CHARS_CODE = 15000` | C code tokenizes ~1 char/token vs ~4 chars/token for prose. 25000-char C file can exceed 8192-token limit of text-embedding-3-small. |
| Fail-fast for all size guards | Silent truncation drops closing braces, `free()`, `unlock()` → false-positive vulnerability reports. Both `_guard_sizes` and `_guard_metadata_size` raise instead of truncating. |
| Regex separators `\n\s*}\n` for code chunking | IDA/Ghidra always indents closing braces (`    }\n`, `        }\n`). Exact string `"\n}\n"` misses 90% of block boundaries. |
| `query_string *` for delete-by-source and sibling fetch | Document API has no filter-delete or filter-fetch endpoint. Wildcard query with filter collects IDs; then delete/fetch by ID. |
| PINECONE_NAMESPACE from config | Prevents hardcoding; enables multi-target analysis separation (different binaries/systems in different namespaces). |
| yaml.safe_load via frontmatter_to_doc() reuse | `convert_vuln_pattern()` reuses `frontmatter_to_doc()` which calls `yaml.safe_load` — no arbitrary Python object deserialization risk. |
| filter param exposed to LLM on all search tools | LLM agents can precisely scope retrieval without relying on semantic matching alone (e.g., restrict to one binary's functions). |

---

**End of Function Reference**

Use this as a **single-source lookup** when tracing execution, understanding call graphs, or implementing changes.
