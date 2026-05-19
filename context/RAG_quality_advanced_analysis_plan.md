# Native Hybrid RAG Migration Plan

## Context

The Pinecone index "vuln-analysis-rag" uses an **Integrated Hybrid Schema** with three fields:
- `dense_embedding` (1536 dims, dotproduct) — dense semantic
- `sparse_embedding` — sparse lexical (schema-defined)
- `text` — full-text BM25 (indexed, but NOT returned in query results)

The current codebase uses `langchain_pinecone.PineconeVectorStore` which targets the standard `values` field — incompatible. This plan migrates to the Pinecone v7 `search_records` / `upsert_records` API for native hybrid retrieval.

**Thesis narrative:** "Multi-signal hybrid index — dense semantic retrieval + server-side BM25 lexical retrieval, fused natively by Pinecone — enables simultaneous lookup of vulnerability concepts (semantic) and decompiled code identifiers like function/struct names (lexical), which single-signal dense retrieval fails on."

---

## Confirmed API (Pinecone SDK 7.3.0)

```python
# Upsert (upsert_records, not upsert):
index.upsert_records(namespace=self._namespace, records=[{  # namespace from config
    "_id": "hash-id",
    "dense_embedding": [0.12, ...],   # 1536 dims — SINGULAR (not dense_embeddings)
    "text": "raw chunk text",          # BM25 indexed, NOT returned in query
    # all other keys → filterable metadata
    "chunk_text": "raw chunk text",    # copy for retrieval return
    "type": "c_function",
    "source": "rag_docs/decompiled/qvm.c",
    "function_name": "vdshmem_vwrite",
    ...
}])

# Query (search_records — true hybrid, raw query, no flatten):
from pinecone import SearchQuery, SearchQueryVector
resp = index.search_records(
    namespace=self._namespace,
    query=SearchQuery(
        inputs={"text": query_text},         # raw query → BM25 full-text
        top_k=k,
        filter=filter_dict,                  # optional metadata filter (exposed to LLM)
        vector=SearchQueryVector(values=dense_vec),  # raw embed → dense
    ),
    fields=["chunk_text", "type", "source", "function_name", "section",
            "doc_id", "page", "origin", "doc_title", "toc_section", "parent_content"],
)
# Results: resp.result.hits — each hit has ._id, .score, .fields
```

---

## Architecture Overview

```
rag_docs/
├── qnx-doc/        HTML dirs → parse inline → Markdown+frontmatter   [origin: processed]
├── vuln-pattern/   .md YAML frontmatter, hand-written                 [origin: processed]
├── decompiled/     LLM-refactored .c with /* ==== */ dividers         [origin: processed]
├── build-config/   .build, .sh, .layout                               [origin: processed]
└── other/          .pdf, .c, .h, .md, .txt (generic)                  [origin: unprocessed]

Ingestion pipeline:
  File → converter → YAML-frontmatter MD strings
  → frontmatter_to_doc() → Document
  → Chunker (parent-child / atomic)
  → For dense embedding: flatten_for_embedding(text) if doc_type is text-based
                         raw text if doc_type is code/config
  → OpenAI embed → dense_embedding (1536d)
  → upsert_records: { dense_embedding, text (raw for BM25), chunk_text (copy), ...metadata }

Retrieval:
  query_text (raw, no flatten) → embed → dense_vec
  → search_records(inputs={"text": query_text}, vector=dense_vec, filter, top_k, namespace)
  → resp.result.hits → _format() → _dedup_contexts() → JSON to Claude
```

---

## 5 Architectural Corrections

### Fix 1: Type-Aware Flattening (not universal)

**Problem:** Applying `flatten_for_embedding()` to C code destroys semantic meaning — `{`, `}`, `*`, `&`, indentation carry ~50% of program semantics. Flattening decompiled code into prose makes embedding models lose directionality completely.

**Solution:** Route by `doc_type` — flatten only text-based documents:

```python
# ingestion/embedder.py
TEXT_TYPES = frozenset({
    "reference_document", "analysis_result", "vulnerability_pattern",
})

def text_for_dense_embedding(text: str, doc_type: str) -> str:
    """
    Return the text variant to use for dense embedding.
    Text-based docs: flatten Markdown syntax to plain prose (better semantic density).
    Code/config docs: use raw text (syntax carries semantic meaning).
    """
    if doc_type in TEXT_TYPES:
        return flatten_for_embedding(text)
    return text  # c_function, c_struct, c_constants, c_section, build_*, etc.
```

In `pinecone_client.py` upsert:
```python
doc_type = doc.metadata.get("type", "")
text_for_embed = text_for_dense_embedding(doc.page_content, doc_type)
dense_vec = embedder.embed_documents([text_for_embed])[0]
```

### Fix 2: search_records API for true hybrid

**Problem:** Calling `index.query(vector=dense_vec)` only triggers dense search — BM25 is NOT activated.

**Solution:** Use `index.search_records()` with both `inputs` (activates BM25) and `vector` (activates dense). Pinecone server fuses both signals.

```python
from pinecone import SearchQuery, SearchQueryVector

resp = index.search_records(
    namespace="default",
    query=SearchQuery(
        inputs={"text": query_text},                  # BM25 full-text signal
        top_k=k,
        filter=filter_dict,
        vector=SearchQueryVector(values=dense_vec),   # dense semantic signal
    ),
    fields=["chunk_text", "type", "source", "function_name", "section",
            "doc_id", "page", "origin", "doc_title", "toc_section", "parent_content"],
)
hits = resp.result.hits
```

### Fix 3: No flattening on query text

**Problem:** LLM may query with code-like strings (e.g., `"void *memcpy(void *dst, ...)"`) — flattening removes `*`, `(`, `)` and degrades vector search precision.

**Solution:** Never flatten the query. Generate dense embedding from the raw query string, and pass the raw query to `inputs["text"]` for BM25.

```python
def _raw_query(self, query: str, k: int, filter=None):
    dense_vec = self._embedder.embed_query(query)  # raw query, no flattening
    resp = index.search_records(
        namespace="default",
        query=SearchQuery(
            inputs={"text": query},               # raw query for BM25
            top_k=k,
            filter=filter,
            vector=SearchQueryVector(values=dense_vec),
        ),
        fields=[...],
    )
```

### Fix 4: Correct field name — `dense_embedding` (singular)

**Problem:** Plan said `dense_embeddings` (plural) — actual schema uses `dense_embedding` (singular).

**Solution:** All upsert records use `"dense_embedding"` (singular):
```python
record = {
    "_id": id_,
    "dense_embedding": dense_vec,   # ← singular
    "text": doc.page_content,
    "chunk_text": ...,
    ...metadata...
}
```

### Fix 5: Metadata size guard — fail-fast for code, warn for text

**Problem:** `chunk_text` in metadata is a copy of `chunk.page_content`. Pinecone metadata limit ~40KB/vector.

**Reality check:** Child chunks bounded by `CHILD_CHUNK_SIZE = 1500 chars`. Atomic types pass through `_guard_sizes()`. But for code: OpenAI's tokenizer splits special chars (`*`, `&`, `{`, hex literals) as 1 token each — 25000 chars of C code can easily exceed 8192 tokens (hard limit of `text-embedding-3-small`). 

**Two-tier fix:**

1. **`MAX_EMBEDDING_CHARS` by type** in `_guard_sizes()`:
   ```python
   MAX_EMBEDDING_CHARS = 25000        # text/prose (safe: ~6250 tokens)
   MAX_EMBEDDING_CHARS_CODE = 15000   # C code (conservative: dense token packing)
   
   def _guard_sizes(docs):
       for doc in docs:
           limit = MAX_EMBEDDING_CHARS_CODE if doc.metadata.get("type", "") in CODE_TYPES else MAX_EMBEDDING_CHARS
           if len(doc.page_content) > limit:
               _log(f"  [WARN] Chunk truncated ...")
               doc.page_content = doc.page_content[:limit]
   ```

2. **`_guard_metadata_size()` for metadata copy** — differentiated by type:
   ```python
   MAX_CHUNK_TEXT_METADATA = 20000  # safety net for metadata copy
   
   def _guard_metadata_size(records):
       for r in records:
           ct = r.get("chunk_text", "")
           if len(ct) > MAX_CHUNK_TEXT_METADATA:
               doc_type = r.get("type", "")
               if doc_type in CODE_TYPES:
                   raise ValueError(
                       f"Code chunk exceeds metadata limit ({len(ct)} chars): "
                       f"type={doc_type} source={r.get('source','?')} "
                       f"function={r.get('function_name','?')} — "
                       f"review Chunker CHILD_CHUNK_SIZE / ATOMIC_TYPES config."
                   )
               _log(f"  [WARN] Text chunk truncated in metadata ({len(ct)} chars): {r.get('source','?')}")
               r["chunk_text"] = ct[:MAX_CHUNK_TEXT_METADATA]
   ```

### Fix 6: Namespace from config (no hardcode)

**Problem:** Plan hardcoded `namespace="default"` in all upsert/query calls.

**Solution:** Read from config and pass through class instances:

```python
# config.py
PINECONE_NAMESPACE: str = os.getenv("PINECONE_NAMESPACE", "default")

# pinecone_client.py VectorStore.__init__:
self._namespace = PINECONE_NAMESPACE

# retriever.py DocumentRetriever.__init__:
self._namespace = PINECONE_NAMESPACE
```

All `upsert_records(namespace=...)` and `search_records(namespace=...)` use `self._namespace`.

### Fix 7: yaml.safe_load enforcement

**Solution:** `convert_vuln_pattern()` must call `frontmatter_to_doc()` from `router.py` (which already uses `yaml.safe_load`) rather than parsing YAML itself. This is already the plan — making it explicit:

```python
# converters/vuln_pattern_converter.py
from ingestion.router import frontmatter_to_doc  # uses yaml.safe_load internally

def convert_vuln_pattern(file_path: str, source: str) -> List[str]:
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    doc = frontmatter_to_doc(text)  # safe_load, no yaml.load()
    ...
```

### Fix 8: Expose metadata filter to LLM via MCP tools

**Problem:** `_raw_query()` supports `filter` param internally but MCP tools don't expose it — LLM can only do global search.

**Solution:** Add `filter` param to `search_component_context`, `search_vulnerability_patterns`, and `search_by_function`. LLM can construct filter dicts for precise scoping:

```python
@mcp.tool()
def search_component_context(
    component_name: str,
    extra_context: str = "",
    k: int = 7,
    filter: Optional[Dict] = None,
) -> List[Dict[str, str]]:
    """
    ...
    filter: Optional Pinecone metadata filter dict for precise scoping. Examples:
      {"type": {"$eq": "c_function"}} — only decompiled functions
      {"source": {"$eq": "rag_docs/decompiled/qvm.c"}} — only from qvm.c
      {"function_name": {"$in": ["parse_packet", "handle_input"]}} — specific functions
    Combining: {"$and": [{"type": {"$eq": "c_function"}}, {"source": ...}]}
    """
```

Same pattern for `search_vulnerability_patterns` and `search_by_function`.

---

## Files Modified/Created

### NEW: `src/ingestion/embedder.py`

```python
# ingestion/embedder.py — Text normalization + dense embedding

TEXT_TYPES = frozenset({
    "reference_document", "analysis_result", "vulnerability_pattern",
})

def flatten_for_embedding(text: str) -> str:
    """
    Convert Markdown syntax to plain prose for dense embedding.
    Only applied to text-based doc types, never to code or query strings.

    ## Section Title  →  Section Title:
    **Field:** value  →  Field: value
    - bullet         →  bullet
    ```lang\ncode```  →  code (fences stripped)
    """
    # 4 regex transforms + whitespace normalization

def text_for_dense_embedding(text: str, doc_type: str) -> str:
    """Route to flatten (text types) or raw (code/config types)."""
    return flatten_for_embedding(text) if doc_type in TEXT_TYPES else text

class Embedder:
    def embed_documents(self, texts: List[str]) -> List[List[float]]: ...
    def embed_query(self, text: str) -> List[float]: ...
```

### NEW: `src/converters/vuln_pattern_converter.py`

Thin pass-through for hand-written `.md` vuln-pattern files:
- Reads `.md` file with YAML frontmatter
- Validates required fields: `doc_id`, `vuln_type` — warns but doesn't skip if missing
- Sets `type: vulnerability_pattern`, injects `source`, `file_name`
- Returns single YAML-frontmatter string (atomic — no splitting in converter)

### `src/store/pinecone_client.py` — upsert migration

Replace `PineconeVectorStore.from_documents()` / `.add_documents()` with `index.upsert_records()`.

New constants + helpers:
```python
MAX_CHUNK_TEXT_METADATA = 20000  # safety net (see Fix 5)
CODE_TYPES = frozenset({...})    # code/config types — raise on overflow

def _guard_metadata_size(records): ...  # fail-fast for code, warn+truncate for text
```

`__init__`: add `self._namespace = PINECONE_NAMESPACE` (Fix 6).

`_upsert()` rewrite:
```python
def _upsert(self, docs, ids):
    docs = _guard_sizes(docs)
    embedder = Embedder()
    dense_vecs = embedder.embed_documents([
        text_for_dense_embedding(d.page_content, d.metadata.get("type", ""))
        for d in docs
    ])
    records = _guard_metadata_size([{
        "_id": id_,
        "dense_embedding": dense,
        "text": doc.page_content,        # BM25 indexed field
        "chunk_text": doc.page_content,  # metadata copy for retrieval return
        **{k: v for k, v in doc.metadata.items() if v is not None and v != ""},
    } for id_, dense, doc in zip(ids, dense_vecs, docs)])
    index = self._index()
    for batch in _batched(records, 100):
        index.upsert_records(namespace=self._namespace, records=batch)
```

Remove: `_vs()`, `langchain_pinecone` import, `langchain_openai` import.  
Keep: `_index()`, `make_vector_id()`, `_guard_sizes()`, `_fetch_existing_ids()`, `_delete_by_source()`, `upsert_incremental()`, `upsert_chunks()`.

### `src/retriever.py` — query migration

`__init__`: add `self._namespace = PINECONE_NAMESPACE` (Fix 6).

```python
from pinecone import Pinecone, SearchQuery, SearchQueryVector
from ingestion.embedder import Embedder

RETRIEVE_FIELDS = [
    "chunk_text", "parent_content", "type", "source", "file_name",
    "function_name", "section", "doc_id", "page", "origin",
    "doc_title", "toc_section", "entry_id",
]

class DocumentRetriever:
    def _raw_query(self, query: str, k: int, filter=None):
        # No flattening on query — raw string for both BM25 and dense (Fix 3)
        dense_vec = self._embedder.embed_query(query)
        resp = self._pc.Index(self._index_name).search_records(
            namespace=self._namespace,
            query=SearchQuery(
                inputs={"text": query},
                top_k=k,
                filter=filter,
                vector=SearchQueryVector(values=dense_vec),
            ),
            fields=RETRIEVE_FIELDS,
        )
        return [(hit.fields, hit.score) for hit in resp.result.hits]
```

`_format()`: reads `fields.get("chunk_text", "")` for `content`, `fields.get("parent_content", "")` for `context`.

Remove: `rank_bm25`, `BM25Okapi`, `_bm25_rerank()`, `PineconeVectorStore`, `alpha` param from all methods.

### `src/ingestion/chunker.py` — code-aware separators

Add a second child splitter for code types with separators that respect C statement/block boundaries. Current `_child_splitter` uses `separators=["\n\n", "\n", ". ", " ", ""]` — the `". "` and `" "` fallbacks can split inside expressions if no newline is found within 1500 chars.

```python
# Regex separators — bắt mọi dạng thụt lề của decompiled C:
#   \n\s*}\n — closing brace at any indent level (IDA/Ghidra output always indented)
#   ;\n       — end of statement
#   \n\n      — blank line
#   \n        — line boundary (fallback)
_CODE_SEPARATORS = [r"\n\s*\}\n", r";\n", r"\n\n", r"\n", r""]

CODE_CHILD_TYPES = frozenset({
    "c_function", "c_section",
    "build_section", "build_suid", "build_hypervisor",
})

class Chunker:
    def __init__(self):
        ...
        self._code_child_splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHILD_CHUNK_SIZE,
            chunk_overlap=CHILD_CHUNK_OVERLAP,
            separators=_CODE_SEPARATORS,
            is_separator_regex=True,  # required for \s* to work
        )

    def _split_into_children(self, section_text, section_meta):
        doc_type = section_meta.get("type", "")
        splitter = self._code_child_splitter if doc_type in CODE_CHILD_TYPES else self._child_splitter
        ...
```

This handles IDA/Ghidra indented output like `    }\n`, `        }\n` correctly via `\s*` — exact string `"\n}\n"` would miss 90% of block boundaries.

### `src/ingestion/router.py` — add HTML + .md vuln-pattern routing

**HTML for qnx-doc:**
- Add `convert_html(html_path, source, toc_map)` — inline BeautifulSoup + markdownify logic
- Add `_load_toc_map(html_dir)` — reads `main.xml` from the plugin's parent dir, caches per directory
- `convert_file()` under `qnx-doc`: if `.html` → `convert_html()`; else keep `_load_md_file()`
- Add `.html` to `SUPPORTED_EXTS`
- Soft-import `bs4`, `markdownify` inside function (avoid hard dep)

**`.md` vuln-pattern:**
- `convert_file()` under `vuln-pattern`: if `.md` → `convert_vuln_pattern()`; `.json` → `convert_json()` (backward compat)

### `src/converters/__init__.py`
Export `convert_vuln_pattern`.

### `src/config.py`
```python
PINECONE_INDEX_NAME: str = os.getenv("PINECONE_INDEX_NAME", "vuln-analysis-rag")
PINECONE_NAMESPACE: str = os.getenv("PINECONE_NAMESPACE", "default")
```
Remove `HYBRID_ALPHA`.

### `src/main.py`
Remove `HYBRID_ALPHA` import. Remove `alpha` params from MCP tools. Add `filter: Optional[Dict] = None` param to `search_component_context`, `search_vulnerability_patterns`, `search_by_function` (Fix 8). Update docstrings: mention "native hybrid (dense + BM25 full-text)", document filter format with examples.

### `requirements.txt`
```
Remove: langchain-pinecone>=0.2.0, rank-bm25>=0.2.2
Keep:   pinecone>=3.0.0 (already at 7.3.0 per installed version)
        langchain-openai>=0.2.0, langchain-core>=0.3.0
Add:    beautifulsoup4>=4.12.0, markdownify>=0.11.0
```

### `rag_docs/vuln-pattern/SPEC.md`
Update from JSON schema to `.md` YAML frontmatter format:
```markdown
---
doc_id: pattern-buffer-overflow-memcpy   # required
vuln_type: buffer_overflow               # required
sink: memcpy
component: network_stack
severity: HIGH
cwe: ["CWE-120"]
binary_indicators: ["memcpy(dst, src, guest_len)"]
tags: ["memory_corruption"]
---

## Description ...
## Apply When ...
## Root Cause ...
## Code Pattern
```c
// vulnerable vs secure
```
```
Required: `doc_id`, `vuln_type`. Backward compat: `.json` files still work via `convert_json()`.

---

## Implementation Order

1. `requirements.txt`
2. `src/ingestion/embedder.py` — NEW
3. `src/store/pinecone_client.py` — upsert migration
4. `src/retriever.py` — query migration + remove BM25 rerank
5. `src/config.py` — defaults + cleanup
6. `src/ingestion/chunker.py` — code-aware separators
7. `src/converters/vuln_pattern_converter.py` — NEW
8. `src/ingestion/router.py` — HTML + .md routing
9. `src/converters/__init__.py` — export
10. `src/main.py` — remove alpha, add filter params
11. `rag_docs/vuln-pattern/SPEC.md` — update spec

---

## Verification

1. **flatten unit test:** `assert "**" not in flatten_for_embedding("**Field:** val")`
2. **Code passthrough:** `assert text_for_dense_embedding("memcpy(dst, src, n);", "c_function") == "memcpy(dst, src, n);"`
3. **Upsert smoke:** `python src/pipeline.py --paths decompiled/qvm.c --append-only` → no error
4. **Query smoke:** `python src/retriever.py` → non-empty `content` field in results
5. **Identifier recall (BM25):** query `"vdshmem_vwrite"` → rank 1 is that function
6. **Semantic recall:** query `"buffer overflow unchecked length"` → rank 1 is a pattern card
7. **MCP health:** `get_knowledge_info()` → `status: connected`, `index_name: vuln-analysis-rag`
8. **Metadata size:** upsert large decompiled chunk → no 40KB error
