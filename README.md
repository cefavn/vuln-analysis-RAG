# RAG MCP Server - QNX Vulnerability Analysis

A Model Context Protocol (MCP) server that provides Retrieval-Augmented Generation (RAG) capabilities for security analysis of QNX vulnerabilities. Integrates semantic search over a vector database of PDFs, documentation, and vulnerability pattern cards with Claude AI.

## Features

- **Semantic Search**: Query the knowledge base using natural language for QNX documentation, architecture context, and vulnerability patterns
- **Vulnerability Pattern Matching**: Search specific bug classes (buffer overflow, integer overflow, race conditions, use-after-free, TOCTOU, etc.)
- **Component Context Retrieval**: Access prior analysis results and data structure layouts
- **Vector Database**: Powered by Pinecone and OpenAI embeddings
- **Docker Support**: Easy deployment with containerization
- **Smart Document Processing**: Automatic chunking, heading detection, and OCR for PDFs

## Evaluation and Benchmarking

This repository includes a semantic benchmark toolkit under `evaluation/` using an LLM-as-judge pipeline for GĐ1 vs GĐ2 comparison.

See:
- `evaluation/README.md` for detailed step-by-step benchmark instructions
- `evaluation/templates/bug_intake.template.yaml` to curate bug cases from Internet sources
- `evaluation/build_eval_bundle_from_intake.py` to generate analysis input + ground truth
- `evaluation/build_judge_packets.py` and `evaluation/aggregate_judge_results.py` for judge scoring pipeline
- `evaluation/reports/judge/*` outputs for per-model ranking and side-by-side case comparison

## Requirements

- Docker
- Pinecone API key - [Sign up](https://app.pinecone.io/)
- OpenAI API key - [Get key](https://platform.openai.com/api-keys)
- Claude Desktop

## Quick Start (Docker)

### 1. Setup Environment

```bash
# Clone repository
git clone https://github.com/cefavn/vuln-analysis-RAG
cd vuln-analysis-RAG

# DM to get .env file
```

Edit `.env` with your API keys:
```
PINECONE_API_KEY=your-pinecone-api-key
PINECONE_INDEX_NAME=rag-mcp-gd2

# Embedding provider: openai | third_party | proxy
EMBEDDINGS_PROVIDER=openai
EMBEDDINGS_API_KEY=your-openai-or-provider-api-key
EMBEDDINGS_API_BASE=               # Required only for third_party/proxy
EMBEDDING_MODEL=text-embedding-3-small

TESSERACT_PATH=/usr/bin/tesseract
RETRIEVAL_MIN_SCORE=0.0            # Optional: filter results below this score
```

### 2. Build Docker Image

```bash
docker build -t rag-mcp-gd2:latest .
```

### 3. Build Vector Database (Optional - Initial Setup Only)

**Option A: Build from local documents**
```bash
# This processes documents in rag_docs/ and upserts to Pinecone
docker run --rm -i --network host --env-file .env \
  -v "$PWD/rag_docs:/app/rag_docs" \
  rag-mcp-gd2:latest python /app/pipeline.py
```

Pipeline uses incremental source-level indexing:
- Unchanged sources are skipped (no re-embedding cost)
- New/changed sources are refreshed and re-embedded
- If you delete sections/files and need cleanup for a specific source (including a file removed from rag_docs), force refresh it:
  `FORCE_REFRESH_SOURCES="rag_docs/path/to/file.md"`

**Option B: Use pre-loaded Pinecone index**

If you've already uploaded documents to Pinecone, skip the build step and proceed directly to step 4.

### 4. Connect to Claude Desktop

**Windows:**
Edit `%APPDATA%\Claude\claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "rag-knowledge": {
      "command": "C:\\Users\\YourUsername\\path\\to\\ragmcpserver\\run_mcp_in_docker.bat"
    }
  }
}
```

**Linux/macOS:**
Edit `~/.config/Claude/claude_desktop_config.json` (Linux) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):
```json
{
  "mcpServers": {
    "rag-knowledge": {
      "command": "/absolute/path/to/ragmcpserver/run_mcp_in_docker.sh"
    }
  }
}
```

```bash
# Make script executable
chmod +x run_mcp_in_docker.sh

# Add user to docker group (Linux)
sudo usermod -aG docker $USER
# Then logout/login or restart system
```

## Using the Server

### Available Tools

Once connected to Claude Desktop, you have access to the following query tools, write tools, and workflow prompts:

#### Query Tools

#### 1. `query_knowledge(query, k=5)`
General-purpose semantic search over the entire knowledge base.

**Returns:** k most relevant chunks with source, page, section, and type metadata

**Best for:** Architecture context, component documentation, prior analysis results

#### 2. `query_knowledge_with_scores(query, k=5)`
Same as `query_knowledge` but includes cosine similarity scores.

**Best for:** Judging retrieval confidence — a score below ~0.70 suggests the knowledge base may not have relevant content for this query.

#### 3. `search_vulnerability_patterns(vuln_type, code_context="", k=5)`
Search vulnerability pattern cards filtered by bug class.

**Parameters:**
- `vuln_type`: Bug class (e.g., "buffer overflow memcpy", "integer overflow size calculation", "race condition shared state", "use-after-free lifecycle", "TOCTOU double fetch")
- `code_context`: Optional code snippet for better matching
- `k`: Number of results (1-10)

**Returns:** Pattern cards with apply_when conditions, CVE evidence, and indicators

**Best for:** Step 3 of analysis workflow — after identifying Source→Sink paths

#### 4. `search_component_context(component_name, extra_context="", k=7)`
Search for architecture context, data structure layouts, and prior analysis for a QNX component or binary.

**Parameters:**
- `component_name`: Binary or struct name to search (e.g. "vdev-shmem", "qvm", "shmem_hdr")
- `extra_context`: Additional context (field names, function names)
- `k`: Number of results (1-15)

**Returns:** Architecture docs, struct layouts, trust boundaries, prior analysis

**Best for:** Steps 1-2 of analysis — establish context before code examination

#### Write / Info Tools

#### 5. `add_knowledge_text(text, source_name="analysis_result")`
Persist distilled analysis findings into the knowledge base for future retrieval.

Call this **after** completing analysis of a function or file. Supports two formats:
- **FORMAT A** — text starting with `PATTERN CARD:` → stored as `vulnerability_pattern`, retrievable via `search_vulnerability_patterns`
- **FORMAT B** — free-form architecture/function summary → stored as `analysis_result`

#### 6. `get_knowledge_info()`
Return connection status and configuration of the knowledge base. Use this to verify the RAG server is connected and healthy before starting an analysis session.

#### MCP Prompts (Workflow Templates)

| Prompt | Purpose |
|--------|---------|
| `analyze_current_function` | Full 6-step vulnerability analysis on the currently selected decompiled function |
| `triage_module` | Fast attack-surface scan — classifies each function as ENTRY / HANDLER / LIFECYCLE / SINK / UTILITY |
| `trace_data_flow` | Trace a guest-controlled value across a multi-function call chain from source to sink |
| `refactor_current_function` | Rename function and variables with IVC-semantic names before deep analysis |
| `generate_poc` | Write a minimal QNX guest-side PoC program for a MEDIUM/HIGH confidence hypothesis |
| `map_attack_surface` | Synthesize all findings into a complete IVC attack surface map with Mermaid diagram |
| `identify_fuzzing_targets` | Convert MEDIUM/HIGH hypotheses into actionable fuzzing specifications |
| `benchmark_analysis` | Run a full analysis on a known-vulnerable function to benchmark retrieval quality |

### Analysis Workflow

Follow this 3-step search pattern for vulnerability analysis:

1. **Component Context** (Steps 1-2 of analysis)
   ```
   search_component_context("binary_name") 
   → Get architecture, data structures, prior analysis
   ```

2. **Field-Level Context** (Steps 1-2 continued)
   ```
   search_component_context("struct_name", extra_context="field_name")
   → Get trust boundaries, layout details
   ```

3. **Vulnerability Pattern Matching** (Step 3, after identifying Source→Sink)
   ```
   search_vulnerability_patterns("bug_class", code_context="code_snippet")
   → Get pattern cards with CVE evidence and apply_when conditions
   ```

## Managing Documents

### Adding/Updating Documents

**Option A: Via local files**
```bash
# 1. Add or replace documents in rag_docs/ (place in the correct subdirectory)
cp my_documentation.pdf rag_docs/other/
cp vulnerability_patterns.json rag_docs/vuln-pattern/

# 2. Rebuild vector database (incremental: unchanged sources are skipped)
docker run --rm -i --network host --env-file .env \
  -v "$PWD/rag_docs:/app/rag_docs" \
  rag-mcp-gd2:latest python /app/pipeline.py

# Optional: ingest only specific files or folders (paths are relative to rag_docs/)
docker run --rm -i --network host --env-file .env \
  -v "$PWD/rag_docs:/app/rag_docs" \
  rag-mcp-gd2:latest python /app/pipeline.py \
  --paths new_docs \
  --paths other/file.pdf

# Optional: append-only upsert for selected docs (skip delete/check)
docker run --rm -i --network host --env-file .env \
  -v "$PWD/rag_docs:/app/rag_docs" \
  rag-mcp-gd2:latest python /app/pipeline.py \
  --append-only \
  --paths new_docs,other/file.pdf

# Optional: force refresh one source (useful when content was only removed)
docker run --rm -i --network host --env-file .env \
  -e FORCE_REFRESH_SOURCES="rag_docs/my_documentation.pdf" \
  -v "$PWD/rag_docs:/app/rag_docs" \
  rag-mcp-gd2:latest python /app/pipeline.py

# 3. Restart MCP server
docker run --rm -i --env-file .env rag-mcp-gd2:latest python /app/main.py

Notes:
- `--paths` is repeatable and also accepts comma-separated values.
- `--append-only` skips existing-vector checks and source deletion; it will always embed and upsert the selected docs.
- Logs include step timings and explicit "Embedding + upsert in progress" markers.
```

**Option B: Via Pinecone Web Console**
Upload documents directly to your Pinecone index using the web console. The retriever will immediately access them without rebuilding.

**Document Types:**
- **PDF**: Architecture documentation, reverse-engineering results (auto-processed with heading detection and OCR)
- **TXT**: Markdown or plaintext documentation
- **JSON**: Vulnerability pattern cards with metadata

### Local Development (without Docker)

```bash
# Setup Python environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# OPTION A: Build vector database from local documents
python src/pipeline.py

# OPTION B: Run MCP server with pre-loaded Pinecone index
python src/main.py

# Access retriever directly in Python
from src.retriever import get_retriever
retriever = get_retriever()
results = retriever.query("your search query", k=5)
```

### Docker Deployment Options

**Option A: Full build (build + run server)**
```bash
# Build vector database first
docker run --rm -i --network host --env-file .env \
  -v "$PWD/rag_docs:/app/rag_docs" \
  rag-mcp-gd2:latest python /app/pipeline.py

# Then run the MCP server
docker run --rm -i --env-file .env rag-mcp-gd2:latest python /app/main.py
```

**Option B: Skip build (use pre-loaded Pinecone)**
```bash
# Run the MCP server directly without building
docker run --rm -i --env-file .env rag-mcp-gd2:latest python /app/main.py
```

## Troubleshooting

### Docker Permission Issues (Linux)

```bash
# Check if user is in docker group
groups | grep docker

# If not in group, add it
sudo usermod -aG docker $USER

# Apply new group (no logout required)
newgrp docker

# Verify
docker ps
```

### Pinecone Connection Failed

- Verify `PINECONE_API_KEY` is set correctly in `.env`
- Check Pinecone index exists at https://app.pinecone.io/
- Ensure network connectivity to Pinecone API

### Embedding API Errors

- Verify `EMBEDDINGS_API_KEY` is set correctly in `.env`
- For `EMBEDDINGS_PROVIDER=third_party` or `proxy`, ensure `EMBEDDINGS_API_BASE` is also set
- Check API key has sufficient credits and `EMBEDDING_MODEL` is available in your account

### No Results from Knowledge Base

- Verify documents were built successfully: `python helper/pinecone_interact.py` shows Pinecone index stats
- Check if query is semantically similar to document content
- Try broader search terms or use `query_knowledge()` instead of filtered searches

### Test Docker Manually

```bash
# Test Docker works
docker ps

# Test script directly
./run_mcp_in_docker.sh

# Test container (should wait for input, Ctrl+C to exit)
docker run --rm -i --env-file .env rag-mcp-gd2:latest python -u /app/main.py
```

## Project Structure

```
vuln-analysis-RAG/
├── src/                            # Main source (copied flat into /app/ in Docker)
│   ├── main.py                     # MCP server — registers all tools and prompts
│   ├── pipeline.py                 # Ingestion pipeline CLI + DocumentPipeline class
│   ├── retriever.py                # DocumentRetriever — similarity search interface
│   ├── config.py                   # Centralized configuration from .env
│   ├── prompts.py                  # MCP prompt template strings
│   ├── logger.py                   # Structured logging for MCP tool calls
│   ├── ingestion/
│   │   ├── loader.py               # File discovery and loading (discover_documents, load_documents)
│   │   ├── router.py               # Routes files to converters by directory or extension
│   │   └── chunker.py              # Parent-child chunking (Chunker class)
│   ├── converters/
│   │   ├── pdf_converter.py        # PDF → Markdown with OCR (Tesseract)
│   │   ├── json_converter.py       # JSON vulnerability pattern cards → Documents
│   │   ├── c_converter.py          # C/H source and decompiled code → Documents
│   │   ├── build_converter.py      # .build / .sh / .layout → Documents
│   │   └── utils.py                # Shared frontmatter helpers
│   └── store/
│       └── pinecone_client.py      # VectorStore — embed, upsert, incremental update
├── rag_docs/                       # Knowledge base documents (mounted into Docker)
│   ├── vuln-pattern/               # JSON vulnerability pattern cards
│   ├── qnx-doc/                    # QNX documentation (pre-converted Markdown)
│   ├── decompiled/                 # Decompiled C/H from reverse engineering
│   ├── c-code/                     # Original C/H source code
│   ├── build-config/               # .build / .sh / .layout build configuration
│   └── other/                      # PDFs and miscellaneous (extension-routed)
├── helper/                         # Standalone utility scripts (not deployed to Docker)
│   ├── pinecone_interact.py        # Inspect and manage the Pinecone index
│   ├── quick_retrieval_test.py     # Quick retrieval quality test
│   ├── qnx-doc-converter.py        # Convert QNX HTML docs to Markdown
│   └── claude-token-count.py       # Count tokens for Claude prompts
├── evaluation/                     # Benchmark and evaluation pipeline
│   ├── build_eval_bundle_from_intake.py
│   ├── build_judge_packets.py
│   ├── aggregate_judge_results.py
│   └── reports/                    # Evaluation outputs
├── RAG-gd1/                        # GD1 (baseline) server — archived for comparison
├── Dockerfile
├── requirements.txt
├── run_mcp_in_docker.sh
└── .env                            # API keys (not tracked in git)
```

### Ingestion Pipeline Flow

```
rag_docs/
  └── ingestion/loader.py      (discover_documents → load_documents)
        └── ingestion/router.py    (convert_file: directory-based routing)
              └── converters/          (pdf, json, c, build → YAML-frontmatter strings)
                    └── ingestion/chunker.py  (Chunker.chunk_all: atomic | parent-child)
                          └── store/pinecone_client.py  (VectorStore.upsert_incremental)
                                └── Pinecone index
```

## API Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PINECONE_API_KEY` | Pinecone API key (required) | — |
| `PINECONE_INDEX_NAME` | Pinecone index name (required) | — |
| `EMBEDDINGS_PROVIDER` | Embedding provider: `openai`, `third_party`, or `proxy` | `openai` |
| `EMBEDDINGS_API_KEY` | API key for the embedding provider (required) | — |
| `EMBEDDINGS_API_BASE` | Base URL for third-party/proxy providers | — |
| `EMBEDDING_MODEL` | Embedding model name | `text-embedding-3-small` |
| `TESSERACT_PATH` | Path to Tesseract OCR binary | `/usr/bin/tesseract` |
| `RETRIEVAL_MIN_SCORE` | Minimum cosine similarity score for results (0.0 = disabled) | `0.0` |
| `FORCE_REFRESH_SOURCES` | Comma-separated source paths to force re-embed on next pipeline run | — |

### Document Metadata Fields

Retrieved documents include:
- `rank`: Result rank (1 = most relevant)
- `content`: The matched child chunk
- `context`: Full parent section containing the chunk (equals `content` for atomic types and small sections)
- `section`: Markdown heading path (e.g., "IVC Architecture > Configuration")
- `source`: Canonical source path (`rag_docs/<rel_path>`) — stable across Docker and local runs
- `source_file`: File basename for readability
- `page`: Page number (PDF) or index (JSON)
- `type`: `"vulnerability_pattern"`, `"reference_document"`, `"analysis_result"`, or converter-specific type
- `doc_id`: Pattern card ID (for vulnerability patterns)
- `origin`: `"curated"` (from rag_docs) or `"llm_generated"` (from `add_knowledge_text`)
- `score`: Cosine similarity score (when using `query_knowledge_with_scores` or filtered searches)

## Additional Commands

### Inspect Pinecone Database

```bash
# Check vector database statistics
python helper/pinecone_interact.py

# List metadata values (sample-based)
python helper/pinecone_interact.py --list-metadata --fields source,type,file_name --top 20

# Delete by metadata filter (requires explicit confirmation)
python helper/pinecone_interact.py --filter source=rag_docs/path/to/file.md --delete --yes
```

Shows index info, vector count, metadata stats, and sample vectors.

## Support & Contributing

For issues, questions, or contributions, please open an issue on the GitHub repository.
