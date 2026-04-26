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

- Docker Desktop
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
OPENAI_API_KEY=your-openai-api-key
PINECONE_INDEX_NAME=rag-mcp-gd2
TESSERACT_PATH=/usr/bin/tesseract
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
  rag-mcp-gd2:latest python /app/builder.py
```

Builder uses incremental source-level indexing:
- Unchanged sources are skipped (no re-embedding cost)
- New/changed sources are refreshed and re-embedded
- If you delete sections/files and need cleanup for a specific source (including a file removed from rag_docs), force refresh it:
  `FORCE_REFRESH_SOURCES="rag_docs/path/to/file.md"`

**Option B: Use pre-loaded Pinecone index (Web Console)**
If you've already uploaded documents to Pinecone via the web console, skip the build step and proceed directly to step 4.

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

**Linux/macOS Setup:**
```bash
# Make script executable
chmod +x run_mcp_in_docker.sh

# Add user to docker group (Linux)
sudo usermod -aG docker $USER
# Then logout/login or restart system
```

## Using the Server

### Available Tools

Once connected to Claude Desktop, you have access to three query tools:

#### 1. `query_knowledge(query, k=5)`
General-purpose semantic search over the entire knowledge base.

**Usage:**
```
Search for QNX vdev-shmem architecture and the connect_map field layout.
```

**Returns:** k most relevant chunks with source, page, section, and type metadata

**Best for:** Architecture context, component documentation, prior analysis results

#### 2. `search_vulnerability_patterns(vuln_type, code_context="", k=5)`
Search vulnerability pattern cards filtered by bug class.

**Usage:**
```
Search for buffer overflow patterns with memcpy function calls
```

**Parameters:**
- `vuln_type`: Bug class (e.g., "buffer overflow memcpy", "integer overflow size calculation", "race condition shared state", "use-after-free lifecycle", "TOCTOU double fetch")
- `code_context`: Optional code snippet for better matching
- `k`: Number of results (1-10)

**Returns:** Pattern cards with apply_when conditions, CVE evidence, and indicators

**Best for:** Step 3 of analysis workflow - after identifying Source→Sink paths

#### 3. `search_component_context(component_name, extra_context="", k=7)`
Search for architecture context, data structure layouts, and prior analysis for a QNX component or binary.

**Usage:**
```
Search for architecture context for component "vdev-shmem" with struct "ivc_connect_req"
```

**Parameters:**
- `component_name`: Binary or struct name to search
- `extra_context`: Additional context (field names, function names)
- `k`: Number of results (1-20)

**Returns:** Architecture docs, struct layouts, trust boundaries, prior analysis

**Best for:** Steps 1-2 of analysis - establish context before code examination

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
# 1. Add or replace documents in rag_docs/
cp my_documentation.pdf rag_docs/
cp vulnerability_patterns.json rag_docs/

# 2. Rebuild vector database (incremental: unchanged sources are skipped)
docker run --rm -i --network host --env-file .env \
  -v "$PWD/rag_docs:/app/rag_docs" \
  rag-mcp-gd2:latest python /app/builder.py

# Optional: force refresh one source (useful when content was only removed)
docker run --rm -i --network host --env-file .env \
  -e FORCE_REFRESH_SOURCES="rag_docs/my_documentation.pdf" \
  -v "$PWD/rag_docs:/app/rag_docs" \
  rag-mcp-gd2:latest python /app/builder.py

# 3. Restart MCP server
docker run --rm -i --env-file .env rag-mcp-gd2:latest python /app/main.py
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
python src/builder.py

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
  rag-mcp-gd2:latest python /app/builder.py

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

### OpenAI API Errors

- Verify `OPENAI_API_KEY` is set correctly in `.env`
- Check API key has sufficient credits
- Ensure text-embedding-3-small model is available in your account

### No Results from Knowledge Base

- Verify documents were built successfully: `inspect_pinecone.py` shows Pinecone index stats
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

(missing)

## API Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PINECONE_API_KEY` | Pinecone API key (required) | - |
| `OPENAI_API_KEY` | OpenAI API key (required) | - |
| `PINECONE_INDEX_NAME` | Pinecone index name | `rag-mcp-gd2` |
| `EMBEDDING_MODEL` | OpenAI embedding model | `text-embedding-3-small` |
| `TESSERACT_PATH` | Path to Tesseract OCR binary | `/usr/bin/tesseract` |
| `CHUNK_SIZE` | Parent chunk size in characters | `1000` |
| `CHUNK_OVERLAP` | Parent chunk overlap | `200` |
| `CHILD_CHUNK_SIZE` | Child chunk size in characters | `500` |
| `CHILD_CHUNK_OVERLAP` | Child chunk overlap | `80` |

### Document Metadata Fields

Retrieved documents include:
- `content`: The matched child chunk
- `context`: Full parent section containing the chunk
- `section`: Markdown heading path (e.g., "IVC Architecture > Configuration")
- `source`: Document filename
- `page`: Page number (PDF) or index (JSON)
- `type`: "vulnerability_pattern", "reference_document", or "analysis_result"
- `doc_id`: Pattern card ID (for vulnerability patterns)
- `score`: Cosine similarity score (when using `query_with_scores()`)

## Additional Commands

### Inspect Pinecone Database

```bash
# Check vector database statistics
python inspect_pinecone.py
```

Shows index info, vector count, metadata stats, and sample vectors.

## Support & Contributing

For issues, questions, or contributions, please open an issue on the GitHub repository.
