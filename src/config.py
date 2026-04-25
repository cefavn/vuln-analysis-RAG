# config.py - Centralized configuration for RAG MCP Server
import os
from dotenv import load_dotenv

load_dotenv()

PINECONE_API_KEY: str = os.getenv("PINECONE_API_KEY", "")
PINECONE_INDEX_NAME: str = os.getenv("PINECONE_INDEX_NAME", "")
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
TESSERACT_PATH: str = os.getenv("TESSERACT_PATH", "")

EMBEDDING_MODEL: str = "text-embedding-3-small"

# Optional retrieval confidence gate. 0.0 disables score filtering.
RETRIEVAL_MIN_SCORE: float = float(os.getenv("RETRIEVAL_MIN_SCORE", "0.0"))


# Parent chunk: max size before splitting into children.
# A Markdown section larger than this gets child-split.
CHUNK_SIZE: int = 1000
CHUNK_OVERLAP: int = 200

# Child chunk: small units used for precise embedding search.
CHILD_CHUNK_SIZE: int = 500
CHILD_CHUNK_OVERLAP: int = 80

# Max chars stored as parent_content in child metadata (Pinecone 40 KB limit).
PARENT_CONTENT_MAX: int = 2000

# Resolve rag_docs directory.
# Works in both Docker (flat /app/) and local dev (src/ subdirectory).
_here = os.path.dirname(os.path.abspath(__file__))
_flat_candidate = os.path.join(_here, "rag_docs")
_parent_candidate = os.path.join(os.path.dirname(_here), "rag_docs")
DOCS_DIR: str = _flat_candidate if os.path.exists(_flat_candidate) else _parent_candidate
