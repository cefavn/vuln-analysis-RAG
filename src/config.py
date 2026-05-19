# config.py - Centralized configuration for RAG MCP Server
import os
from typing import Any, Dict, Tuple
from dotenv import load_dotenv

load_dotenv()

PINECONE_API_KEY: str = os.getenv("PINECONE_API_KEY", "")
PINECONE_INDEX_NAME: str = os.getenv("PINECONE_INDEX_NAME", "vuln-analysis-rag")
PINECONE_NAMESPACE: str = os.getenv("PINECONE_NAMESPACE", "default")
TESSERACT_PATH: str = os.getenv("TESSERACT_PATH", "")

EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "")
EMBEDDINGS_PROVIDER: str = os.getenv("EMBEDDINGS_PROVIDER", "openai")
EMBEDDINGS_API_BASE: str = os.getenv("EMBEDDINGS_API_BASE", "")
EMBEDDINGS_API_KEY: str = os.getenv("EMBEDDINGS_API_KEY", "")
# Texts per embedding API call. Third-party proxies often timeout on large batches;
# set EMBEDDINGS_CHUNK_SIZE=1 in .env to send one text at a time.
EMBEDDINGS_CHUNK_SIZE: int = int(os.getenv("EMBEDDINGS_CHUNK_SIZE", "5" if os.getenv("EMBEDDINGS_PROVIDER", "openai") in {"third_party", "proxy"} else "100"))
# Request timeout in seconds for the embedding API call.
EMBEDDINGS_TIMEOUT: float = float(os.getenv("EMBEDDINGS_TIMEOUT", "60"))

# Optional retrieval confidence gate. 0.0 disables score filtering.
RETRIEVAL_MIN_SCORE: float = float(os.getenv("RETRIEVAL_MIN_SCORE", "0.0"))


def _resolve_embeddings_credentials() -> Tuple[str, str]:
	provider = EMBEDDINGS_PROVIDER
	api_key = EMBEDDINGS_API_KEY
	api_base = EMBEDDINGS_API_BASE
	if provider not in {"openai", "third_party", "proxy"}:
		raise ValueError("EMBEDDINGS_PROVIDER must be 'openai' or 'third_party'/'proxy'.")

	if not api_key:
		raise ValueError(f"Embeddings API key not set for provider '{provider}'.")
	if provider in {"third_party", "proxy"} and not api_base:
		raise ValueError("EMBEDDINGS_API_BASE not set for third_party/proxy provider.")
	return api_key, api_base


def embeddings_client_kwargs() -> Dict[str, Any]:
	api_key, api_base = _resolve_embeddings_credentials()
	kwargs: Dict[str, str] = {
		"model": EMBEDDING_MODEL,
		"openai_api_key": api_key,
		"chunk_size": EMBEDDINGS_CHUNK_SIZE,
		"request_timeout": EMBEDDINGS_TIMEOUT,
	}
	if api_base:
		kwargs["openai_api_base"] = api_base
	return kwargs


def apply_embeddings_env() -> None:
	api_key, api_base = _resolve_embeddings_credentials()
	os.environ.setdefault("OPENAI_API_KEY", api_key)
	if api_base:
		os.environ.setdefault("OPENAI_API_BASE", api_base)


# Parent chunk: max size before splitting into children.
# A Markdown section larger than this gets child-split.
CHUNK_SIZE: int = 1000
CHUNK_OVERLAP: int = 200

# Child chunk: small units used for precise embedding search.
# 1500 chars ≈ 250–350 tokens — large enough to keep #ifdef blocks and
# if/else branches intact while staying well under the 8191-token limit
# of text-embedding-3-small.
CHILD_CHUNK_SIZE: int = 1500
CHILD_CHUNK_OVERLAP: int = 200

# Max chars stored as parent_content in child metadata (Pinecone 40 KB limit).
# 3000 chars = ~500 tokens; gives the LLM more function body context at
# retrieval time without approaching Pinecone's per-field limit.
PARENT_CONTENT_MAX: int = 3000

# Resolve rag_docs directory.
# Works in both Docker (flat /app/) and local dev (src/ subdirectory).
_here = os.path.dirname(os.path.abspath(__file__))
_flat_candidate = os.path.join(_here, "rag_docs")
_parent_candidate = os.path.join(os.path.dirname(_here), "rag_docs")
DOCS_DIR: str = _flat_candidate if os.path.exists(_flat_candidate) else _parent_candidate
