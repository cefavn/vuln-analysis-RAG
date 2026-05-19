# ingestion/embedder.py — Text normalization for dense embedding + OpenAI embeddings client.
#
# Dense embedding quality depends on input text type:
#   Text-based docs (reference_document, vulnerability_pattern, analysis_result):
#       Markdown syntax (##, **, -) is noise for semantic embedding — flatten to prose.
#   Code/config docs (c_function, c_struct, build_*, etc.):
#       Syntax characters ({, }, *, &, indentation) carry semantic meaning — keep raw.
#
# Query strings are NEVER flattened — LLM may query with code-like patterns.
import re
import sys
from typing import List

TEXT_TYPES = frozenset({
    "reference_document",
    "analysis_result",
    "vulnerability_pattern",
})

_MD_HEADER = re.compile(r'^#{1,6}\s+(.+)$', re.MULTILINE)
_BOLD_FIELD = re.compile(r'\*\*([^*]+?):?\*\*:?\s*')
_CODE_FENCE = re.compile(r'```[a-z]*\n(.*?)```', re.DOTALL)
_BULLET = re.compile(r'^[-*]\s+', re.MULTILINE)


def flatten_for_embedding(text: str) -> str:
    """
    Convert Markdown syntax to plain prose for dense embedding.

    ## Section Title  →  Section Title:
    **Field:** value  →  Field: value
    - bullet item     →  bullet item
    ```lang\\ncode```  →  code (fences stripped)
    """
    t = _MD_HEADER.sub(lambda m: m.group(1) + ':', text)
    t = _BOLD_FIELD.sub(lambda m: m.group(1) + ': ', t)
    t = _CODE_FENCE.sub(lambda m: m.group(1).strip(), t)
    t = _BULLET.sub('', t)
    t = re.sub(r'\n{3,}', '\n\n', t)
    return t.strip()


def text_for_dense_embedding(text: str, doc_type: str) -> str:
    """
    Return the text variant to embed for dense retrieval.

    Text-based doc types: flattened prose (better semantic density).
    Code/config types: raw text (syntax carries meaning, must not be stripped).
    """
    if doc_type in TEXT_TYPES:
        return flatten_for_embedding(text)
    return text


class Embedder:
    """Wraps OpenAIEmbeddings; shared by pinecone_client (upsert) and retriever (query)."""

    def __init__(self) -> None:
        from langchain_openai import OpenAIEmbeddings
        from config import embeddings_client_kwargs
        self._model = OpenAIEmbeddings(**embeddings_client_kwargs())

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return self._model.embed_documents(texts)

    def embed_query(self, text: str) -> List[float]:
        return self._model.embed_query(text)


if __name__ == "__main__":
    sample_md = "## Buffer Overflow\n**Apply when:** guest length unchecked\n- memcpy call\n```c\nmemcpy(dst, src, n);\n```"
    flattened = flatten_for_embedding(sample_md)
    print("Flattened:", repr(flattened))
    assert "**" not in flattened
    assert "##" not in flattened
    assert "Buffer Overflow:" in flattened
    print("text_for_dense_embedding c_function passthrough:", text_for_dense_embedding("memcpy(dst, src, n);", "c_function"))
    print("All assertions passed.", file=sys.stderr)
