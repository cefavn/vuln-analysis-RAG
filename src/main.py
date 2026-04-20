# main.py - QNX Vulnerability RAG MCP Server
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
from typing import Dict, List

from mcp.server.fastmcp import FastMCP

from builder import DocumentBuilder
from retriever import get_retriever
from prompts import (
    prompt_analyze_current_function,
    prompt_triage_module,
    prompt_trace_data_flow,
    prompt_refactor_current_function,
)
from config import RETRIEVAL_MIN_SCORE

mcp = FastMCP("QNX-Vuln-RAG")

# Shared DocumentBuilder instance (reuses the OpenAI embeddings client)
_builder: DocumentBuilder | None = None


def _ensure_json_serializable(value):
    """
    Ensure a value is JSON-serializable.
    For strings, validates they don't contain unescaped characters that break JSON.
    For dicts/lists, validates all nested values are serializable.
    """
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError) as e:
        # If it fails to serialize, convert to string and escape
        if isinstance(value, str):
            return json.loads(json.dumps(value))
        return {"error": f"Value not JSON-serializable: {e}"}


def _get_builder() -> DocumentBuilder:
    global _builder
    if _builder is None:
        _builder = DocumentBuilder()
    return _builder


def _no_evidence(query: str, min_score: float) -> List[Dict[str, str]]:
    return [{
        "status": "no_evidence",
        "query": query,
        "message": f"No chunks met confidence threshold (min_score={min_score}).",
    }]


# ---------------------------------------------------------------------------
# RAG Query Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def query_knowledge(query: str, k: int = 5) -> List[Dict[str, str]]:
    """
    Semantic search over the entire knowledge base.

    Use this as a general-purpose search for any topic — QNX documentation,
    prior reverse-engineering results, architecture context, vulnerability patterns.

    Returns the k most relevant chunks with source and page metadata.
    Follow the system prompt's 3-step search workflow:
      1. Search component name / binary name for architecture context.
      2. Search struct or field names visible in the code.
      3. Search vulnerability pattern type after identifying Source→Sink paths.

    Args:
        query: Natural-language or keyword query (e.g. "vdev-shmem connect_map field layout")
        k: Number of chunks to return (1–20, default 5)
    """
    k = min(max(1, k), 20)
    try:
        results = get_retriever().query(
            query,
            k=k,
            min_score=RETRIEVAL_MIN_SCORE,
        )
        if RETRIEVAL_MIN_SCORE > 0 and not results:
            return _ensure_json_serializable(_no_evidence(query, RETRIEVAL_MIN_SCORE))
        return _ensure_json_serializable(results)
    except Exception as e:
        return [{"error": f"query_knowledge failed: {e}"}]


@mcp.tool()
def search_vulnerability_patterns(vuln_type: str, code_context: str = "", k: int = 5) -> List[Dict[str, str]]:
    """
    Search only vulnerability pattern cards for a specific bug class.

    Use this in Step 3 of the analysis workflow — after identifying unvalidated
    Source→Sink paths, call this to retrieve pattern cards with apply_when conditions,
    CVE evidence, and binary indicators for that specific bug class.

    Searches are filtered to type=vulnerability_pattern so PDF documentation
    chunks do not dilute the results.

    Args:
        vuln_type: Bug class to search (e.g. "buffer overflow memcpy", "integer overflow
                   size calculation", "race condition shared state", "use-after-free lifecycle",
                   "TOCTOU double fetch", "information disclosure uninitialized memory")
        code_context: Optional — paste a short snippet of the suspicious code path to
                      improve semantic matching (e.g. "memcpy(buf, guest_data, guest_len)")
        k: Number of pattern cards to return (1–10, default 5)
    """
    k = min(max(1, k), 10)
    combined_query = f"{vuln_type} {code_context}".strip()
    try:
        results = get_retriever().query_with_scores(
            combined_query,
            k=k,
            filter={"type": "vulnerability_pattern"},
            min_score=RETRIEVAL_MIN_SCORE,
        )
        if RETRIEVAL_MIN_SCORE > 0 and not results:
            return _no_evidence(combined_query, RETRIEVAL_MIN_SCORE)
        return results
    except Exception as e:
        return [{"error": f"search_vulnerability_patterns failed: {e}"}]


@mcp.tool()
def search_component_context(component_name: str, extra_context: str = "", k: int = 7) -> List[Dict[str, str]]:
    """
    Search knowledge base for architecture context, data structure layouts, and prior
    reverse-engineering results for a specific QNX component or binary.

    Use this at the START of analysis (Steps 1–2 in the system prompt) to retrieve
    known context before examining code — this prevents fabrication and anchors the
    analysis in documented facts.

    Args:
        component_name: Binary or component to search for (e.g. "vdev-shmem", "qvm",
                        "vdshmem_vwrite", "guest_shm_factory", "shmem_hdr")
        extra_context: Optional additional terms to narrow the search
                       (e.g. "MMIO write handler" or "connect_map field")
        k: Number of chunks to return (1–15, default 7)
    """
    k = min(max(1, k), 15)
    combined_query = f"{component_name} {extra_context}".strip()
    try:
        results = get_retriever().query_with_scores(
            combined_query,
            k=k,
            min_score=RETRIEVAL_MIN_SCORE,
        )
        if RETRIEVAL_MIN_SCORE > 0 and not results:
            return _no_evidence(combined_query, RETRIEVAL_MIN_SCORE)
        return results
    except Exception as e:
        return [{"error": f"search_component_context failed: {e}"}]


@mcp.tool()
def query_knowledge_with_scores(query: str, k: int = 5) -> List[Dict[str, str]]:
    """
    Same as query_knowledge but includes cosine similarity scores.

    Use this when you need to judge retrieval confidence — a score below ~0.70
    suggests the knowledge base may not have relevant information for this query.
    Prefer query_knowledge for normal lookups; use this when score transparency matters.

    Args:
        query: Natural-language or keyword query
        k: Number of chunks to return (1–20, default 5)
    """
    k = min(max(1, k), 20)
    try:
        results = get_retriever().query_with_scores(
            query,
            k=k,
            min_score=RETRIEVAL_MIN_SCORE,
        )
        if RETRIEVAL_MIN_SCORE > 0 and not results:
            return _no_evidence(query, RETRIEVAL_MIN_SCORE)
        return results
    except Exception as e:
        return [{"error": f"query_knowledge_with_scores failed: {e}"}]


# ---------------------------------------------------------------------------
# Knowledge Base Write Tool
# ---------------------------------------------------------------------------

@mcp.tool()
def add_knowledge_text(text: str, source_name: str = "analysis_result") -> Dict[str, str]:
    """
    Persist distilled analysis findings into the knowledge base for future retrieval.

    Call this AFTER completing analysis of a function or file to store non-redundant
    conclusions. Future analysis sessions can then retrieve prior findings via
    search_component_context, avoiding re-analysis of already-examined code.

    Recommended format:
      "Analysis of [function_name]/[filename]: [key findings about purpose,
       data flow, vulnerabilities, or verification steps needed]"

    Do NOT store:
      - Raw decompiled code
      - RAG-retrieved text verbatim
      - Speculative content without any evidence label

    Args:
        text: Distilled finding to store (plain text, no code blocks)
        source_name: Logical label for this entry (e.g. "vdev-shmem-analysis",
                     "vdshmem_vwrite-hypothesis")
    """
    if not text or not text.strip():
        return {"status": "error", "message": "Text content is empty."}
    try:
        return _get_builder().add_text_to_db(text_content=text, source_name=source_name)
    except Exception as e:
        return {"status": "error", "message": f"Failed to add knowledge: {e}"}


# ---------------------------------------------------------------------------
# Knowledge Base Info Tool
# ---------------------------------------------------------------------------

@mcp.tool()
def get_knowledge_info() -> Dict[str, str]:
    """
    Return connection status and configuration of the knowledge base.

    Use this to verify the RAG server is connected and healthy before starting
    an analysis session.
    """
    try:
        info = get_retriever().get_db_info()
        info["retrieval_min_score"] = str(RETRIEVAL_MIN_SCORE)
        return info
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# MCP Prompts — Workflow Templates for Claude
# ---------------------------------------------------------------------------

@mcp.prompt()
def analyze_current_function() -> str:
    """
    Full 6-step vulnerability analysis on the currently selected decompiled function.
    Covers Source→Sink identification, pattern matching, hypothesis formulation, and exploit trigger.
    KB update only for HIGH-confidence findings or novel architecture discoveries.
    """
    prompt_text = prompt_analyze_current_function()
    return _ensure_json_serializable(prompt_text)


@mcp.prompt()
def triage_module() -> str:
    """
    Fast attack-surface scan of all functions in the current binary/module.
    Classifies each function as ENTRY / HANDLER / LIFECYCLE / SINK / UTILITY.
    Use this first to decide which functions deserve deep analysis.
    No KB update.
    """
    prompt_text = prompt_triage_module()
    return _ensure_json_serializable(prompt_text)


@mcp.prompt()
def trace_data_flow() -> str:
    """
    Trace a guest-controlled value across a multi-function call chain from source to sink.
    Use after triage identifies a suspicious path spanning multiple functions.
    Produces an annotated call chain and path verdict (VALIDATED / UNVALIDATED / PARTIAL / OPAQUE).
    KB update only on confirmed unvalidated or partial-guard paths.
    """
    prompt_text = prompt_trace_data_flow()
    return _ensure_json_serializable(prompt_text)


@mcp.prompt()
def refactor_current_function() -> str:
    """
    Rename the current function and variables using IVC-semantic names, insert security comments.
    Run this before deep analysis to make decompiled code readable.
    Silent — no output, no KB update.
    """
    prompt_text = prompt_refactor_current_function()
    return _ensure_json_serializable(prompt_text)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
