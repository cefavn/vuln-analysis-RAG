# main.py - QNX Vulnerability RAG MCP Server
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import time
from typing import Dict, List, Optional

from mcp.server.fastmcp import FastMCP

from pipeline import DocumentPipeline
from retriever import get_retriever
from prompts import (
    prompt_analyze_current_function,
    prompt_refactor_decompiled,
    prompt_triage_module,
    prompt_trace_data_flow,
    prompt_refactor_current_function,
    prompt_generate_poc,
    prompt_map_attack_surface,
    prompt_identify_fuzzing_targets,
    prompt_benchmark_analysis,
)
from config import RETRIEVAL_MIN_SCORE
from logger import log_call, log_server_start

mcp = FastMCP("QNX-Vuln-RAG")

# Shared DocumentPipeline instance (reuses the OpenAI embeddings client)
_pipeline: DocumentPipeline | None = None


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
        if isinstance(value, str):
            return json.loads(json.dumps(value))
        return {"error": f"Value not JSON-serializable: {e}"}


def _get_pipeline() -> DocumentPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = DocumentPipeline()
    return _pipeline


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
    Semantic + lexical search over the entire knowledge base (native hybrid index).

    General-purpose lookup for topics not covered by Phase A or Phase B: prior analysis
    results, structural facts, build metadata, QNX API documentation.
    For component/function context use search_component_context (Phase A).
    For vulnerability patterns use search_vulnerability_patterns (Phase B).

    If result is {"status": "no_evidence"}: try ONE rephrased query with shorter terms
    or a synonym. If still no_evidence after one retry, proceed without RAG context and
    note the gap explicitly. Do NOT retry more than once with similar queries.

    Args:
        query: Natural-language or keyword query (e.g. "vdev-shmem connect_map field layout")
        k: Number of chunks to return (1–20, default 5)
    """
    k = min(max(1, k), 20)
    t0 = time.monotonic()
    try:
        results = get_retriever().query(
            query,
            k=k,
            min_score=RETRIEVAL_MIN_SCORE,
        )
        if RETRIEVAL_MIN_SCORE > 0 and not results:
            results = _no_evidence(query, RETRIEVAL_MIN_SCORE)
        results = _ensure_json_serializable(results)
        log_call("query_knowledge", {"query": query, "k": k},
                 ok=True, ms=(time.monotonic() - t0) * 1000, extra={"n": len(results)})
        return results
    except Exception as e:
        log_call("query_knowledge", {"query": query, "k": k},
                 ok=False, ms=(time.monotonic() - t0) * 1000, extra={"error": str(e)})
        return [{"error": f"query_knowledge failed: {e}"}]


@mcp.tool()
def search_vulnerability_patterns(
    vuln_type: str,
    code_context: str = "",
    k: int = 5,
    filter: Optional[Dict] = None,
) -> List[Dict[str, str]]:
    """
    Phase B — search vulnerability pattern cards for a specific bug class.

    Uses native hybrid index (dense semantic + BM25 lexical). Call after identifying
    unvalidated Source→Sink paths to retrieve pattern cards with apply_when conditions,
    CVE evidence, and binary indicators.
    Automatically filters to type=vulnerability_pattern (override via filter param).

    If result is {"status": "no_evidence"}: try ONE rephrased query with a broader class
    name or synonym. If still no_evidence after one retry, proceed without pattern context
    and note the gap explicitly. Do NOT retry more than once with similar queries.

    Args:
        vuln_type: Bug class to search (e.g. "buffer overflow memcpy", "integer overflow
                   size calculation", "race condition shared state", "use-after-free lifecycle",
                   "TOCTOU double fetch", "information disclosure uninitialized memory")
        code_context: Optional — paste a short snippet of the suspicious code path to
                      improve semantic matching (e.g. "memcpy(buf, guest_data, guest_len)")
        k: Number of pattern cards to return (1–10, default 5)
        filter: Optional additional metadata filter. Default restricts to vulnerability_pattern.
                Override example: {"$and": [{"type": {"$eq": "vulnerability_pattern"}},
                                            {"tags": {"$in": ["memory_corruption"]}}]}
    """
    k = min(max(1, k), 10)
    combined_query = f"{vuln_type} {code_context}".strip()
    effective_filter = filter if filter is not None else {"type": {"$eq": "vulnerability_pattern"}}
    t0 = time.monotonic()
    try:
        results = get_retriever().query_with_scores(
            combined_query,
            k=k,
            filter=effective_filter,
            min_score=RETRIEVAL_MIN_SCORE,
        )
        if RETRIEVAL_MIN_SCORE > 0 and not results:
            results = _no_evidence(combined_query, RETRIEVAL_MIN_SCORE)
        log_call("search_vulnerability_patterns", {"vuln_type": vuln_type, "code_context": code_context, "k": k},
                 ok=True, ms=(time.monotonic() - t0) * 1000, extra={"n": len(results)})
        return results
    except Exception as e:
        log_call("search_vulnerability_patterns", {"vuln_type": vuln_type, "k": k},
                 ok=False, ms=(time.monotonic() - t0) * 1000, extra={"error": str(e)})
        return [{"error": f"search_vulnerability_patterns failed: {e}"}]


@mcp.tool()
def search_component_context(
    component_name: str,
    extra_context: str = "",
    k: int = 7,
    filter: Optional[Dict] = None,
) -> List[Dict[str, str]]:
    """
    Phase A — retrieve architecture context, data structure layouts, and prior
    reverse-engineering results for a specific QNX component or binary.

    Uses native hybrid index (dense semantic + BM25 lexical). Call at the START of
    analysis to anchor findings in documented facts and prevent fabrication.
    Automatically excludes vulnerability_pattern docs (override via filter param).

    If result is {"status": "no_evidence"}: try ONE rephrased query with shorter terms
    or an alternate name. If still no_evidence after one retry, proceed without KB context
    and note the gap explicitly. Do NOT retry more than once with similar queries.

    Args:
        component_name: Binary or component to search for (e.g. "vdev-shmem", "qvm",
                        "vdshmem_vwrite", "guest_shm_factory", "shmem_hdr")
        extra_context: Optional additional terms to narrow the search
                       (e.g. "MMIO write handler" or "connect_map field")
        k: Number of chunks to return (1–15, default 7)
        filter: Optional Pinecone metadata filter for precise scoping. Examples:
                {"type": {"$eq": "decompiled"}} — only decompiled chunks
                {"source": {"$eq": "rag_docs/decompiled/qvm.c"}} — only from qvm.c
                {"function_name": {"$in": ["parse_packet", "handle_input"]}}
                {"$and": [{"type": {"$eq": "decompiled"}}, {"source": ...}]}
                Default excludes vulnerability_pattern type.
    """
    k = min(max(1, k), 15)
    combined_query = f"{component_name} {extra_context}".strip()
    effective_filter = filter if filter is not None else {"type": {"$ne": "vulnerability_pattern"}}
    t0 = time.monotonic()
    try:
        results = get_retriever().query_with_scores(
            combined_query,
            k=k,
            filter=effective_filter,
            min_score=RETRIEVAL_MIN_SCORE,
        )
        if RETRIEVAL_MIN_SCORE > 0 and not results:
            results = _no_evidence(combined_query, RETRIEVAL_MIN_SCORE)
        log_call("search_component_context", {"component_name": component_name, "extra_context": extra_context, "k": k},
                 ok=True, ms=(time.monotonic() - t0) * 1000, extra={"n": len(results)})
        return results
    except Exception as e:
        log_call("search_component_context", {"component_name": component_name, "k": k},
                 ok=False, ms=(time.monotonic() - t0) * 1000, extra={"error": str(e)})
        return [{"error": f"search_component_context failed: {e}"}]


@mcp.tool()
def search_by_function(
    function_name: str,
    binary_name: str = "",
    filter: Optional[Dict] = None,
) -> List[Dict[str, str]]:
    """
    Exact metadata lookup for all chunks from a specific decompiled function.

    Filters on the function_name metadata field directly — more precise than
    semantic search when you know the exact function name from IDA output.

    Args:
        function_name: Exact decompiled function name (e.g. "vdshmem_vwrite", "qvm_ivc_connect")
        binary_name:   Optional — narrow by binary to disambiguate (e.g. "vdev-shmem")
        filter: Optional additional metadata filter to combine with function_name lookup.
                Example: {"source": {"$eq": "rag_docs/decompiled/qvm.c"}}
    """
    t0 = time.monotonic()
    try:
        results = get_retriever().query_by_function_name(
            function_name=function_name,
            binary_name=binary_name,
        )
        if not results:
            results = _no_evidence(function_name, 0.0)
        log_call("search_by_function", {"function_name": function_name, "binary_name": binary_name},
                 ok=True, ms=(time.monotonic() - t0) * 1000, extra={"n": len(results)})
        return results
    except Exception as e:
        log_call("search_by_function", {"function_name": function_name},
                 ok=False, ms=(time.monotonic() - t0) * 1000, extra={"error": str(e)})
        return [{"error": f"search_by_function failed: {e}"}]


@mcp.tool()
def query_knowledge_with_scores(query: str, k: int = 5) -> List[Dict[str, str]]:
    """
    Same as query_knowledge but includes similarity scores.

    Use when you need to judge retrieval confidence — a low score suggests the
    knowledge base may not have relevant information for this query.
    Prefer query_knowledge for normal lookups; use this when score transparency matters.

    Args:
        query: Natural-language or keyword query
        k: Number of chunks to return (1–20, default 5)
    """
    k = min(max(1, k), 20)
    t0 = time.monotonic()
    try:
        results = get_retriever().query_with_scores(
            query,
            k=k,
            min_score=RETRIEVAL_MIN_SCORE,
        )
        if RETRIEVAL_MIN_SCORE > 0 and not results:
            results = _no_evidence(query, RETRIEVAL_MIN_SCORE)
        log_call("query_knowledge_with_scores", {"query": query, "k": k},
                 ok=True, ms=(time.monotonic() - t0) * 1000, extra={"n": len(results)})
        return results
    except Exception as e:
        log_call("query_knowledge_with_scores", {"query": query, "k": k},
                 ok=False, ms=(time.monotonic() - t0) * 1000, extra={"error": str(e)})
        return [{"error": f"query_knowledge_with_scores failed: {e}"}]


# ---------------------------------------------------------------------------
# Knowledge Base Write Tool
# ---------------------------------------------------------------------------

@mcp.tool()
def add_knowledge_text(text: str, source_name: str = "analysis_result") -> Dict[str, str]:
    """
    Persist distilled analysis findings into the knowledge base for future retrieval.

    Call this AFTER completing analysis of a function or file. Use FORMAT A for
    vulnerability hypotheses and FORMAT B for architecture/function findings.

    ── FORMAT A: Vulnerability Pattern Card ─────────────────────────────────────
    Use when you found a suspicious Source→Sink path (MEDIUM or HIGH confidence).
    Text MUST start with "PATTERN CARD:" to be retrievable via search_vulnerability_patterns.

      PATTERN CARD: <name> [CONFIDENCE: HIGH|MEDIUM|LOW]
      apply_when: <which code construct makes this pattern apply, 1-2 sentences>
      root_cause: <why it is exploitable — one sentence>
      severity: HIGH|MEDIUM|LOW | cwe: CWE-XXX
      binary_indicators: <comma-separated observable signals in decompiled code>
      seen_in: <binary_name> / <function_name>

    ── FORMAT B: Architecture / Function Analysis Result ───────────────────────
    Use for struct layouts, call graph findings, or function purpose summaries.

      "Analysis of <function_name>/<filename>: <key findings about purpose,
       data flow, security properties, or what still needs verification>"

    Do NOT store:
      - Raw decompiled code or RAG-retrieved text verbatim
      - Speculation without labelling it in verify_next

    Args:
        text: Distilled finding (plain text, no code blocks)
        source_name: Label identifying this finding. Convention: "<binary>-<topic>"
                     e.g. "vdev-shmem-toctou-hypothesis", "qvm-ivc-race-condition"
    """
    t0 = time.monotonic()
    try:
        result = _get_pipeline().add_text(text_content=text, source_name=source_name)
        chunks_added = int(result.get("chunks_added", 0))
        log_call("add_knowledge_text", {"source_name": source_name, "text_len": len(text)},
                 ok=(result.get("status") == "success"),
                 ms=(time.monotonic() - t0) * 1000,
                 extra={"chunks": chunks_added})
        return result
    except Exception as e:
        log_call("add_knowledge_text", {"source_name": source_name, "text_len": len(text)},
                 ok=False, ms=(time.monotonic() - t0) * 1000, extra={"error": str(e)})
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
    t0 = time.monotonic()
    try:
        info = get_retriever().get_db_info()
        info["retrieval_min_score"] = str(RETRIEVAL_MIN_SCORE)
        log_call("get_knowledge_info", {},
                 ok=(info.get("status") == "connected"),
                 ms=(time.monotonic() - t0) * 1000,
                 extra={"status": info.get("status")})
        return info
    except Exception as e:
        log_call("get_knowledge_info", {},
                 ok=False, ms=(time.monotonic() - t0) * 1000, extra={"error": str(e)})
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


@mcp.prompt()
def generate_poc() -> str:
    """
    Write a minimal QNX guest-side PoC program for the MEDIUM/HIGH hypothesis from the preceding analysis.
    Gate: refuses if confidence is LOW or path verdict is OPAQUE — prompts to run trace_data_flow first.
    Retrieves struct offsets from KB before writing code to avoid hardcoded guesses.
    Outputs compilable QNX C using shm_open/mmap/mmap_device_memory only — no Linux APIs.
    """
    prompt_text = prompt_generate_poc()
    return _ensure_json_serializable(prompt_text)


@mcp.prompt()
def map_attack_surface() -> str:
    """
    Synthesize all findings from the current analysis session into a complete IVC attack surface map.
    Run AFTER triage_module + at least one analyze_current_function session.
    Outputs: Mermaid data-flow diagram, attack surface table, thesis-ready summary paragraph.
    KB update: saves high-level attack surface summary for future sessions.
    """
    prompt_text = prompt_map_attack_surface()
    return _ensure_json_serializable(prompt_text)


@mcp.prompt()
def identify_fuzzing_targets() -> str:
    """
    Convert MEDIUM/HIGH confidence hypotheses into actionable fuzzing specifications.
    Skips LOW confidence and OPAQUE paths. Retrieves field constraints from KB.
    Outputs per-hypothesis: mutation strategy, seed corpus, crash oracle, QNX harness skeleton.
    """
    prompt_text = prompt_identify_fuzzing_targets()
    return _ensure_json_serializable(prompt_text)


@mcp.prompt()
def benchmark_analysis() -> str:
    """
    Run a full analysis workflow on a known-vulnerable function to benchmark retrieval quality and latency.
    Use this to validate RAG server performance and relevance before starting real analysis.
    Outputs detailed timing and relevance metrics for each step.
    """
    prompt_text = prompt_benchmark_analysis()
    return _ensure_json_serializable(prompt_text)

@mcp.prompt()
def refactor_decompiled() -> str:
    """
    Refactor decompiled code for readability: rename variables, insert comments.
    Output .c file for ingesting into RAG.
    """
    prompt_text = prompt_refactor_decompiled()
    return _ensure_json_serializable(prompt_text)

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log_server_start(min_score=RETRIEVAL_MIN_SCORE)
    mcp.run()
