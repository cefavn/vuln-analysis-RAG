#!/usr/bin/env python3
"""
Quick retrieval test runner for predefined query strings.

Usage (from repo root):
  python helper/quick_retrieval_test.py
  python helper/quick_retrieval_test.py --queries-file queries.txt --k 5
  python helper/quick_retrieval_test.py --filter type=vulnerability_pattern
  python helper/quick_retrieval_test.py --filter-json '{"type": {"$eq": "reference_document"}}'
  python helper/quick_retrieval_test.py --json                    # Output in MCP JSON format
"""
import argparse
import json
import os
import sys
from typing import Dict, List, Optional


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

from retriever import DocumentRetriever  # noqa: E402


DEFAULT_QUERIES = [
    # "vdev-shmem connect_map field layout",
    # "ivc connect request structure",
    # "virtqueue size bounds check",
    # "buffer overflow memcpy guest length",
    # "Smmuman DMA Direct Memory Access hypervisor",
    # "Buffer Overflow in Virtual Device I/O Handler",
    "vdevpeer"
]


def _parse_filter_specs(filter_specs: List[str], filter_json: Optional[str]) -> Dict:
    if filter_specs and filter_json:
        raise ValueError("Use either --filter or --filter-json, not both")

    if filter_json:
        raw = json.loads(filter_json)
        if not isinstance(raw, dict):
            raise ValueError("--filter-json must be a JSON object")
        return raw

    if not filter_specs:
        return {}

    parsed: Dict[str, Dict[str, str]] = {}
    for spec in filter_specs:
        if "=" not in spec:
            raise ValueError(f"Invalid --filter '{spec}' (expected key=value)")
        key, value = spec.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"Invalid --filter '{spec}' (empty key)")
        parsed[key] = {"$eq": value}
    return parsed


def _load_queries(path: str) -> List[str]:
    queries: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            queries.append(line)
    return queries


def _print_result(result: Dict[str, str], max_chars: int, show_context: bool) -> None:
    score = result.get("score", "")
    score_part = f" | score {score}" if score else ""
    header = (
        f"- rank {result.get('rank')} | {result.get('source')} "
        f"(p{result.get('page')}){score_part}"
    )
    print(header)

    content = result.get("context") if show_context else result.get("content")
    if content is None:
        content = ""
    snippet = content[:max_chars].replace("\n", " ")
    if len(content) > max_chars:
        snippet += "..."
    print(f"  {snippet}")


def _print_result_json(result: Dict[str, str]) -> None:
    """Print result in JSON format (same format as MCP tool returns)."""
    print(json.dumps(result, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(description="Quick RAG retrieval test runner")
    parser.add_argument(
        "--queries-file",
        help="Path to a text file with one query per line",
    )
    parser.add_argument("--k", type=int, default=5, help="Top-k results")
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Minimum similarity score filter (0 disables)",
    )
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        help="Metadata filter in key=value form (repeatable)",
    )
    parser.add_argument(
        "--filter-json",
        help="Metadata filter as raw JSON object",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=400,
        help="Max characters per snippet",
    )
    parser.add_argument(
        "--show-context",
        action="store_true",
        help="Show parent context instead of child chunk content",
    )
    parser.add_argument(
        "--output-jsonl",
        help="Optional JSONL output file for all results",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format (same as MCP tool returns)",
    )
    args = parser.parse_args()

    queries = DEFAULT_QUERIES
    if args.queries_file:
        queries = _load_queries(args.queries_file)

    if not queries:
        print("No queries to run. Provide --queries-file or edit DEFAULT_QUERIES.")
        return 1

    metadata_filter = _parse_filter_specs(args.filter, args.filter_json)
    min_score = args.min_score if args.min_score and args.min_score > 0 else None

    retriever = DocumentRetriever()
    jsonl_handle = None
    if args.output_jsonl:
        jsonl_handle = open(args.output_jsonl, "w", encoding="utf-8")

    try:
        for query in queries:
            print("\n" + "=" * 80)
            print(f"Query: {query}")
            results = retriever.query_with_scores(
                query,
                k=args.k,
                filter=metadata_filter or None,
                min_score=min_score,
            )
            if not results:
                print("- (no results)")
                continue

            for result in results:
                if args.json:
                    _print_result_json(result)
                else:
                    _print_result(result, args.max_chars, args.show_context)
                if jsonl_handle:
                    payload = {"query": query, "result": result}
                    jsonl_handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    finally:
        if jsonl_handle:
            jsonl_handle.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
