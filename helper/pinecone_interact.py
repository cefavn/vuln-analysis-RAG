#!/usr/bin/env python3
"""
inspect_pinecone.py - Inspect and manage what's stored in the Pinecone index.

Usage (from project root):
    python3 inspect_pinecone.py
    python3 inspect_pinecone.py --sample 5
    python3 inspect_pinecone.py --list-metadata
    python3 inspect_pinecone.py --filter source=rag_docs/foo.md --delete --yes
"""
import sys
import os
import argparse
import json
from collections import defaultdict
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from dotenv import load_dotenv
load_dotenv()

from pinecone import Pinecone
from config import PINECONE_API_KEY, PINECONE_INDEX_NAME


def _clear_llm_knowledge(index, source_name: str = "", yes: bool = False) -> None:
    """Delete chunks written by the LLM via add_knowledge_text (origin=llm_generated)."""
    if source_name:
        delete_filter: Dict = {
            "$and": [
                {"origin": {"$eq": "llm_generated"}},
                {"source": {"$eq": source_name}},
            ]
        }
        scope = f"source='{source_name}'"
    else:
        delete_filter = {"origin": {"$eq": "llm_generated"}}
        scope = "ALL llm_generated chunks"

    print(f"\nClear LLM knowledge — scope: {scope}")
    print(f"Filter: {json.dumps(delete_filter, indent=2)}")

    if not yes:
        print("Refusing to delete without --yes. Re-run with --yes to confirm.")
        sys.exit(1)

    index.delete(filter=delete_filter)
    print(f"Deleted {scope} from knowledge base.")


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


def _sample_matches(index, dim, total, metadata_filter=None, top_k: int = 200):
    dim_size = int(dim) if str(dim).isdigit() else 1536
    zero_vec = [0.0] * dim_size
    response = index.query(
        vector=zero_vec,
        top_k=min(top_k, int(total) if str(total).isdigit() else top_k),
        include_metadata=True,
        filter=metadata_filter or None,
    )
    return response.get("matches", [])


def _print_metadata_options(matches, fields: List[str], top_n: int) -> None:
    counts = {field: defaultdict(int) for field in fields}
    for match in matches:
        meta = match.get("metadata", {}) or {}
        for field in fields:
            value = meta.get(field)
            if value is None:
                continue
            counts[field][str(value)] += 1

    print("\nMetadata options (sample-based):")
    for field in fields:
        print(f"\n- {field}")
        for value, count in sorted(counts[field].items(), key=lambda kv: kv[1], reverse=True)[:top_n]:
            print(f"  {value} ({count})")


def main(
    sample_k: int = 0,
    list_metadata: bool = False,
    fields: str = "source,file_name,type,doc_id,section",
    top_n: int = 20,
    filter_specs: Optional[List[str]] = None,
    filter_json: Optional[str] = None,
    delete: bool = False,
    clear_llm: bool = False,
    llm_source: str = "",
    yes: bool = False,
):
    if not PINECONE_API_KEY:
        print("ERROR: PINECONE_API_KEY not set in .env")
        sys.exit(1)

    pc = Pinecone(api_key=PINECONE_API_KEY)
    index = pc.Index(PINECONE_INDEX_NAME)

    # -----------------------------------------------------------------------
    # 1. Index-level stats
    # -----------------------------------------------------------------------
    stats = index.describe_index_stats()
    total = stats.get("total_vector_count", stats.get("totalVectorCount", "?"))
    dim   = stats.get("dimension", "?")

    print("=" * 60)
    print(f"Index   : {PINECONE_INDEX_NAME}")
    print(f"Vectors : {total}")
    print(f"Dimension: {dim}")
    print("=" * 60)

    if total == 0:
        print("\nIndex is empty — run builder.py to ingest documents.")
        return

    try:
        metadata_filter = _parse_filter_specs(filter_specs or [], filter_json)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    if clear_llm:
        _clear_llm_knowledge(index, source_name=llm_source, yes=yes)
        return

    if delete:
        if not metadata_filter:
            print("ERROR: --delete requires --filter or --filter-json")
            sys.exit(1)
        if not yes:
            print("Refusing to delete without --yes confirmation.")
            sys.exit(1)
        print("\nDelete requested with filter:")
        print(json.dumps(metadata_filter, indent=2))
        try:
            filtered_stats = index.describe_index_stats(filter=metadata_filter)
            matched = filtered_stats.get("total_vector_count", filtered_stats.get("totalVectorCount", "?"))
            print(f"Approximate match count: {matched}")
        except Exception as exc:
            print(f"Could not fetch filtered stats: {exc}")
        index.delete(filter=metadata_filter)
        print("Delete request submitted.")
        return

    # -----------------------------------------------------------------------
    # 2. Sample vectors to collect unique sources
    #    Pinecone doesn't have a native "list all metadata" API for serverless,
    #    so we query with a zero vector to grab representative samples.
    # -----------------------------------------------------------------------
    print("\nSampling vectors to discover uploaded sources...\n")
    if metadata_filter:
        print("Sampling with filter:")
        print(json.dumps(metadata_filter, indent=2))

    # Fetch up to 200 vectors for source discovery (max top_k = 10000 on some plans)
    matches = _sample_matches(index, dim, total, metadata_filter=metadata_filter, top_k=200)

    sources = defaultdict(lambda: {"count": 0, "types": set(), "pages": set(), "doc_ids": set()})

    for match in matches:
        meta = match.get("metadata", {})
        src  = meta.get("file_name") or meta.get("source") or "unknown"
        sources[src]["count"] += 1
        if meta.get("type"):
            sources[src]["types"].add(meta["type"])
        if meta.get("page") is not None:
            sources[src]["pages"].add(str(meta["page"]))
        if meta.get("doc_id"):
            sources[src]["doc_ids"].add(meta["doc_id"])

    # -----------------------------------------------------------------------
    # 3. Print per-source summary
    # -----------------------------------------------------------------------
    print(f"{'Source':<45} {'Chunks':>7}  {'Type':<22}  Doc IDs / pages")
    print("-" * 110)
    for src, info in sorted(sources.items()):
        types   = ", ".join(sorted(info["types"])) or "-"
        doc_ids = ", ".join(sorted(info["doc_ids"])) if info["doc_ids"] else ""
        pages   = f"pages: {', '.join(sorted(info['pages'], key=lambda x: int(x) if x.isdigit() else 0)[:5])}" if info["pages"] else ""
        extra   = doc_ids or pages
        print(f"{src:<45} {info['count']:>7}  {types:<22}  {extra}")

    print("-" * 110)
    sampled = len(matches)
    print(f"\nShowing {len(sources)} unique source(s) from {sampled} sampled vectors (total in index: {total})")

    if str(total).isdigit() and sampled < int(total):
        print(f"Note: only {sampled}/{total} vectors were sampled — increase top_k or run in batches for full coverage.")

    if list_metadata:
        field_list = [f.strip() for f in fields.split(",") if f.strip()]
        _print_metadata_options(matches, field_list, top_n)

    # -----------------------------------------------------------------------
    # 4. Optional: print sample content per source
    # -----------------------------------------------------------------------
    if sample_k > 0:
        print(f"\n{'='*60}")
        print(f"Sample content ({sample_k} chunk(s) per source):")
        shown = defaultdict(int)
        for match in matches:
            meta    = match.get("metadata", {})
            src     = meta.get("file_name") or meta.get("source") or "unknown"
            if shown[src] >= sample_k:
                continue
            shown[src] += 1
            content = meta.get("text", match.get("metadata", {}).get("page_content", ""))
            print(f"\n--- {src} | {meta.get('type','')} | page {meta.get('page','?')} ---")
            print(content[:400] + ("..." if len(content) > 400 else ""))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inspect Pinecone index contents")
    parser.add_argument("--sample", type=int, default=0,
                        help="Print N sample chunks per source (default: 0 = off)")
    parser.add_argument("--list-metadata", action="store_true",
                        help="List metadata field values from sampled vectors")
    parser.add_argument("--fields", default="source,file_name,type,doc_id,section",
                        help="Comma-separated metadata fields to list with --list-metadata")
    parser.add_argument("--top", type=int, default=20,
                        help="Top values to show per field when listing metadata")
    parser.add_argument("--filter", action="append", default=[],
                        help="Filter for delete/query in key=value form (repeatable)")
    parser.add_argument("--filter-json", default=None,
                        help="Raw JSON filter for Pinecone delete/query")
    parser.add_argument("--delete", action="store_true",
                        help="Delete vectors matching the filter")
    parser.add_argument("--clear-llm", action="store_true",
                        help="Delete all chunks written by the LLM (origin=llm_generated)")
    parser.add_argument("--llm-source", default="",
                        help="Restrict --clear-llm to a specific source label (e.g. 'vdev-shmem-toctou-hypothesis')")
    parser.add_argument("--yes", action="store_true",
                        help="Confirm deletion (required with --delete or --clear-llm)")
    args = parser.parse_args()
    main(
        sample_k=args.sample,
        list_metadata=args.list_metadata,
        fields=args.fields,
        top_n=args.top,
        filter_specs=args.filter,
        filter_json=args.filter_json,
        delete=args.delete,
        clear_llm=args.clear_llm,
        llm_source=args.llm_source,
        yes=args.yes,
    )
