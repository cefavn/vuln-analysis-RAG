#!/usr/bin/env python3
"""
inspect_pinecone.py - Show what's currently stored in the Pinecone index.

Usage (from project root):
    python3 inspect_pinecone.py
    python3 inspect_pinecone.py --sample 5     # fetch 5 sample vectors per source
"""
import sys
import os
import argparse
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from dotenv import load_dotenv
load_dotenv()

from pinecone import Pinecone
from config import PINECONE_API_KEY, PINECONE_INDEX_NAME


def main(sample_k: int = 0):
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

    # -----------------------------------------------------------------------
    # 2. Sample vectors to collect unique sources
    #    Pinecone doesn't have a native "list all metadata" API for serverless,
    #    so we query with a zero vector to grab representative samples.
    # -----------------------------------------------------------------------
    print("\nSampling vectors to discover uploaded sources...\n")

    dim_size = int(dim) if str(dim).isdigit() else 1536
    zero_vec = [0.0] * dim_size

    # Fetch up to 200 vectors for source discovery (max top_k = 10000 on some plans)
    response = index.query(
        vector=zero_vec,
        top_k=min(200, int(total) if str(total).isdigit() else 200),
        include_metadata=True,
    )

    sources = defaultdict(lambda: {"count": 0, "types": set(), "pages": set(), "doc_ids": set()})

    for match in response.get("matches", []):
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
    sampled = len(response.get("matches", []))
    print(f"\nShowing {len(sources)} unique source(s) from {sampled} sampled vectors (total in index: {total})")

    if str(total).isdigit() and sampled < int(total):
        print(f"Note: only {sampled}/{total} vectors were sampled — increase top_k or run in batches for full coverage.")

    # -----------------------------------------------------------------------
    # 4. Optional: print sample content per source
    # -----------------------------------------------------------------------
    if sample_k > 0:
        print(f"\n{'='*60}")
        print(f"Sample content ({sample_k} chunk(s) per source):")
        shown = defaultdict(int)
        for match in response.get("matches", []):
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
    args = parser.parse_args()
    main(sample_k=args.sample)
