#!/usr/bin/env python3
"""
create_index.py — Create a Pinecone document-schema index (hybrid BM25 + dense).

Uses Pinecone SDK 7.3+ preview API (pc.preview.indexes).
Run from the project root:

    python helper/create_index.py --name vuln-analysis-rag-v3 [--wait]

After creation, update .env:
    PINECONE_INDEX_NAME=vuln-analysis-rag-v3
"""
import argparse
import os
import sys
import time

from dotenv import load_dotenv
load_dotenv()

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY", "")
DEFAULT_INDEX    = "vuln-analysis-rag-v3"
EMBEDDING_DIM    = 1536   # text-embedding-3-small


def build_schema():
    from pinecone.preview import PreviewSchemaBuilder
    # The 2026-01.alpha API only allows search fields in the schema declaration.
    # All other fields (type, source, section, parent_id, ...) are metadata —
    # they are auto-indexed for filtering when passed on upsert.
    return (
        PreviewSchemaBuilder()
        .add_dense_vector_field("embedding", dimension=EMBEDDING_DIM, metric="cosine")
        .add_string_field("text", full_text_search=True, language="en", stemming=True)
        .build()
    )


def create_index(name: str, wait: bool) -> None:
    if not PINECONE_API_KEY:
        print("ERROR: PINECONE_API_KEY not set in .env")
        sys.exit(1)

    from pinecone import Pinecone
    pc = Pinecone(api_key=PINECONE_API_KEY)

    if pc.preview.indexes.exists(name):
        print(f"Index '{name}' already exists. Nothing to do.")
        print(f"\nTo use it, set in .env:\n  PINECONE_INDEX_NAME={name}")
        return

    schema = build_schema()
    print(f"Creating index '{name}' ({EMBEDDING_DIM}d cosine + BM25)...")

    pc.preview.indexes.create(name=name, schema=schema)
    print("Create request submitted.")

    if wait:
        print("Waiting for index to become ready", end="", flush=True)
        deadline = time.monotonic() + 300  # 5-minute timeout
        while time.monotonic() < deadline:
            time.sleep(5)
            try:
                desc = pc.preview.indexes.describe(name)
                state = str(getattr(getattr(desc, "status", None), "state", ""))
                if state == "Ready":
                    print(" Ready!")
                    break
            except Exception:
                pass
            print(".", end="", flush=True)
        else:
            print("\nTimed out. Check Pinecone console.")
            return

    print(f"\nDone. Update .env:\n  PINECONE_INDEX_NAME={name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create Pinecone preview document-schema index")
    parser.add_argument("--name", default=DEFAULT_INDEX,
                        help=f"Index name (default: {DEFAULT_INDEX})")
    parser.add_argument("--wait", action="store_true",
                        help="Poll until the index is Ready before exiting")
    args = parser.parse_args()
    create_index(args.name, args.wait)
