#!/usr/bin/env python3
"""
Targeted ingestion: upsert individual records one-by-one.
Focuses on the specific file types needed for RAG retrieval evaluation.
"""
import os, sys, time
sys.path.insert(0, 'src')
from dotenv import load_dotenv
load_dotenv('.env')

from ingestion.loader import discover_documents, load_documents
from ingestion.chunker import Chunker
from ingestion.embedder import Embedder, text_for_dense_embedding
from store.pinecone_client import make_vector_id, _guard_sizes
from pinecone import Pinecone
from config import PINECONE_API_KEY, PINECONE_INDEX_NAME, PINECONE_NAMESPACE

pc = Pinecone(api_key=PINECONE_API_KEY)
idx = pc.preview.index(name=PINECONE_INDEX_NAME)
e = Embedder()

# Target only the files needed for evaluation queries
TARGET_DIRS = ['vuln-pattern', 'decompiled']
all_files = discover_documents()
files = [f for f in all_files if any(d in f for d in TARGET_DIRS)]
print(f"Target files: {len(files)}")
for f in files:
    print(f"  {f.split('rag_docs/')[-1]}")

docs = load_documents(files)
chunks = Chunker().chunk_all(docs)
docs_guarded = _guard_sizes(chunks)
print(f"\nTotal chunks to upsert: {len(docs_guarded)}")

ok = 0
fail = 0
for i, doc in enumerate(docs_guarded):
    try:
        text = text_for_dense_embedding(doc.page_content, doc.metadata.get('type', ''))
        vec = e.embed_documents([text])[0]
        meta = {k: v for k, v in doc.metadata.items() if v is not None and v != ''}
        # Truncate parent_content if present
        if 'parent_content' in meta and len(str(meta['parent_content'])) > 3000:
            meta['parent_content'] = str(meta['parent_content'])[:3000]
        rec = {
            '_id': make_vector_id(doc),
            'embedding': vec,
            'text': doc.page_content[:10000],    # FTS field cap
            'chunk_text': doc.page_content[:5000],
            **meta,
        }
        result = idx.documents.batch_upsert(
            namespace=PINECONE_NAMESPACE,
            documents=[rec],
            batch_size=1,
        )
        ok += 1
        if ok % 20 == 0:
            print(f"  [{i+1}/{len(docs_guarded)}] {ok} ok, {fail} fail | last: {doc.metadata.get('source','?').split('/')[-1]} ({doc.metadata.get('type','?')})")
    except Exception as ex:
        fail += 1
        print(f"  ERROR [{i+1}]: {ex} | {doc.metadata.get('source','?')}")

print(f"\nDone: {ok} upserted, {fail} failed")

# Verify
time.sleep(15)
for q in ['buffer overflow memcpy', 'vdshmem_vwrite', 'race condition']:
    resp = idx.documents.search(namespace=PINECONE_NAMESPACE, top_k=3,
        score_by=[{'type': 'text', 'field': 'text', 'query': q}])
    print(f"  '{q}': {len(resp.matches)} results")
