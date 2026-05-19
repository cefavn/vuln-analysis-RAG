Index của bạn là Hybrid Index (Search by both meaning and exact words) — loại mạnh nhất hiện tại của Pinecone Serverless cho RAG text-heavy + code.
1. Thông số Index hiện tại

Tên: vuln-analysis-rag
Kiểu: Hybrid (Dense + Sparse + Full-text Search)
Dense field: dense_embeddings (dimension=1536, metric=dotproduct)
Sparse field: sparse_embeddings
Full-text field: text (BM25, language=en, stemming=true, stop_words=false)
Region: us-east-1 (Free tier)

Đây là kiểu multi-signal index, cho phép kết hợp rất tốt:

Semantic (dense): Hiểu logic vuln, pattern bug
Lexical/Exact (sparse + full-text): Tìm chính xác function name, API, string literal, register...

2. Cấu trúc Document (Record) khuyến nghị
Mỗi record upsert nên có dạng sau:
Python{
    "id": "unique-chunk-id",           # Ví dụ: qnx-71-network-parse_packet-001
    "dense_embeddings": [0.0123, 0.0456, ...],   # vector 1536 dims
    "sparse_embeddings": {                       # sparse vector
        "indices": [12, 45, 678, ...],
        "values": [1.5, 0.8, 2.1, ...]
    },
    "text": "FULL TEXT của chunk (dùng cho BM25 + keyword search)", 
    "metadata": {
        "product": "QNX",
        "version": "7.1",
        "module": "network_stack",
        "function_name": "parse_packet",
        "type": "decompiled",
        "chunk_type": "function",
        "source_file": "xxx.c",
        "vuln_keywords": ["buffer_overflow", "null_deref"],
        "processed": True
    }
}
3. Code Python mẫu (dành cho Claude implement)
Pythonfrom pinecone import Pinecone
import json

pc = Pinecone(api_key="YOUR_API_KEY")
index = pc.Index("vuln-analysis-rag")

# === UPSERT EXAMPLE ===
def upsert_chunks(chunks):
    vectors = []
    for chunk in chunks:
        vectors.append({
            "id": chunk["id"],
            "dense_embeddings": chunk["dense_vector"],      # list[float] 1536 dims
            "sparse_embeddings": chunk["sparse_vector"],    # {"indices": [...], "values": [...]}
            "text": chunk["text"],                          # Quan trọng cho BM25
            "metadata": chunk["metadata"]
        })
    
    index.upsert(vectors=vectors, namespace="default")   # hoặc namespace theo version/product
4. Query Hybrid (Quan trọng nhất)
Pythondef hybrid_search(query_text: str, top_k=20, filters=None, alpha=0.7):
    # Generate embeddings (bạn cần model tương ứng)
    dense_vec = get_dense_embedding(query_text)      # text-embedding-3-large
    sparse_vec = get_sparse_embedding(query_text)    # pinecone-sparse hoặc BM25

    results = index.query(
        vector=dense_vec,
        sparse_vector=sparse_vec,
        top_k=top_k,
        include_metadata=True,
        include_values=False,
        filter=filters,          # Ví dụ: {"version": {"$eq": "7.1"}, "module": {"$eq": "network"}}
        # alpha=alpha            # Một số version hỗ trợ trực tiếp
    )
    return results
Metadata filtering (rất mạnh cho vuln analysis):
Pythonfilter_example = {
    "product": {"$eq": "QNX"},
    "version": {"$eq": "7.1"},
    "function_name": {"$in": ["parse_packet", "handle_input"]},
    "vuln_keywords": {"$in": ["buffer_overflow"]}
}
5. Best Practices cho project Vuln Analysis

Chunking: Ưu tiên function-level (atomic) + Parent-Child.
Embedding: Dùng text-embedding-3-large cho dense. Sparse dùng Pinecone hosted hoặc BM25Encoder.
Retrieval: Hybrid → Reranker (bge-reranker hoặc Claude judge) → Context cho LLM.
Agentic RAG: Cho Claude tool calling với các tool như:
hybrid_search(filter=...)
get_function_context(function_name, version)
search_vuln_pattern(keyword)