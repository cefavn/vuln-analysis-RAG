#!/usr/bin/env python3
"""
HTTP evaluation server for gd2 (hybrid BM25+dense, Pinecone Document API).

  GET /query?q=<text>&k=<int>&mode=<hybrid|dense|bm25>  → {"results": [...]}
  GET /health                                             → {"status": "ok"}

Start inside the container:
  docker run -d -p 8080:8080 --env-file .env rag-gd2:latest python /app/eval_server.py
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import PINECONE_INDEX_NAME
from retriever import DocumentRetriever

_retriever = None


def _get():
    global _retriever
    if _retriever is None:
        _retriever = DocumentRetriever(index_name=PINECONE_INDEX_NAME)
    return _retriever


def _do_query(query: str, k: int, mode: str) -> list:
    r = _get()
    if mode == "dense":
        matches = r._dense_query(query, k=k)
    elif mode == "bm25":
        matches = r._bm25_query(query, k=k)
    else:
        matches = r._hybrid_query(query, k=k)
    return r._format_results(matches)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/health":
            self._send(200, {"status": "ok"})
            return

        if parsed.path != "/query":
            self._send(404, {"error": "not found"})
            return

        query = params.get("q", [""])[0]
        k = int(params.get("k", ["10"])[0])
        mode = params.get("mode", ["hybrid"])[0]

        if not query:
            self._send(400, {"error": "q parameter required"})
            return

        try:
            self._send(200, {"results": _do_query(query, k, mode)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _send(self, code: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("EVAL_PORT", 8080))
    print(f"[eval_server] gd2 | :{port}", flush=True)
    HTTPServer(("0.0.0.0", port), _Handler).serve_forever()
