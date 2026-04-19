#!/bin/bash
# run_mcp_in_docker.sh - Wrapper script to run MCP server in Docker with stdio (Linux/macOS)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DOCKER_ARGS=(
  --rm
  -i
  --network host
  --env-file "${SCRIPT_DIR}/.env"
)

# Optional runtime overrides from Claude Desktop MCP config.
if [[ -n "${RAG_MODE:-}" ]]; then
  DOCKER_ARGS+=(-e "RAG_MODE=${RAG_MODE}")
fi
if [[ -n "${RETRIEVAL_MIN_SCORE:-}" ]]; then
  DOCKER_ARGS+=(-e "RETRIEVAL_MIN_SCORE=${RETRIEVAL_MIN_SCORE}")
fi

docker run "${DOCKER_ARGS[@]}" \
  rag-mcp-gd2:latest \
  python -u /app/main.py
