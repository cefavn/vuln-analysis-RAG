#!/bin/bash
# run_mcp_in_docker.sh - Wrapper script to run MCP server in Docker with stdio (Linux/macOS)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure the host-side logs directory exists before mounting.
# Logs are written to /app/logs/ inside the container and survive container deletion.
mkdir -p "${SCRIPT_DIR}/logs"

DOCKER_ARGS=(
  --rm
  -i
  --network host
  --env-file "${SCRIPT_DIR}/.env"
  # Mount host logs/ → /app/logs/ so mcp_usage.jsonl persists across runs.
  -v "${SCRIPT_DIR}/logs:/app/logs"
  -e "LOG_DIR=/app/logs"
)

# Optional runtime overrides from Claude Desktop MCP config.
if [[ -n "${RETRIEVAL_MIN_SCORE:-}" ]]; then
  DOCKER_ARGS+=(-e "RETRIEVAL_MIN_SCORE=${RETRIEVAL_MIN_SCORE}")
fi

docker run "${DOCKER_ARGS[@]}" \
  rag-mcp-gd2:latest \
  python -u /app/main.py
