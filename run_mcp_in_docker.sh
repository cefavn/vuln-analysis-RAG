#!/bin/bash
# run_mcp_in_docker.sh - Wrapper script to run MCP server in Docker with stdio (Linux/macOS)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker run --rm -i \
  --network host \
  --env-file "${SCRIPT_DIR}/.env" \
  rag-mcp-server:latest \
  python -u /app/main.py
