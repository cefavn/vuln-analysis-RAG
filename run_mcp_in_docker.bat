@echo off
REM run_mcp_in_docker.bat - Wrapper script to run MCP server in Docker with stdio
docker run --rm -i ^
  --env-file "%~dp0.env" ^
  rag-mcp-server:latest ^
  python -u /app/main.py
