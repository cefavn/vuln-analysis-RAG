# Dockerfile for RAG MCP Server
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-eng \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy main logic code
COPY src/ ./

# Copy documents folder (no need if ingest locally)
# COPY rag_docs/ ./rag_docs/

# Default command: Run MCP server in stdio mode (no HTTP, no port)
# This is required for Claude Desktop MCP protocol
CMD ["python", "-u", "/app/main.py"]