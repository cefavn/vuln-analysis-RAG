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

# Copy application code
COPY main.py .
COPY builder.py .
COPY retriever.py .
COPY prompts.py .

# Copy documents folder (if exists)
COPY ghidra_docs/ ./ghidra_docs/

# Set environment variables for Tesseract
ENV TESSERACT_PATH=/usr/bin/tesseract

# Default command: Run MCP server in stdio mode (no HTTP, no port)
# This is required for Claude Desktop MCP protocol
CMD ["python", "-u", "/app/main.py"]
