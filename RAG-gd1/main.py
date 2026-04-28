"""
FastMCP quickstart example.

cd to the `examples/snippets/clients` directory and run:
    uv run server fastmcp_quickstart stdio
"""
from typing import List, Dict
from mcp.server.fastmcp import FastMCP
from builder import DocumentBuilder
from retriever import get_retriever
from prompts import (
   prompt_analyze_current_function,
prompt_analyze_current_file,
   prompt_benchmark_analysis,
prompt_refactor_current_function,
prompt_refactor_entire_file
)

# Create an MCP server
mcp = FastMCP("Demo")

@mcp.tool()
def query_knowledge(query: str, k: int = 5) -> List[Dict[str, str]]:
    """Query the knowledge base for relevant chunks
    """
    try:
        # Limit k to avoid overload
        k = min(max(1, k), 20)
        
        retriever = get_retriever()
        results = retriever.query(query, k=k)
        
        return results
    except Exception as e:
        return [{"error": f"Failed to query knowledge base: {str(e)}"}]

@mcp.tool()
def query_knowledge_with_scores(query: str, k: int = 5) -> List[Dict[str, str]]:
    """Query the knowledge base with similarity scores
    """
    try:
        # Limit k to avoid overload
        k = min(max(1, k), 20)
        
        retriever = get_retriever()
        results = retriever.query_with_scores(query, k=k)
        
        return results
    except Exception as e:
        return [{"error": f"Failed to query knowledge base: {str(e)}"}]

@mcp.tool()
def add_knowledge_text(text: str, source_name: str = "manual_entry") -> Dict[str, str]:
    """Add text content directly to knowledge base (for conclusions, notes, analysis results)
    """
    try:
        if not text or not text.strip():
            return {"status": "error", "message": "Text content is empty"}
        
        builder = DocumentBuilder()
        result = builder.add_text_to_db(text_content=text, source_name=source_name)
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Failed to add text: {str(e)}"}

@mcp.tool()
def get_knowledge_info() -> Dict[str, str]:
    """Get information about the knowledge base (index name, status)

    """
    try:
        retriever = get_retriever()
        info = retriever.get_db_info()
        return info
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.prompt()
def analyze_current_function() -> str:
    """Perform a full security review of the current function in the QNX module."""
    return prompt_analyze_current_function()

@mcp.prompt()
def analyze_current_file() -> str:
    """Perform a full security review of all functions in the current QNX module."""
    return prompt_analyze_current_file()

@mcp.prompt()
def refactor_current_function() -> str:
    """Refactor the current function using the exact workflow below."""
    return prompt_refactor_current_function()

@mcp.prompt()
def refactor_entire_file() -> str:
    """Refactor the entire file using the exact workflow below."""
    return prompt_refactor_entire_file()

@mcp.prompt()
def benchmark_analysis() -> str:
    """
    Run a full analysis workflow on a known-vulnerable function to benchmark retrieval quality and latency.
    Use this to validate RAG server performance and relevance before starting real analysis.
    Outputs detailed timing and relevance metrics for each step.
    """
    return prompt_benchmark_analysis()

# Entry point for MCP server
if __name__ == "__main__":
    mcp.run()
