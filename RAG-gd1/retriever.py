# retriever.py - Query and retrieve from vector database
from langchain_pinecone import PineconeVectorStore
from langchain_openai import OpenAIEmbeddings
import os
from typing import List, Dict
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Load from environment variables (from .env file)
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_INDEX_NAME = os.getenv("PINECONE_INDEX_NAME", "rag-mcp-server")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Validate required API keys
if not PINECONE_API_KEY:
    raise ValueError("PINECONE_API_KEY not found in environment variables. Please set it in .env file.")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not found in environment variables. Please set it in .env file.")

# Set API keys as environment variables (for langchain)
os.environ["PINECONE_API_KEY"] = PINECONE_API_KEY
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY


class DocumentRetriever:
    """Handle queries and similarity search from vector database"""
    
    def __init__(self, index_name: str = PINECONE_INDEX_NAME):
        self.index_name = index_name
        self.embeddings = OpenAIEmbeddings(
            model="text-embedding-3-small",
            openai_api_key=OPENAI_API_KEY
        )
        self.vectorstore = None
    
    def connect(self):
        """Connect to existing Pinecone vector database"""
        if self.vectorstore is None:
            self.vectorstore = PineconeVectorStore(
                index_name=self.index_name,
                embedding=self.embeddings
            )
        return self.vectorstore
    
    def query(self, query: str, k: int = 5) -> List[Dict[str, str]]:
        """Query to get k most relevant chunks
        """
        if self.vectorstore is None:
            self.connect()
        
        # Similarity search
        results = self.vectorstore.similarity_search(query, k=k)
        
        # Format results - convert all values to strings for MCP compatibility
        formatted_results = []
        for i, doc in enumerate(results):
            formatted_results.append({
                "rank": str(i + 1),
                "content": doc.page_content,
                "source": str(doc.metadata.get("source", "unknown")),
                "page": str(doc.metadata.get("page", "unknown"))
            })
        
        return formatted_results
    
    def query_with_scores(self, query: str, k: int = 5) -> List[Dict[str, str]]:
        """Query with similarity scores
        
        """
        if self.vectorstore is None:
            self.connect()
        
        # Similarity search with scores
        results = self.vectorstore.similarity_search_with_score(query, k=k)
        
        # Format results
        formatted_results = []
        for i, (doc, score) in enumerate(results):
            formatted_results.append({
                "rank": str(i + 1),
                "score": f"{score:.4f}",
                "content": doc.page_content,
                "source": str(doc.metadata.get("source", "unknown")),
                "page": str(doc.metadata.get("page", "unknown"))
            })
        
        return formatted_results
    
    def get_db_info(self) -> Dict[str, str]:
        """Get database information
        
        """
        try:
            if self.vectorstore is None:
                self.connect()
            
            return {
                "status": "exists",
                "index_name": self.index_name,
                "message": "Connected to Pinecone index"
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}


# Singleton instance
_retriever = None

def get_retriever() -> DocumentRetriever:
    """Get or create retriever instance"""
    global _retriever
    if _retriever is None:
        _retriever = DocumentRetriever()
    return _retriever


if __name__ == "__main__":
    # Test retrieval
    retriever = DocumentRetriever()
    
    query = "How to implement a watchdog in a Linux or Android guest?"
    print(f"Query: {query}\n")
    
    results = retriever.query(query, k=3)
    for result in results:
        print(f"\n--- Rank {result['rank']} (Source: {result['source']}, Page: {result['page']}) ---")
        print(result['content'][:200] + "...")
    
    print("\nDone.")
