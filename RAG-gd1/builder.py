# builder.py - Build vector database from PDF documents
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_pinecone import PineconeVectorStore
from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document
import os
import hashlib
from typing import List
import fitz  # PyMuPDF
from PIL import Image
import pytesseract
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Auto-discover all PDF and TXT files in ghidra_docs folder
DOCS_DIR = os.path.join(SCRIPT_DIR, "ghidra_docs")
DOCUMENT_PATHS = []
if os.path.exists(DOCS_DIR):
    for file in os.listdir(DOCS_DIR):
        if file.lower().endswith(('.pdf', '.txt')):
            DOCUMENT_PATHS.append(os.path.join(DOCS_DIR, file))
    DOCUMENT_PATHS.sort()  # Sort alphabetically for consistent processing

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

pytesseract.pytesseract.tesseract_cmd = os.getenv("TESSERACT_PATH", "C:\\Program Files\\Tesseract-OCR\\tesseract.exe")


def make_id(source: str, page: int, chunk_id: int) -> str:
    key = f"{source}-{page}-{chunk_id}"
    return hashlib.sha256(key.encode()).hexdigest()


class DocumentBuilder:
    """Build and manage vector database from PDF documents"""
    
    def __init__(self, document_paths: List[str] = None, index_name: str = PINECONE_INDEX_NAME):
        self.document_paths = document_paths or DOCUMENT_PATHS
        self.index_name = index_name
        self.embeddings = OpenAIEmbeddings(
            model="text-embedding-3-small",
            openai_api_key=OPENAI_API_KEY
        )
    
    def extract_text_with_ocr(self, pdf_path: str) -> List[Document]:
        """Extract text from PDF using OCR (for scanned PDF images)"""
        documents = []
        pdf_document = fitz.open(pdf_path)
        
        total_pages = len(pdf_document)
        print(f"Processing {total_pages} pages from {os.path.basename(pdf_path)}...")
        
        for page_num in range(total_pages):
            page = pdf_document[page_num]
            
            text = page.get_text()
            if len(text.strip()) < 100:
                mat = fitz.Matrix(2.0, 2.0)  # 2x zoom
                pix = page.get_pixmap(matrix=mat)
                
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                
                try:
                    text = pytesseract.image_to_string(img, lang='eng')
                except Exception as e:
                    print(f"OCR failed for page {page_num}: {e}")
                    text = ""
            
            if text.strip():
                documents.append(Document(
                    page_content=text,
                    metadata={
                        "source": pdf_path,
                        "file_name": os.path.basename(pdf_path),
                        "page": page_num,
                        "text_length": len(text)
                    }
                ))
        
        pdf_document.close()
        print(f"Extracted {len(documents)} pages with content")
        return documents
    
    def chunk_documents(self, documents: List[Document]) -> List[Document]:
        """Split documents into chunks optimized for text-embedding-3-small"""
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=800,  
            chunk_overlap=160,
            separators=["\n\n", "\n", "class ", "def ", "public void", ". "]
        )
        splits = text_splitter.split_documents(documents)
        
        # Add chunk_id to metadata
        for i, split in enumerate(splits):
            split.metadata["chunk_id"] = i
            if "text_length" not in split.metadata:
                split.metadata["text_length"] = len(split.page_content)
        
        print(f"Created {len(splits)} chunks")
        return splits
    
    def load_documents(self) -> List[Document]:
        """Load all documents from configured paths"""
        all_docs = []
        
        print(f"Found {len(self.document_paths)} document(s) to process")
        
        for doc_path in self.document_paths:
            if not os.path.exists(doc_path):
                print(f"File not found: {doc_path}")
                continue
                
            try:
                if doc_path.lower().endswith('.pdf'):
                    docs = self.extract_text_with_ocr(doc_path)
                        
                elif doc_path.lower().endswith('.txt'):
                    loader = TextLoader(doc_path, encoding='utf-8')
                    docs = loader.load()
                else:
                    print(f"Unsupported file type: {doc_path}")
                    continue
                
                # Check content
                if docs:
                    total_chars = sum(len(doc.page_content) for doc in docs)
                    if total_chars == 0:
                        print(f"No content extracted from: {doc_path}")
                        continue
                
                all_docs.extend(docs)
            except Exception as e:
                print(f"Error processing {doc_path}: {e}")
                continue
        
        if not all_docs:
            raise ValueError("No documents found to process")
        
        return all_docs
    
    def build_and_upsert(self) -> PineconeVectorStore:
        """Build vector database: load PDFs, OCR, chunk, embed, and upsert to Pinecone"""
        print("=" * 60)
        print("Starting document ingestion pipeline...")
        print("=" * 60)
        
        print("\n[1/3] Loading documents...")
        all_docs = self.load_documents()
        print(f"Total documents loaded: {len(all_docs)}")
        
        print("\n[2/3] Chunking documents...")
        splits = self.chunk_documents(all_docs)
        
        if not splits:
            raise ValueError("Cannot create chunks from documents")
        
        print(f"\n[3/3] Embedding and upserting {len(splits)} chunks to Pinecone...")
        
        ids = [
            make_id(
                doc.metadata.get("source", "unknown"),
                doc.metadata.get("page", 0),
                doc.metadata.get("chunk_id", i)
            )
            for i, doc in enumerate(splits)
        ]
        
        vectorstore = PineconeVectorStore.from_documents(
            documents=splits,
            embedding=self.embeddings,
            ids=ids,
            index_name=self.index_name
        )
        
        print("\n" + "=" * 60)
        print("✓ Vector database built successfully!")
        print(f"✓ Index: {self.index_name}")
        print(f"✓ Total chunks: {len(splits)}")
        print("=" * 60)
        
        return vectorstore
    
    def add_text_to_db(self, text_content: str, source_name: str = "manual_entry", metadata: dict = None) -> dict:
        """Add text content directly to existing vector database

        """
        if not text_content or not text_content.strip():
            return {"status": "error", "message": "Text content is empty"}
        
        try:
            # Prepare metadata
            doc_metadata = {
                "source": source_name,
                "file_name": source_name,
                "type": "manual_entry",
                "added_by": "builder",
                "text_length": len(text_content)
            }
            if metadata:
                doc_metadata.update(metadata)
            
            # Create document
            doc = Document(
                page_content=text_content,
                metadata=doc_metadata
            )
            
            # Chunk if text is long (threshold = chunk_size = 800)
            if len(text_content) > 800:
                chunks = self.chunk_documents([doc])
            else:
                chunks = [doc]
                doc.metadata["chunk_id"] = 0
            
            # Generate deterministic IDs
            ids = [
                make_id(
                    chunk.metadata.get("source", source_name),
                    chunk.metadata.get("page", 0),
                    chunk.metadata.get("chunk_id", i)
                )
                for i, chunk in enumerate(chunks)
            ]
            
            # Add to vector store
            vectorstore = PineconeVectorStore(
                index_name=self.index_name,
                embedding=self.embeddings
            )
            vectorstore.add_documents(chunks, ids=ids)
            
            return {
                "status": "success",
                "message": f"Added {len(chunks)} chunk(s) from '{source_name}'",
                "chunks_added": str(len(chunks)),
                "source": source_name
            }
        except Exception as e:
            return {"status": "error", "message": f"Failed to add: {str(e)}"}


if __name__ == "__main__":
    # Build vector database
    builder = DocumentBuilder()
    builder.build_and_upsert()
    print("\nDone.")
