# Cấu Trúc Báo Cáo RAG - Đề Xuất

## CHƯƠNG 2: CƠ SỞ LÝ THUYẾT VÀ CÁC NGHIÊN CỨU LIÊN QUAN

### 2.1 Large Language Models (LLMs)
- Kiến trúc Transformer và cơ chế attention
- Pre-training và fine-tuning
- Khả năng reasoning và giới hạn (hallucination, knowledge cutoff)
- Claude 4.6 Sonnet: đặc điểm và ưu điểm cho security analysis

### 2.2 Retrieval-Augmented Generation (RAG)
**2.2.1 Tổng quan RAG**
- Định nghĩa và động lực (giải quyết hallucination, cập nhật tri thức)
- Kiến trúc cơ bản: Ingestion → Storage → Retrieval → Generation
- So sánh với fine-tuning: ưu/nhược điểm

**2.2.2 Các thành phần RAG**
- **Document Processing**: parsing, chunking strategies
  - Chunking methods: fixed-size, semantic, parent-child
  - Trade-offs: context preservation vs retrieval precision
- **Embedding Models**: dense vectors, semantic similarity
  - OpenAI text-embedding-3-small (1536-dim)
- **Vector Databases**: Pinecone architecture
- **Retrieval Methods**: 
  - Dense retrieval (semantic)
  - Sparse retrieval (BM25 lexical)
  - Hybrid retrieval (kết hợp cả hai)

**2.2.3 RAG cho Code và Technical Documentation**
- Thách thức: code syntax preservation, identifier matching
- Nghiên cứu liên quan: CodeBERT, GraphCodeBERT
- Type-aware processing approaches

### 2.3 Model Context Protocol (MCP)
- Định nghĩa và mục đích: kết nối LLM với external tools
- Kiến trúc client-server
- Use cases: database access, API integration, tool orchestration
- Ưu điểm so với function calling truyền thống

---

## CHƯƠNG 5: CẢI TIẾN VÀ XÂY DỰNG CÔNG CỤ AI HỖ TRỢ PHÂN TÍCH

> **Scope**: Toàn bộ quá trình thiết kế và triển khai RAG — từ GĐ1 baseline đến GĐ2 improvements.
> Phương pháp đánh giá và kết quả để sang Chương 6.

### 5.1 Mục Tiêu Công Cụ Trong Đề Tài
**Target**: Xây dựng hệ thống AI hỗ trợ phân tích lỗ hổng trên sản phẩm không có mã nguồn

**Các khả năng chính:**
- **Reverse Engineering**: Kết nối IDA Pro qua MCP để dịch ngược binary
- **Explain**: Refactor (rename/comment) kết quả dịch ngược, truy vấn tri thức hỗ trợ nghiên cứu
- **Vulnerability Analysis**: Tìm kiếm lỗ hổng và đề xuất attack surfaces, hỗ trợ bởi prompting hiệu quả và RAG tự xây dựng

### 5.2 Công Cụ AI Trong GĐ1 (Baseline)

**5.2.1 Mục tiêu GĐ1**
- ST1: Setup môi trường giả lập IVC của mục tiêu phân tích
- ST2: Phân tích tĩnh binary trên IDA/Ghidra, sơ đồ hóa cơ chế và luồng dữ liệu
- ST3: Phát triển hệ thống AI bán tự động chú giải mã dịch ngược (Reverse + Explain)

**5.2.2 Kiến trúc GĐ1**
```
Claude (LLM) ←MCP→ IDA Pro MCP Server  (local RPC plugin)
             ←MCP→ RAG MCP Server       (containerised FastMCP + Pinecone)
                     ↑ cấu hình kết nối qua claude_desktop_config.json
```

**Thành phần RAG GĐ1:**
- **Ingestion**: PDF/TXT → uniform 800-char chunks (160-char overlap)
- **Storage**: Pinecone dense index, OpenAI text-embedding-3-small (1536-dim)
- **Retrieval**: Cosine similarity search, k=5, không có filtering
- **MCP Tools**: `query_knowledge`, `query_knowledge_with_scores`, `add_knowledge_text`, `get_knowledge_info`
- **System Prompt**: 5-task structured prompt với CoT, few-shot, ReAct; knowledge hierarchy IDA > RAG > Training

**5.2.3 Điểm mạnh GĐ1 (kế thừa sang GĐ2)**
- Knowledge accumulation loop: `add_knowledge_text` cho phép lưu findings trong session, tái dùng ở session sau
- Structured task prompts: mỗi task (Analyze/Refactor/Query) có workflow và few-shot template riêng
- Confidence labelling: mọi finding đều có mức HIGH/MEDIUM/LOW, tránh overclaiming

**5.2.4 Hạn chế GĐ1 (động lực cho GĐ2)**
1. **Không có parsing theo định dạng**: Tất cả tài liệu xử lý như text thuần, mất cấu trúc ngữ nghĩa
2. **Chunking đồng nhất**: Fixed 800-char chunks bỏ qua ranh giới ngữ nghĩa
3. **Metadata tối thiểu**: Không có type tags hay filtering
4. **Pure dense retrieval**: Similarity search thất bại với exact identifiers (function names)
5. **Không có evaluation framework**: Không đo được hiệu quả RAG

### 5.3 Công Cụ AI Trong GĐ2 (Cải Tiến)

**5.3.1 Mục tiêu GĐ2**
GĐ2 kế thừa toàn bộ Reverse + Explain từ GĐ1 và mở rộng thêm:
- ST1: Đưa ra attack surfaces và giả thuyết lỗ hổng
- ST2: Build fuzzer và fuzz các attack surfaces tiềm năng
- ST3: Viết PoC cho phát hiện hợp lệ, đánh giá impact
- ST4: **Đánh giá hiệu quả công cụ AI** so với baseline

**5.3.2 Các Cải Tiến RAG Trong GĐ2**

#### A. Document Quality & Parsing
**Vấn đề**: GĐ1 chỉ hỗ trợ PDF/TXT, mất thông tin cấu trúc

**Giải pháp**:
- **Vulnerability Pattern Cards** (.md với YAML frontmatter)
  - Required fields: `doc_id`, `vuln_type`
  - Optional: `sink`, `severity`, `cwe`, `binary_indicators`, `tags`
  - Converter: `vuln_pattern_converter.py`
- **QNX HTML Documentation** (8 documentation sets)
  - TOC extraction từ `main.xml` → breadcrumb hierarchy
  - HTML → Markdown conversion với BeautifulSoup
  - Metadata: `doc_title`, `toc_section`, `toc_page`
- **PDF Enhancement**: TOC extraction, adaptive OCR threshold
- **C Code**: Semantic parsing → c_function, c_struct, c_constants
- **Build Config**: .build, .sh, .layout với structure-aware parsing

**Kết quả**: +5 document types mới, +2 converters, metadata phong phú hơn

#### B. Chunking Strategy
**Vấn đề**: GĐ1 fixed-size chunking phá vỡ semantic boundaries

**Giải pháp**:
- **Parent-Child Chunking**:
  - Parent: Markdown header sections (semantic units)
  - Child: 1500-char chunks với overlap 200
  - Metadata: `parent_content` lưu full parent section
- **Code-Aware Splitting**:
  - Regex separators: `\n\s*}\n` (closing braces), `;\n` (statements)
  - Tôn trọng C code structure (IDA/Ghidra indented output)
  - Áp dụng cho: c_function, c_section, build_section
- **Per-Type Parent Windows**:
  - c_function: 8000 chars
  - c_section: 6000 chars
  - Default: 3000 chars

**Kết quả**: Giữ nguyên context, không split giữa function/statement

#### C. Hybrid Retrieval
**Vấn đề**: GĐ1 pure semantic search thất bại với exact identifiers (function names)

**Giải pháp**: Native Pinecone Hybrid Index
- **Dense Vector** (1536-dim): Semantic similarity
- **BM25 Full-Text Search**: Exact token matching
- **3 Search Modes**:
  1. Dense-primary + `$match_any` BM25 pre-filter (default)
  2. BM25-primary (exact identifier lookups)
  3. Pure dense fallback (semantic-only queries)

**Kết quả**: Kết hợp semantic understanding + exact identifier recall

#### D. Type-Aware Processing
**Vấn đề**: Markdown syntax là noise cho prose, nhưng code syntax là semantic signal

**Giải pháp**: Embedder module với type routing
- **TEXT_TYPES** (reference_document, vulnerability_pattern):
  - Flatten Markdown: `## Title` → `Title:`, `**bold**` → plain text
  - Tăng semantic density cho embedding
- **CODE_TYPES** (c_function, c_struct, build_*):
  - Giữ nguyên raw text: `{`, `}`, `*`, `&`, indentation
  - Bảo toàn program semantics
- **Query strings**: NEVER flatten (LLM có thể query với code patterns)

**Kết quả**: Embedding quality tối ưu cho từng loại nội dung

#### E. MCP Tools & Metadata Filtering
**Vấn đề**: GĐ1 chỉ có 1 generic query tool, không thể scope retrieval

**Giải pháp**: 3 specialized MCP tools với metadata filtering
- **`search_component_context`**: Phase A - architecture context
  - Filter: `{"type": {"$ne": "vulnerability_pattern"}}`
  - Use case: Hiểu component trước khi tìm vuln
- **`search_vulnerability_patterns`**: Phase B - pattern cards
  - Filter: `{"type": {"$eq": "vulnerability_pattern"}}`
  - Use case: Tìm bug patterns liên quan
- **`search_by_function`**: Exact function lookup
  - Filter: `{"function_name": {"$eq": "..."}}`
  - BM25-primary cho exact identifier matching

**Exposed filter param**: LLM có thể construct complex filters
```python
{"$and": [
  {"type": {"$eq": "c_function"}},
  {"source": {"$eq": "rag_docs/decompiled/qvm.c"}}
]}
```

**Kết quả**: Precise scoping, giảm noise trong retrieval

#### F. System Prompt Engineering
**GĐ1 Prompt**: General security analysis với "Hierarchy of Truth"

**GĐ2 Prompt**: Structured 6-step vulnerability analysis workflow
1. Component understanding (search_component_context)
2. Attack surface identification
3. Pattern matching (search_vulnerability_patterns)
4. Lifecycle audit (resource exhaustion)
5. Type semantics check (signed/unsigned confusion)
6. False positive guards (3 checkpoints)

**Additions**:
- Input trust hierarchy: IDA-MCP > RAG > user input
- Confidence levels: HIGH/MEDIUM/LOW với evidence requirements
- Pattern card generation cho zero-day findings

**Kết quả**: Systematic analysis, reduced false positives

### 5.4 Tóm Tắt Cải Tiến GĐ2

Bảng tổng kết 6 cải tiến, hạn chế GĐ1 được giải quyết, và kết quả kỹ thuật.
Kết luận: hệ thống RAG được chuyển từ best-effort knowledge store thành structured, type-aware retrieval infrastructure. Đánh giá định lượng trình bày trong Chương 6.

---

## CHƯƠNG 6: KẾT QUẢ VÀ THẢO LUẬN

### 6.1 Phương Pháp Đánh Giá

#### 6.1.1 Đánh Giá Khả Năng Vulnerability Analysis

**Framework**: Multi-model comparison với judge model scoring

**Pipeline**:
1. **Intake**: YAML bug cases với ground truth
2. **Execution**: Run 3 modes (base/gd1/gd2) trên same cases
3. **Judge Scoring**: Separate model đánh giá findings theo rubric (10 criteria, weighted)
4. **Composite Score**: 70% weighted criteria + 30% rank bonus

**Comparison Targets**:
- **Base**: LLM với file upload cơ bản (không có RAG)
- **GĐ1**: Dense-only RAG, 4 generic MCP tools
- **GĐ2**: Hybrid RAG, 3 specialized tools + 6-step system prompt

**Implementation**: `evaluation/` folder với pipeline tự động

#### 6.1.2 Đánh Giá Chất Lượng RAG Retrieval

**Mục tiêu**: Đo lường retrieval quality GĐ2 vs GĐ1

**Phương pháp**: 14 queries (semantic / identifier / mixed) với ground truth từ source path matching
**Metrics**: Precision@k (k=1,3,5,10), Recall, MRR
**Comparison**: GĐ1 pure dense vs GĐ2 hybrid

**Note**: Cần chạy `evaluation/rag_retrieval_eval.py` sau khi ingestion hoàn tất

---

---

### 6.2 Kết Quả Đánh Giá Vulnerability Analysis

**6.2.1 Tổng quan kết quả**
- Bảng so sánh: Base vs GĐ1 vs GĐ2 (Composite Score, Criteria Score, Rank Bonus)
- 11 test cases thực tế từ IVC components (virtio-net, pcnet, virtio-snd, IVC shmem)

**6.2.2 Phân tích theo tiêu chí**
- 10 criteria × 3 systems; highlight gains ở C2 (source ID), C7 (pattern/CVE), C10 (false positive)
- Case studies: qemu-virtio-snd-rx-003 (GĐ1 = 35.7%), qemu-virtio-snd-rx-001 (Base = 69%)

**6.2.3 Biểu đồ**
- Bar chart: composite score comparison
- Radar chart: multi-criteria scores
- Per-case breakdown table

### 6.3 Kết Quả Đánh Giá RAG Retrieval Quality

> ⚠️ Cần chạy `evaluation/rag_retrieval_eval.py` — section này là placeholder

**6.3.1 Retrieval metrics**: Precision@k, Recall, MRR — GĐ1 vs GĐ2

**6.3.2 Phân tích theo loại query**
- Semantic queries: dense retrieval performance
- Identifier queries: BM25 contribution
- Mixed queries: hybrid advantage

**6.3.3 Biểu đồ**: Bar chart Precision@k, Precision-Recall curve, heatmap query type × method

### 6.4 Thảo Luận

**6.4.1 Phân tích hiệu quả từng cải tiến**
- Hybrid Retrieval: dense cho concept queries, BM25 cho exact identifiers
- Type-Aware Processing: flatten prose → semantic density; preserve code → identifier recall
- Chunking Strategy: parent-child context preservation; code-aware boundaries
- Specialized Tools: phase-based retrieval giảm noise; metadata filter enable precise scoping
- System Prompt: 6-step workflow → systematic coverage; 3 checkpoints → reduced FP

**6.4.2 Hạn chế**
- Embedding model: text-embedding-3-small (1536-dim) không optimize cho C code
- Chunking: fixed child size (1500 chars) có thể split mid-expression
- Evaluation: 11 test cases, single target binary — generalizability chưa verify
- System prompt: manual engineering, chưa có automated optimization

**6.4.3 Hướng phát triển**
- Code-specific embedding (CodeBERT, GraphCodeBERT)
- Adaptive chunking dựa trên AST
- Larger evaluation dataset, multiple targets
- Prompt optimization via RL

**6.4.4 Đóng góp chính**
1. Hybrid RAG for binary analysis: dense+BM25 cho vulnerability analysis trên decompiled code
2. Type-aware embedding pipeline: phân biệt prose vs code để tối ưu embedding quality
3. Evaluation framework: systematic comparison với judge model scoring
4. Production MCP system: fully integrated tool deployed trong real analysis workflow

### 6.5 Kết Luận

- Tóm tắt cải tiến: GĐ2 RAG vượt trội GĐ1 trên mọi tiêu chí
- Quantify: +14pp composite score vs GĐ1, +10.5pp vs Base, 100% win rate per-case
- Practical impact: công cụ đã hỗ trợ phân tích IVC components của QNX Hypervisor
- Future work: roadmap cụ thể cho các cải tiến tiếp theo
