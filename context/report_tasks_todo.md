# Công Việc Cần Làm Thêm Cho Báo Cáo

## 1. Đánh Giá Khả Năng Reverse Engineering Explain

### 1.1 Thiết kế Experiment
**Mục tiêu**: So sánh hiệu quả AI-assisted vs manual reverse engineering

**Cần làm**:
- [ ] Chọn N functions từ target binary (đề xuất: 10-15 functions)
  - Tiêu chí chọn: Độ phức tạp đa dạng (simple/medium/complex)
  - Đảm bảo representative của codebase
- [ ] Định nghĩa tasks cụ thể cho mỗi function:
  - Task 1: Identify function purpose
  - Task 2: Rename variables/parameters
  - Task 3: Add comments explaining logic
  - Task 4: Identify potential bugs/issues
- [ ] Thiết kế rubric đánh giá:
  - Rename accuracy: % correct names (verified by expert)
  - Comment quality: Usefulness score (1-5 scale)
  - Comprehension: Quiz questions về function behavior
  - Time efficiency: Minutes to complete all tasks

### 1.2 Thu Thập Dữ Liệu
**Cần làm**:
- [ ] **Manual baseline**: Tự thực hiện hoặc recruit 2-3 security researchers
  - Record time per function
  - Collect annotations (renames, comments)
  - Administer comprehension quiz
- [ ] **Basic AI baseline**: Upload code to LLM (Claude/GPT-4)
  - Simulate file upload limit (e.g., 5 files max)
  - Record time and quality
- [ ] **GĐ2 full system**: Use MCP + RAG integration
  - Record time and quality
  - Track RAG queries made

### 1.3 Phân Tích Kết Quả
**Cần làm**:
- [ ] Statistical analysis:
  - T-test for time differences
  - Inter-rater reliability for quality scores
  - Correlation: time vs quality
- [ ] Qualitative analysis:
  - Case studies: Where GĐ2 excels/fails
  - User feedback: Usability, trust, workflow integration

**Estimated effort**: 2-3 weeks (experiment design + data collection + analysis)

---

## 2. Đánh Giá Chất Lượng RAG Retrieval

### 2.1 Xây Dựng Test Query Set
**Mục tiêu**: Tạo benchmark queries với ground truth

**Cần làm**:
- [ ] Tạo 3 loại queries (đề xuất: 30-50 queries total):
  - **Semantic queries** (15-20): "buffer overflow in memcpy", "race condition in IPC"
  - **Identifier queries** (10-15): "vdshmem_vwrite function", "QNX_MSG_PULSE struct"
  - **Mixed queries** (10-15): "QNX hypervisor IPC mechanism", "shared memory vulnerability patterns"
- [ ] Annotate ground truth:
  - List relevant document IDs for each query
  - Rank relevance: Highly relevant / Relevant / Marginally relevant
  - Source: Manual inspection of rag_docs/

### 2.2 Implement Evaluation Script
**Cần làm**:
- [ ] Script để run queries trên cả GĐ1 và GĐ2:
  ```python
  # evaluation/rag_retrieval_eval.py
  def evaluate_retrieval(queries, ground_truth, mode='gd2'):
      results = []
      for query in queries:
          retrieved = retriever.query(query, k=10)
          precision_at_k = compute_precision(retrieved, ground_truth[query])
          recall = compute_recall(retrieved, ground_truth[query])
          mrr = compute_mrr(retrieved, ground_truth[query])
          results.append({...})
      return aggregate_metrics(results)
  ```
- [ ] Metrics implementation:
  - Precision@k (k=1,3,5,10)
  - Recall
  - MRR (Mean Reciprocal Rank)
  - NDCG (Normalized Discounted Cumulative Gain)

### 2.3 Run Experiments & Analyze
**Cần làm**:
- [ ] Run evaluation on GĐ1 mode:
  - Set `RAG_MODE='gd1'` in config
  - Collect metrics
- [ ] Run evaluation on GĐ2 mode:
  - Default hybrid retrieval
  - Collect metrics
- [ ] Statistical comparison:
  - Paired t-test for metric differences
  - Query type breakdown (semantic vs identifier vs mixed)
- [ ] Ablation study (optional):
  - GĐ2 dense-only (disable BM25)
  - GĐ2 BM25-only (disable dense)
  - Quantify hybrid contribution

**Estimated effort**: 1-2 weeks (query set creation + implementation + analysis)

---

## 3. Vulnerability Analysis Evaluation (Đã Có Framework)

### 3.1 Kiểm Tra Hiện Trạng
**Cần làm**:
- [ ] Review `evaluation/` folder:
  - Check intake cases: Đủ đa dạng chưa? (buffer overflow, race condition, integer overflow, etc.)
  - Check judge model: Rubric có comprehensive chưa?
  - Check artifacts: Results đã được generate chưa?

### 3.2 Bổ Sung (Nếu Cần)
**Cần làm**:
- [ ] Nếu chưa có results:
  - Run `evaluation/compare_mode.py` trên all intake cases
  - Generate judge packets, scores, rankings
- [ ] Nếu test cases ít:
  - Add more diverse bug cases (đề xuất: 15-20 cases minimum)
- [ ] Statistical analysis:
  - Aggregate scores across cases
  - Compute confidence intervals
  - Significance tests

**Estimated effort**: 1 week (nếu framework đã sẵn, chỉ cần run + analyze)

---

## 4. Biểu Đồ và Visualization

### 4.1 Chuẩn Bị Dữ Liệu
**Cần làm**:
- [ ] Export results to CSV/JSON:
  - Vuln analysis: scores by mode, by case, by criteria
  - Rev explain: time, quality scores by mode
  - RAG retrieval: precision, recall, MRR by query type
- [ ] Organize data structure for plotting

### 4.2 Generate Charts
**Cần làm**:
- [ ] Python scripts (matplotlib/seaborn/plotly):
  - Bar charts: Accuracy, time comparisons
  - Line charts: Precision-recall curves
  - Box plots: Score distributions
  - Heatmaps: Query type vs method performance
  - Radar charts: Multi-criteria scores
- [ ] Export high-resolution images (PNG/PDF) for report

**Estimated effort**: 3-5 days

---

## 5. Viết Nội Dung Chi Tiết Cho Report

### 5.1 Chương 2: Cơ Sở Lý Thuyết
**Cần làm**:
- [ ] Literature review:
  - RAG papers: Lewis et al. (2020), recent surveys
  - Code embedding: CodeBERT, GraphCodeBERT papers
  - Hybrid retrieval: BM25+dense fusion methods
- [ ] Viết sections theo outline đã đề xuất
- [ ] Add citations (IEEE format)

**Estimated effort**: 1 week

### 5.2 Chương 5: Cải Tiến và Đánh Giá
**Cần làm**:
- [ ] Expand mỗi subsection với:
  - Problem statement (GĐ1 limitation)
  - Solution design (GĐ2 approach)
  - Implementation details (code snippets, architecture diagrams)
  - Rationale (why this approach)
- [ ] Add architecture diagrams:
  - GĐ1 vs GĐ2 comparison diagram
  - Hybrid retrieval flow diagram
  - Type-aware processing pipeline
  - Evaluation framework diagram
- [ ] Code snippets (nếu cần minh họa)

**Estimated effort**: 2 weeks

### 5.3 Chương 6: Kết Quả và Thảo Luận
**Cần làm**:
- [ ] Fill in actual numbers from experiments
- [ ] Write analysis paragraphs for each result section
- [ ] Discussion: Interpret results, explain why GĐ2 better/worse in specific cases
- [ ] Limitations: Honest assessment
- [ ] Future work: Concrete next steps

**Estimated effort**: 1 week (after experiments done)

---

## 6. Tổng Hợp Timeline

| Task | Estimated Effort | Priority |
|------|------------------|----------|
| 1. Rev Explain Evaluation | 2-3 weeks | HIGH (no data yet) |
| 2. RAG Retrieval Evaluation | 1-2 weeks | HIGH (no data yet) |
| 3. Vuln Analysis Check | 1 week | MEDIUM (framework exists) |
| 4. Visualization | 3-5 days | MEDIUM (after data ready) |
| 5. Chapter 2 Writing | 1 week | LOW (can parallelize) |
| 6. Chapter 5 Writing | 2 weeks | MEDIUM (after experiments) |
| 7. Chapter 6 Writing | 1 week | HIGH (final synthesis) |

**Total estimated time**: 6-8 weeks (with parallelization: 4-6 weeks)

**Critical path**: Rev Explain + RAG Retrieval evaluations → Results → Chapter 6

---

## 7. Câu Hỏi Cần Thảo Luận

1. **Rev Explain Evaluation**:
   - Có thể recruit được security researchers để làm manual baseline không?
   - Nếu không, có thể dùng chính bạn làm baseline (với time tracking cẩn thận)?
   - Số lượng functions: 10-15 có đủ representative không?

2. **RAG Retrieval Evaluation**:
   - Ground truth annotation: Tự làm hay cần inter-rater reliability (2+ annotators)?
   - Query set size: 30-50 queries có đủ không?
   - Có cần ablation study (dense-only, BM25-only) hay chỉ so sánh GĐ1 vs GĐ2?

3. **Vuln Analysis**:
   - Evaluation framework hiện tại đã chạy chưa? Có results chưa?
   - Số lượng test cases hiện tại: bao nhiêu? Có cần thêm không?

4. **Timeline**:
   - Deadline nộp report: khi nào?
   - Có thể parallelize tasks không (e.g., viết Chapter 2 trong khi chạy experiments)?

---

## 8. Next Steps

1. **Immediate**: Thảo luận 4 câu hỏi trên để clarify approach
2. **Week 1-2**: Start Rev Explain evaluation (design + pilot)
3. **Week 2-3**: Start RAG Retrieval evaluation (query set + implementation)
4. **Week 3-4**: Run experiments, collect data
5. **Week 4-5**: Analysis + visualization
6. **Week 5-6**: Write Chapters 5-6 with actual results
7. **Week 6+**: Polish, review, finalize

**Recommendation**: Prioritize experiments first (Tasks 1-3), then writing can proceed with concrete data.
