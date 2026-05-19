# Overall

**Target**: Build an AI system to support vuln searching on no-source product.

- **Reverse** → connect external tool via MCP to reverse target binaries
- **Explain** → refactor (rename/comment) rev result for human reading
- **Analyse** → search for vuln and suggest attack surfaces (for fuzzing) on rev result, supported by efficient prompting and knowledge in a self-built RAG connected via MCP

## Nhiệm vụ GĐ2

### Data flow analysis

- data flow + control flow diagram cho 2 cơ chế IVC
- xác định các giả thuyết lỗ hổng dựa trên kết quả dịch ngược gđ1 → danh sách attack surface
- nếu có lỗ hổng, viết PoC → PoC + demo

### Fuzzer development

- thiết kế và build fuzzer → tool + demo

### Fuzzing and debugging

- viết các ứng dụng đơn giản chạy trong QNX guest để mô phỏng IVC trực quan hơn (demo hiện tại đang dựa trên file shmem-test có sẵn và ping) → demo
- gắn GDB vào tiến trình qvm trên QNX host → demo
- chạy fuzzer trên các mục tiêu đã chọn (theo thứ tự ưu tiên). Nếu có crash, dùng GDB phân tích nguyên nhân → report

### AI-tool improvement + evaluation

- kế hoạch đánh giá hiệu quả LLM trong phân tích an ninh → khung tiêu chí đánh giá, cách thu thập số liệu và tính toán kết quả
- nạp thêm kiến thức (data flow diagram, CVE, docs) vào LLM để yêu cầu đề xuất các attack surface tiềm năng → danh sách attack surface
- so sánh và đánh giá kết quả đạt được dưới sự hỗ trợ của AI → bảng đánh giá chi tiết

## Ý tưởng GĐ2 cho phần AI-tool

### Xác định mục tiêu

- GĐ1: hệ thống RAG hỗ trợ quá trình tìm hiểu và dịch ngược QH
    - Claude với prompt hướng dẫn quy trình sử dụng đến các công cụ bên ngoài thông qua MCP (RAG, IDA)
    - IDA cung cấp thông tin metadata + decompiled cho binary mục tiêu
    - RAG cung cấp các chunk thông tin phù hợp từ database chứa knowledge về QNX Hypervisor và xử lí các knowledge mới được thêm vào
- GĐ2: hệ thống RAG hỗ trợ phân tích lỗ hổng trong cơ chế IVC của QH
- Các giai đoạn chính trong hệ thống RAG
    - tìm kiếm/tạo ra knowledge
    - xử lí knowledge để lưu vào DB
    - truy xuất knowledge phù hợp với mục đích
    - phân tích/suy luận dựa trên knowledge từ RAG và model

### Cải tiến hệ thống RAG cho GĐ2

- cần knowledge gì cho phù hợp?
    1. Context: QNX Hypervisor docs, Rev of IVC binaries.
    2. Vulnerability Pattern: vulnerability pattern card
    3. Heuristic (optional): tư duy bug hunter
        - loại biến này thường map với vuln nào nếu bị kiểm soát
        - lưu ý các cặp Sink & Source**:** "Source" là bất kỳ vùng nhớ shmem nào Guest có quyền ghi, và "Sink" là các hàm `memcpy`, `malloc`, hoặc pointer dereference bên trong `qvm`.
- xử lí knowledge vào DB như nào cho hiệu quả?
    - phân chunk size như thế nào thì các knowledge có ý nghĩa độc lập cũng phải đảm bảo trong khoảng đó
- truy xuất knowledge như nào cho hiệu quả?
    - xác định max context windows của Claude
    - knowledge lv1 nên truy xuất theo tên
    - knowledge lv2+3 nên truy xuất hết
- phân tích/suy luận như nào? (khảo sát các phương pháp Prompt engineering và chọn các kĩ thuật phù hợp nhất)
    - Chain of thought prompting
        1. Lấy Decompiled từ IDA
        2. RAG lv1 → Xác định: entry point, functions, data structure
        3. Với mỗi entry point, phân tích data flow: data từ guest đi từ đâu → validata → use
        4. RAG lv2 → Đối chiếu với vuln patterns và đề xuất giả thuyết
        5. Đánh giá và ranking các giả thuyết

### Đánh giá kết quả cải tiến về khả năng phân tích vuln trên các binary nhỏ

- LV1: source
- LV2: no source
- Đánh giá output
    
    
    | ID | Mô tả tiêu chí | Trọng số |
    | --- | --- | --- |
    | 1 | LLM mô tả đúng chức năng của function/binary, nhận diện đúng component/context (vd: shmem vdev, virtqueue, MMIO handler…) | 1 |
    | 2 | Chỉ ra fields nào guest-controlled (Source) | 2 |
    | 3 | Trace data flow từ guest input → dangerous operation (Source → Sink) | 3 |
    | 4 | Nêu giả thuyết lỗ hổng | 3 |
    | 5 | Giải thích mechanism bug (tại sao bug xảy ra, root-cause) | 2 |
    | 6 | Chỉ đúng dòng/function chứa bug | 2 |
    | 7 | Reference CVE tương tự hoặc vuln pattern đã biết (RAG) | 2 |
    | 8 | Mô tả cách trigger bug + PoC concept | 2 |
    | 9 | Phân loại đúng mức impact (DoS / Info leak / Memory corruption / Escape) | 2 |
    | 10 | False positive thấp (finding có thể verify được) | 2 |
- Đánh giá độ hiệu quả trong việc cải tiến hệ thống → Chạy cùng 1 binary qua 2 config rồi đánh giá số tiêu chí đạt được
    - Config A: Claude + code (source/decompiled) + tầng 1 (Context)
    - Config B: Claude + code (source/decompiled) + 3 tầng

### Áp dụng phân tích và đề xuất các attack surface cho QNX Hypervisor

- Input: QNX vdev binaries
- Expected: LLM đề xuất attack surfaces, giả thuyết lỗ hổng, fuzzing targets
- Metric: Tỷ lệ attack surfaces được xác nhận qua manual review / fuzzing results

### Góp ý của giảng viên về nội dung báo cáo

- so sánh với các cách tiếp cận prompt engineering khác → chốt 1 phương án cuối
- chia thành các research question → pipeline task cụ thể → khó khăn xảy ra → giải pháp → kết quả → đánh giá
- quan hệ giữa các bài toán