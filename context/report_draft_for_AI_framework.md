# Preliminaries

## Large Language Models (LLMs)

### Definition and Capabilities

- Operate as next-token predictors that generate text based on probability distributions.
- Provide valuable assistance in code comprehension, semantic annotation, and vulnerability hypothesis generation.

### Limitations Relevant to Security Analysis

(trình bày các hạn chế theo hướng mà đề tài này đã giải quyết được)

## Retrieval-Augmented Generation (RAG)

### Definition and Capabilities

- Mitigates hallucinations and enables dynamic knowledge updates without expensive retraining.
- The pipeline consists of four sequential phases: Ingestion, Storage, Retrieval, and Generation.

### Architecture

(hình minh họa, đã có)

Kiến trúc phổ biến là 1 công cụ có khả năng xử lí, chuyển đổi dữ liệu thành các vector để lưu trữ vào 1 DB để truy xuất có hiệu quả các vector (liên kết với cụm dữ liệu) tương đồng về mặt ngữ nghĩa hoặc từ vựng với câu truy vấn cần bổ sung context

Các pipeline chính

- Ingestion
    - Parsing
    - Chunking
    - Embedding (into dense / sparse vector)
    - Upserting with metadata (vd: doc_id, text)
- Retrieval
    - Query rewrite (for effective embedding)
    - Searching
    - Responding (result can be aggregrated/filtered/formated before return to LLM)

## Model Context Protocol (MCP)

### Definition and Capabilities

- A standardized protocol connecting LLMs to external tools, decoupling models from bespoke integrations.
- Advantages over Traditional Function Calling

### Architecture

(hình minh họa, đã có)

- Comprises an MCP Host, Client, and Server that expose specific Resources, Tools, and Prompts

---

# AI-Augmented Vulnerability Analysis Framework

## Tool objectives

Để đáp ứng yêu cầu hỗ trợ Vulnerability analysis của đề tài, framework này được xây dựng với 3 mục tiêu chính như sau:

- O1: Truy vấn kiến thức về mục tiêu (QNX Hypervisor)
- O2: Tự động việc chú thích mã decompile
- O3: Phân tích và đề xuất các lỗ hổng tiềm năng để tập trung testing/fuzzing sâu hơn để xác minh

## Architecture

(hình ảnh kiến trúc hệ thống, đã có)

Framework bao gồm thành phần cốt lõi là 1 LLM model mạnh về suy luận và đọc hiểu mã được tích hợp 2 công cụ với khả năng chuyên biệt:

1. Công cụ dịch ngược có khả năng decompile file mã nhị phân của mục tiêu cần phân tích. Cụ thể trong đề tài này là file qvm (khởi tạo và quản lí máy ảo) và các file vdev của cơ chế IVC (vdev-shmem.so, vdev-virtio-net.so, vdev-virtio-blk.so)
2. Công cụ hỗ trợ lưu trữ và truy xuất các tri thức liên quan đến mục tiêu

LLM sẽ kết nối và giao tiếp với các công cụ qua MCP - một giao thức chuẩn được tạo ra dành cho việc mở rộng khả năng của các AI model.

Kiến trúc này sẽ giải quyết 3 mục tiêu đã đề ra như sau:

- O1 được giải quyết thông qua công cụ RAG có khả năng lưu trữ và truy xuất 1 cách hiệu quả dựa trên tính chất của các tài liệu được tổng hợp, và cung cấp các tính năng đó cho LLM qua giao thức MCP
- O2 được giải quyết thông qua công cụ dịch ngược được cộng đồng đánh giá cao, có thể an tâm về chất lượng mã decompile, công cụ này phải có tính năng hoặc cho phép phát triển plugin để cung cấp khả năng truy xuất thông tin mã và refactor (rename/comment) lên mã đó để hỗ trợ người dùng trong quá trình đọc hiểu và phân tích tĩnh cơ chế hoạt động.
- O3 được giải quyết thông qua system prompt được thiết kế theo các kĩ thuật prompting có hiệu quả đã được nghiên cứu để hướng dẫn LLM phối hợp sử dụng các công cụ cho việc phân tích lỗ hổng và hỗ trợ các yêu cầu có liên quan của người dùng.

## LLM Component

Phần này giới thiệu ngắn gọn về Claude và giải thích vì sao chọn Claude làm thành phần LLM cho framework, trong đó model Claude 4.6 sẽ được chọn làm model chính cho các tác vụ thông thường và trong phần evaluation

Có thể giải thích theo các ý sau (mở rộng thêm nếu có)

- Claude là có thể xem là 1 trong các mô hình mạnh nhất hiện tại về khả năng suy luận và đọc hiểu mã
- Claude Desktop cho phép tích hợp các công cụ bên ngoài thông qua MCP
- Claude cho phép cấu hình system prompt thông qua tính năng Project và kích hoạt nhanh các MCP tool và tool prompt (các prompt có sẵn được cung cấp bởi MCP server cho các tác vụ nhất định mà tool đó hỗ trợ)

So sánh các khía cạnh nổi bật này với các model khác như Gemini, GPT, Ollama,… để thể hiện sự lựa chọn đã qua quá trình cân nhắc kĩ càng.

## Decompiler Component

Phần này giới thiệu ngắn gọn về IDA và giải thích vì sao chọn IDA làm thành phần Decompiler cho framework.

Đây là lí do thật sự của tôi khi chọn IDA:

- Tôi đã sử dụng qua IDA like fixed-size, semantic, or parent-child., Binary Ninja và Ghidra trước đó để dịch ngược các binary khi tham gia các giải CTF
- IDA và Binary Ninja có giao diện thân thiện và dễ sử dụng hơn vì là phần mềm thương mại, còn Ghidra là open source
- Cả 3 công cụ này đều không có tính năng MCP tích hợp sẵn như Claude nhưng cho phép tích hợp qua các plugin tự viết hoặc từ cộng đồng chia sẻ. Cả 3 công cụ đều có sẵn plugin MCP từ cộng đồng và các tính năng plugin này cung cấp đã đủ nhu cầu cho mục tiêu của tôi. Tuy nhiên các plugin đều là open-source nên dễ dàng customize để mở rộng nếu cần.
- Binary Ninja và IDA thì tôi đều có license nhưng plugin của Binary Ninja lại không chạy được vì lí do nào đó, nên cuối cùng tôi lựa chọn IDA. Ghidra vẫn là 1 lựa chọn tốt nếu quen sử dụng. Nói dung việc lựa chọn decompiler không ảnh hưởng đến framework vì các công cụ đều được kết nối qua 1 giao thức chuẩn, không phụ thuộc vào tool nên việc mở rộng, thay đổi rất dễ dàng.

Theo tôi, bạn có thể trình bày cả 3 như các option để lựa chọn và dẫn link MCP plugin tương ứng nếu như không thể chứng minh thuyết phục rằng IDA là lựa chọn tốt nhất cho framework này.

(1-2 hình ảnh về việc kết nối, đặt câu hỏi và yêu cầu refactor file đang mở trong IDA)

## RAG Component

Để xây dựng 1 RAG có hiệu quả, ta sẽ chia thành các bài toán nhỏ bằng cách phân tích và giải quyết tốt giai đoạn chính đã đề cập ở phần Premilinaries/RAG/Architecture.

### Documents

Đây là bài toán quan trọng nhất vì chất lượng của câu trả lời phụ thuộc vào nó. Các dữ liệu được đưa vào RAG phải đảm bảo tính chính xác và hỗ trợ tốt về mặt thông tin cho mục tiêu truy vấn. Các tài liệu được tổng hợp và phân loại thành các thư mục như sau nhằm hỗ trợ cho giai đoạn parsing.

| Thư mục | Số lượng file | Nguồn gốc | Vai trò |
| --- | --- | --- | --- |
| `qnx-doc` |  |  |  |
| `vuln-pattern` |  |  |  |
| `decompiled` |  |  |  |
| `build-config` |  |  |  |
| `other` |  |  |  |

### Parsing

Để quá trình parsing đạt hiệu quả, ta sẽ phải xem xét tính chất của các tài liệu và đưa ra 1 phương án xử lí hiệu quả cho mỗi loại. Tuy nhiên nếu phải xem xét cho tất cả thì rất tốn thời gian, đặc biệt là đối với các loại tài liệu thư mục other, vì chúng được tổng hợp ngẫu nhiên từ nhiều nguồn và không có đặc điểm chung. Do đó tatext-embedding-3-small sẽ chỉ tập trung phân tích và xử lí đặc biệt cho 4 loại thư mục là qnx-doc, vuln-pattern, decompiled, build-config - đây cũng là các tài liệu có giá trị thông tin quan trọng cho RAG.

Đối với thư mục qnx-doc, các tài liệu có định dạng html với cấu trúc rõ ràng, ta sẽ …. (nói tiếp về cơ chế parsing sang định dạng md-yaml và vì sao cách parsing như thế này mang lại hiệu quả cho các giai đoạn tiếp theo)

Đối với thư mục vuln-pattern, các tài liệu được tổng hợp và soạn theo cấu trúc nhất định (định nghĩa trong file SPEC.md của thư mục) nên logic parsing cũng dựa vào đó. (nói tiếp về cơ chế parsing sang định dạng md-yaml và vì sao cách parsing như thế này mang lại hiệu quả cho các giai đoạn tiếp theo)

Đối với thư mục decompiled, đây là các file mã decompiled được tạo ra bởi IDA, sau đó sử dụng framework LLM-RAG-IDA được build đơn giản ở gd1 để refactor theo cấu trúc nhất quán với các block comment (defined trong [SPEC.md](http://SPEC.md) của thư mục) để parsing 1 cách đơn giản. (nói tiếp về cơ chế parsing sang định dạng md-yaml và vì sao cách parsing như thế này mang lại hiệu quả cho các giai đoạn tiếp theo)

Đối với thư mục build-config, đây là các file cấu hình mặc định để chạy host và guest os được QNX cung cấp sẵn trong thư mục qnx-710/bsp khi tải product xuống từ QNX Software Center, gồm các file .build, .sh và .layout. (nói tiếp về cơ chế parsing sang định dạng md-yaml và vì sao cách parsing như thế này mang lại hiệu quả cho các giai đoạn tiếp theo)

Đối với thư mục other, đây là các file được tổng hợp từ nhiều nguồn, gồm các bài báo khoa học có liên quan đến QNX Hypervisor, các file code c demo của QNX để chạy giao tiếp shmem, các mô tả CVE liên quan đến QNX và report research của team về QNX Hypervisor IVC ở gd1. Cấu trúc các file ở thư mục này đa dạng và có thể mở rộng số lượng trong tương lai nên sẽ được parsing với option chung, tùy vào extension. (nói tiếp về cơ chế parsing sang định dạng md-yaml của từng loại extension và vì sao cách parsing như thế này mang lại hiệu quả cho các giai đoạn tiếp theo)

### chunking

(nói về logic chunking cụ thể dựa trên basecode hiện tại và giải thích vì sao cơ chế này mang lại hiệu quả cho các giai đoạn tiếp theo)

### embedding

giới thiệu về model text-embedding-3-small được sử dụng, so sánh với các lựa chọn khác để làm nổi bật lí do được chọn (chi phí, khả năng)

### upserting

giới thiệu về Pinecone, so sánh với các lựa chọn khác để làm nổi bật lí do lựa chọn

giới thiệu về cơ chế lưu trữ trên Pinecone (tham khảo https://docs.pinecone.io/guides/index-data/create-an-index)

**Pinecone hiện chỉ có 1 loại index chính (Serverless Index)**, nhưng index đó **có thể được cấu hình để chứa và index một hoặc nhiều loại dữ liệu** trong 3 loại sau:

1. **Documents** (Document Schema / Full-text Search)
2. **Dense Vectors**
3. **Sparse Vectors**

**Documents** là cách mạnh nhất và hiện đại nhất hiện nay.
Khi bạn tạo index kiểu **"Full-text Search"**, bạn đang tạo một **Document Schema Index**. Index này có thể:

- Chứa dense_vector
- Chứa sparse_vector
- Chứa string field với full_text_search (BM25)
- Chứa rất nhiều metadata fields
    
    → Đây là kiểu **multi-signal index**, cho phép mix tất cả trong cùng một index.
    

**Dense Vectors** và **Sparse Vectors** là hai kiểu dữ liệu cơ bản có thể được lưu **bên trong** index đó.

Nói về lựa chọn cho framework này: **Documents** schema setup trên Pinecone để upsert các chunk sau khi xử lí để tạo thành format (gồm các field …) → dense vector + BM25. Tôi không dùng cơ chế kết hợp lưu trữ dense vector + sparse vector vì phải tốn chi phí để sử dụng 2 model embedding, ko chắc hiệu quả hơn.

Giải thích vai trò của mỗi field trong schema (dạng bảng)

### query rewrite

- RAG truyền thống: query -> RAG -> chunk context + query -> LLM -> response
- RAG connected to LLM (Claude) via MCP (Agentic AI?): query được LLM tự rewrite, suy luận để gọi các MCP tool từ RAG (hoặc các MCP server khác) lấy context rồi tổng hợp để response.

Hệ thống là Agentic RAG via MCP — Claude tự quyết định khi nào gọi tool, với query gì, và gọi bao nhiêu lần. Không phải pipeline cố định. Vì vậy các phần như query rewriting, multi-hop retrieval đã được Claude xử lý tự nhiên.

### searching

nói về cơ chế searching trên Pinecone để tìm kiếm trong hàng triệu các vector tương đồng theo cosine/dot product với 1 vector được truy vấn, sử dụng thuật toán ANN. Ngoài ra còn cho phép query với filter và reranking (tham khảo: https://docs.pinecone.io/guides/search/search-overview)

nói về cơ chế searching cụ thể đối với 1 query gửi từ LLM, sử dụng dense kết hợp BM25 và các metadate filter như thế nào để tận dụng tối đa tính năng của Pinecone và chất lượng search về semantic và lexical với tính chất của data (doc vs code)

### responding

khi nhận được các chunk từ Pinecone, RAG sẽ tổng hợp lại dựa vào các child chunk id để khôi phục context đầy đủ của các hàm bị split trong giai đoạn chunking, điều này đảm bảo LLM nhận đủ context của thông tin (giải thích chi tiết dựa vào codebase)

nói về format của data trả về cho LLM và vai trò của nó trong việc mang lại hiệu quả thông tin cho LLM để suy luận, tracing, query tiếp.

### MCP tools

RAG sẽ cung cấp các tính năng của nó thông qua các MCP tool và prompt để LLM hiểu (thông qua tool doc string và sử dụng thông qua giao thức MCP)

Liệt kê các MCP tool và prompt (dựa vào codebase) và giải thích vai trò, đáp ứng nhu cầu của tool object như thế nào)

## System prompt Component

Nói về cơ chế hoạt động của Project instruction trong Claude, có thể được sử dụng như 1 system prompt trong các chat được tạo ra trong Project.

Nói về các mục tiêu của system prompt:

- hướng dẫn sử dụng các tool với mục đích phù hợp
- hướng dẫn quy trình suy luận lỗ hổng và phối hợp sử dụng các công cụ
- hướng dẫn phương pháp giảm thiểu sai sót, ảo giác trong quá trình suy luận

Nói về các kĩ thuật prompting được ứng dụng và hiệu quả mang lại

## Token usage

Nói về độ dài của system prompt, các gói tin MCP, số lượng tool use trung bình và ảnh hưởng của nó đối với chi phí token trong 1 session chat như thế nào, ước lượng số truy vấn mà người dùng có thể hỏi khi sử dụng Pro Plan, model Sonnet 4.6 có đáp ứng được mục tiêu Vuln analysis hay không.

## Chapter Summary

tóm tắt lại các thành phần đã xây dựng cho AI framework và cách nó được dự đoán là sẽ giải quyết được các mục tiêu đặt ra trước đó.

---

# Results and Discussion

## AI Framework Evaluation

### Evaluation Methods

Ta sẽ tập trung đánh giá 2 khía cạnh được xây dựng trong đề tài này đó là Vuln analysis và RAG, còn phần Reverse refactor phụ thuộc phần lớn vào hiệu quả của decompiler và MCP plugin có sẵn nên tạm thời bỏ qua việc đánh giá về tính chính xác, nhưng hiệu quả nó mang lại trong việc giảm thời gian refactor thủ công đã được xác nhận bởi các thành viên khi sử dụng trong quá trình thực hiện đề tài này.

### RAG Retrieval Quality Evaluation

Khía cạnh này sẽ được đánh giá và so sánh giữa ở các giai đoạn sau:

- Chunking: structure aware của gd2 và default chunking của gd1 (nói rõ thêm dựa vào codebase), cùng sử dụng dense searching để cô lập đóng góp về hiệu quả của phần searching
- Searching: dense vs bm25 vs hybrid của gd2 để chứng minh cơ chế hybrid vượt trội nhất.

Test Dataset

Scoring Methodology

Result Analysis

nhận xét các hình ảnh thống kê gen từ thư mục evaluation

### Vulnerability Analysis Evaluation

Hiệu quả của khía cạnh này dựa trên chất lượng của System prompt và sự bổ trợ về thông tin giữa các công cụ được tích hợp. Ta sẽ đánh giá và so sánh giữa 2 phần là gd2 (LLM-RAG-MCP) với base (Sonnet 4.6 với tính năng file upload bị giới hạn về số lượng file)

Test Dataset

Scoring Methodology

Result Analysis

nhận xét các hình ảnh thống kê gen từ thư mục evaluation

### Summary

Tóm tắt về kết quả đánh giá và phân tích các ưu điểm và hạn chế của framework đối chiếu với mục tiêu của đề tài và mục tiêu của Tool đã đặt ra.