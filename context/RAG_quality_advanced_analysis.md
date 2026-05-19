## RAG quality advanced analysis

### requirement

- hiểu kiến trúc của hệ thống để cân nhắc trong các giải pháp sao cho phù hợp và hiệu quả nhất
    - RAG truyền thống: query -> RAG -> chunk context + query -> LLM -> response
    - RAG connected to LLM (Claude) via MCP (Agentic AI?): query được LLM tự rewrite, suy luận để gọi các MCP tool từ RAG (hoặc các MCP server khác) lấy context rồi tổng hợp để response.
- hiểu mục tiêu gd2: vuln analysis on no-source product (binary and documentation only), chi tiết đọc file @context.md  
- ở mỗi phần (heading):
    - phân tích input, output, ý tưởng được cung cấp (có thể chưa phải tốt nhất, cần phản biện và thảo luận thêm)
    - đảm bảo hiệu quả thiết kế của hệ thống thông qua việc phân tích và trả lời các câu hỏi đặt ra, kiểm tra toàn bộ codebase ở thư mục src/ (hoặc tra cứu nhanh về logic các hàm thông qua doc @codebase-docs/src_FUNCTION_REFERENCE.md ) xem đã aware đến vấn đề này chưa, nếu chưa thì giải pháp hiệu quả nhất là gì (tìm kiếm các nguồn tài liệu uy tín của giới học thuật, báo khoa học top tier để tìm ra các phương pháp tốt nhất đã được nghiên cứu và kiểm chứng có thể áp dụng vào mục tiêu project này, đảm bảo giải pháp được chọn phù hợp, khai thác tốt các điểm mạnh đã có). Trao đổi để thống nhất phương án cuối cùng.

### parsing

- input: mulple format docs
- output: file YAML-frontmatter Markdown có cấu trúc nội dung sẵn sàng cho bước chunking (metadata-content)
- ý tưởng: rag_docs chứa 2 loại tài liệu: processed và unprocessed
    - loại processed: các tài liệu phải được xử lí bên ngoài và convert về format cụ thể rồi mới đặt vào đây để được parsing sang md (nếu chưa là md), cấu trúc và bố cục nội dung sao cho phù hợp để parsing phải được define sẵn trong file SPEC.md. Các loại doc thuộc loại processed là các doc có giá trị thông tin cao, có thể xử lí bằng code hoặc LLM (nếu phức tạp), bao gồm:
        - qnx-doc: các tài liệu dưới dạng html đã có cấu trúc heading, đã được convert sang md bằng script @helper/qnx-doc-converter.py  
        - vuln-pattern: các file chứa thông tin mô tả về các loại bug có liên quan được tổng hợp từ các tài liệu thông qua LLM, cần được define các thông tin tối thiểu cần có khi tổng hợp và cấu trúc để việc parsing (nếu cần) và hỗ trợ tri thức về vuln analysis đạt hiệu quả cao
        - decompiled: các binary được IDA dịch ngược sang mã giả c, cấu trúc ko đảm bảo như 1 file c hợp lệ chạy đc, loại file này sẽ được refactor thông qua LLM để rename/comment để human readable hơn, cần được define về cấu trúc refactor sao cho code convert parsing hiệu quả các thông tin
        - build-config: có thể xử lí convert bằng code hoặc refactor lại bằng LLM nếu cần thiết, hãy read các file để phân tích thêm
            - `.build` gồm các file cấu hình để build image boot trong QEMU cho host và cấu hình chạy guest. Mỗi lệnh config có cấu trúc như sau:
                - Dạng file mapping: `([key=value( key=value)*])? file_name(=path_to_search_in_local)?`
                - Dạng file create: `([key=value( key=value)*])? file_name={content}`
                - Dạng config declare: `[key=value( key=value)*]`
            - `.layout` cấu hình disk partrition, nội dung ngắn chỉ vài dòng
            - `.sh` script bash
    - loại unprocessed: các tài liệu random được thu thập từ internet hoặc các nguồn tin cậy nhưng ko có cấu trúc cụ thể với số lượng lớn để chủ động phân tích hoặc giá trị thông tin ko cao, hoặc thường xuyên được bổ sung, hoặc mã nguồn có cú pháp hợp lệ dễ tích hợp các tool/library mạnh để parsing hiệu quả. Các file này sẽ được parsing theo tiêu chuẩn chung tùy vào loại file để tiết kiệm thời gian, hiện tại bao gồm: pdf, source .c .h, md, txt
- câu hỏi:
    - file pdf sử dụng OCR khi extract < 100 char 1 file: có rủi ro bỏ qua các page có ảnh nhưng nhỏ, cần define lại threshold này hợp lí hơn, vd extract < baseline history of the document hoặc ước tính số char at this font size can cover > 80% page size.
    - SPEC.md đã mô tả đủ yêu cầu tối thiểu để xử lí các các doc dir chưa, các thông tin khác sẽ được xử lí ntn?
    - các metadata sinh ra đóng vai trò như thế nào cho context, tracing và retrieving?

### chunking + upserting

- input: formated docs
- output: chunks — each contains metadata+content with suitable size
- câu hỏi
    - [atomic types pass through] → có đảm bảo giới hạn input của embedding model ko? chunking atomic ntn có hiệu quả truy xuất ko?
    - phương pháp parent-child chunking liệu có hiệu quả với data dạng code ko? còn những phương pháp chunking nào khác đã được nghiên cứu và sử dụng ko?
    - vector database có phải giải pháp tốt nhất cho loại data mà project này sử dụng ko? còn các mô hình lưu trữ tri thức nào khác cho RAG ko?
    - phương pháp ingesting hiện tại có tốt nhất với data dạng code ko? còn phương pháp nào khác ngoài vector - thường được sử dụng cho truy vấn dạng semantic text ko?
    - các metadata sinh ra đóng vai trò như thế nào cho context, tracing và retrieving?
    - các Thresholds về chunk size có hiệu quả khi cân nhắc trên các khía cạnh mà nó ảnh hưởng (embedding model, token wasted when LLM use, data chunk semantic)

### retrieving

- input: query
- output: chunks with ranking
- câu hỏi
    - searching algo phù hợp với tính chất data ko?
    - phương pháp retrieving hiện tại có tốt nhất với data dạng code ko? còn phương pháp nào khác ngoài vector - thường được sử dụng cho truy vấn dạng semantic text ko? sparse vs dense retrieval?

### API (MCP tools) + LLM sysmtem prompt

- input: query/data, options
- output: json data
- câu hỏi
    - các tool RAG cung cấp có được LLM hiểu và tận dụng 1 cách hiệu quả ko? docstring có được viết rõ ràng và cụ thể context sử dụng ko? các tool được sử dụng kết hợp trong các tình huống nào? phần hướng dẫn này được đặt ở đâu?
    - các tool đã cung cấp hết những tính năng cần thiết cho mục tiêu project chưa?
    - json data trả về có tối ưu về mặt thông tin (kích thước, nội dung) ko, vì nó cũng ảnh hưởng đến context window và token wasted? thông tin đủ context hay nửa vời? metadata trả về có giá trị sử dụng với LLM ko?
    - nếu query ko có kết quả thì LLM nên xử lí ntn? avoid loop?
    - LLM có biết cách tạo ra query (query rewrite) sao cho việc truy vấn RAG hiệu quả nhất ko?
    - Tool add_knowledge_text có quy định cho LLM tạo knowledge với cấu trúc trước khi thêm vào sao cho hiệu quả chưa?
---
Sau khi đã nắm rõ các yêu cầu, ngữ cảnh và vấn đề, hãy bắt đầu cuộc thảo luận với các câu hỏi quan trọng để nhanh chóng tìm ra 1 giải pháp toàn diện, hiệu quả và đột phá để trình bày trong đồ án tốt nghiệp.