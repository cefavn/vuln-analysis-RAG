import os
import zipfile
import xml.etree.ElementTree as ET
import yaml
from bs4 import BeautifulSoup
from markdownify import markdownify as md

# Danh sách các file rác cần loại bỏ (không đưa vào RAG)
BLACKLIST_FILES = {"about.html", "copyright.html"}

def parse_toc_xml(xml_path):
    # [Giữ nguyên code như cũ]
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hierarchy_map = {}

    def traverse(element, current_path):
        label = element.attrib.get('label', '').strip()
        new_path = current_path + [label] if label else current_path
        link = element.attrib.get('topic') or element.attrib.get('href')
        if link:
            clean_link = link.split('#')[0]
            hierarchy_map[clean_link] = new_path
        for child in element:
            if child.tag == 'topic':
                traverse(child, new_path)

    traverse(root, [])
    return hierarchy_map

def clean_and_convert_html(html_bytes, file_path, hierarchy):
    # [Giữ nguyên code như cũ]
    soup = BeautifulSoup(html_bytes, 'html.parser')

    for tag in soup(['nav', 'script', 'style', 'footer', 'header', 'meta', 'link']):
        tag.decompose()

    main_content = soup.find('div', class_='body') or soup.find('body') or soup

    for img in main_content.find_all('img'):
        alt_text = img.get('alt', 'Không có mô tả')
        src = img.get('src', 'unknown_image')
        img.replace_with(soup.new_string(f"\n> [IMAGE: {src} | Mô tả: {alt_text}]\n"))

    md_text = md(str(main_content), heading_style="ATX", autolinks=False)

    meta = {"type": "reference_document", "source_html": file_path}
    if hierarchy:
        meta["doc_title"] = hierarchy[0]
        if len(hierarchy) >= 2:
            meta["toc_page"] = hierarchy[-1]
        if len(hierarchy) >= 3:
            meta["toc_section"] = " > ".join(hierarchy[1:-1])
    else:
        title = soup.title.string if soup.title else os.path.basename(file_path)
        meta["toc_page"] = title.strip()

    frontmatter = "---\n" + yaml.safe_dump(meta, allow_unicode=True, sort_keys=False) + "---\n\n"
    return frontmatter + md_text.strip()

def process_qnx_plugin(plugin_dir, output_base_dir):
    plugin_name = os.path.basename(os.path.normpath(plugin_dir))
    xml_path = os.path.join(plugin_dir, 'main.xml')
    zip_path = os.path.join(plugin_dir, 'doc.zip')

    if not os.path.exists(zip_path):
        print(f"[-] Không tìm thấy doc.zip trong {plugin_dir}. Bỏ qua.")
        return

    # 1. Parse XML để lấy cây thư mục (Và dùng làm Whitelist)
    hierarchy_map = {}
    if os.path.exists(xml_path):
        print(f"[+] Đang phân tích file {xml_path}...")
        hierarchy_map = parse_toc_xml(xml_path)
    else:
        print(f"[*] Không tìm thấy main.xml, sẽ dùng thẻ <title> của HTML làm Header.")

    output_dir = os.path.join(output_base_dir, plugin_name)
    os.makedirs(output_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, 'r') as z:
        html_files = [f for f in z.namelist() if f.endswith('.html')]
        
        # 2. LOGIC LỌC FILE MỚI: Whitelist + Blacklist
        valid_html_files = []
        for f in html_files:
            # "Kim bài miễn tử": Nếu file có nằm trong cấu trúc main.xml -> Chắc chắn giữ lại
            if f in hierarchy_map:
                valid_html_files.append(f)
            # Nếu không có trong XML, check xem có dính Blacklist không
            elif os.path.basename(f).lower() not in BLACKLIST_FILES:
                # Chỉ lọc những file rác kiểu 'about.html' mà không nằm trong cấu trúc mục lục
                valid_html_files.append(f)
        
        print(f"[+] Đã lọc {len(html_files) - len(valid_html_files)} file rác.")
        print(f"[+] Đang convert {len(valid_html_files)} file HTML hợp lệ...")

        for file_path in valid_html_files:
            html_bytes = z.read(file_path)
            hierarchy = hierarchy_map.get(file_path, [])
            md_content = clean_and_convert_html(html_bytes, file_path, hierarchy)
            
            out_md_path = os.path.join(output_dir, file_path.replace('.html', '.md'))
            os.makedirs(os.path.dirname(out_md_path), exist_ok=True)
            
            with open(out_md_path, 'w', encoding='utf-8') as f:
                f.write(md_content)

    print(f"[✓] Hoàn thành! Dữ liệu đã lưu tại: {output_dir}")
    
if __name__ == "__main__":
    # Thay đổi đường dẫn theo máy của bạn
    plugin_dirs =[
        "com.qnx.doc.hypervisor.vdev_3.0.0.20201222",
        "com.qnx.doc.hypervisor.vdev.api_3.0.0.20201222",
        "com.qnx.doc.hypervisor.user_3.0.0.20201222",
        "com.qnx.doc.neutrino.sys_arch_3.0.0.20241027",
        "com.qnx.doc.neutrino.prog_3.0.0.20241027",
        "com.qnx.doc.neutrino.lib_ref_3.0.0.20241027",
        "com.qnx.doc.security.system_3.0.0.20241027",
        # "com.qnx.doc.core_networking_3.0.0.20241027",
        "com.qnx.doc.neutrino.utilities_3.0.0.20241027"
    ]
    
    for plugin in plugin_dirs:
        INPUT_PLUGIN_DIR = os.path.expanduser(f"~/qnx710/target/qnx7/usr/help/eclipse/plugins/{plugin}")
        OUTPUT_RAG_DIR = os.path.expanduser("~/datn/vuln-analysis-RAG/rag_docs/qnx-doc") # Trỏ thẳng vào thư mục RAG của bạn
        print(f"\n=== Xử lý plugin: {plugin} ===")
        process_qnx_plugin(INPUT_PLUGIN_DIR, OUTPUT_RAG_DIR)

    print("=== QNX Documentation to RAG Markdown Converter ===")
    process_qnx_plugin(INPUT_PLUGIN_DIR, OUTPUT_RAG_DIR)