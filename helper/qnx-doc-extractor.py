#!/usr/bin/env python3
"""
QNX Documentation HTML Extractor
Unzip doc.zip từ plugin dirs → lưu HTML gốc + main.xml vào rag_docs/qnx-doc
(Thay thế bước pre-convert bằng qnx-doc-converter.py)
"""
import os
import zipfile
import shutil
from pathlib import Path

# Plugin dirs từ QNX installation
PLUGIN_DIRS = [
    "com.qnx.doc.hypervisor.vdev_3.0.0.20201222",
    "com.qnx.doc.hypervisor.vdev.api_3.0.0.20201222",
    "com.qnx.doc.hypervisor.user_3.0.0.20201222",
    "com.qnx.doc.neutrino.sys_arch_3.0.0.20241027",
    "com.qnx.doc.neutrino.prog_3.0.0.20241027",
    "com.qnx.doc.neutrino.lib_ref_3.0.0.20241027",
    "com.qnx.doc.security.system_3.0.0.20241027",
    "com.qnx.doc.neutrino.utilities_3.0.0.20241027"
]

QNX_PLUGINS_DIR = os.path.expanduser("~/qnx710/target/qnx7/usr/help/eclipse/plugins")
OUTPUT_RAG_DIR = os.path.expanduser("~/datn/vuln-analysis-RAG/rag_docs/qnx-doc")

KEEP_DIRS = {"topic"}
KEEP_FILES = {"main.xml"}

BLACKLIST_FILES = {"copyright.html"}


def remove_blacklist_files(root_dir: str) -> int:
    """Remove blacklist files recursively"""
    removed = 0

    for root, _, files in os.walk(root_dir):
        for file in files:
            if file in BLACKLIST_FILES:
                path = os.path.join(root, file)

                try:
                    os.remove(path)
                    removed += 1
                except Exception as e:
                    print(f"    [WARN] Could not remove {path}: {e}")

    return removed


def cleanup_plugin(output_plugin_dir: str) -> None:
    """
    Keep only:
      - topic/
      - main.xml

    Then remove blacklist files recursively.
    """
    removed_count = 0

    # 1. Remove everything except topic/ and main.xml
    for entry in os.listdir(output_plugin_dir):
        path = os.path.join(output_plugin_dir, entry)

        if os.path.isdir(path) and entry in KEEP_DIRS:
            continue

        if os.path.isfile(path) and entry in KEEP_FILES:
            continue

        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)

            removed_count += 1

        except Exception as e:
            print(f"    [WARN] Could not remove {path}: {e}")

    # 2. Remove blacklist files inside topic/
    removed_blacklist = remove_blacklist_files(output_plugin_dir)

    print(
        f"    ✓ Removed {removed_count} extra item(s), "
        f"{removed_blacklist} blacklist file(s)"
    )
    

def extract_plugin(plugin_name: str) -> None:
    """Extract doc.zip + copy main.xml từ plugin → rag_docs/qnx-doc/<plugin_name>/"""
    plugin_path = os.path.join(QNX_PLUGINS_DIR, plugin_name)
    zip_path = os.path.join(plugin_path, "doc.zip")
    xml_path = os.path.join(plugin_path, "main.xml")
    
    if not os.path.exists(plugin_path):
        print(f"[SKIP] Plugin dir không tồn tại: {plugin_path}")
        return
    
    if not os.path.exists(zip_path):
        print(f"[SKIP] doc.zip không tìm thấy: {plugin_path}")
        return
    
    output_plugin_dir = os.path.join(OUTPUT_RAG_DIR, plugin_name)
    os.makedirs(output_plugin_dir, exist_ok=True)
    
    # 1. Unzip doc.zip
    print(f"[+] Unzipping {plugin_name}...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(output_plugin_dir)
        print(f"    ✓ Unzipped to {output_plugin_dir}")
    except Exception as e:
        print(f"    [ERROR] Failed to unzip: {e}")
        return
    
    # 2. Remove blacklist files from plugin root
    cleanup_plugin(output_plugin_dir)
    
    # 3. Copy main.xml nếu tồn tại
    if os.path.exists(xml_path):
        try:
            output_xml = os.path.join(output_plugin_dir, "main.xml")
            shutil.copy2(xml_path, output_xml)
            print(f"    ✓ Copied main.xml")
        except Exception as e:
            print(f"    [WARN] Could not copy main.xml: {e}")
    else:
        print(f"    [WARN] main.xml not found in {plugin_path}")


def main():
    print("=== QNX Documentation HTML Extractor ===\n")
    
    # Verify output dir
    os.makedirs(OUTPUT_RAG_DIR, exist_ok=True)
    
    # Extract all plugins
    for plugin_name in PLUGIN_DIRS:
        extract_plugin(plugin_name)
    
    print(f"\n[✓] Done! HTML files saved to: {OUTPUT_RAG_DIR}")
    print(f"[*] router.py will now convert HTML → Markdown on-the-fly\n")


if __name__ == "__main__":
    main()
