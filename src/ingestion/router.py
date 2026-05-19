# ingestion/router.py — Maps a file path to its converter output.
#
# Primary dispatch: top-level directory under rag_docs/ (see rag_docs/*/SPEC.md).
# Fallback dispatch: file extension (for other/ and unrecognized directories).
import os
import sys
import yaml
from typing import Any, Dict, List, Optional

from langchain_core.documents import Document

from config import DOCS_DIR, TESSERACT_PATH
from converters import (
    convert_build_config, convert_c, convert_decompiled, convert_pdf,
)
from converters.utils import make_frontmatter

SUPPORTED_EXTS = (".pdf", ".txt", ".md", ".c", ".h", ".build", ".sh", ".layout", ".html")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Path utilities
# ---------------------------------------------------------------------------

def get_doc_dir(file_path: str) -> str:
    """Top-level directory directly under DOCS_DIR, e.g. 'qnx-doc', 'decompiled', 'other'."""
    docs_root = os.path.abspath(DOCS_DIR)
    rel = os.path.relpath(os.path.abspath(file_path), docs_root)
    parts = rel.replace("\\", "/").split("/")
    return parts[0] if len(parts) > 1 else ""


def canonical_source(file_path: str) -> str:
    """Stable, Docker-agnostic source identifier: 'rag_docs/<rel_path>'."""
    if not file_path:
        return "unknown"
    abs_path = os.path.abspath(file_path)
    docs_root = os.path.abspath(DOCS_DIR)
    try:
        rel = os.path.relpath(abs_path, docs_root)
    except Exception:
        return abs_path.replace("\\", "/")
    if rel and rel != "." and not rel.startswith(".."):
        return os.path.join("rag_docs", rel).replace("\\", "/")
    return abs_path.replace("\\", "/")


def is_supported(file_path: str) -> bool:
    return file_path.lower().endswith(SUPPORTED_EXTS)


# ---------------------------------------------------------------------------
# Frontmatter parsing (used by both router and loader)
# ---------------------------------------------------------------------------

def frontmatter_to_doc(text: str) -> Optional[Document]:
    """Parse a YAML-frontmatter Markdown string into a LangChain Document."""
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            try:
                meta: Dict = yaml.safe_load(text[4:end]) or {}
            except Exception:
                meta = {}
            content = text[end + 5:].strip()
            if content:
                return Document(page_content=content, metadata=meta)
            return None
    stripped = text.strip()
    return Document(page_content=stripped, metadata={}) if stripped else None



# ---------------------------------------------------------------------------
# qnx-doc HTML converter (inline — replicates helper/qnx-doc-converter.py logic)
# ---------------------------------------------------------------------------

_toc_map_cache: Dict[str, Dict[str, List[str]]] = {}


def _load_toc_map(plugin_dir: str) -> Dict[str, List[str]]:
    """
    Parse main.xml in plugin_dir to build {html_file_path: [doc_title, section..., page]}
    hierarchy map. Results are cached per directory.
    """
    if plugin_dir in _toc_map_cache:
        return _toc_map_cache[plugin_dir]

    xml_path = os.path.join(plugin_dir, "main.xml")
    if not os.path.exists(xml_path):
        _toc_map_cache[plugin_dir] = {}
        return {}

    try:
        import xml.etree.ElementTree as ET
        root = ET.parse(xml_path).getroot()
        hierarchy_map: Dict[str, List[str]] = {}

        def _traverse(element, path: List[str]) -> None:
            label = element.attrib.get("label", "").strip()
            new_path = path + [label] if label else path
            link = element.attrib.get("topic") or element.attrib.get("href")
            if link:
                hierarchy_map[link.split("#")[0]] = new_path
            for child in element:
                if child.tag == "topic":
                    _traverse(child, new_path)

        _traverse(root, [])
        _toc_map_cache[plugin_dir] = hierarchy_map
        return hierarchy_map
    except Exception as e:
        _log(f"  [WARN] Could not parse {xml_path}: {e}")
        _toc_map_cache[plugin_dir] = {}
        return {}


def _convert_html(html_path: str, source: str) -> List[str]:
    """
    Convert a single QNX HTML file to YAML-frontmatter Markdown.
    Strips navigation/script/style; uses markdownify for body content.
    TOC hierarchy is read from main.xml in the plugin directory.
    """
    try:
        from bs4 import BeautifulSoup
        from markdownify import markdownify as md
    except ImportError:
        _log("  [ERROR] beautifulsoup4 / markdownify not installed — cannot convert HTML")
        return []

    file_name = os.path.basename(html_path)
    # Plugin dir is the parent of the directory containing the html file.
    # Structure: rag_docs/qnx-doc/<plugin>/topic/subdir/file.html
    # We walk upward to find main.xml.
    plugin_dir = os.path.dirname(html_path)
    while plugin_dir and plugin_dir != os.path.dirname(plugin_dir):
        if os.path.exists(os.path.join(plugin_dir, "main.xml")):
            break
        plugin_dir = os.path.dirname(plugin_dir)

    # Compute relative path within plugin dir for TOC lookup
    try:
        rel_path = os.path.relpath(html_path, plugin_dir).replace("\\", "/")
    except Exception:
        rel_path = file_name

    toc_map = _load_toc_map(plugin_dir)
    hierarchy = toc_map.get(rel_path, [])

    try:
        with open(html_path, "rb") as f:
            html_bytes = f.read()
    except OSError as e:
        _log(f"  [ERROR] Cannot read {html_path}: {e}")
        return []

    soup = BeautifulSoup(html_bytes, "html.parser")
    for tag in soup(["nav", "script", "style", "footer", "header", "meta", "link"]):
        tag.decompose()

    main_content = soup.find("div", class_="body") or soup.find("body") or soup

    for img in main_content.find_all("img"):
        alt = img.get("alt", "")
        src = img.get("src", "unknown_image")
        img.replace_with(soup.new_string(f"\n> [IMAGE: {src}{' | ' + alt if alt else ''}]\n"))

    md_text = md(str(main_content), heading_style="ATX", autolinks=False)

    meta: Dict[str, Any] = {
        "type": "reference_document",
        "source": source,
        "file_name": file_name,
        "page": 0,
    }
    if hierarchy:
        meta["doc_title"] = hierarchy[0]
        if len(hierarchy) >= 2:
            meta["toc_page"] = hierarchy[-1]
        if len(hierarchy) >= 3:
            meta["toc_section"] = " > ".join(hierarchy[1:-1])
    else:
        title = soup.title.string if soup.title else file_name
        meta["toc_page"] = title.strip()

    content = md_text.strip()
    if not content:
        return []
    return [make_frontmatter(meta, content)]


# ---------------------------------------------------------------------------
# .md / .txt handler (shared between qnx-doc routing and extension fallback)
# ---------------------------------------------------------------------------

def _load_md_file(path: str, source: str, file_name: str) -> List[str]:
    """
    Read a .md/.txt file.
    Files with existing YAML frontmatter (e.g. qnx-doc after conversion) have their
    metadata preserved; canonical source and file_name are always injected/overwritten.
    Plain-text files are wrapped with default reference_document metadata.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    stripped = text.strip()
    if not stripped:
        return []

    if stripped.startswith("---\n"):
        doc = frontmatter_to_doc(stripped)
        if doc:
            doc.metadata.update({"source": source, "file_name": file_name})
            doc.metadata.setdefault("type", "reference_document")
            doc.metadata.setdefault("page", 0)
            return [make_frontmatter(doc.metadata, doc.page_content)]
        return []

    meta: Dict[str, Any] = {
        "source": source, "file_name": file_name, "type": "reference_document", "page": 0,
    }
    return [make_frontmatter(meta, stripped)]


# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

def convert_file(file_path: str, source: str) -> List[str]:
    """
    Route a file to its converter and return YAML-frontmatter Markdown strings.
    Returns [] for unsupported, empty, or errored files.
    """
    file_name = os.path.basename(file_path)
    ext = os.path.splitext(file_path)[1].lower()
    doc_dir = get_doc_dir(file_path)

    # ── Primary: directory-based routing ────────────────────────────────────
    if doc_dir == "vuln-pattern":
        if ext == ".md":
            from converters.vuln_pattern_converter import convert_vuln_pattern
            md_strings = convert_vuln_pattern(file_path, source)
        else:
            _log(f"  [SKIP] Unexpected extension in vuln-pattern/: {file_name}")
            return []
        _log(f"  Loaded {len(md_strings)} pattern(s) from {file_name}")

    elif doc_dir == "build-config":
        if ext not in (".build", ".sh", ".layout"):
            _log(f"  [SKIP] Unexpected extension in build-config/: {file_name}")
            return []
        md_strings = convert_build_config(file_path, source)
        _log(f"  Extracted {len(md_strings)} chunk(s) from {file_name}")

    elif doc_dir == "decompiled":
        if ext not in (".c", ".h"):
            _log(f"  [SKIP] Unexpected extension in decompiled/: {file_name}")
            return []
        md_strings = convert_decompiled(file_path, source)
        _log(f"  Extracted {len(md_strings)} chunk(s) from {file_name}")

    elif doc_dir == "qnx-doc":
        if ext == ".html":
            md_strings = _convert_html(file_path, source)
            _log(f"  Converted HTML: {file_name}")
        else:
            _log(f"  [SKIP] Unexpected extension in qnx-doc/: {file_name}")
            return []

    # ── Fallback: extension-based (other/ and unrecognized directories) ──────
    elif ext == ".pdf":
        md_strings = convert_pdf(file_path, source, tesseract_path=TESSERACT_PATH)
        _log(f"  Extracted {len(md_strings)} page(s) from {file_name}")
    # elif ext == ".json":
    #     md_strings = convert_json(file_path, source)
    #     _log(f"  Loaded {len(md_strings)} pattern(s) from {file_name}")
    elif ext in (".c", ".h"):
        md_strings = convert_c(file_path, source)
        _log(f"  Extracted {len(md_strings)} chunk(s) from {file_name}")
    # elif ext == ".build":
    #     md_strings = convert_build(file_path, source)
    #     _log(f"  Extracted {len(md_strings)} chunk(s) from {file_name}")
    # elif ext == ".sh":
    #     md_strings = convert_sh(file_path, source)
    #     _log(f"  Loaded {len(md_strings)} script(s) from {file_name}")
    # elif ext == ".layout":
    #     md_strings = convert_layout(file_path, source)
    #     _log(f"  Extracted {len(md_strings)} chunk(s) from {file_name}")
    elif ext in (".txt", ".md"):
        md_strings = _load_md_file(file_path, source, file_name)
    else:
        _log(f"  [SKIP] Unsupported: {file_path}")
        return []

    return md_strings
