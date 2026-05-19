# converters/pdf_converter.py — PDF → Markdown+frontmatter converter.
#
# Heading detection strategy (priority order):
#   1. Embedded TOC metadata (pdf.get_toc()) — highest fidelity, exact chapter/section titles.
#   2. Font-size heuristic on text spans — fallback for PDFs without embedded TOC.
# OCR fallback:
#   - Pages below an adaptive threshold (15% of the per-document median page length,
#     min 50 chars) are treated as scanned/image pages.
#
# Output: one frontmatter-wrapped Markdown string per page with content.
import os
from statistics import median
from typing import Dict, List, Tuple

import fitz
import pytesseract
from PIL import Image

from converters.utils import make_frontmatter


def convert_pdf(file_path: str, source: str, tesseract_path: str = "/usr/bin/tesseract") -> List[str]:
    """
    Convert a PDF file to a list of Markdown strings (one per page with content).
    Each string is prefixed with YAML frontmatter containing source/type/page metadata.

    Heading enrichment: if the PDF has an embedded Table of Contents (get_toc()),
    the chapter/section title is prepended to the corresponding page's content as a
    Markdown heading. This is more reliable than font-size detection for structured
    research documents. Font-size heuristic still runs for body text on all pages.

    Args:
        file_path:      Absolute path to the PDF file.
        source:         Canonical source identifier (e.g. "rag_docs/other/doc.pdf").
        tesseract_path: Path to the tesseract binary for OCR fallback.
    """
    pytesseract.pytesseract.tesseract_cmd = tesseract_path

    pdf = fitz.open(file_path)
    total = len(pdf)
    file_name = os.path.basename(file_path)
    print(f"  Processing {total} pages: {file_name}")

    # Build a 0-based page → (toc_level, title) map from embedded TOC.
    # get_toc() returns [[level, title, page_1based], ...]; keep the first
    # (highest-level) entry per page so chapter titles take precedence over
    # sub-section titles that start on the same page.
    page_headings: Dict[int, Tuple[int, str]] = {}
    for level, title, page_1based in pdf.get_toc():
        page_0based = page_1based - 1
        if 0 <= page_0based < total and page_0based not in page_headings:
            page_headings[page_0based] = (level, title.strip())

    sample_lengths = [len(pdf[i].get_text().strip()) for i in range(min(5, total))]
    ocr_threshold = max(50, int(median(sample_lengths) * 0.15))

    results: List[str] = []
    for page_num in range(total):
        page = pdf[page_num]
        raw_text = page.get_text()

        if len(raw_text.strip()) < ocr_threshold:
            # Scanned/image page — OCR fallback
            mat = fitz.Matrix(2.0, 2.0)
            pix = page.get_pixmap(matrix=mat)
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            try:
                md_text = pytesseract.image_to_string(img, lang="eng")
            except Exception as e:
                print(f"    OCR failed page {page_num}: {e}")
                md_text = ""
        else:
            # Text-based page — layout-aware Markdown conversion
            md_text = _page_to_markdown(page)
            if not md_text.strip():
                md_text = raw_text  # final fallback

        # Prepend TOC heading when available — placed before the font-heuristic
        # headings so the document's own chapter title leads the chunk.
        if md_text.strip() and page_num in page_headings:
            level, title = page_headings[page_num]
            hdr = "#" * min(level, 3)  # cap at h3 to stay within splitter range
            md_text = f"{hdr} {title}\n\n{md_text}"

        if md_text.strip():
            meta = {
                "source": source,
                "file_name": file_name,
                "type": "reference_document",
                "page": page_num,
            }
            results.append(make_frontmatter(meta, md_text))

    pdf.close()
    print(f"  Extracted {len(results)} pages with content")
    return results


def _page_to_markdown(page: fitz.Page) -> str:
    """
    Convert one PDF page to Markdown using font-size heading detection.

    Algorithm:
      - Extract all text spans with font size and bold flag.
      - Body font size = median of all span sizes on the page.
      - Lines with max span size >= 1.4x body → ## heading.
      - Lines with max span size >= 1.15x body OR bold → ### heading.
      - Everything else → plain paragraph text.
    """
    try:
        blocks = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)["blocks"]
    except Exception:
        return page.get_text()

    sizes: List[float] = [
        span["size"]
        for block in blocks if block.get("type") == 0
        for line in block.get("lines", [])
        for span in line.get("spans", [])
        if span.get("text", "").strip()
    ]
    if not sizes:
        return ""

    body_size = median(sizes)
    output_blocks: List[str] = []

    for block in blocks:
        if block.get("type") != 0:
            continue

        block_lines: List[str] = []
        for line in block.get("lines", []):
            text_parts: List[str] = []
            max_size = 0.0
            is_bold = False

            for span in line.get("spans", []):
                t = span.get("text", "")
                if not t.strip():
                    continue
                text_parts.append(t)
                max_size = max(max_size, span.get("size", 12.0))
                font = span.get("font", "").lower()
                if "bold" in font or "heavy" in font or "black" in font:
                    is_bold = True

            line_text = "".join(text_parts).strip()
            if not line_text:
                continue

            ratio = max_size / body_size if body_size > 0 else 1.0
            if ratio >= 1.4:
                block_lines.append(f"## {line_text}")
            elif ratio >= 1.15 or is_bold:
                block_lines.append(f"### {line_text}")
            else:
                block_lines.append(line_text)

        if block_lines:
            output_blocks.append("\n".join(block_lines))

    return "\n\n".join(output_blocks)
