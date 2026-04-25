# converters/json_converter.py — Vulnerability pattern JSON → Markdown+frontmatter converter.
#
# Supports two JSON layouts:
#   - Single object  (buffer_overflow.json)  → 1 document
#   - Array of objects (root_cause.json)     → N documents, one per pattern
#
# Each pattern card is rendered as structured Markdown with proper #/##/###
# headings so that MarkdownHeaderTextSplitter can split large cards (root_cause.json
# variants) at semantic boundaries while keeping small cards atomic.
import json
import os
from typing import Any, Dict, List

from converters.utils import make_frontmatter


def convert_json(file_path: str, source: str) -> List[str]:
    """
    Convert a vulnerability pattern JSON file to a list of Markdown+frontmatter strings.

    Args:
        file_path: Absolute path to the .json file.
        source:    Canonical source identifier.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    patterns = data if isinstance(data, list) else [data]
    file_name = os.path.basename(file_path)
    results: List[str] = []

    for i, pattern in enumerate(patterns):
        md_content = _pattern_to_markdown(pattern)
        if not md_content.strip():
            continue

        meta = {
            "source": source,
            "file_name": file_name,
            "type": "vulnerability_pattern",
            "doc_id": pattern.get("doc_id", f"{file_name}-{i}"),
            "severity": pattern.get("severity", ""),
            "tags": ", ".join(pattern.get("tags", [])),
            "page": i,
        }
        results.append(make_frontmatter(meta, md_content))

    return results


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _pattern_to_markdown(pattern: Dict[str, Any]) -> str:
    """
    Render one vulnerability pattern dict as structured Markdown.

    Uses #/##/### headings so MarkdownHeaderTextSplitter can split large
    patterns (e.g. root_cause.json with many variants) at semantic boundaries
    while keeping small single-pattern cards as a single atomic chunk.
    """
    lines: List[str] = []

    name = pattern.get("pattern_name", pattern.get("name", "Unknown Pattern"))
    doc_id = pattern.get("doc_id", "")
    severity = pattern.get("severity", "")
    cwes = ", ".join(pattern.get("cwe", []))
    tags = ", ".join(pattern.get("tags", []))

    lines.append(f"# {name}")
    meta_parts = [p for p in [
        f"**ID:** {doc_id}" if doc_id else "",
        f"**Severity:** {severity}" if severity else "",
        f"**CWE:** {cwes}" if cwes else "",
    ] if p]
    if meta_parts:
        lines.append(" | ".join(meta_parts))
    if tags:
        lines.append(f"**Tags:** {tags}")
    lines.append("")

    if pattern.get("root_cause_class"):
        lines += ["## Root Cause", pattern["root_cause_class"], ""]

    if pattern.get("description"):
        lines += ["## Description", pattern["description"], ""]

    if pattern.get("apply_when"):
        lines += ["## Apply When", pattern["apply_when"], ""]

    if pattern.get("not_this_pattern"):
        lines += ["## Not This Pattern", pattern["not_this_pattern"], ""]

    if pattern.get("subtypes"):
        lines.append("## Subtypes")
        for st in pattern["subtypes"]:
            lines.append(f"### {st.get('name', 'Subtype')}")
            if st.get("trigger"):
                lines.append(f"**Trigger:** {st['trigger']}")
            lines.append("")

    if pattern.get("variants"):
        lines.append("## Variants")
        for v in pattern["variants"]:
            vid = v.get("id", "")
            vname = v.get("name", "")
            lines.append(f"### {vid}: {vname}")
            if v.get("root_cause"):
                lines.append(f"**Root cause:** {v['root_cause']}")
            if v.get("dangerous_pattern"):
                lines.append(f"**Pattern:** `{v['dangerous_pattern']}`")
            if v.get("trigger"):
                lines.append(f"**Trigger:** {v['trigger']}")
            if v.get("note"):
                lines.append(f"*{v['note']}*")
            lines.append("")

    if pattern.get("cve_evidence"):
        lines.append("## CVE Evidence")
        for cve in pattern["cve_evidence"]:
            cve_id = cve.get("cve", "")
            cvss = cve.get("cvss", "")
            product = cve.get("product", "")
            desc = cve.get("root_cause", cve.get("one_line", ""))
            lesson = cve.get("key_lesson", cve.get("root_cause_match", ""))
            lines.append(f"### {cve_id}")
            detail_parts = [p for p in [
                f"**CVSS:** {cvss}" if cvss else "",
                f"**Product:** {product}" if product else "",
            ] if p]
            if detail_parts:
                lines.append(" | ".join(detail_parts))
            if desc:
                lines.append(f"**Root cause:** {desc}")
            if lesson:
                lines.append(f"**Key lesson:** {lesson}")
            lines.append("")

    if pattern.get("binary_indicators"):
        lines.append("## Binary Indicators")
        for ind in pattern["binary_indicators"]:
            lines.append(f"- {ind}")
        lines.append("")

    return "\n".join(lines)
