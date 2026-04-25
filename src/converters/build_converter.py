# converters/build_converter.py — QNX .build + shell script → Markdown+frontmatter converter.
#
# .build files (QNX Image Filesystem Builder config):
#   Produces one document per logical unit — global config params, [virtual=...] boot
#   image blocks, [+script] startup blocks, and ### Section ### delimited sections.
#   Sections whose name contains "suid" or "hypervisor/qvm" get dedicated types so
#   the retrieval layer can filter them independently (attack-surface analysis).
#
# .sh files (shell scripts):
#   Treated as build_script (atomic) — the full script is one document so the LLM
#   can reason about the complete startup/mount/network sequence without fragmentation.
import os
import re
from typing import Any, Dict, List, Tuple

from converters.utils import make_frontmatter

# ---------------------------------------------------------------------------
# Regexes for .build parsing
# ---------------------------------------------------------------------------

# ### Section Name ### delimiters (20+ # characters per line)
_BUILD_SECT_RE = re.compile(
    r"^#{20,}\n"
    r"#{0,3}[ \t]*(.+?)[ \t]*#{0,3}?\n"
    r"#{20,}",
    re.MULTILINE,
)

# [optional attrs] name = { content \n}  or  name { content \n}
_BUILD_BLOCK_RE = re.compile(
    r"(?:(\[[^\]]*\])\s+)?"
    r"([\w./\-]+)\s*=?\s*\{\n"
    r"(.*?)\n\}",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def convert_build(file_path: str, source: str) -> List[str]:
    """
    Convert a QNX .build image configuration file to Markdown+frontmatter strings.

    Produces:
      build_config     — global image parameters ([image=...], search paths)
      build_image      — [virtual=...] boot image blocks
      build_script     — [+script] startup script blocks
      build_section    — ### Section ### file-mapping blocks
      build_suid       — sections whose name contains "suid"
      build_hypervisor — sections whose name contains "hypervisor" or "qvm"

    Args:
        file_path: Absolute path to the .build file.
        source:    Canonical source identifier.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    fname = os.path.basename(file_path)
    base: Dict[str, Any] = {
        "source": source,
        "file_name": fname,
        "type": "build_config",
        "page": 0,
    }
    results: List[str] = []

    # ── 1. Global config: image parameter lines ──────────────────────────────
    first_special = min(
        (m.start() for m in [_BUILD_SECT_RE.search(text), _BUILD_BLOCK_RE.search(text)] if m),
        default=len(text),
    )
    config_lines = [
        line.strip()
        for line in text[:first_special].split("\n")
        if line.strip().startswith("[") and any(
            k in line for k in ("num_inodes", "num_sectors", "search", "image=", "prefix=")
        )
    ]
    if config_lines:
        body = (
            f"# {fname} — Image Configuration\n\n"
            "## Global Parameters\n\n"
            + "\n".join(f"- `{l}`" for l in config_lines)
        )
        meta = {**base, "type": "build_config", "section": "global_config"}
        results.append(make_frontmatter(meta, body))

    # ── 2. Special blocks: [virtual=...] boot images and [+script] scripts ───
    for bm in _BUILD_BLOCK_RE.finditer(text):
        attrs = bm.group(1) or ""
        name = bm.group(2)
        content = bm.group(3)

        if "virtual=" in attrs:
            body = (
                f"# {fname} — Boot Image: {name}\n\n"
                f"**Attributes:** `{attrs}`\n\n"
                f"```\n{attrs} {name} = {{\n{content}\n}}\n```"
            )
            meta = {**base, "type": "build_image", "section": f"boot_image/{name}", "block_name": name}
            results.append(make_frontmatter(meta, body))

        elif "+script" in attrs:
            body = f"# {fname} — Startup Script: {name}\n\n```sh\n{content}\n```"
            meta = {**base, "type": "build_script", "section": f"startup_script/{name}", "block_name": name}
            results.append(make_frontmatter(meta, body))

    # ── 3. Sections: ### Section Name ### delimited blocks ───────────────────
    section_matches = list(_BUILD_SECT_RE.finditer(text))
    for idx, sm in enumerate(section_matches):
        section_name = sm.group(1).strip()
        sec_start = sm.end()
        sec_end = section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(text)
        section_content = text[sec_start:sec_end]

        if not section_content.strip():
            continue

        md_lines = [f"# {fname} — {section_name}", ""]

        # Embedded inline blocks (non-virtual, non-script)
        for ib in _BUILD_BLOCK_RE.finditer(section_content):
            attrs = ib.group(1) or ""
            if "virtual=" in attrs or "+script" in attrs:
                continue
            iname = ib.group(2)
            icontent = ib.group(3)
            md_lines.append(f"### Embedded: {iname}")
            if attrs:
                md_lines.append(f"**Attrs:** `{attrs}`")
            md_lines.append(f"```\n{icontent}\n```")
            md_lines.append("")

        # File mapping lines (outside inline blocks)
        mapping_lines = _extract_mapping_lines(section_content)
        if mapping_lines:
            md_lines.append("### File Mappings")
            md_lines.append("```")
            md_lines.extend(mapping_lines)
            md_lines.append("```")

        sname_lower = section_name.lower()
        if "suid" in sname_lower:
            doc_type = "build_suid"
        elif "hypervisor" in sname_lower or "qvm" in sname_lower:
            doc_type = "build_hypervisor"
        else:
            doc_type = "build_section"

        meta = {
            **base,
            "type": doc_type,
            "section": f"section/{section_name}",
            "section_name": section_name,
        }
        results.append(make_frontmatter(meta, "\n".join(md_lines)))

    # Fallback: emit raw text if nothing was extracted
    if not results:
        meta = {**base, "type": "build_config", "section": "raw"}
        results.append(make_frontmatter(meta, text))

    return results


def convert_sh(file_path: str, source: str) -> List[str]:
    """
    Convert a shell script (.sh) to a single Markdown+frontmatter document.

    Shell scripts in the QNX boot image (startup.sh, mount_fs.sh, etc.) describe
    the system initialization sequence and are critical for attack-surface analysis.
    They are treated as build_script (atomic) — the full script is one chunk so the
    LLM can reason about the complete execution flow without fragmentation.

    Args:
        file_path: Absolute path to the .sh file.
        source:    Canonical source identifier.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    if not text.strip():
        return []

    fname = os.path.basename(file_path)
    script_name = os.path.splitext(fname)[0]
    body = f"# {fname} — Shell Script\n\n```sh\n{text.strip()}\n```"
    meta = {
        "source": source,
        "file_name": fname,
        "type": "build_script",
        "section": f"startup_script/{fname}",
        "block_name": script_name,
        "page": 0,
    }
    return [make_frontmatter(meta, body)]


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _extract_mapping_lines(section_content: str) -> List[str]:
    """Extract file mapping lines (target=source) that fall outside inline blocks."""
    mapping_lines: List[str] = []
    in_inline = False
    for line in section_content.split("\n"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.search(r"=\s*\{$|\{$", s):
            in_inline = True
            continue
        if s == "}":
            in_inline = False
            continue
        if in_inline:
            continue
        if "=" in s and "{" not in s:
            mapping_lines.append(s)
        elif s.startswith("[") and "{" not in s:
            mapping_lines.append(s)
    return mapping_lines
