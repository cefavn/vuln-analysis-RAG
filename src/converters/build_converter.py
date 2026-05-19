# converters/build_converter.py — QNX build-config files → Markdown+frontmatter converter.
#
# Handles .build (IFS config), .sh (shell scripts), .layout (disk partition config).
# All output is type=build_config.
#
# .build files: split by ### Section ### comment delimiters if present; otherwise
# the whole file is one document (e.g. ifs.build which uses [virtual=]/[+script] blocks
# without named section delimiters).
import os
import re
from typing import Any, Dict, List

from converters.utils import make_frontmatter

# ### Section Name ### delimiters (20+ # characters per line)
_BUILD_SECT_RE = re.compile(
    r"^#{20,}\n"
    r"#{0,3}[ \t]*(.+?)[ \t]*#{0,3}?\n"
    r"#{20,}",
    re.MULTILINE,
)


def convert_build_config(file_path: str, source: str) -> List[str]:
    """
    Convert a QNX build-config file (.build, .sh, .layout) to Markdown+frontmatter strings.
    All output documents have type=build_config.

    .sh / .layout: single atomic document (full file content in a code block).
    .build without ### Section ### delimiters: single atomic document.
    .build with sections: one document per section plus a preamble document if non-empty.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    if not text.strip():
        return []

    fname = os.path.basename(file_path)
    ext = os.path.splitext(fname)[1].lower()
    base: Dict[str, Any] = {"source": source, "file_name": fname, "type": "build_config", "page": 0}

    if ext in (".sh", ".layout"):
        lang = "sh" if ext == ".sh" else ""
        body = f"# {fname}\n\n```{lang}\n{text.strip()}\n```"
        return [make_frontmatter({**base, "section": fname}, body)]

    # .build: split by named sections if present
    section_matches = list(_BUILD_SECT_RE.finditer(text))

    if not section_matches:
        body = f"# {fname}\n\n```\n{text.strip()}\n```"
        return [make_frontmatter({**base, "section": "full"}, body)]

    results: List[str] = []

    preamble = text[:section_matches[0].start()].strip()
    if preamble:
        body = f"# {fname} — Configuration\n\n```\n{preamble}\n```"
        results.append(make_frontmatter({**base, "section": "preamble"}, body))

    for idx, sm in enumerate(section_matches):
        section_name = sm.group(1).strip()
        sec_start = sm.end()
        sec_end = section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(text)
        content = text[sec_start:sec_end].strip()
        if not content:
            continue
        body = f"# {fname} — {section_name}\n\n```\n{content}\n```"
        meta = {**base, "section": f"section/{section_name}", "page": idx + 1}
        results.append(make_frontmatter(meta, body))

    return results or [make_frontmatter({**base, "section": "raw"}, text)]
