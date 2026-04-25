# converters/utils.py — Shared helpers for all converter modules.
import yaml
from typing import Any, Dict


def make_frontmatter(meta: Dict[str, Any], content: str) -> str:
    """
    Wrap Markdown content with a YAML frontmatter block.

    None and empty-string values are stripped before serialization to keep
    the frontmatter compact. yaml.safe_dump handles quoting of special chars
    (colons, hashes, commas) automatically.

    Example output:
        ---
        file_name: qvm.c
        page: 0
        source: rag_docs/decompiled-code/qvm.c
        type: c_function
        ---

        ## Function: foo ...
    """
    clean = {k: v for k, v in meta.items() if v is not None and v != ""}
    fm = yaml.safe_dump(
        clean,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=True,
    ).rstrip()
    return f"---\n{fm}\n---\n\n{content}"
