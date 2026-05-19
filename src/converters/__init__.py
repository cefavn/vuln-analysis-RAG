# converters/ — Extract & Transform stage of the ETL pipeline.
#
# Each converter accepts a file path + pre-computed canonical source string
# and returns List[str], where every string is a Markdown document prefixed
# with a YAML frontmatter block carrying all relevant metadata.
#
# The standard intermediate format:
#
#   ---
#   source: rag_docs/decompiled-code/qvm.c
#   type: c_function
#   file_name: qvm.c
#   section: function/handle_write
#   func_name: handle_write
#   page: 0
#   ---
#
#   ## Function: handle_write  [Section 2: Functions]
#   ...
#
# builder.py (the Loader) reads these strings, parses the frontmatter into
# LangChain Document.metadata, and routes to Atomic or Parent-Child chunking
# based on the `type` field.
from converters.pdf_converter import convert_pdf
from converters.c_converter import convert_c, convert_decompiled
from converters.build_converter import convert_build_config
from converters.vuln_pattern_converter import convert_vuln_pattern

__all__ = ["convert_pdf", "convert_c", "convert_decompiled", "convert_build_config", "convert_vuln_pattern"]
