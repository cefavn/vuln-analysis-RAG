def prompt_analyze_current_function() -> str:
    """Security analysis of the current function using reverse tools + internal RAG."""
    return f"""
Analyze the current function opened in the MCP reverse tool using the workflow below.

------------------------------------------------------------
1. RETRIEVE FUNCTION CONTEXT
------------------------------------------------------------
- Decompile the currently selected function using the configured MCP reverse tool.
- Treat the decompiled code as internal context (do NOT output it).

------------------------------------------------------------
2. INTERNAL RAG LOOKUP (PRIORITY)
------------------------------------------------------------
When reasoning about APIs, patterns, or behaviors:
- First retrieve supporting information from the **internal knowledge base** via `query_knowledge_with_scores`.
- Only if internal data is insufficient, use external domain knowledge and clearly mark it as **[External Reference]**.

Do NOT include any RAG text in the output.

------------------------------------------------------------
3. ANALYSIS OUTPUT (NO CODE, NO RAG CONTENT)
------------------------------------------------------------
Provide a concise, high-signal analysis including:

- **Purpose of the function** in the context of QNX Hypervisor / QNX Neutrino.
- **Behavior summary** describing what the function does.
- **security implications** (if applicable), such as:
  * IPC spoofing opportunities  
  * Memory corruption risks  
  * Hypervisor boundary or privilege interactions  
  * VM isolation concerns  
  * Input validation weaknesses  
  * Race condition / concurrency issues  
- Optional **MITRE ATT&CK / ICS / Embedded mapping**.

Do NOT output:
- Decompiled function code  
- RAG retrieved text  
- Raw tool output  

------------------------------------------------------------
4. KNOWLEDGE BASE UPDATE
------------------------------------------------------------
Save the final distilled findings using `add_knowledge_text`.

Format:
"Analysis of [function name]/[file name]: [your findings]"

Only save meaningful, non-redundant content.
"""

def prompt_analyze_current_file() -> str:
    """Perform a full security review of all functions in the current QNX module."""
    return f"""
Perform a comprehensive security analysis of the current file opened in the reverse tool.

------------------------------------------------------------
1. ENUMERATE & DECOMPILE FUNCTIONS (INTERNAL)
------------------------------------------------------------
- List all functions in the file.
- Decompile each function internally (NOT printed).

------------------------------------------------------------
2. INTERNAL RAG LOOKUP (STRICT PRIORITY)
------------------------------------------------------------
When analyzing semantics or security behavior:
- Prefer internal knowledge via `query_knowledge_with_scores`.
- External knowledge may be used only when necessary, and must be marked **[External Reference]**.

No RAG text should appear in the final output.

------------------------------------------------------------
3. PER-FUNCTION ANALYSIS (NO CODE)
------------------------------------------------------------
For each function, provide:
- Purpose and behavior
- Key risks
- Likely vulnerabilities
- Recommended test cases or attack vectors

------------------------------------------------------------
4. FILE-LEVEL SECURITY SUMMARY
------------------------------------------------------------
Provide:
- Common vulnerability themes
- Exposed attack surfaces  
- Hypervisor or IPC boundary issues  
- Entry points that handle untrusted data  
- Privileged or sensitive operations  

------------------------------------------------------------
5. KNOWLEDGE BASE UPDATE
------------------------------------------------------------
Store results using `add_knowledge_text`.

Formats:
- "Analysis of [function name]/[filename]: [findings]"
- "Analysis of [filename]: [file-level findings]"

Only save core insights.

Do NOT include:
- Decompiled code
- RAG retrieved text
"""

def prompt_refactor_current_function() -> str:
    """Decompile → get refactor suggestions → optional RAG → apply via reverse tool (no output)."""
    return f"""
Refactor the current function using the exact workflow below.
Do NOT print any code or suggestions in the output.

------------------------------------------------------------
1. DECOMPILE (INTERNAL ONLY)
------------------------------------------------------------
- Decompile the currently selected function using the configured MCP reverse tool.
- Keep the code as internal context only.
- Do NOT output the code.

------------------------------------------------------------
2. REFACTORING SUGGESTIONS (ASK CLAUDE)
------------------------------------------------------------
Using the internal decompiled code, produce:

A) A more descriptive **function name**  
B) Improved **semantic variable names**  
   (IPC, memory regions, hypervisor args, counters, state variables…)  
C) **Short comments**, including:  
   - One-line purpose of the function  
   - Simple workflow description  
   - Basic security observations  
     (unchecked memcpy, missing validation, unsafe parsing, HV boundary issues)

If necessary, internally call `query_knowledge_with_scores` for additional context.

Rules:
- Internal RAG is top priority.
- External info may be used only if explicitly marked **[External Reference]**.
- No RAG text should be shown in the output.

These suggestions must remain internal.

------------------------------------------------------------
3. APPLY REFACTORING USING THE REVERSE TOOL
------------------------------------------------------------
Apply the internal suggestions through the MCP reverse tool:

- Rename the function  
- Rename variables  
- Insert comments in relevant locations  

All modifications must be applied silently.

------------------------------------------------------------
4. NO OUTPUT
------------------------------------------------------------
Do NOT output:
- Decompiled code
- Suggestions
- Variable names
- Comments
- RAG content
- Any analysis

The refactoring is applied directly in the reverse-engineering environment.
"""

def prompt_refactor_entire_file() -> str:
    """Decompile all functions → get refactor suggestions → optional RAG → apply via reverse tool (no output)."""
    return f"""
Refactor ALL functions inside the currently opened file using the workflow below.
Do NOT print any code or suggestions in the output.

------------------------------------------------------------
1. ENUMERATE & DECOMPILE ALL FUNCTIONS (INTERNAL ONLY)
------------------------------------------------------------
- Enumerate all functions in the file/module.
- Decompile each function internally.
- Do NOT output any code.

------------------------------------------------------------
2. REFACTORING SUGGESTIONS (ASK CLAUDE)
------------------------------------------------------------
For EACH function, using its decompiled code, propose:

A) Improved function name  
B) Improved semantic variable names  
C) Short, meaningful comments explaining:
   - purpose  
   - workflow  
   - simple security risks  

Claude may internally use `query_knowledge_with_scores` if needed.

Rules:
- Internal RAG > external references  
- External references must be marked **[External Reference]**  
- No RAG content or suggestions should appear in the output  

------------------------------------------------------------
3. APPLY REFACTORING USING THE REVERSE TOOL
------------------------------------------------------------
For EACH function:

- Rename function  
- Rename variables  
- Insert comments  

Apply everything silently via reverse tool APIs.

------------------------------------------------------------
4. NO OUTPUT
------------------------------------------------------------
Do NOT output:
- Decompiled code  
- Suggestions  
- Per-function logs  
- RAG content  
- Comments  

The final result is that the entire file is refactored inside the reverse-engineering environment.
"""

def prompt_benchmark_analysis() -> str:
    """
    Neutral output formatter for benchmarking gd1 vs gd2.
    Must NOT guide reasoning — reasoning is the system prompt's job.
    Schema extended to capture cascade/heuristic fields that gd2-v2 may produce.
    """
    return """
Analyze the provided case input and return STRICT JSON only using this schema:
{
  "case_id": "string",
  "abstained": false,
  "findings": [
    {
      "vuln_type": "string",
      "location": "string",
      "confidence": "LOW|MEDIUM|HIGH",
      "impact": "string",
      "pattern_basis": "string or null",
      "source_fields": ["string"],
      "source_to_sink": "string",
      "root_cause": "string",
      "trigger_strategy": "string",
      "evidence": ["string"]
    }
  ],
  "reasoning_summary": "string"
}
Rules:
- Use any of your available context/tools (project prompt, MCP server).
- If no vulnerability is found, set "abstained": true and "findings": []
- For each finding: source_fields, source_to_sink, root_cause, and trigger_strategy are required — do not leave empty or null.
- pattern_basis: cite a specific CVE, CVE family, or pattern class if known. Null only if genuinely unknown.
"""