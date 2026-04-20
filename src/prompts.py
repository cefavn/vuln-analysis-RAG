# prompts.py - MCP prompt templates for QNX IVC binary vulnerability analysis
#
# Available prompts:
#   analyze_current_function  — full 6-step vuln analysis on one decompiled function
#   triage_module             — fast attack-surface scan of all functions in a binary
#   trace_data_flow           — trace a guest-controlled value across a multi-function call chain
#   refactor_current_function — rename + annotate for readability before deep analysis


def prompt_analyze_current_function() -> str:
    """
    Orchestrates the full 6-step vulnerability analysis defined in the System Prompt.
    Handles RAG retrieval timing (Phase A before Steps 1-2, Phase B before Step 3)
    and KB update criteria. Does not redefine the analysis steps themselves.
    """
    return """
Analyze the currently selected function for security vulnerabilities.
Execute the 6-step analysis framework defined in the System Prompt.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 0 — DECOMPILE & RETRIEVE (before any analysis)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Decompile the current function via the reverse tool. Keep code internal — do NOT output it.

2. Phase A — Architecture Context (before Steps 1–2):
   search_component_context(component_name="<binary or function name>")
   If struct/field names are visible in the code:
   search_component_context(component_name="<struct name>", extra_context="<field name>")

3. Execute Steps 1 through 6 exactly as defined in the System Prompt.

4. Phase B — Vulnerability Patterns (after Step 2, before Step 3):
   For each unvalidated Source→Sink path found in Step 2, call:
   search_vulnerability_patterns(vuln_type="<bug class>", code_context="<suspicious snippet>")

Do NOT output decompiled code or RAG text verbatim.
Label every non-trivial claim: [FACT] [OBSERVATION] [HYPOTHESIS].

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KNOWLEDGE BASE UPDATE — only when justified
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Call add_knowledge_text ONLY IF at least one of these is true:
  - A HIGH-confidence hypothesis was found (novel unvalidated Source→Sink).
  - A new data structure layout or trust boundary was discovered not in the KB.
  - This function is a confirmed entry point for guest data not previously documented.

Format: "Analysis of [function]/[binary]: [distilled finding — one paragraph max]"
Do NOT save: LOW-confidence speculation, already-known patterns, routine summaries.
"""


def prompt_triage_module() -> str:
    """
    Fast attack-surface triage of all functions in the currently opened binary/module.
    Goal: identify which functions deserve deep analysis. No KB update.
    """
    return """
Perform a fast attack-surface triage of all functions in the current binary/module.
Goal: rank functions by likelihood of containing exploitable guest-controlled paths.
Do NOT do full 6-step analysis yet — this is reconnaissance, not deep-dive.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 0 — CONTEXT LOOKUP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
search_component_context(component_name="<binary/module name>")
→ retrieves known architecture context before classifying functions.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — ENUMERATE & CLASSIFY (internal, no output of code)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
List all functions. For each, do a fast decompile pass and assign ONE label:

  ENTRY     — directly handles MMIO write / virtqueue descriptor / shared memory
               (receives raw guest data as first-class input)
  HANDLER   — called by an ENTRY function, receives guest data as parameter
  LIFECYCLE — connect / disconnect / detach / create / destroy handler
               (race condition and use-after-free risk)
  SINK      — contains dangerous operations (memcpy, mmap, kill, MsgSendPulse)
               but origin of inputs unclear from function signature alone
  UTILITY   — internal helper with no visible guest contact

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — OUTPUT: TRIAGE TABLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
| Priority | Function Name | Label | Reason | Recommended Next Action |
|----------|--------------|-------|--------|------------------------|
| 1        | ...          | ENTRY | ...    | analyze_current_function |

Sort by: ENTRY first, LIFECYCLE second, HANDLER third, SINK fourth, UTILITY last.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — ATTACK SURFACE SUMMARY (3–5 sentences)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summarize:
- How many ENTRY points exist and what guest-controlled inputs they accept.
- Which LIFECYCLE functions could be involved in race conditions or UAF.
- Any SINK functions that appear reachable from ENTRY without obvious validation.
- Top 3 functions to analyze next, ranked by attack surface priority.

Do NOT output decompiled code.
Do NOT call add_knowledge_text — triage findings are working notes, not KB-worthy insights.
"""


def prompt_trace_data_flow() -> str:
    """
    Trace a guest-controlled value across a multi-function call chain.
    Use after triage identifies a suspicious path: entry → ... → dangerous sink.
    KB update: only if a confirmed cross-function unvalidated path is found.
    """
    return """
Trace how a guest-controlled value propagates through a sequence of function calls
from the IVC entry point to a dangerous sink operation.

Use this prompt when you have already identified:
  - A function that directly receives guest-controlled data (the SOURCE function).
  - A downstream function that performs a dangerous operation (the SINK function).
  - One or more intermediate functions in the call chain between them.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 0 — CONTEXT LOOKUP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
search_component_context(component_name="<binary name> <source function name>")
→ retrieve prior knowledge about this call chain before tracing.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — DECOMPILE THE CALL CHAIN (internal)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Decompile each function in the call chain via the reverse tool.
Keep all code internal — do NOT output it.

For each function, identify:
  - Which parameter or variable carries the guest-controlled value.
  - Whether the value is validated (bounds check, type check, sanitization) before being passed on.
  - Whether the value is transformed (truncated, cast, modified) — and if so, does the
    transformation protect against the dangerous use downstream?

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — OUTPUT: ANNOTATED CALL CHAIN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Show the path as a chain. For each function in the chain:

  [function_name]
    Input : <what this function receives — parameter name, type, origin>
    Action: <what it does with the value — copy, arithmetic, pass-through, validate>
    Output: <what it passes to the next function — same value / modified / result of arithmetic>
    Guard : <any validation before passing — YES (describe) / NO / PARTIAL (describe gap)>
    ↓
  [next_function]
  ...
    ↓
  [SINK: dangerous operation]
    Operation: <memcpy / mmap / kill / MsgSendPulse / ...>
    Guest data used as: <length / destination / PID / size argument>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — PATH VERDICT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
After completing the chain, state ONE of:

  VALIDATED PATH   — guest data is checked at some point before the sink. State where.
  UNVALIDATED PATH — guest data reaches the sink with no effective guard. State the gap.
  PARTIAL GUARD    — validation exists but is incomplete (e.g., checks upper bound but
                     not integer overflow, checks after use, TOCTOU window). Describe the gap.
  OPAQUE           — one or more intermediate functions are not available for analysis.
                     Before declaring OPAQUE, attempt a KB lookup:
                       query_knowledge(query="<missing_function_name> <binary_name>")
                     → if prior analysis exists for that function in another context,
                       incorporate it and re-evaluate. Only declare OPAQUE if the
                     function is truly absent from both the reverse tool and the KB.
                     State which function is missing and what cannot be determined.

For UNVALIDATED PATH or PARTIAL GUARD: output a Hypothesis in Step 4 format
(from the system prompt: Type / Location / Root cause / Pattern basis / Confidence / Status).

Then call:
  search_vulnerability_patterns(vuln_type="<bug class>", code_context="<sink operation>")
  → to confirm which pattern card matches this cross-function path.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KNOWLEDGE BASE UPDATE — only on confirmed unvalidated path
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Call add_knowledge_text ONLY IF verdict is UNVALIDATED PATH or PARTIAL GUARD.

Format:
"Data flow [source_function] → [sink_function] in [binary]:
 Guest-controlled [param] reaches [sink op] via [intermediate functions].
 Guard status: [none / partial — describe gap].
 Hypothesis: [type], confidence [HIGH/MEDIUM]."

Do NOT save VALIDATED PATH results or OPAQUE paths with insufficient evidence.
"""


def prompt_refactor_current_function() -> str:
    """
    Rename function + variables, insert security-focused comments.
    Run this BEFORE deep analysis to make decompiled code readable.
    No output. No KB update.
    """
    return """
Rename and annotate the current function to make it readable for security analysis.
All work is applied silently via the reverse tool — do NOT print anything.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — DECOMPILE (internal only)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Decompile the current function. Keep code internal — do NOT output it.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — GENERATE SUGGESTIONS (internal only)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Produce internally (no output):

A) Function name — describe its role in QNX IVC context.
   Examples: vdev_shmem_create_handler, ivc_validate_guest_size, qvm_detach_cleanup

B) Variable names — use semantic names for:
   - Guest-controlled inputs: guest_len, guest_offset, guest_pid, factory_name
   - Host buffers: host_buf, shm_header, region_map
   - Size/count values: requested_size, page_count, byte_len
   - State/control flags: conn_state, is_attached, detach_pending

C) Inline comments — insert at:
   - Function entry: one-line purpose
   - Each guest-controlled parameter read: // guest-controlled — untrusted
   - Each copy/arithmetic/syscall with guest data: // potential sink — verify bounds
   - Validation checks: // guard: validates X before Y
   - Lifecycle state changes: // state transition: X → Y

If context needed for naming:
   query_knowledge_with_scores(query="<struct or component name>")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — APPLY VIA REVERSE TOOL (silent)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Apply via reverse tool APIs: rename function, rename variables, insert comments.
No output. No KB update.
"""
