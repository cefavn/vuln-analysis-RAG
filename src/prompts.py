# prompts.py - MCP prompt templates for QNX IVC binary vulnerability analysis
#
# Available prompts:
#   analyze_current_function  — full 6-step vuln analysis on one decompiled function
#   triage_module             — fast attack-surface scan of all functions in a binary
#   trace_data_flow           — trace a guest-controlled value across a multi-function call chain
#   refactor_current_function — rename + annotate for readability before deep analysis
#   generate_poc              — write minimal QNX guest-side PoC from a confirmed hypothesis
#   map_attack_surface        — synthesize session findings into IVC attack surface map + diagram
#   identify_fuzzing_targets  — convert hypotheses into fuzzing specs with harness skeleton


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


def prompt_generate_poc() -> str:
    """
    Write a minimal QNX guest-side PoC from a MEDIUM/HIGH confidence hypothesis.
    Gate: refuses if confidence is LOW or path verdict is OPAQUE.
    Forces QNX-specific APIs; retrieves struct offsets from KB before writing code.
    """
    return """
Write a minimal QNX guest-side PoC program that triggers the vulnerability hypothesis
produced by the preceding analysis session.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 0 — GATE CHECK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Check the most recent hypothesis or trace_data_flow verdict.

STOP and respond "PoC deferred — run trace_data_flow first to confirm the path" if:
  - All hypotheses have confidence LOW, OR
  - Path verdict from trace_data_flow is OPAQUE.

Otherwise extract:
  - Attack vector: SHMEM | MMIO | VIRTQUEUE
  - Target function and dangerous operation (sink)
  - Which guest-controlled field to corrupt and the malicious value
  - Required precondition (e.g., "shmem region must be attached first")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — RETRIEVE STRUCT LAYOUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
search_component_context(component_name="<binary>", extra_context="<target struct> field offset layout")
→ retrieve exact field offsets and sizes from the KB before writing any code.
Do NOT hardcode offsets that were not confirmed by IDA-MCP or RAG.
If offsets are unavailable, mark them with: /* OFFSET_UNKNOWN — verify in IDA */

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — PoC CODE (QNX guest-side ONLY)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Use ONLY these QNX guest-side primitives. Do NOT use Linux-specific APIs.

  SHMEM vector — guest writes to shared memory read by qvm:
    fd  = shm_open("/dev/shmem/<name>", O_RDWR, 0)
    ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)
    // cast ptr to target struct, write malicious field value, trigger the operation

  MMIO vector — guest writes to memory-mapped register:
    ptr = mmap_device_memory(NULL, len, PROT_READ|PROT_WRITE|PROT_NOCACHE, 0, phys_addr)
    // write trigger value to register at known offset

  VIRTQUEUE vector — guest crafts malicious descriptor:
    // write addr/len/flags directly into descriptor ring at known offset

Structure of the PoC:
  1. Setup   — open and map the attack surface (setup preconditions if any)
  2. Trigger — write the malicious value; annotate every write:
               // [HYPOTHESIS N] triggers <type> at <function>:<operation>
  3. Observe — comment on expected observable effect:
               // Expected: qvm crashes (DoS) / memory read possible (Info Leak)
  4. Cleanup — munmap + close fd

Compile command: qcc -Vgcc_ntoaarch64le poc.c -o poc

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — VERIFICATION CHECKLIST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
State for each PoC:
  - Crash oracle:  pidin | grep qvm  → qvm entry disappears = confirmed crash
  - GDB validation: break <sink_function>  then examine registers/stack at hit
  - False positive signal: qvm keeps running, no fault in slogger2 output

Do NOT call add_knowledge_text — PoC source belongs in source control, not the KB.
"""


def prompt_map_attack_surface() -> str:
    """
    Top-down synthesis of IVC attack surface across a full analysis session.
    Produces Mermaid data-flow diagram + attack surface table + thesis-ready summary.
    Run AFTER triage_module + at least one analyze_current_function session.
    KB update: saves high-level attack surface summary.
    """
    return """
Synthesize all findings from this analysis session into a complete IVC attack surface map.

Run this AFTER completing triage_module and at least one analyze_current_function.
Base every node and edge ONLY on facts confirmed by IDA-MCP or RAG — do NOT invent paths.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 0 — CONTEXT RETRIEVAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
search_component_context(component_name="<binary name>")
search_component_context(component_name="IVC <shmem|virtio> mechanism", extra_context="trust boundary data flow")
→ retrieve architecture context and any prior attack surface summaries from the KB.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — DATA FLOW DIAGRAM (Mermaid)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Output a Mermaid flowchart tracing guest data from entry to dangerous operation.
Use confirmed function names from the analysis. Mark unknown nodes with "??".

```mermaid
flowchart LR
    G[Guest VM] -- "UNTRUSTED: <field>" --> E[<entry_function>]
    E -- "validated? YES/NO/PARTIAL" --> M[<intermediate_function>]
    M --> S["SINK: <dangerous_op>"]
```

Edge labels: UNTRUSTED | VALIDATED | PARTIALLY_VALIDATED | OPAQUE
Node shape: rectangles for functions, parallelograms for data stores.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — ATTACK SURFACE TABLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Aggregate all hypotheses and unanalyzed entry points:

| # | Entry Point | Guest Input | Validation | Sink | Hypothesis | Confidence | Priority |
|---|------------|-------------|-----------|------|-----------|-----------|---------|

  - Include ALL Source→Sink paths from this session (any confidence).
  - Mark uninvestigated functions from the triage table as "?? — not yet analyzed".
  - Priority = HIGH/MEDIUM/LOW based on confidence × impact.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — THESIS SUMMARY (3–5 sentences)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Write a concise paragraph for the report:
  - Number of entry points identified and IVC mechanism covered.
  - Distribution of Source→Sink paths: how many validated vs unvalidated.
  - Highest-confidence hypothesis with type and impact.
  - What remains uninvestigated and recommended next steps.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KNOWLEDGE BASE UPDATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Call add_knowledge_text with:
Format: "Attack surface map [binary] [date]: [N] entry points, [N] UNVALIDATED paths.
 Top hypothesis: [type] at [location], [HIGH/MEDIUM] confidence.
 Uninvestigated: [list of ?? functions from Step 2]."
"""


def prompt_identify_fuzzing_targets() -> str:
    """
    Convert MEDIUM/HIGH hypotheses into fuzzing specs: mutation strategy, seed corpus,
    crash oracle, and QNX harness skeleton. Input for building a fuzzer harness.
    Skips LOW confidence and OPAQUE paths.
    """
    return """
Convert the MEDIUM/HIGH confidence hypotheses from this session into fuzzing specifications.

Run this AFTER analyze_current_function or trace_data_flow has produced hypotheses.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 0 — FILTER HYPOTHESES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
From this session, select only:
  - Hypotheses with confidence MEDIUM or HIGH.
  - Paths with verdict UNVALIDATED PATH or PARTIAL GUARD.
Skip LOW confidence and OPAQUE paths — state which were skipped and why.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — RETRIEVE FIELD CONSTRAINTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
For each selected hypothesis:
  search_component_context(component_name="<target function> <binary>",
                           extra_context="<fuzz field> size type constraints valid range")
→ retrieve field width, declared max size, and any known valid values from the KB.
Use this to compute meaningful boundary values — do not guess.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — FUZZING SPEC (one block per hypothesis)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
For each selected hypothesis, produce:

  Target:
    Binary / Function : <name>
    Attack vector     : SHMEM | MMIO | VIRTQUEUE
    Fuzz field        : <struct field or register offset>
    Field type        : <uint32_t / char[N] / size_t / ...>

  Mutation strategy:
    Boundary values   : 0, 1, declared_max-1, declared_max, declared_max+1
    Overflow probes   : UINT32_MAX, INT32_MAX, INT32_MAX+1, SIZE_MAX
    Page boundaries   : 0x1000-1, 0x1000, 0x10000, 0x100000
    Valid seed        : <known-good value from IDA or KB>

  Crash oracle (in order of reliability):
    1. pidin | grep qvm  →  entry disappears = qvm crashed (confirmed DoS)
    2. slogger2 shows fault at <expected function>
    3. Guest-side operation returns error code unexpectedly (may indicate host fault)

  Harness skeleton (QNX guest C):
    // Setup: identical to PoC — open and map the attack surface
    uint32_t mutations[] = { /* boundary values above */ };
    for (int i = 0; i < N; i++) {
        write mutations[i] to fuzz_field at known offset
        trigger the operation that causes qvm to read the field
        check crash oracle (poll pidin or check return code)
        reset state if possible (re-attach, re-open)
    }

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — PRIORITY TABLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
| # | Target Function | Fuzz Field | Vector | Confidence | Expected Impact | Fuzz First? |
|---|----------------|-----------|--------|-----------|----------------|------------|

Order: HIGH confidence first, then by impact severity (VM Escape > Memory Corruption > DoS > Info Leak).

Do NOT call add_knowledge_text — fuzzing specs belong in an engineering document, not the KB.
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
      "compounding_impact": "string or null",
      "pattern_basis": "string or null",
      "evidence": ["string"]
    }
  ],
  "reasoning_summary": "string"
}
Rules:
- Use any of your available context/tools (project prompt, MCP server).
- If no vulnerability is found, set "abstained": true and "findings": []
"""