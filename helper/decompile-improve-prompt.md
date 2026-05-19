# Decompiled C Improvement Prompt Spec

Use this spec to build or update the system/user prompts given to the LLM when improving IDA-decompiled C files before ingestion into the RAG pipeline.

---

## Quick Reference (Required Output Format)

```c
/*
 * Binary: <binary_filename_with_extension>
 * SHA256: <64-char hex hash>
 * MD5:    <32-char hex hash>
 */

/* ========================================
 * SECTION: <MEANINGFUL SECTION NAME>
 * ======================================== */

/* AUDIT: <one-paragraph attack surface note for this function> */
ReturnType meaningful_function_name(ParamType meaningful_param_name) {
    meaningful_local_var = ...;
}
```

Constraints:
- Preserve ALL `/* ====...==== */` section dividers exactly (regex depends on them)
- Binary metadata header must stay at file top
- Every function must have exactly one `/* AUDIT: */` comment immediately before its signature
- Do not add `/* AUDIT: */` to struct definitions or constant groups

---

## Detailed Prompt Guide

### Objective

Transform IDA-decompiled C (with names like `iVar1`, `uVar2`, `DAT_00104abc`, `FUN_00101234`) into semantically meaningful C that preserves the original logic while making variables, functions, and types readable. The output is consumed by a C-to-Markdown converter that chunks functions as RAG documents for QNX hypervisor vulnerability analysis.

### Context to provide the LLM

Supply the following as context (via RAG or inline in system prompt):

- QNX Hypervisor API documentation (`qnx-doc/com.qnx.doc.hypervisor.*`)
- QNX vdev API reference (especially vdev lifecycle, guest memory access, virtio functions)
- QNX Neutrino IPC primitives (`MsgSend`, `MsgReceive`, pulse handling)
- Existing `vuln-pattern/` JSON files to inform the AUDIT comment

### Renaming rules

| Original pattern | Rename strategy |
|---|---|
| `iVar1`, `iVar2` | Infer from usage context (e.g. `ret`, `fd`, `len`, `offset`) |
| `uVar1` | `count`, `size`, `flags`, etc. based on usage |
| `DAT_00104abc` | Infer from access pattern (e.g. `g_shm_base`, `g_vdev_state`) |
| `FUN_00101234` | Infer from call site and behavior (e.g. `handle_guest_write`) |
| `param_1`, `param_2` | Infer from type and usage (e.g. `vdev`, `guest_paddr`, `len`) |

### AUDIT comment format

```c
/* AUDIT: <function_role>. <data_flow_note>. <risk or attack surface note>.
 * Relevant patterns: <vuln-pattern names if applicable, e.g. buffer_overflow, race_condition>. */
```

Example:
```c
/* AUDIT: Handles guest-initiated write requests to the shared memory vdev.
 * Copies guest_paddr + len into host buffer without bounds check on len.
 * Risk: integer overflow on len → heap overflow in memcpy. Relevant patterns: buffer_overflow, integer_overflow. */
void vdev_shm_write(vdev_t *vdev, uint64_t guest_paddr, size_t len) {
```

### Section naming conventions

Name sections to match the C converter's routing keywords for optimal doc type assignment:

| Section content | Recommended name |
|---|---|
| `#define` constants, enums | `CONSTANTS` or `#DEFINE MACROS` |
| `typedef struct` definitions | `DATA STRUCTURES` |
| Core logic functions | `SECTION 1: <description>` or `FUNCTIONS: <description>` |
| Initialization functions | `SECTION 2: Initialization` |
| Other named groupings | Any descriptive name (becomes `c_section` type) |

### What NOT to change

- Binary metadata header (SHA256, MD5, binary name)
- `/* ====...==== */` section divider format (must have 10+ `=` chars)
- Function signatures that interact with known QNX APIs (only rename parameters, not function names)
- Struct member names that match official QNX SDK types
- Any `#include` paths

### Quality bar before ingesting

The file is ready for `decompiled/` when:
- [ ] All `FUN_` prefixed names are replaced
- [ ] All `iVar`, `uVar`, `param_N` names in function bodies are replaced
- [ ] All `DAT_` global addresses have meaningful names
- [ ] Every function has a `/* AUDIT: */` comment
- [ ] Section dividers are intact
- [ ] File compiles without errors (at minimum: no syntax errors, type mismatches are acceptable)
