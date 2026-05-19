# logger.py — Usage logging for the MCP server.
#
# IMPORTANT: MCP uses stdio transport — stdout is reserved for JSON-RPC messages.
# ALL output here goes to stderr (console) and a file. Never write to stdout.
#
# Two sinks:
#   stderr   — human-readable one-liner per call, visible in MCP client logs.
#   JSONL    — one JSON object per line, persisted to LOG_DIR/mcp_usage.jsonl.
#              In Docker: mount LOG_DIR as a host volume so logs survive container deletion.
#
# Log line format (console):
#   10:30:00 [MCP] query_knowledge           OK   234ms  query='shared memory...' k=5 → 5 results
#
# JSONL format:
#   {"ts":"...","tool":"query_knowledge","args":{...},"ok":true,"ms":234,"n":5}
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Resolve log directory
# ---------------------------------------------------------------------------
# In Docker:  LOG_DIR=/app/logs (set by run_mcp_in_docker.sh), mounted to host.
# Local dev:  defaults to <project_root>/logs/.
_LOG_DIR = Path(os.getenv("LOG_DIR", str(Path(__file__).parent.parent / "logs")))
_LOG_DIR.mkdir(parents=True, exist_ok=True)
_LOG_FILE = _LOG_DIR / "mcp_usage.jsonl"

# ---------------------------------------------------------------------------
# Console logger (stderr only — stdout is the MCP stdio channel)
# ---------------------------------------------------------------------------
_logger = logging.getLogger("mcp_usage")
_logger.setLevel(logging.DEBUG)
_logger.propagate = False

_sh = logging.StreamHandler(sys.stderr)
_sh.setFormatter(logging.Formatter("%(asctime)s [MCP] %(message)s", datefmt="%H:%M:%S"))
_logger.addHandler(_sh)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def log_server_start(min_score: float) -> None:
    """Log one session-start marker so log segments are easy to identify."""
    entry = {
        "ts": _now(),
        "event": "server_start",
        "min_score": min_score,
    }
    _write_jsonl(entry)
    _logger.info(f"{'─' * 60}")
    _logger.info(f"Server started  min_score={min_score}  log={_LOG_FILE}")
    _logger.info(f"{'─' * 60}")


def log_call(
    tool: str,
    args: Dict[str, Any],
    *,
    ok: bool,
    ms: float,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Record one tool invocation.

    Args:
        tool:  MCP tool name (e.g. "query_knowledge").
        args:  Dict of argument names → values (truncated automatically).
        ok:    True if the call succeeded without exception.
        ms:    Wall-clock duration in milliseconds.
        extra: Optional extra fields to include in the JSONL record
               (e.g. {"n": 5} for result count, {"error": "..."} on failure).
    """
    entry: Dict[str, Any] = {
        "ts": _now(),
        "tool": tool,
        "args": _truncate_args(args),
        "ok": ok,
        "ms": round(ms),
        **(extra or {}),
    }
    _write_jsonl(entry)

    status = "OK " if ok else "ERR"
    args_str = _fmt_args(args)
    extra_str = ""
    if extra:
        extra_str = "  " + "  ".join(f"{k}={v}" for k, v in extra.items())
    _logger.info(f"{tool:<40} {status} {ms:6.0f}ms  {args_str}{extra_str}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _write_jsonl(entry: Dict[str, Any]) -> None:
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as e:
        _logger.warning(f"Could not write to log file {_LOG_FILE}: {e}")


def _truncate_args(args: Dict[str, Any], max_len: int = 120) -> Dict[str, Any]:
    """Truncate long string values so JSONL lines stay compact."""
    out = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > max_len:
            out[k] = v[:max_len] + "…"
        else:
            out[k] = v
    return out


def _fmt_args(args: Dict[str, Any], max_val: int = 50) -> str:
    parts = []
    for k, v in args.items():
        if isinstance(v, str):
            s = repr(v[:max_val] + ("…" if len(v) > max_val else ""))
        else:
            s = repr(v)
        parts.append(f"{k}={s}")
    return "  ".join(parts)
