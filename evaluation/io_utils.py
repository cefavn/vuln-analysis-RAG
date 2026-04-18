from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, List


def read_jsonl(path: str | Path) -> List[dict[str, Any]]:
    data: List[dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")

    raw = p.read_text(encoding="utf-8")

    # First, try strict JSONL parsing (one object per non-empty line).
    parse_error: Exception | None = None
    for i, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            parse_error = ValueError(f"Invalid JSONL at {p}:{i}: {exc}")
            data = []
            break
        if not isinstance(row, dict):
            raise ValueError(f"Each JSONL row must be an object, got {type(row).__name__} at line {i}")
        data.append(row)

    if data:
        return data

    # Fallback 1: support pretty JSON files (array of objects or single object).
    try:
        payload = json.loads(raw)
        if isinstance(payload, list):
            if any(not isinstance(x, dict) for x in payload):
                raise ValueError(f"JSON array in {p} must contain objects only")
            return payload
        if isinstance(payload, dict):
            return [payload]
    except json.JSONDecodeError:
        pass

    # Fallback 2: support concatenated JSON objects in one file.
    decoder = json.JSONDecoder()
    idx = 0
    stream_rows: List[dict[str, Any]] = []
    n = len(raw)
    while idx < n:
        while idx < n and raw[idx].isspace():
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = decoder.raw_decode(raw, idx)
        except json.JSONDecodeError:
            stream_rows = []
            break
        if not isinstance(obj, dict):
            raise ValueError(f"Concatenated JSON in {p} must contain objects only")
        stream_rows.append(obj)
        idx = end

    if stream_rows:
        return stream_rows

    if parse_error is not None:
        raise parse_error
    raise ValueError(f"File {p} is neither valid JSONL nor valid JSON object/array")
    return data


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def write_csv(path: str | Path, headers: list[str], rows: Iterable[list[Any]]) -> None:
    import csv

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)
