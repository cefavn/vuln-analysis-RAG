from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from .io_utils import read_jsonl

try:
    import yaml
except Exception as exc:  # pragma: no cover
    raise RuntimeError("PyYAML is required. Install with: pip install PyYAML") from exc


class JudgePacketError(ValueError):
    pass


def _load_jsonl_by_case(path: str) -> Dict[str, Dict[str, Any]]:
    rows = read_jsonl(path)
    by_case: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise JudgePacketError(f"Invalid case_id in {path}")
        if case_id in by_case:
            raise JudgePacketError(f"Duplicate case_id in {path}: {case_id}")
        by_case[case_id] = row
    return by_case


def _load_rubric(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Rubric file not found: {path}")
    payload = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "rubric" not in payload:
        raise JudgePacketError("Rubric file must be a YAML object with 'rubric' key")
    return payload


def _write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build judge packets from ground truth + model output + rubric")
    parser.add_argument("--ground-truth", required=True, help="Ground truth JSONL")
    parser.add_argument("--model-output", required=True, help="Claude output JSONL")
    parser.add_argument("--rubric", required=True, help="Rubric YAML file")
    parser.add_argument("--system-id", required=True, help="System id, e.g. rag_gd1_context_only")
    parser.add_argument("--run-id", default="run-1", help="Run id")
    parser.add_argument("--output", required=True, help="Judge packet JSONL output")
    args = parser.parse_args()

    gt_by_case = _load_jsonl_by_case(args.ground_truth)
    out_by_case = _load_jsonl_by_case(args.model_output)
    rubric = _load_rubric(args.rubric)

    packets: List[Dict[str, Any]] = []
    for case_id, gt in gt_by_case.items():
        model_row = out_by_case.get(case_id)
        if model_row is None:
            model_row = {
                "case_id": case_id,
                "abstained": True,
                "findings": [],
                "raw_output": "",
            }

        packets.append(
            {
                "case_id": case_id,
                "system_id": args.system_id,
                "run_id": args.run_id,
                "ground_truth": gt,
                "model_output": model_row,
                "rubric": rubric["rubric"],
                "judge_instructions": (
                    "Score each criterion in [0,1] based on alignment between ground truth and model output. "
                    "Return strict JSON using judge_output_schema."
                ),
            }
        )

    out_path = Path(args.output)
    _write_jsonl(out_path, packets)

    print(
        json.dumps(
            {
                "status": "ok",
                "packets": len(packets),
                "missing_model_output_cases": len([cid for cid in gt_by_case if cid not in out_by_case]),
                "output": str(out_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()