from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .io_utils import read_jsonl

try:
    import yaml
except Exception as exc:  # pragma: no cover
    raise RuntimeError("PyYAML is required. Install with: pip install PyYAML") from exc


class JudgePacketError(ValueError):
    pass


def _parse_model_output_specs(specs: List[str]) -> List[Tuple[str, str]]:
    parsed: List[Tuple[str, str]] = []
    seen_system_ids: set[str] = set()

    for spec in specs:
        if "=" not in spec:
            raise JudgePacketError(
                "Invalid --model-output-spec. Expected format: system_id=path/to/model_output.jsonl"
            )

        system_id, path = spec.split("=", 1)
        system_id = system_id.strip()
        path = path.strip()

        if not system_id:
            raise JudgePacketError("Invalid --model-output-spec: empty system_id")
        if not path:
            raise JudgePacketError(f"Invalid --model-output-spec for '{system_id}': empty path")
        if system_id in seen_system_ids:
            raise JudgePacketError(f"Duplicate system_id in --model-output-spec: {system_id}")

        seen_system_ids.add(system_id)
        parsed.append((system_id, path))

    return parsed


def _resolve_system_inputs(args: argparse.Namespace) -> List[Tuple[str, str]]:
    if args.model_output_spec:
        if args.model_output or args.system_id:
            raise JudgePacketError(
                "Use either multi-model mode (--model-output-spec ...) or single-model mode "
                "(--model-output + --system-id), not both"
            )
        return _parse_model_output_specs(args.model_output_spec)

    if not args.model_output:
        raise JudgePacketError("Single-model mode requires --model-output")
    if not args.system_id:
        raise JudgePacketError("Single-model mode requires --system-id")

    system_id = str(args.system_id).strip()
    model_output_path = str(args.model_output).strip()
    if not system_id:
        raise JudgePacketError("Single-model mode: --system-id must be non-empty")
    if not model_output_path:
        raise JudgePacketError("Single-model mode: --model-output must be non-empty")

    return [(system_id, model_output_path)]


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
    parser.add_argument(
        "--model-output",
        help="Model output JSONL (single-model mode)",
    )
    parser.add_argument(
        "--model-output-spec",
        action="append",
        default=[],
        help=(
            "Multi-model mode. Repeat with format system_id=path/to/model_output.jsonl "
            "(e.g. --model-output-spec gd1=evaluation/tmp/claude_outputs_gd1.jsonl)"
        ),
    )
    parser.add_argument("--rubric", required=True, help="Rubric YAML file")
    parser.add_argument("--system-id", help="System id (single-model mode), e.g. rag_gd1_context_only")
    parser.add_argument("--run-id", default="run-1", help="Run id")
    parser.add_argument("--output", required=True, help="Judge packet JSONL output")
    args = parser.parse_args()

    system_inputs = _resolve_system_inputs(args)
    gt_by_case = _load_jsonl_by_case(args.ground_truth)
    rubric = _load_rubric(args.rubric)

    packets: List[Dict[str, Any]] = []
    missing_by_system: Dict[str, int] = {}

    for system_id, model_output_path in system_inputs:
        out_by_case = _load_jsonl_by_case(model_output_path)
        missing_count = 0

        for case_id, gt in gt_by_case.items():
            model_row = out_by_case.get(case_id)
            if model_row is None:
                missing_count += 1
                model_row = {
                    "case_id": case_id,
                    "abstained": True,
                    "findings": [],
                    "raw_output": "",
                }

            packets.append(
                {
                    "case_id": case_id,
                    "system_id": system_id,
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

        missing_by_system[system_id] = missing_count

    out_path = Path(args.output)
    _write_jsonl(out_path, packets)

    print(
        json.dumps(
            {
                "status": "ok",
                "systems": [system_id for system_id, _ in system_inputs],
                "cases_per_system": len(gt_by_case),
                "packets_total": len(packets),
                "missing_model_output_cases": missing_by_system,
                "output": str(out_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()