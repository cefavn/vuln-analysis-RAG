from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, List

from .io_utils import read_jsonl, write_csv, write_json

try:
    import yaml
except Exception as exc:  # pragma: no cover
    raise RuntimeError("PyYAML is required. Install with: pip install PyYAML") from exc


class JudgeResultError(ValueError):
    pass


def _load_rubric(path: str) -> Dict[str, Any]:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "rubric" not in payload or "criteria" not in payload["rubric"]:
        raise JudgeResultError("Rubric YAML must contain rubric.criteria")
    return payload


def _validate_criteria_scores(case_id: str, criteria_scores: Dict[str, Any], criteria_keys: List[str]) -> Dict[str, float]:
    if not isinstance(criteria_scores, dict):
        raise JudgeResultError(f"Case {case_id}: criteria must be object")

    out: Dict[str, float] = {}
    for key in criteria_keys:
        if key not in criteria_scores:
            raise JudgeResultError(f"Case {case_id}: missing criteria.{key}")
        value = criteria_scores[key]
        if not isinstance(value, (int, float)):
            raise JudgeResultError(f"Case {case_id}: criteria.{key} must be numeric")
        score = float(value)
        if score < 0.0 or score > 1.0:
            raise JudgeResultError(f"Case {case_id}: criteria.{key} out of range [0,1]")
        out[key] = score
    return out


def _weighted_score(criteria: Dict[str, float], weights: Dict[str, float]) -> float:
    total_weight = sum(weights.values())
    if total_weight <= 0:
        return 0.0
    weighted_sum = sum(criteria[k] * weights[k] for k in weights)
    return weighted_sum / total_weight


def aggregate_judge_results(judge_rows: List[Dict[str, Any]], rubric: Dict[str, Any]) -> Dict[str, Any]:
    criteria_defs = rubric["rubric"]["criteria"]
    criteria_keys = [str(c["key"]) for c in criteria_defs]
    weights = {str(c["key"]): float(c.get("weight", 1.0)) for c in criteria_defs}
    total_weight = sum(weights.values())

    case_results: List[Dict[str, Any]] = []
    criteria_buckets: Dict[str, List[float]] = {k: [] for k in criteria_keys}

    proposed_total = 0
    validated_manual_total = 0
    validated_fuzzing_total = 0

    for row in judge_rows:
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise JudgeResultError("Each judge row must have non-empty case_id")

        criteria_scores = _validate_criteria_scores(case_id, row.get("criteria", {}), criteria_keys)
        weighted = _weighted_score(criteria_scores, weights)

        attack_surface = row.get("attack_surface", {})
        if not isinstance(attack_surface, dict):
            raise JudgeResultError(f"Case {case_id}: attack_surface must be object")
        proposed = int(attack_surface.get("proposed", 0))
        validated_manual = int(attack_surface.get("validated_manual", 0))
        validated_fuzzing = int(attack_surface.get("validated_fuzzing", 0))

        proposed_total += proposed
        validated_manual_total += validated_manual
        validated_fuzzing_total += validated_fuzzing

        for key, score in criteria_scores.items():
            criteria_buckets[key].append(score)

        case_results.append(
            {
                "case_id": case_id,
                "system_id": str(row.get("system_id", "unknown")),
                "run_id": str(row.get("run_id", "run-1")),
                "weighted_score": round(weighted, 6),
                "weighted_score_percent": round(weighted * 100.0, 3),
                "criteria": criteria_scores,
                "attack_surface": {
                    "proposed": proposed,
                    "validated_manual": validated_manual,
                    "validated_fuzzing": validated_fuzzing,
                },
                "verdict": str(row.get("verdict", "")),
                "rationale": str(row.get("rationale", "")),
            }
        )

    weighted_scores = [c["weighted_score"] for c in case_results]
    aggregate = {
        "cases": len(case_results),
        "rubric_total_weight": round(total_weight, 6),
        "weighted_score_mean": round(mean(weighted_scores), 6) if weighted_scores else 0.0,
        "weighted_score_median": round(median(weighted_scores), 6) if weighted_scores else 0.0,
        "weighted_score_mean_percent": round(mean(weighted_scores) * 100.0, 3) if weighted_scores else 0.0,
        "attack_surface_proposed_total": proposed_total,
        "attack_surface_validated_manual_total": validated_manual_total,
        "attack_surface_validated_fuzzing_total": validated_fuzzing_total,
        "attack_surface_precision_manual": round(validated_manual_total / proposed_total, 6) if proposed_total else 0.0,
        "attack_surface_precision_fuzzing": round(validated_fuzzing_total / proposed_total, 6) if proposed_total else 0.0,
    }

    criteria_summary = {
        k: {
            "weight": weights[k],
            "mean": round(mean(v), 6) if v else 0.0,
            "median": round(median(v), 6) if v else 0.0,
        }
        for k, v in criteria_buckets.items()
    }

    return {
        "aggregate": aggregate,
        "criteria_summary": criteria_summary,
        "cases": case_results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate judge model JSONL outputs")
    parser.add_argument("--judge-results", required=True, help="Judge output JSONL")
    parser.add_argument("--rubric", required=True, help="Rubric YAML")
    parser.add_argument("--system-id", required=True, help="System label")
    parser.add_argument("--run-id", default="run-1", help="Run id")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    args = parser.parse_args()

    judge_rows = read_jsonl(args.judge_results)
    rubric = _load_rubric(args.rubric)
    summary = aggregate_judge_results(judge_rows, rubric)

    payload = {
        "meta": {
            "system_id": args.system_id,
            "run_id": args.run_id,
            "judge_results_path": args.judge_results,
            "rubric_path": args.rubric,
            "tool": "evaluation.aggregate_judge_results",
        },
        **summary,
    }

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    write_json(out / "judge_summary.json", payload)

    write_csv(
        out / "judge_aggregate.csv",
        headers=list(payload["aggregate"].keys()),
        rows=[list(payload["aggregate"].values())],
    )

    criteria_headers = ["criterion", "weight", "mean", "median"]
    criteria_rows = [[k, v["weight"], v["mean"], v["median"]] for k, v in payload["criteria_summary"].items()]
    write_csv(out / "judge_criteria_summary.csv", headers=criteria_headers, rows=criteria_rows)

    case_headers = [
        "case_id",
        "system_id",
        "run_id",
        "weighted_score",
        "weighted_score_percent",
        "verdict",
        "rationale",
    ]
    case_rows = [
        [
            c["case_id"],
            c["system_id"],
            c["run_id"],
            c["weighted_score"],
            c["weighted_score_percent"],
            c["verdict"],
            c["rationale"],
        ]
        for c in payload["cases"]
    ]
    write_csv(out / "judge_case_scores.csv", headers=case_headers, rows=case_rows)

    print(json.dumps(payload["aggregate"], indent=2))


if __name__ == "__main__":
    main()