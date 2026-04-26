from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, List, Tuple

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


def _normalize_system_id(row: Dict[str, Any]) -> str:
    raw = row.get("system_id", "unknown")
    if not isinstance(raw, str):
        return "unknown"
    value = raw.strip()
    return value if value else "unknown"


def _parse_system_alias_specs(specs: List[str]) -> Dict[str, str]:
    aliases: Dict[str, str] = {}

    for spec in specs:
        if "=" not in spec:
            raise JudgeResultError(
                "Invalid --system-alias. Expected format: old_system_id=new_system_id"
            )

        old, new = spec.split("=", 1)
        old = old.strip()
        new = new.strip()

        if not old or not new:
            raise JudgeResultError(
                "Invalid --system-alias. Both old and new system_id must be non-empty"
            )

        aliases[old] = new

    return aliases


def _apply_system_aliases(rows: List[Dict[str, Any]], aliases: Dict[str, str]) -> None:
    if not aliases:
        return

    for row in rows:
        current = _normalize_system_id(row)
        row["system_id"] = aliases.get(current, current)


def _normalize_run_id(row: Dict[str, Any]) -> str:
    raw = row.get("run_id", "run-1")
    if not isinstance(raw, str):
        return "run-1"
    value = raw.strip()
    return value if value else "run-1"


def _compact_text(value: Any) -> str:
    return " ".join(str(value).split())


def _load_many_judge_rows(paths: List[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in paths:
        rows.extend(read_jsonl(path))
    return rows


def _ensure_unique_case_rows(judge_rows: List[Dict[str, Any]]) -> None:
    seen: set[Tuple[str, str, str]] = set()
    duplicates: List[Tuple[str, str, str]] = []

    for row in judge_rows:
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise JudgeResultError("Each judge row must have non-empty case_id")

        key = (case_id.strip(), _normalize_system_id(row), _normalize_run_id(row))
        if key in seen:
            duplicates.append(key)
            continue
        seen.add(key)

    if duplicates:
        sample = ", ".join([f"{cid}/{sid}/{rid}" for cid, sid, rid in duplicates[:5]])
        raise JudgeResultError(
            "Duplicate judge rows found for (case_id, system_id, run_id). "
            f"Sample duplicates: {sample}"
        )


def _group_rows_by_system(judge_rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in judge_rows:
        grouped[_normalize_system_id(row)].append(row)
    return {system_id: grouped[system_id] for system_id in sorted(grouped)}


def _build_system_ranking(per_system_summary: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    ranking: List[Dict[str, Any]] = []

    for system_id, summary in per_system_summary.items():
        agg = summary["aggregate"]
        ranking.append(
            {
                "system_id": system_id,
                "cases": int(agg["cases"]),
                "weighted_score_mean": float(agg["weighted_score_mean"]),
                "weighted_score_median": float(agg["weighted_score_median"]),
                "weighted_score_mean_percent": float(agg["weighted_score_mean_percent"]),
                "attack_surface_precision_manual": float(agg["attack_surface_precision_manual"]),
                "attack_surface_precision_fuzzing": float(agg["attack_surface_precision_fuzzing"]),
            }
        )

    ranking.sort(
        key=lambda x: (
            -x["weighted_score_mean"],
            -x["weighted_score_median"],
            -x["attack_surface_precision_manual"],
            -x["attack_surface_precision_fuzzing"],
            x["system_id"],
        )
    )

    for idx, row in enumerate(ranking, start=1):
        row["rank"] = idx

    return ranking


def _attach_ranking_explanations(
    ranking: List[Dict[str, Any]],
    per_system_summary: Dict[str, Dict[str, Any]],
    criteria_order: List[str],
) -> List[Dict[str, Any]]:
    if not ranking:
        return ranking

    leader = ranking[0]
    leader_system = leader["system_id"]
    leader_pct = leader["weighted_score_mean_percent"]
    leader_criteria = per_system_summary[leader_system]["criteria_summary"]

    for row in ranking:
        system_id = row["system_id"]
        criteria_summary = per_system_summary[system_id]["criteria_summary"]

        top_criteria = sorted(
            criteria_order,
            key=lambda k: (
                -float(criteria_summary[k]["mean"]),
                -float(criteria_summary[k]["weight"]),
                k,
            ),
        )[:3]
        top_bits = ", ".join([f"{k}={criteria_summary[k]['mean']:.3f}" for k in top_criteria])

        if row["rank"] == 1:
            row["explanation"] = (
                f"Highest weighted mean ({row['weighted_score_mean_percent']:.2f}%) "
                f"with strongest criteria: {top_bits}."
            )
            continue

        delta = leader_pct - row["weighted_score_mean_percent"]
        gap_rows: List[Tuple[str, float]] = []
        for key in criteria_order:
            gap = float(leader_criteria[key]["mean"]) - float(criteria_summary[key]["mean"])
            if gap > 0:
                gap_rows.append((key, gap))
        gap_rows.sort(key=lambda x: (-x[1], x[0]))

        if gap_rows:
            gap_text = ", ".join([f"{k} (-{gap:.3f})" for k, gap in gap_rows[:2]])
            row["explanation"] = (
                f"Trails rank 1 by {delta:.2f} points; largest criterion gaps: {gap_text}."
            )
        else:
            row["explanation"] = (
                f"Ties leader on criterion means, ranked lower by tie-breakers "
                f"(median/precision/system_id ordering)."
            )

    return ranking


def _load_packet_analysis_by_key(path: str) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    rows = read_jsonl(path)
    out: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for row in rows:
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            continue

        system_id = _normalize_system_id(row)
        run_id = _normalize_run_id(row)
        key = (case_id.strip(), system_id, run_id)

        model_output = row.get("model_output", {})
        if not isinstance(model_output, dict):
            model_output = {}

        findings = model_output.get("findings", [])
        findings_count = len(findings) if isinstance(findings, list) else 0
        first_location = ""
        if findings_count and isinstance(findings[0], dict):
            first_location = _compact_text(findings[0].get("location", ""))

        out[key] = {
            "analysis_summary": _compact_text(model_output.get("reasoning_summary", "")),
            "findings_count": findings_count,
            "first_finding_location": first_location,
        }

    return out


def _build_case_comparison(
    per_system_summary: Dict[str, Dict[str, Any]],
    ranked_system_ids: List[str],
    packet_analysis_by_key: Dict[Tuple[str, str, str], Dict[str, Any]],
) -> Tuple[List[str], List[List[Any]]]:
    by_case_run: Dict[Tuple[str, str], Dict[str, Dict[str, Any]]] = defaultdict(dict)

    for system_id, summary in per_system_summary.items():
        for case_row in summary["cases"]:
            key = (str(case_row["case_id"]), str(case_row["run_id"]))
            by_case_run[key][system_id] = case_row

    headers: List[str] = [
        "case_id",
        "run_id",
        "best_system",
        "best_score_percent",
        "margin_to_second_percent",
    ]
    for system_id in ranked_system_ids:
        headers.extend(
            [
                f"{system_id}_score_percent",
                f"{system_id}_verdict",
                f"{system_id}_judge_rationale",
                f"{system_id}_analysis_summary",
                f"{system_id}_findings_count",
                f"{system_id}_first_finding_location",
            ]
        )

    rows: List[List[Any]] = []
    for (case_id, run_id) in sorted(by_case_run.keys(), key=lambda x: (x[1], x[0])):
        per_system_case = by_case_run[(case_id, run_id)]
        scored = sorted(
            [
                (system_id, float(case["weighted_score_percent"]))
                for system_id, case in per_system_case.items()
            ],
            key=lambda x: (-x[1], x[0]),
        )

        best_system = scored[0][0] if scored else ""
        best_score = scored[0][1] if scored else 0.0
        second_score = scored[1][1] if len(scored) > 1 else best_score
        margin = best_score - second_score

        row_values: List[Any] = [
            case_id,
            run_id,
            best_system,
            round(best_score, 3),
            round(margin, 3),
        ]

        for system_id in ranked_system_ids:
            case = per_system_case.get(system_id)
            if case is None:
                row_values.extend(["", "", "", "", "", ""])
                continue

            packet_info = packet_analysis_by_key.get((case_id, system_id, run_id), {})
            row_values.extend(
                [
                    round(float(case["weighted_score_percent"]), 3),
                    _compact_text(case.get("verdict", "")),
                    _compact_text(case.get("rationale", "")),
                    _compact_text(packet_info.get("analysis_summary", "")),
                    int(packet_info.get("findings_count", 0)),
                    _compact_text(packet_info.get("first_finding_location", "")),
                ]
            )

        rows.append(row_values)

    return headers, rows


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
    parser.add_argument(
        "--judge-results",
        required=True,
        action="append",
        help="Judge output JSONL (repeat this flag to merge multiple files)",
    )
    parser.add_argument("--rubric", required=True, help="Rubric YAML")
    parser.add_argument("--system-id", help="System label override (single-system mode)")
    parser.add_argument("--run-id", default="run-1", help="Run id")
    parser.add_argument(
        "--judge-packets",
        help="Optional judge packet JSONL to enrich comparison report with model analysis summaries",
    )
    parser.add_argument(
        "--system-alias",
        action="append",
        default=[],
        help=(
            "Optional system id remapping in format old_system_id=new_system_id. "
            "Repeat this flag to normalize inconsistent labels across files."
        ),
    )
    parser.add_argument("--output-dir", required=True, help="Output directory")
    args = parser.parse_args()

    judge_rows = _load_many_judge_rows(args.judge_results)
    if not judge_rows:
        raise JudgeResultError("No judge rows found")

    forced_system_id = ""
    if args.system_id is not None:
        forced_system_id = args.system_id.strip()
        if not forced_system_id:
            raise JudgeResultError("--system-id must be non-empty when provided")
        if len(args.judge_results) > 1:
            raise JudgeResultError(
                "--system-id is only supported with a single --judge-results file. "
                "For multi-model aggregation, omit --system-id and use --system-alias if needed."
            )

    aliases = _parse_system_alias_specs(args.system_alias)
    _apply_system_aliases(judge_rows, aliases)

    if forced_system_id:
        for row in judge_rows:
            row["system_id"] = forced_system_id

    _ensure_unique_case_rows(judge_rows)
    rubric = _load_rubric(args.rubric)

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    grouped = _group_rows_by_system(judge_rows)
    systems = list(grouped.keys())

    if len(systems) == 1:
        only_system = systems[0]
        summary = aggregate_judge_results(grouped[only_system], rubric)
        payload = {
            "meta": {
                "mode": "single_system",
                "system_id": args.system_id or only_system,
                "run_id": args.run_id,
                "systems": systems,
                "judge_results_paths": args.judge_results,
                "system_aliases": aliases,
                "rubric_path": args.rubric,
                "tool": "evaluation.aggregate_judge_results",
            },
            **summary,
        }

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
        return

    per_system_summary: Dict[str, Dict[str, Any]] = {
        system_id: aggregate_judge_results(rows, rubric) for system_id, rows in grouped.items()
    }
    criteria_order = [str(c["key"]) for c in rubric["rubric"]["criteria"]]
    ranking = _build_system_ranking(per_system_summary)
    ranking = _attach_ranking_explanations(ranking, per_system_summary, criteria_order)
    ranked_system_ids = [row["system_id"] for row in ranking]

    packet_analysis_by_key: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    if args.judge_packets:
        packet_analysis_by_key = _load_packet_analysis_by_key(args.judge_packets)
        if aliases:
            remapped: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
            for (case_id, system_id, run_id), payload in packet_analysis_by_key.items():
                remapped[(case_id, aliases.get(system_id, system_id), run_id)] = payload
            packet_analysis_by_key = remapped

    case_comparison_headers, case_comparison_rows = _build_case_comparison(
        per_system_summary,
        ranked_system_ids,
        packet_analysis_by_key,
    )

    rank_index = {system_id: idx for idx, system_id in enumerate(ranked_system_ids)}
    long_case_rows: List[Dict[str, Any]] = []
    for system_id in ranked_system_ids:
        long_case_rows.extend(per_system_summary[system_id]["cases"])
    long_case_rows.sort(key=lambda c: (str(c["run_id"]), str(c["case_id"]), rank_index[str(c["system_id"])]))

    aggregate_headers = [
        "system_id",
        "cases",
        "weighted_score_mean",
        "weighted_score_median",
        "weighted_score_mean_percent",
        "attack_surface_proposed_total",
        "attack_surface_validated_manual_total",
        "attack_surface_validated_fuzzing_total",
        "attack_surface_precision_manual",
        "attack_surface_precision_fuzzing",
    ]
    aggregate_rows = []
    for system_id in ranked_system_ids:
        agg = per_system_summary[system_id]["aggregate"]
        aggregate_rows.append([agg[h] if h != "system_id" else system_id for h in aggregate_headers])

    ranking_headers = [
        "rank",
        "system_id",
        "cases",
        "weighted_score_mean",
        "weighted_score_mean_percent",
        "weighted_score_median",
        "attack_surface_precision_manual",
        "attack_surface_precision_fuzzing",
        "explanation",
    ]
    ranking_rows = [
        [
            row["rank"],
            row["system_id"],
            row["cases"],
            row["weighted_score_mean"],
            row["weighted_score_mean_percent"],
            row["weighted_score_median"],
            row["attack_surface_precision_manual"],
            row["attack_surface_precision_fuzzing"],
            row.get("explanation", ""),
        ]
        for row in ranking
    ]

    criteria_headers = ["system_id", "criterion", "weight", "mean", "median"]
    criteria_rows: List[List[Any]] = []
    for system_id in ranked_system_ids:
        criteria_summary = per_system_summary[system_id]["criteria_summary"]
        for criterion in criteria_order:
            stats = criteria_summary[criterion]
            criteria_rows.append([system_id, criterion, stats["weight"], stats["mean"], stats["median"]])

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
        for c in long_case_rows
    ]

    payload = {
        "meta": {
            "mode": "multi_system",
            "run_id": args.run_id,
            "systems": ranked_system_ids,
            "judge_results_paths": args.judge_results,
            "judge_packets_path": args.judge_packets,
            "system_aliases": aliases,
            "rubric_path": args.rubric,
            "tool": "evaluation.aggregate_judge_results",
        },
        "ranking": ranking,
        "systems": {system_id: per_system_summary[system_id] for system_id in ranked_system_ids},
        "case_comparison": {
            "rows": len(case_comparison_rows),
            "columns": len(case_comparison_headers),
        },
    }

    write_json(out / "judge_summary.json", payload)
    write_csv(out / "judge_aggregate.csv", headers=aggregate_headers, rows=aggregate_rows)
    write_csv(out / "judge_model_ranking.csv", headers=ranking_headers, rows=ranking_rows)
    write_csv(out / "judge_criteria_summary.csv", headers=criteria_headers, rows=criteria_rows)
    write_csv(out / "judge_case_scores.csv", headers=case_headers, rows=case_rows)
    write_csv(out / "judge_case_comparison.csv", headers=case_comparison_headers, rows=case_comparison_rows)

    print(
        json.dumps(
            {
                "mode": "multi_system",
                "systems": ranked_system_ids,
                "ranking": [
                    {
                        "rank": row["rank"],
                        "system_id": row["system_id"],
                        "weighted_score_mean_percent": row["weighted_score_mean_percent"],
                    }
                    for row in ranking
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()