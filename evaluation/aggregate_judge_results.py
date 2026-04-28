from __future__ import annotations

import argparse
import datetime
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


def _compute_case_rank_scores(per_system_summary: Dict[str, Dict[str, Any]]) -> Dict[str, float]:
    """Per-case rank each system by weighted_score; return mean normalized rank score per system.

    Normalized rank: rank-1 (best) → 1.0, rank-n (worst) → 0.0.
    Ties receive the same (best) rank among tied systems.
    """
    n_systems = len(per_system_summary)
    if n_systems <= 1:
        return {sid: 0.0 for sid in per_system_summary}

    case_scores: Dict[Tuple[str, str], Dict[str, float]] = defaultdict(dict)
    for system_id, summary in per_system_summary.items():
        for case in summary["cases"]:
            key = (str(case["case_id"]), str(case["run_id"]))
            case_scores[key][system_id] = float(case["weighted_score"])

    rank_buckets: Dict[str, List[float]] = {sid: [] for sid in per_system_summary}

    for scores_by_system in case_scores.values():
        sorted_pairs = sorted(scores_by_system.items(), key=lambda x: -x[1])
        rank_map: Dict[str, int] = {}
        current_rank = 1
        for i, (sid, score) in enumerate(sorted_pairs):
            if i > 0 and score < sorted_pairs[i - 1][1]:
                current_rank = i + 1
            rank_map[sid] = current_rank

        for sid, rank in rank_map.items():
            normalized = (n_systems - rank) / (n_systems - 1)
            rank_buckets[sid].append(max(0.0, min(1.0, normalized)))

    return {
        sid: round(mean(scores), 6) if scores else 0.0
        for sid, scores in rank_buckets.items()
    }


_COMPOSITE_WEIGHT = 0.9  # weight for criteria score vs rank score


def _build_system_ranking(
    per_system_summary: Dict[str, Dict[str, Any]],
    rank_scores: Dict[str, float],
) -> List[Dict[str, Any]]:
    """Build ranking using composite_score = 0.9 * weighted_score_mean + 0.1 * rank_score_mean."""
    ranking: List[Dict[str, Any]] = []

    for system_id, summary in per_system_summary.items():
        agg = summary["aggregate"]
        ws_mean = float(agg["weighted_score_mean"])
        rs_mean = rank_scores.get(system_id, 0.0)
        composite = _COMPOSITE_WEIGHT * ws_mean + (1 - _COMPOSITE_WEIGHT) * rs_mean
        ranking.append(
            {
                "system_id": system_id,
                "cases": int(agg["cases"]),
                "weighted_score_mean": ws_mean,
                "weighted_score_median": float(agg["weighted_score_median"]),
                "weighted_score_mean_percent": float(agg["weighted_score_mean_percent"]),
                "rank_score_mean": round(rs_mean, 6),
                "rank_score_mean_percent": round(rs_mean * 100.0, 3),
                "composite_score": round(composite, 6),
                "composite_score_percent": round(composite * 100.0, 3),
                "attack_surface_precision_manual": float(agg["attack_surface_precision_manual"]),
                "attack_surface_precision_fuzzing": float(agg["attack_surface_precision_fuzzing"]),
            }
        )

    ranking.sort(
        key=lambda x: (
            -x["composite_score"],
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
                f"Highest composite score ({row['composite_score_percent']:.2f}%) "
                f"[criteria: {row['weighted_score_mean_percent']:.2f}%, rank bonus: {row['rank_score_mean_percent']:.2f}%] "
                f"with strongest criteria: {top_bits}."
            )
            continue

        delta = leader["composite_score_percent"] - row["composite_score_percent"]
        gap_rows: List[Tuple[str, float]] = []
        for key in criteria_order:
            gap = float(leader_criteria[key]["mean"]) - float(criteria_summary[key]["mean"])
            if gap > 0:
                gap_rows.append((key, gap))
        gap_rows.sort(key=lambda x: (-x[1], x[0]))

        if gap_rows:
            gap_text = ", ".join([f"{k} (-{gap:.3f})" for k, gap in gap_rows[:2]])
            row["explanation"] = (
                f"Composite score {row['composite_score_percent']:.2f}% "
                f"(criteria: {row['weighted_score_mean_percent']:.2f}%, rank bonus: {row['rank_score_mean_percent']:.2f}%); "
                f"trails rank 1 by {delta:.2f} points; largest criterion gaps: {gap_text}."
            )
        else:
            row["explanation"] = (
                f"Composite score {row['composite_score_percent']:.2f}% "
                f"(criteria: {row['weighted_score_mean_percent']:.2f}%, rank bonus: {row['rank_score_mean_percent']:.2f}%); "
                f"ties leader on criterion means, ranked lower by tie-breakers "
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


def _parse_compare_results(
    paths: List[str],
) -> Tuple[List[Dict[str, Any]], Dict[Tuple[str, str], Dict[str, float]]]:
    """Parse compare-mode judge results (one row per case, all models bundled).

    Returns:
        judge_rows: flat per-system rows compatible with aggregate_judge_results()
        judge_rank_scores: {(case_id, run_id): {system_id: normalized_rank_score}}
            normalized: rank-1 → 1.0, rank-n → 0.0
    """
    raw_rows: List[Dict[str, Any]] = []
    for path in paths:
        raw_rows.extend(read_jsonl(path))

    judge_rows: List[Dict[str, Any]] = []
    judge_rank_scores: Dict[Tuple[str, str], Dict[str, float]] = {}

    for row in raw_rows:
        case_id = str(row.get("case_id", "")).strip()
        run_id = str(row.get("run_id", "run-1")).strip() or "run-1"

        results = row.get("results", [])
        if not isinstance(results, list) or not results:
            raise JudgeResultError(f"Case {case_id}: compare result must have non-empty 'results' list")

        # Explode into per-system rows
        for result in results:
            system_id = str(result.get("system_id", "")).strip()
            if not system_id:
                raise JudgeResultError(f"Case {case_id}: result entry missing system_id")
            judge_rows.append(
                {
                    "case_id": case_id,
                    "system_id": system_id,
                    "run_id": run_id,
                    "criteria": result.get("criteria", {}),
                    "attack_surface": result.get("attack_surface", {"proposed": 0, "validated_manual": 0, "validated_fuzzing": 0}),
                    "verdict": result.get("verdict", ""),
                    "rationale": result.get("rationale", ""),
                }
            )

        # Extract judge-provided ranking into normalized scores
        ranking = row.get("ranking", [])
        if isinstance(ranking, list) and ranking:
            n = len(ranking)
            case_rank_scores: Dict[str, float] = {}
            for entry in ranking:
                rank = int(entry.get("rank", 0))
                sid = str(entry.get("system_id", "")).strip()
                if sid and n > 1:
                    case_rank_scores[sid] = max(0.0, (n - rank) / (n - 1))
                elif sid:
                    case_rank_scores[sid] = 1.0
            judge_rank_scores[(case_id, run_id)] = case_rank_scores

    return judge_rows, judge_rank_scores


def _rank_scores_from_judge(
    judge_rank_scores: Dict[Tuple[str, str], Dict[str, float]],
    per_system_summary: Dict[str, Dict[str, Any]],
) -> Dict[str, float]:
    """Aggregate per-case judge rank scores into per-system mean rank score."""
    rank_buckets: Dict[str, List[float]] = {sid: [] for sid in per_system_summary}

    for (case_id, run_id), scores_by_system in judge_rank_scores.items():
        for sid, score in scores_by_system.items():
            if sid in rank_buckets:
                rank_buckets[sid].append(score)

    return {
        sid: round(mean(scores), 6) if scores else 0.0
        for sid, scores in rank_buckets.items()
    }


def _write_markdown_report(
    out_path: Path,
    ranking: List[Dict[str, Any]],
    per_system_summary: Dict[str, Dict[str, Any]],
    criteria_order: List[str],
    run_id: str,
) -> None:
    ranked_sids = [r["system_id"] for r in ranking]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines: List[str] = []

    lines += [f"# Evaluation Report — {run_id}", f"\nGenerated: {now}  ", ""]

    # --- Final Ranking ---
    lines += ["## Final Ranking", ""]
    lines.append(
        "| Rank | System | Composite Score | Criteria Score | Rank Bonus | Cases |"
    )
    lines.append("|:----:|--------|:--------------:|:--------------:|:----------:|:-----:|")
    for row in ranking:
        lines.append(
            f"| {row['rank']} | **{row['system_id']}** "
            f"| {row['composite_score_percent']:.2f}% "
            f"| {row['weighted_score_mean_percent']:.2f}% "
            f"| {row['rank_score_mean_percent']:.2f}% "
            f"| {row['cases']} |"
        )
    lines.append("")
    for row in ranking:
        if "explanation" in row:
            lines.append(f"> **#{row['rank']} {row['system_id']}**: {row['explanation']}  ")
    lines.append("")

    # --- Criteria Breakdown ---
    lines += ["## Criteria Breakdown", ""]
    header = "| Criterion | Weight |" + "".join(f" {sid} |" for sid in ranked_sids)
    sep = "|-----------|:------:|" + "".join(":------:|" for _ in ranked_sids)
    lines += [header, sep]

    criteria_summaries = {sid: per_system_summary[sid]["criteria_summary"] for sid in ranked_sids}
    for c in criteria_order:
        weight = criteria_summaries[ranked_sids[0]][c]["weight"]
        scores = "".join(
            f" {criteria_summaries[sid][c]['mean']:.3f} |" for sid in ranked_sids
        )
        lines.append(f"| `{c}` | {weight} |{scores}")
    lines.append("")

    # --- Per-Case Comparison ---
    lines += ["## Per-Case Results", ""]
    header = "| Case |" + "".join(f" {sid} | {sid} verdict |" for sid in ranked_sids) + " Best |"
    sep = "|------|" + "".join("------:|---------|" for _ in ranked_sids) + "------|"
    lines += [header, sep]

    by_case: Dict[str, Dict[str, Any]] = defaultdict(dict)
    for sid in ranked_sids:
        for case in per_system_summary[sid]["cases"]:
            by_case[case["case_id"]][sid] = case

    for case_id in sorted(by_case.keys()):
        row_parts = [f"| `{case_id}` |"]
        scores: Dict[str, float] = {}
        for sid in ranked_sids:
            case = by_case[case_id].get(sid)
            if case:
                scores[sid] = case["weighted_score_percent"]
                row_parts.append(f" {case['weighted_score_percent']:.1f}% | {case['verdict']} |")
            else:
                row_parts.append(" — | — |")
        best = max(scores, key=lambda s: scores[s]) if scores else "—"
        row_parts.append(f" **{best}** |")
        lines.append("".join(row_parts))

    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate judge model JSONL outputs")
    parser.add_argument(
        "--judge-results",
        action="append",
        default=[],
        help="Per-model judge output JSONL (repeat to merge files). Use with normal packets.",
    )
    parser.add_argument(
        "--compare-results",
        action="append",
        default=[],
        help=(
            "Compare-mode judge output JSONL (multi-model format from --compare packets). "
            "Repeat to merge files. Provides judge-ranked rank scores instead of post-hoc computation."
        ),
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

    if not args.judge_results and not args.compare_results:
        raise JudgeResultError("Provide at least one of --judge-results or --compare-results")
    if args.judge_results and args.compare_results:
        raise JudgeResultError("Use either --judge-results or --compare-results, not both")

    # Parse inputs — compare mode provides judge-ranked scores; normal mode uses post-hoc ranking
    judge_rank_scores_from_judge: Dict[Tuple[str, str], Dict[str, float]] = {}

    if args.compare_results:
        judge_rows, judge_rank_scores_from_judge = _parse_compare_results(args.compare_results)
    else:
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

    if judge_rank_scores_from_judge:
        rank_scores = _rank_scores_from_judge(judge_rank_scores_from_judge, per_system_summary)
        rank_source = "judge"
    else:
        rank_scores = _compute_case_rank_scores(per_system_summary)
        rank_source = "post_hoc"

    ranking = _build_system_ranking(per_system_summary, rank_scores)
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
        "composite_score_percent",
        "weighted_score_mean_percent",
        "rank_score_mean_percent",
        "weighted_score_mean",
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
            row["composite_score_percent"],
            row["weighted_score_mean_percent"],
            row["rank_score_mean_percent"],
            row["weighted_score_mean"],
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
            "rank_score_source": rank_source,
            "judge_results_paths": args.judge_results or args.compare_results,
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
    _write_markdown_report(out / "judge_report.md", ranking, per_system_summary, criteria_order, args.run_id)

    print(
        json.dumps(
            {
                "mode": "multi_system",
                "systems": ranked_system_ids,
                "ranking": [
                    {
                        "rank": row["rank"],
                        "system_id": row["system_id"],
                        "composite_score_percent": row["composite_score_percent"],
                        "weighted_score_mean_percent": row["weighted_score_mean_percent"],
                        "rank_score_mean_percent": row["rank_score_mean_percent"],
                    }
                    for row in ranking
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()