from __future__ import annotations

import argparse
import json
import math
from statistics import mean, median
from typing import Dict, List, Sequence, Tuple

from .io_utils import write_csv, write_json


def _load_summary(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError(f"Invalid summary JSON: {path}")
    return payload


def _paired_scores(summary_a: dict, summary_b: dict) -> Tuple[List[float], List[float], List[str]]:
    cases_a = {c["case_id"]: c for c in summary_a.get("cases", [])}
    cases_b = {c["case_id"]: c for c in summary_b.get("cases", [])}
    shared = sorted(set(cases_a).intersection(cases_b))
    if not shared:
        raise ValueError("No shared case_id between judge summaries")
    scores_a = [float(cases_a[cid]["weighted_score"]) for cid in shared]
    scores_b = [float(cases_b[cid]["weighted_score"]) for cid in shared]
    return scores_a, scores_b, shared


def _sign_or_wilcoxon(scores_a: Sequence[float], scores_b: Sequence[float]) -> dict:
    diffs = [a - b for a, b in zip(scores_a, scores_b)]
    non_zero = [d for d in diffs if abs(d) > 1e-12]
    if not non_zero:
        return {
            "method": "sign_test",
            "n": 0,
            "p_value": 1.0,
            "median_diff": 0.0,
            "mean_diff": 0.0,
        }

    pos = sum(1 for d in non_zero if d > 0)
    neg = sum(1 for d in non_zero if d < 0)
    n = pos + neg
    k = min(pos, neg)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    p_value = min(1.0, 2 * tail)
    method = "sign_test"

    try:
        from scipy.stats import wilcoxon  # type: ignore

        stat = wilcoxon(scores_a, scores_b, zero_method="wilcox", alternative="two-sided")
        p_value = float(stat.pvalue)
        method = "wilcoxon"
    except Exception:
        pass

    return {
        "method": method,
        "n": n,
        "p_value": round(float(p_value), 8),
        "median_diff": round(median(non_zero), 6),
        "mean_diff": round(mean(non_zero), 6),
    }


def compare_judge_summaries(summary_a: dict, summary_b: dict) -> dict:
    scores_a, scores_b, shared = _paired_scores(summary_a, summary_b)
    test = _sign_or_wilcoxon(scores_a, scores_b)

    agg_a = summary_a.get("aggregate", {})
    agg_b = summary_b.get("aggregate", {})

    def _delta(metric: str) -> float:
        return float(agg_a.get(metric, 0.0)) - float(agg_b.get(metric, 0.0))

    crit_a = summary_a.get("criteria_summary", {})
    crit_b = summary_b.get("criteria_summary", {})
    crit_keys = sorted(set(crit_a).intersection(crit_b))
    delta_criteria = {
        k: round(float(crit_a[k].get("mean", 0.0)) - float(crit_b[k].get("mean", 0.0)), 6)
        for k in crit_keys
    }

    return {
        "meta": {
            "system_a": summary_a.get("meta", {}).get("system_id", "A"),
            "run_a": summary_a.get("meta", {}).get("run_id", "run-a"),
            "system_b": summary_b.get("meta", {}).get("system_id", "B"),
            "run_b": summary_b.get("meta", {}).get("run_id", "run-b"),
            "shared_cases": len(shared),
        },
        "delta_metrics_a_minus_b": {
            "weighted_score_mean": round(_delta("weighted_score_mean"), 6),
            "weighted_score_mean_percent": round(_delta("weighted_score_mean_percent"), 6),
            "attack_surface_precision_manual": round(_delta("attack_surface_precision_manual"), 6),
            "attack_surface_precision_fuzzing": round(_delta("attack_surface_precision_fuzzing"), 6),
        },
        "delta_criteria_mean_a_minus_b": delta_criteria,
        "paired_test": test,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare judge summaries for A/B evaluation")
    parser.add_argument("--summary-a", required=True)
    parser.add_argument("--summary-b", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--output-csv", required=False)
    args = parser.parse_args()

    summary_a = _load_summary(args.summary_a)
    summary_b = _load_summary(args.summary_b)
    payload = compare_judge_summaries(summary_a, summary_b)
    write_json(args.output, payload)

    if args.output_csv:
        row = payload["delta_metrics_a_minus_b"]
        test = payload["paired_test"]
        write_csv(
            args.output_csv,
            headers=[
                "delta_weighted_score_mean",
                "delta_weighted_score_mean_percent",
                "delta_attack_surface_precision_manual",
                "delta_attack_surface_precision_fuzzing",
                "paired_test_method",
                "paired_test_p_value",
                "paired_test_median_diff",
                "paired_test_mean_diff",
            ],
            rows=[[
                row["weighted_score_mean"],
                row["weighted_score_mean_percent"],
                row["attack_surface_precision_manual"],
                row["attack_surface_precision_fuzzing"],
                test["method"],
                test["p_value"],
                test["median_diff"],
                test["mean_diff"],
            ]],
        )

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()