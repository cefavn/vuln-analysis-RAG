from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .io_utils import read_jsonl

try:
    import yaml
except Exception as exc:  # pragma: no cover
    raise RuntimeError("PyYAML is required. Install with: pip install PyYAML") from exc


class IntakeError(ValueError):
    pass


def _expect_str(row: Dict[str, Any], key: str, required: bool = True) -> str:
    if required and key not in row:
        raise IntakeError(f"Missing field '{key}'")
    value = row.get(key, "")
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise IntakeError(f"Field '{key}' must be string")
    return value


def _expect_list_of_str(row: Dict[str, Any], key: str, required: bool = False) -> List[str]:
    if required and key not in row:
        raise IntakeError(f"Missing field '{key}'")
    value = row.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise IntakeError(f"Field '{key}' must be list[str]")
    return value


def _load_markdown_intake(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")

    front_matter = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, flags=re.DOTALL)
    if front_matter:
        return yaml.safe_load(front_matter.group(1))

    fenced = re.search(r"```ya?ml\s*\n(.*?)\n```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        return yaml.safe_load(fenced.group(1))

    raise IntakeError("Markdown intake must contain YAML front matter or a fenced yaml block")


def _load_intake(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Intake file not found: {p}")

    suffix = p.suffix.lower()
    if suffix in {".jsonl"}:
        rows = read_jsonl(p)
        return rows

    if suffix in {".yaml", ".yml"}:
        payload = yaml.safe_load(p.read_text(encoding="utf-8"))
    elif suffix in {".md", ".markdown"}:
        payload = _load_markdown_intake(p)
    else:
        raise IntakeError("Supported intake formats: .jsonl, .yaml/.yml, .md/.markdown")

    if isinstance(payload, dict) and "cases" in payload:
        cases = payload["cases"]
    elif isinstance(payload, list):
        cases = payload
    else:
        raise IntakeError("YAML/Markdown intake must be a list or object with 'cases' list")

    if not isinstance(cases, list) or any(not isinstance(c, dict) for c in cases):
        raise IntakeError("'cases' must be list[object]")
    return cases


def _validate_ground_truth(case_id: str, gt: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(gt, dict):
        raise IntakeError(f"Case {case_id}: 'ground_truth' must be object")

    has_vulnerability = bool(gt.get("has_vulnerability", False))
    vulns = gt.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        raise IntakeError(f"Case {case_id}: ground_truth.vulnerabilities must be list")

    out_vulns: List[Dict[str, Any]] = []
    for i, v in enumerate(vulns):
        if not isinstance(v, dict):
            raise IntakeError(f"Case {case_id}: vulnerability[{i}] must be object")
        vuln_type = _expect_str(v, "vuln_type", required=has_vulnerability)
        if has_vulnerability and not vuln_type.strip():
            raise IntakeError(f"Case {case_id}: vulnerability[{i}].vuln_type is required")

        out_vulns.append(
            {
                "vuln_id": _expect_str(v, "vuln_id", required=False) or f"{case_id}-v{i+1}",
                "vuln_type": vuln_type,
                "severity": _expect_str(v, "severity", required=False),
                "min_impact": _expect_str(v, "min_impact", required=False),
                "location_keywords": _expect_list_of_str(v, "location_keywords", required=False),
                "evidence_keywords": _expect_list_of_str(v, "evidence_keywords", required=False),
                "source_fields": _expect_list_of_str(v, "source_fields", required=False),
                "sink_ops": _expect_list_of_str(v, "sink_ops", required=False),
                "root_cause": _expect_str(v, "root_cause", required=False),
                "trigger_concept": _expect_str(v, "trigger_concept", required=False),
            }
        )

    if has_vulnerability and not out_vulns:
        raise IntakeError(f"Case {case_id}: has_vulnerability=true but vulnerabilities is empty")

    return {
        "has_vulnerability": has_vulnerability,
        "vulnerabilities": out_vulns,
    }


def _build_analysis_input(case: Dict[str, Any]) -> str:
    prompt = _expect_str(case, "prompt")
    context = _expect_str(case, "analysis_context", required=False)
    source_code = _expect_str(case, "source_code", required=False)

    parts = [
        "CASE TASK:",
        prompt,
        "",
        "ANALYSIS CONTEXT:",
        context or "(no extra context provided)",
        "",
        "SOURCE / DECOMPILED CODE:",
        source_code or "(no code snippet provided)",
    ]
    return "\n".join(parts).strip()


def _convert_case(case: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    case_id = _expect_str(case, "case_id")
    title = _expect_str(case, "title")
    component = _expect_str(case, "component", required=False)
    tags = _expect_list_of_str(case, "tags", required=False)
    refs = _expect_list_of_str(case, "references", required=False)
    notes = _expect_str(case, "notes", required=False)

    gt = _validate_ground_truth(case_id, case.get("ground_truth", {}))

    analysis_row = {
        "case_id": case_id,
        "title": title,
        "component": component,
        "tags": tags,
        "analysis_input": _build_analysis_input(case),
    }

    ground_truth_row = {
        "case_id": case_id,
        "title": title,
        "component": component,
        "tags": tags,
        "ground_truth": gt,
        "references": refs,
        "notes": notes,
    }
    return analysis_row, ground_truth_row


def _write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build evaluation bundle from intake: analysis input JSONL + ground truth JSONL"
    )
    parser.add_argument("--intake", required=True, help="Intake file: .jsonl, .yaml/.yml, .md")
    parser.add_argument("--analysis-input-out", required=True, help="Output JSONL for Claude case inputs")
    parser.add_argument("--ground-truth-out", required=True, help="Output JSONL for ground truth")
    args = parser.parse_args()

    intake_cases = _load_intake(args.intake)
    if not intake_cases:
        raise IntakeError("Intake has no cases")

    seen = set()
    analysis_rows: List[Dict[str, Any]] = []
    gt_rows: List[Dict[str, Any]] = []
    for case in intake_cases:
        analysis_row, gt_row = _convert_case(case)
        cid = analysis_row["case_id"]
        if cid in seen:
            raise IntakeError(f"Duplicate case_id in intake: {cid}")
        seen.add(cid)
        analysis_rows.append(analysis_row)
        gt_rows.append(gt_row)

    analysis_out = Path(args.analysis_input_out)
    gt_out = Path(args.ground_truth_out)
    _write_jsonl(analysis_out, analysis_rows)
    _write_jsonl(gt_out, gt_rows)

    print(
        json.dumps(
            {
                "status": "ok",
                "cases": len(analysis_rows),
                "analysis_input_out": str(analysis_out),
                "ground_truth_out": str(gt_out),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()