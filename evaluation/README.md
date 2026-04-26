# Evaluation Pipeline

Benchmark pipeline for QNX vulnerability-analysis RAG system.

- Intake from curated bug cases (YAML/Markdown)
- Claude analysis on fixed prompts
- Semantic scoring by a separate judge model
- Aggregation and reporting

## Pipeline Overview

1. Curate bug cases in intake format.
2. Convert intake to two files:
   - `analysis_inputs.jsonl` for Claude runs
   - `ground_truth_bug.jsonl` for judge comparison
3. Run Claude on the cases using the fixed analysis prompt.
4. Build judge packets from ground truth + model outputs + shared rubric.
5. Ask a separate model to score each packet.
6. Aggregate and report scores.

## Files You Will Use

### Scripts

- `build_eval_bundle_from_intake.py`
- `build_judge_packets.py`
- `aggregate_judge_results.py`

### Templates

- `templates/bug_intake.template.yaml`
- `templates/analysis_prompt_short.txt`
- `templates/judge_prompt_short.txt`
- `templates/judge_rubric.template.yaml`
- `templates/claude_output.template.jsonl`
- `templates/judge_results.template.jsonl`

## Step 0: Prepare Environment

From repo root:

```bash
python -m pip install -r requirements.txt
```

For project venv:

```bash
.venv/bin/python -m pip install -r requirements.txt
```

## Step 1: Fill Intake File

Edit:

- `evaluation/templates/bug_intake.template.yaml`

Minimum per case:

- `case_id`, `title`, `component`, `prompt`
- `analysis_context`
- `source_code` (source or decompiled snippet)
- `ground_truth.has_vulnerability`
- `ground_truth.vulnerabilities[]` (for positive cases)
- `references`

Notes:

- Keep negative controls (`has_vulnerability: false`) in the same dataset.
- Keep all evidence links in `references` for audit.

## Step 2: Build Evaluation Bundle

```bash
.venv/bin/python -m evaluation.build_eval_bundle_from_intake \
  --intake evaluation/testcase2/bug_intake.yaml \
  --analysis-input-out evaluation/testcase2/analysis_inputs.jsonl \
  --ground-truth-out evaluation/tmp/ground_truth_bug.jsonl
```

Outputs:

- `evaluation/tmp/analysis_inputs.jsonl`
- `evaluation/tmp/ground_truth_bug.jsonl`

## Step 3: Run Claude

Use the fixed prompt for all cases:

- `evaluation/templates/analysis_prompt_short.txt`

For each row in `analysis_inputs.jsonl`, send:

1. fixed short prompt
2. the row's `analysis_input`

Save outputs with the schema in `templates/claude_output.template.jsonl`:

- `evaluation/tmp/claude_outputs.jsonl`

## Step 4: Build Judge Packets

Recommended (one-shot for multiple models):

```bash
.venv/bin/python -m evaluation.build_judge_packets \
   --ground-truth evaluation/tmp/ground_truth_bug.jsonl \
   --model-output-spec base=evaluation/tmp/claude_outputs_base.jsonl \
   --model-output-spec gd1=evaluation/tmp/claude_outputs_gd1.jsonl \
   --model-output-spec gd2=evaluation/tmp/claude_outputs_gd2.jsonl \
   --rubric evaluation/templates/judge_rubric.template.yaml \
   --run-id run-1 \
   --output evaluation/tmp/judge_packets_all_models.jsonl
```

Legacy mode (single model per command, still supported):

```bash
.venv/bin/python -m evaluation.build_judge_packets \
  --ground-truth evaluation/tmp/ground_truth_bug.jsonl \
  --model-output evaluation/tmp/claude_outputs_base.jsonl \
  --rubric evaluation/templates/judge_rubric.template.yaml \
  --system-id base \
  --run-id run-1 \
  --output evaluation/tmp/judge_packets_base.jsonl

.venv/bin/python -m evaluation.build_judge_packets \
  --ground-truth evaluation/tmp/ground_truth_bug.jsonl \
  --model-output evaluation/tmp/claude_outputs_gd1.jsonl \
  --rubric evaluation/templates/judge_rubric.template.yaml \
  --system-id gd1 \
  --run-id run-1 \
  --output evaluation/tmp/judge_packets_gd1.jsonl

.venv/bin/python -m evaluation.build_judge_packets \
  --ground-truth evaluation/tmp/ground_truth_bug.jsonl \
  --model-output evaluation/tmp/claude_outputs_gd2.jsonl \
  --rubric evaluation/templates/judge_rubric.template.yaml \
  --system-id gd2 \
  --run-id run-1 \
  --output evaluation/tmp/judge_packets_gd2.jsonl
```

## Step 5: Run Judge Model

Use a separate model and fixed prompt:

- Prompt file: `evaluation/templates/judge_prompt_short.txt`
- Rubric file: `evaluation/templates/judge_rubric.template.yaml`

For each row in judge packets, ask judge model to return strict JSON.

If using one-shot Step 4 output, save combined judge outputs to:

- `evaluation/tmp/judge_results_all_models.jsonl`

If using legacy per-model packets, save one result file per model, then aggregate together in Step 6:

- `evaluation/tmp/judge_results_base.jsonl`
- `evaluation/tmp/judge_results_gd1.jsonl`
- `evaluation/tmp/judge_results_gd2.jsonl`

Judge output format reference:

- `evaluation/templates/judge_results.template.jsonl`

## Step 6: Aggregate Scores

Combined judge results file:

```bash
.venv/bin/python -m evaluation.aggregate_judge_results \
   --judge-results evaluation/tmp/judge_results_all_models.jsonl \
   --judge-packets evaluation/tmp/judge_packets_all_models.jsonl \
   --rubric evaluation/templates/judge_rubric.template.yaml \
   --run-id run-1 \
   --output-dir evaluation/reports/judge/compare/run-1
```

Or merge legacy per-model judge result files in one command:

```bash
.venv/bin/python -m evaluation.aggregate_judge_results \
   --judge-results evaluation/tmp/judge_results_base.jsonl \
   --judge-results evaluation/tmp/judge_results_gd1.jsonl \
   --judge-results evaluation/tmp/judge_results_gd2.jsonl \
   --system-alias rag_gd1=gd1 \
   --system-alias rag_gd2=gd2 \
   --rubric evaluation/templates/judge_rubric.template.yaml \
   --run-id run-1 \
   --output-dir evaluation/reports/judge/compare/run-1
```

Single-model mode is still supported:

```bash
.venv/bin/python -m evaluation.aggregate_judge_results \
   --judge-results evaluation/tmp/judge_results_gd2.jsonl \
   --rubric evaluation/templates/judge_rubric.template.yaml \
   --system-id rag_gd2 \
   --run-id run-1 \
   --output-dir evaluation/reports/judge/rag_gd2/run-1
```

Generated per run:

- `judge_summary.json`
- `judge_aggregate.csv`
- `judge_model_ranking.csv` (multi-model mode)
- `judge_criteria_summary.csv`
- `judge_case_scores.csv`
- `judge_case_comparison.csv` (multi-model mode, side-by-side)

Ranking logic (multi-model mode):

1. Sort by `weighted_score_mean` (descending)
2. Tie-break by `weighted_score_median`
3. Tie-break by attack-surface precision
4. Final tie-break by `system_id`

`judge_model_ranking.csv` also includes short textual explanations for each rank.

## Recommended Reporting Practice

1. Run at least 3 repeats (`run-1`, `run-2`, `run-3`).
2. Keep one frozen intake version per experiment batch.
3. Store all artifacts for audit:
   - intake
   - analysis inputs
   - Claude outputs
   - judge packets
   - judge outputs
   - reports
4. In thesis, separate:
   - benchmark on known/curated cases
   - discovery results on unknown targets

## Troubleshooting

1. `No module named yaml`
   - Install dependencies with `pip install -r requirements.txt`.

2. Missing case output in Claude file
   - `build_judge_packets` will fill missing cases as abstain-empty output.

3. JSON parse errors in model output files
   - Ensure each row is valid JSON object.
   - Use `templates/claude_output.template.jsonl` and `templates/judge_results.template.jsonl` as strict references.

4. Inconsistent model names (`system_id`) across rows
   - Keep `system_id` stable per model (e.g. always `base`, `gd1`, `gd2`) to avoid split aggregates.
   - If legacy files are inconsistent, use `--system-alias old=new` when aggregating.
