# Evaluation Report — run-1

Generated: 2026-04-27 09:31  

## Final Ranking

| Rank | System | Composite Score | Criteria Score | Rank Bonus | Cases |
|:----:|--------|:--------------:|:--------------:|:----------:|:-----:|
| 1 | **gd2** | 100.00% | 100.00% | 100.00% | 3 |
| 2 | **base** | 85.62% | 91.43% | 33.33% | 3 |
| 3 | **gd1** | 68.48% | 72.38% | 33.33% | 3 |

> **#1 gd2**: Highest composite score (100.00%) [criteria: 100.00%, rank bonus: 100.00%] with strongest criteria: c3_trace_source_to_sink=1.000, c4_vuln_hypothesis=1.000, c10_low_false_positive=1.000.  
> **#2 base**: Composite score 85.62% (criteria: 91.43%, rank bonus: 33.33%); trails rank 1 by 14.38 points; largest criterion gaps: c7_pattern_or_cve_reference (-0.667), c4_vuln_hypothesis (-0.067).  
> **#3 gd1**: Composite score 68.48% (criteria: 72.38%, rank bonus: 33.33%); trails rank 1 by 31.52 points; largest criterion gaps: c7_pattern_or_cve_reference (-0.567), c10_low_false_positive (-0.333).  

## Criteria Breakdown

| Criterion | Weight | gd2 | base | gd1 |
|-----------|:------:|:------:|:------:|:------:|
| `c1_context_correct` | 1.0 | 1.000 | 1.000 | 1.000 |
| `c2_identify_source` | 2.0 | 1.000 | 1.000 | 1.000 |
| `c3_trace_source_to_sink` | 3.0 | 1.000 | 1.000 | 0.667 |
| `c4_vuln_hypothesis` | 3.0 | 1.000 | 0.933 | 0.667 |
| `c5_root_cause_explanation` | 2.0 | 1.000 | 0.933 | 0.667 |
| `c6_correct_location` | 2.0 | 1.000 | 1.000 | 1.000 |
| `c7_pattern_or_cve_reference` | 2.0 | 1.000 | 0.333 | 0.433 |
| `c8_trigger_and_poc_concept` | 2.0 | 1.000 | 0.933 | 0.667 |
| `c9_impact_classification` | 2.0 | 1.000 | 1.000 | 0.667 |
| `c10_low_false_positive` | 2.0 | 1.000 | 1.000 | 0.667 |

## Per-Case Results

| Case | gd2 | gd2 verdict | base | base verdict | gd1 | gd1 verdict | Best |
|------|------:|---------|------:|---------|------:|---------|------|
| `qemu-virtio-net-tx-002` | 100.0% | supported | 87.6% | supported | 98.1% | supported | **gd2** |
| `qemu-virtio-snd-rx-001` | 100.0% | supported | 86.7% | supported | 95.2% | supported | **gd2** |
| `qemu-virtio-snd-rx-003` | 100.0% | supported | 100.0% | supported | 23.8% | not_supported | **gd2** |
