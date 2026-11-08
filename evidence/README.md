# Evaluation evidence

This folder holds the evidence behind [EXPERIMENTS.md](../EXPERIMENTS.md), the
single source of truth for TriageBot's results. Every file here was written by
the commands below and is committed unchanged.

## What is here

| Folder | What it holds | Written by |
| --- | --- | --- |
| `experiments/<step>-<side>[-repeat-N]/` | One folder per experiment run (steps 1 to 6): every case's role reports (`results.jsonl`), the saved verdicts (`B-single-agent.json`, `C-council.json`, `D-validated-council.json`), the scores (`evaluation.json`, `evaluation_by_cwe.json`), the run manifest (profile, settings, case-set fingerprint, model, commit, cost) and a short `report.md`. Step 5's `5-after/` also holds `mutation_score.json`. | `python -m triagebot experiment run <step>` (paid) |
| `retrieval/` | The free retrieval-quality check of the semantic set-up (step 4, rules R1 to R5): `semantic_setup_check.md` and `.json`, with provenance | `python verification/semantic_setup_check.py --phase score` |
| `whole_system/` | Semgrep alone vs Semgrep plus TriageBot over the whole benchmark for the four types (a projection from step 6): `6-after` (council) and `6-before` (single agent), `.md` and `.json` | `python verification/whole_system.py --mode council` (or `single`) |

A B/C/D file name means single agent / raw council / council after the
deterministic validator. A missing B file means that run had no single-agent
side; it is not missing data.

## Reading and re-scoring it (free)

```bash
python -m triagebot experiment list
python -m triagebot experiment show 6
python -m triagebot experiment replay 6
```

`show` needs nothing (no API key, no answer key). `replay` re-scores the saved
verdicts against the Benchmark answer key, makes no model calls, and checks the
numbers equal the saved evaluation.

## Safety

- No API key, authentication header, `.env` value or user-specific absolute
  path is in these files.
- Result files contain short excerpts from the public OWASP Benchmark source.
- The answer key is used only by the evaluation code, after the model calls;
  no label appears in a prompt or in `results.jsonl`.

## Earlier runs

The checkpoint run, the original 120-case final evaluation, the 66-case
comparison, the fresh 120-case run and the combined Semgrep scan they used were
moved to [archive/](../archive/README.md). They are superseded by EXPERIMENTS.md
and kept unchanged as the record.
