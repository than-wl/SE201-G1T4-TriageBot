# Archive: superseded runs and documents

Everything in this folder is **superseded by [EXPERIMENTS.md](../EXPERIMENTS.md)**.
No number here is a current result. For current results, read EXPERIMENTS.md.

The files are kept unchanged, as the record that the checkpoint report and the
members' AI-use logs cite. They were moved here with `git mv` on 9 November
2026, so their history is intact. Links inside them still point to where the
files used to be (for example `evidence/fresh-120/` is now
`archive/evidence/fresh-120/`), and the scripts expect their old locations.

## Why these results were replaced

- **Tuned and tested on overlapping cases.** Earlier runs read the cases they
  got wrong, changed the prompts and settings, and then measured on cases that
  overlapped with the ones they had read. A change made after reading a case
  tends to fix that case, so the scores looked better than they were.
  EXPERIMENTS.md keeps the tuning cases and the reported cases apart.
- **The old mutation test compared mismatched baselines.** Its "original"
  verdicts for the council came from a version of the script without council
  mode, and each mutant ran from a folder holding only the mutated file, so the
  related source that normal runs read was missing. It also had only five
  hand-picked pairs, all in one direction. Step 5 rebuilt it fairly.
- **The old fresh test mixed six types, including one with no guidance.** Its
  120 cases covered six weakness types; one of them (CWE-501, trust boundary)
  had no matching guidance, so most of its human-review cases came from that
  gap rather than from the reviewer. Step 6 uses four types with guidance for
  each.

## What is here

| Path | What it is |
| --- | --- |
| `checkpoint/CHECKPOINT_REPORT.md` | The checkpoint deliverable (a graded submission), kept intact |
| `checkpoint/checkpoint-100/` | The checkpoint run: 100 SQL-injection cases and their B/C/D results |
| `FINAL_RESULTS.md` | The first final-results summary (original 120-case run) |
| `IMPROVEMENT_EXPERIMENT_LOG.md` | The 66-case improvement comparison and its re-runs |
| `FINAL_PROJECT_PLAN.md` | The earlier final-evaluation plan |
| `SUBMISSION_CHECKLIST.md` | The submission checklist for the 2 November package |
| `evidence/original-final-120/` | The first frozen 120-case evaluation |
| `evidence/comparison-66/` | The 66-case comparison and every saved run of it |
| `evidence/fresh-120/` | The second ("fresh") 120-case evaluation, its builder and overlap audit |
| `evidence/prior-samples/` | Sample copies the fresh-120 overlap audit reads |
| `evidence/semgrep/` | The combined `p/java` + `p/security-audit` Semgrep scan used by those runs |
| `verification/` | Scripts that only served those runs: `mutation_check.py`, `prepare_comparison_sample.py`, `repeat_check.py`, `context_retrieval_check.py`, `semantic_measurement.py` |

## Still used

Every case in these runs is retired: `data/samples/retired_cases.json` (407
cases) is built from the samples in `archive/checkpoint/` and
`archive/evidence/`, and the final test shares no case with it. The pilot set
must equal `archive/checkpoint/checkpoint-100/selected_alerts.json`. Nothing
else current reads this folder.
