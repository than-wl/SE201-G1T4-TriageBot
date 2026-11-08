# AI use disclosure

This document is the index for TriageBot's final AI-use evidence. It does not
replace the five members' detailed logs.

## Runtime AI in the product

The recorded evaluations used `google/gemini-3.8-flash` through OpenRouter at
temperature 0. TriageBot supplied each call with a Semgrep finding, bounded
source evidence and retrieved security guidance. The OWASP answer-key label was
kept outside all model prompts and used only by the evaluation harness after
predictions were complete.

The twelve experiment runs in [EXPERIMENTS.md](EXPERIMENTS.md) cost US$10.73 in
total, as recorded in their run manifests; the final test (step 6) cost US$0.53
for the single agent and US$1.76 for the council. Model output was treated as
untrusted: the pipeline constrained its structure to a strict JSON schema,
validated exact citations, and converted unsupported output to `human_review`.

## Development assistance by member

| Member | Detailed record | Main recorded contribution areas |
| --- | --- | --- |
| Bradley | [ai-log/bradley.md](ai-log/bradley.md) | Evaluation/scoring harness, mutation-style tests, checkpoint report draft |
| Darren | [ai-log/darren.md](ai-log/darren.md) | Ingest and Semgrep baseline, CLI/setup/CI, repository documentation |
| Hong Yi | [ai-log/hong-yi.md](ai-log/hong-yi.md) | Shared contracts, retrieval/context, review roles, LangGraph and SQLite sessions, semantic retrieval |
| Lisa | [ai-log/lisa.md](ai-log/lisa.md) | Deterministic schema/citation validation and disclosure documentation |
| Wei Lin | [ai-log/wei-lin.md](ai-log/wei-lin.md) | Integration, evaluations, measured architecture improvements, final reporting |

Each member remains responsible for reviewing and explaining submitted work.
The logs record significant tool use, checks performed, and what was kept or
changed. Git-history coverage notes were added on 2 November 2026 so that later
documentation-only work is not mistaken for missing implementation work.

## Final phase: the experiments (8 to 9 November 2026)

Recorded in detail in [ai-log/darren.md](ai-log/darren.md); results in
[EXPERIMENTS.md](EXPERIMENTS.md).

- **Planning and review assistant (Claude, in a chat).** Designed the
  experiment plan, wrote the Claude Code prompts, reviewed the results, and wrote parts of EXPERIMENTS.md (the results, the
  findings and the story). It also graded 24 retrieval chunks blind, without
  seeing the configuration, rank or score
  (`verification/relevance_labels_added.json`).
- **Claude Code (claude-opus-5-5).** Implemented the groundwork (frozen case
  sets, profiles, the experiment runner), steps 1 to 6, the semantic retrieval
  set-up, the mutation set and the final clean-up. It only staged changes;
  Darren reviewed and made every commit.
- **Paid runs.** Every paid model run was started by Darren.

**Where the AI got it wrong, and how it was caught:**

- *Answers cut off.* The output token limit (900) counted the model's hidden
  reasoning, so one call in the step 1 smoke test spent 746 tokens reasoning
  and its answer was cut off. Seen in the smoke test; the limit was raised to
  2,000 (commit `d2c214d`).
- *A test wiped the local vector store.* The checkpoint tests synced the real
  store with a one-chunk fixture, leaving 1 row. Found from a traceback; tests
  now use a temporary store, and a sync that would delete more than half the
  rows is refused (commit `71a9edc`, design decision 30).
- *Normal runs built the store and downloaded a model silently.* A missing
  vector store was built on first use. Normal runs now stop before any model
  call and name the two prepare commands (commit `e39e415`, decision 29).
- *Two old scripts would have switched retrieval silently.* When semantic
  retrieval became the default, `verification/retrieval_comparison.py` and
  `context_retrieval_check.py` would have measured it instead of the map they
  were written for. They were pinned to the map (commit `e39e415`).
- *The old mutation test compared mismatched baselines.* Its council
  "originals" came from a script version without council mode, and mutants
  lacked the related source. Pointed out by Hong Yi and confirmed in the
  planning review; step 5 rebuilt it (decision 30).
- *The council's plausible but incomplete argument.* In step 4 all three
  reviewers dismissed the real path traversal `BenchmarkTest01983`, arguing an
  HTTP header name cannot contain `/` or `\`; `..` is a legal header name and
  still climbs a directory. Found by reading the cases that changed between
  runs; reported in EXPERIMENTS.md, not fixed.

## Known disclosure limitations

- A historical AI-assisted validator commit lacked the required `Assisted-by:`
  trailer. Lisa's log identifies it explicitly; shared history was not rewritten.
- A citation validator proves that quoted text exists. It does not prove the
  model's security interpretation is correct.
- Temperature 0 does not guarantee identical future output because the hosted
  provider and model can change.
- Raw paid-run outputs are excluded from the shared repository because they can
  contain source excerpts. The committed reports retain metrics, methodology,
  limitations and representative failures.

See [RESPONSIBLE_AI_RISK_ASSESSMENT.md](RESPONSIBLE_AI_RISK_ASSESSMENT.md) for
the complete risk register and human-oversight boundary.
