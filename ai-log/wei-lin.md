# AI Use Log: Wei Lin

## 2026-11-02 | Indirect command-injection fix and fresh 120-case evaluation

- **Tool (model):** OpenAI Codex (GPT-5); recorded product calls to
  `google/gemini-3.8-flash` through OpenRouter
- **Files:** related-source retrieval and context tests, `README.md`,
  `FINAL_RESULTS.md`, `IMPROVEMENT_EXPERIMENT_LOG.md`
- **Outcome:** Changed

### What I asked for

Investigate a post-LangGraph CWE-78 regression, fix the underlying evidence
gap without a case-specific shortcut, and run an honest fresh evaluation large
enough to test the latest integrated pipeline rather than reusing the earlier
66 comparison cases.

### How I checked it

Traced the missed sink through an aliased `Runtime.exec(args, argsEnv)` call and
its referenced resource script. Added regression coverage for indirect helper
and local resource retrieval, ran the complete offline suite and CI, then froze
and ran 120 previously untested cases: 60 genuine and 60 safe across six CWEs.
Checked per-CWE metrics, unsafe dismissals, human reviews, latency and cost.

### What I kept or changed

Kept the LangGraph council and earlier bounded-retrieval design. Extended that
bounded evidence path to referenced Java helpers and local shell/batch resources
instead of hard-coding the failed benchmark case. The raw council reached
93.75% precision, 100% recall and 96.77% F1; validated output reached 85.71%
precision, 100% recall and 92.31% F1, with zero unsafe dismissals. The run cost
US$1.922363. Recorded the main remaining limitation: 12 human reviews came from
missing CWE-501 guidance and two from missing citations.

## 2026-10-29 | Measured architecture improvement

- **Tool (model):** OpenAI Codex (GPT-5); comparison calls to
  `google/gemini-3.8-flash` through OpenRouter
- **Files:** context/retrieval, consistency-repair and validation modules,
  regression tests, `IMPROVEMENT_EXPERIMENT_LOG.md`, `FINAL_RESULTS.md`
- **Outcome:** Changed

### What I asked for

Address the failed mutation test and excessive human-review rate using general
evidence and consistency improvements, while preserving the original results
and measuring whether the revised design actually helped on the same cases.

### How I checked it

Used a controlled 66-case comparison with the same model and cases before and
after the change. Added bounded related-source retrieval, CWE-specific review
checks, consistency repair, and validator escalation tests. Preserved both sets
of results and documented regressions as well as gains.

### What I kept or changed

Kept the multi-role council and deterministic safety gate. Improved the evidence
available to the roles and repaired contradictions before validation. The
controlled comparison improved validated F1 to 96.9% and reduced human review;
this was treated as comparative evidence, not as a substitute for the later
fresh 120-case test.

## 2026-10-28 | Frozen final evaluation and high-band evidence

- **Tool (model):** OpenAI Codex (GPT-5); recorded product calls to
  `google/gemini-3.8-flash` through OpenRouter
- **Files:** `FINAL_PROJECT_PLAN.md`, `FINAL_RESULTS.md`,
  `RESPONSIBLE_AI_RISK_ASSESSMENT.md`, `triagebot/config.py`,
  `triagebot/llm/openrouter.py`, ingest/scoring modules, verification scripts,
  tests, and `README.md`
- **Outcome:** Changed

### What I asked for

Complete final-project checkpoints 1-5 against the highest rubric band: lock a
held-out multi-category experiment, fix known reliability issues test-first,
measure the Semgrep recall bottleneck, run and analyse the final evaluation,
and document responsible-AI risks and limitations.

### How I checked it

Recorded the rubric gate before final calls and froze a deterministic 120-case
test sample with no answer-key labels in model inputs. Added red/green tests for
held-out category selection, distant helper context, strict OpenRouter JSON,
and precision/recall/F1. Ran the complete offline suite, a live development
smoke test, Semgrep `p/java` versus `p/java` plus `p/security-audit`, the four
held-out configurations, five mutation pairs, and five repeat cases. Verified
equal case coverage, per-CWE metrics, costs, latency, invalid outputs, ignored
raw artifacts, and source-supported failure examples.

### What I kept or changed

Kept the existing pipeline and evaluator seams. Added strict provider-supported
JSON output, a wider bounded source window, reusable held-out sampling and
per-CWE reporting. Reported the negative mutation result (0/5 required flips)
and category weaknesses rather than tuning after seeing test output. The final
single-plus-council run cost US$1.918870; validation reused council output.

## 2026-10-18 | Final checkpoint integration and recorded run

- **Tool (model):** OpenAI Codex (GPT-5); live product calls to `google/gemini-3.8-flash` through OpenRouter
- **Files:** `triagebot/pipeline.py`, `triagebot/__main__.py`, `tests/test_pipeline.py`, `tests/test_cli.py`, `README.md`, `CHECKPOINT_REPORT.md`
- **Outcome:** Changed

### What I asked for

Review the merged team components, connect the ingest, context, single-agent,
Analyst/Skeptic/Chair, validation and evaluation stages, expose the connected
flow through the terminal menu and subcommands, and prepare the final checkpoint
evidence without exposing the OpenRouter key or answer-key labels to the model.

### How I checked it

Used fixture callers first and ran the complete 177-test offline suite. Then ran
one real single-agent case and one real council case against the pinned OWASP
Benchmark source before the recorded 100-case comparison. Checked equal case
coverage, validation fallbacks, representative failures, and recorded model,
latency, token usage and cost. The recorded single-agent and council runs cost
US$0.355241 and US$1.142351 respectively.

### What I kept or changed

Kept the team's existing plain-function components and injectable caller seam.
Added only the central orchestration and the menu/subcommand wiring needed to
connect them. Analyst and Skeptic run concurrently; Chair runs after both. The
answer key is loaded only by the evaluator after model calls complete.
