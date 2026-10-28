# AI Use Log: Wei Lin

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
