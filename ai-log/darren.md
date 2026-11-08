# AI Use Log: Darren

Entries follow the SE201 AI Use Disclosure Policy v1.00: one entry per
significant use, committed with the work it describes.

## 2026-10-18 — Repository documentation grooming

- **Tool (model):** Claude Code (claude-opus-5-5); plan and prompt from Claude (Cowork)
- **Files:** README.md, Context/README.md, CHECKPOINT_REPORT.md (path fixes only),
  checkpoint/CHECKPOINT_BRADLEY.md, checkpoint/CHECKPOINT_BRIEF.md,
  checkpoint/CHECKPOINT_DARREN.md, checkpoint/CHECKPOINT_TEAM_TASKS.md,
  checkpoint/Checkpoint_WEILIN_FINAL_INTEGRATION_AND_SUBMISSION.md,
  docs/DESIGN_DECISIONS.md (moved from doc/), docs/proposal/G1T4_Proposal.pdf (moved),
  docs/feasibility/FEASIBILITY_CHECK_REPORT.md (moved, path fix),
  docs/feasibility/OPENROUTER_SMOKE_REPORT.md (moved),
  Context/TriageBot_Proposal_two_page_draft.md (deleted),
  docs/architecture/TriageBot_Architecture_Diagram.drawio.svg,
  docs/architecture/TriageBot_Architecture_Diagram.png, ai-log/darren.md
- **Outcome:** Changed

### What I asked for

Reorganise the repository's documentation: rename `doc/` to `docs/`, move the
shared proposal and feasibility reports out of `Context/` into `docs/`, and fix
every reference to the moved files. Rewrite the README as one coherent document
covering the pipeline stages and their status, setup, running, team roles, AI
disclosure and safety rules, without changing any Python behaviour or tests.

### How I checked it

- Reviewed the staged diff.
- Ran the offline tests: all 46 still pass.
- Had Claude Code search for stale references to moved files.
- Reviewed the rewritten README in Cowork.

### What I kept or changed

- Kept the structure and README as written.
- Left two old `doc/` references in teammates' AI logs unchanged, since they record what was true at the time.

## 2026-10-18 — Ingest, answer-key mapping, split and scanner baseline

- **Tool (model):** Claude Code (claude-opus-5-5); spec from Claude (Cowork)
- **Files:** triagebot/nodes/ingest/normalise.py, triagebot/nodes/ingest/answer_key.py,
  triagebot/nodes/ingest/mapping.py, triagebot/nodes/ingest/split.py,
  triagebot/nodes/ingest/run.py, triagebot/nodes/score/metrics.py,
  triagebot/config.py (additive), triagebot/schemas.py (additive), tests/test_ingest.py,
  tests/fixtures/ingest/semgrep.json, tests/fixtures/ingest/expectedresults.csv,
  README.md, docs/DESIGN_DECISIONS.md, ai-log/darren.md
- **Outcome:** Changed

### What I asked for

Build the ingest stage: normalise Semgrep JSON into NormalisedAlerts, load the OWASP
answer key on the evaluation side only, and compute the scanner-only baseline per
category in "file" and "cwe" modes with a CWE mismatch report. Add a stratified
dev/test split, a balanced CWE-89 checkpoint sample, shared metrics functions, offline
tests and a README section, without letting answer-key data reach any LLM-side output.

### How I checked it

- Reviewed the spec with Claude (Cowork) before running it, including the rule that no answer-key data reaches the LLM side.
- Ran the offline test suite: 94 tests pass (46 existing, 48 new).
- Sanity-checked the real-data run: 1,909 findings, 2,740 answer-key cases (1,415 / 1,325), and "file" mode reproduces the proposal's 995 TP / 520 FP exactly.
- Reviewed the four CWE mismatch pairs and decided the equivalences myself: accepted CWE-326 for CWE-327 (same DES/3DES pattern), rejected CWE-79 for CWE-501, CWE-89 and CWE-643 (different weakness).
- Checked that alerts.json and selected_alerts.json contain no answer-key fields, and reviewed the staged diff.

### What I kept or changed

- Kept the modules, tests and outputs as generated.
- Changed the CWE equivalence table from empty to the single crypto pair after reviewing the mismatch report.
- Asked for an empty BENCHMARK_ROOT to be treated as unset, and recorded decisions 17 and 18.
- Kept both matching modes so the proposal's filename-based numbers stay comparable.

## 2026-10-18 — Validator fix: accept review report shape

- **Tool (model):** Claude Code (claude-opus-5-5); spec from Claude (Cowork)
- **Files:** triagebot/nodes/validate/validator.py, tests/test_validator.py,
  docs/DESIGN_DECISIONS.md, ai-log/darren.md
- **Outcome:** Changed

### What I asked for

Fix the integration mismatch where every real `report.assemble()` output failed the
validator's exact-key check ("Invalid result shape") and became human_review. Keep
the required keys, allow role, guidance, latency_seconds, usage and model as optional,
verify guidance refs against the retrieved chunks (decision 15), and carry guidance,
latency, usage, model and role through to the validated record so evaluate.py can
report latency and cost. Keep Lisa's structure and style, and add regression tests.

### How I checked it

- Reproduced the bug first: a real report.assemble() output failed shape validation and became human_review.
- Ran the full suite: 103 tests pass (94 before, 9 new), none skipped.
- Reviewed the two changed existing tests; both reflect the intended behaviour change, not a weakened check.
- Reviewed the one unrequested change (single-object outputs with extra contract fields are now recognised) and kept it.

### What I kept or changed

- Kept Lisa's structure, required keys and message style; added optional fields, the guidance-reference check and the pass-through of latency, usage and model.
- Left the guidance_chunks wiring to the pipeline owner and flagged it to the team.

## 2026-10-18 — Terminal menu and scanner-baseline option

- **Tool (model):** Claude Code (claude-opus-5-5); spec from Claude (Cowork)
- **Files:** triagebot/__main__.py, tests/test_cli.py, README.md,
  verification/requirements.txt (adds rich), ai-log/darren.md
- **Outcome:** Changed

### What I asked for

Add the TriageBot entry point: `python -m triagebot` opens a terminal menu, and the
same actions are available as `baseline`, `triage` and `evaluate` subcommands that
call the same functions. Make option 1 / `baseline` work by reusing the ingest
functions (same outputs in Context/tmp/checkpoint/) and print the ingest summary, the
CWE-matched table, the file-matched comparison, the recall ceiling, the two
lowest-recall categories and the checkpoint sample, with friendly errors that point to
the README Setup steps. Keep options 2 and 3 as marked placeholders for the pipeline
owner, add offline tests, and update the README.

Then redesign the option 1 screen for a first-time reader (our instructor) using `rich`:
state the scan's provenance (Semgrep version, ruleset, saved date, alert count) and the
answer key it is scored against; lead with plain-English CWE-matched headline numbers;
show a table by vulnerability type with readable names; explain what the numbers mean
for TriageBot (noise, recall ceiling, blind spots) and the checkpoint test set; move
the file-matched comparison, mismatch pairs, ingest counts and file list behind
`--details` / `d`. Add a re-scan option (`--rescan` / `r`) that re-runs Semgrep as in
Setup, keeps the previous file and falls back to it on failure, and make the menu wait
for Enter after each option. Tests render through a fixed-width colourless console and
mock Semgrep.

### How I checked it

- Ran the menu myself with the venv Python: option 1 with the saved scan, the details view, and a real re-scan (1,909 alerts again; previous scan kept as a backup).
- Read the baseline screen as a first-time viewer would and asked for a plain-English redesign (headline, readable category names, no internal jargon).
- Ran the full suite: all tests pass.

### What I kept or changed

- Changed the baseline screen from a raw Markdown dump to a presentable rich layout; technical comparisons moved behind --details.
- Kept the saved scan as the default (fast and offline for demos) and added an optional live re-scan with a backup of the previous result.
- Pinned rich to the version Semgrep already installs, and added a friendly message if the environment isn't active.

## 2026-10-18 — Quick start: recorded scan, setup check, README restructure

- **Tool (model):** Claude Code (claude-opus-5-5); spec from Claude (Cowork)
- **Files:** data/semgrep/semgrep-owasp-p-java-1.178.0.json, data/semgrep/README.md,
  triagebot/nodes/ingest/record_scan.py, triagebot/check.py, triagebot/config.py,
  triagebot/__main__.py, triagebot/nodes/ingest/run.py, requirements.txt (moved from
  verification/; now also pins Semgrep), requirements-scan.txt (added, then merged into
  requirements.txt and removed), .gitignore, README.md,
  docs/screenshots/baseline.svg, tests/test_cli.py, tests/test_record_scan.py,
  checkpoint/Checkpoint_WEILIN_FINAL_INTEGRATION_AND_SUBMISSION.md (path fixes only),
  .github/workflows/tests.yml, ai-log/darren.md
- **Outcome:** Changed

### What I asked for

Make TriageBot easy to set up and understand for a first-time reader (our instructor).
Commit a recorded Semgrep scan (paths made relative by a small one-off normaliser, so
it holds nothing machine-specific) and use it unless a local re-scan exists, with the
baseline screen saying which one is in use; re-scans always write to the git-ignored
local file. Standardise the environment on `.venv` with `requirements.txt` at the root
and `requirements-scan.txt` for Semgrep. Add a `python -m triagebot check` setup check
(also run by the menu) that shows OK / MISSING / WARNING with the command to fix each
problem, offers to clone a missing OWASP Benchmark only on an explicit "y", and stops
option 1 while something required is missing. Add `--export-svg` to save the baseline
screen, and restructure the README around a quick start, results, usage, evaluation
method, developer notes and troubleshooting. Offline tests mock git and Semgrep.

Follow-up: merge `requirements-scan.txt` into `requirements.txt` so one `pip install`
sets up everything (confirmed with `pip check`), and add a Troubleshooting entry for
when Semgrep fails to install (TriageBot still works with the recorded scan). Polish:
option 1 offers "r = re-run Semgrep now" only when Semgrep is found, the setup check
labels WARNING fixes "Optional:" and MISSING fixes "To fix:", and a successful re-scan
says it is now used instead of the recorded scan and how to go back.

Cross-platform hardening: `python -m triagebot` first checks for Python 3.10+ and exits
with one plain message on older versions (`__main__.py` stays parseable by Python 3.8
so the check can run); every hint that shows a command (activating .venv, creating
it, installing Python or the requirements) uses the current OS's variant; the README
explains the macOS built-in Python 3.9 pitfall. Add a GitHub Actions workflow that runs
the offline tests and `python -m triagebot check --no-fail` on Windows, macOS and Linux
with Python 3.10 and 3.12 (never cloning the Benchmark or calling OpenRouter), with a
status badge in the README.

### How I checked it

- Noticed the first recorded scan had 1,908 findings instead of the original 1,909, and had it traced: a taint-analysis timeout in a later re-scan suppressed one LDAP finding (BenchmarkTest00530).
- Re-recorded the original 1,909-finding scan; confirmed the baseline matches the earlier numbers exactly (970 TP / 512 FP / 445 FN / 813 TN).
- Confirmed the recorded scan contains no user names or absolute paths, and that only path strings were changed.
- Ran `python -m triagebot check` and `python -m triagebot baseline` on my machine; ran the full suite (165 tests pass).

### What I kept or changed

- Kept the recorded scan, setup check, environment changes and README structure as generated.
- Changed the recorded scan from the later re-scan back to the original run, and documented the run-to-run variation in data/semgrep/README.md.

## 2026-11-02 | Git-history coverage check

This log covers Darren's authored work on repository documentation, ingest and
answer-key mapping, the Semgrep baseline, validator report compatibility, the
terminal interface, setup checks, recorded scan, cross-platform CI, and final
checkpoint-report edits. Git history shows no later Darren-authored project
commits requiring another AI-use entry. This is a completeness check, not a new
claim that every documentation edit used AI. The checkpoint task guides and old
Draw.io/PNG diagram paths named in the historical entries above were superseded
and removed during final repository cleanup; Git history preserves them.


## 2026-11-08 — Experiment groundwork: frozen case sets, profiles, runner

- **Tool (model):** Claude Code (claude-opus-5-5); prompt written by Darren
- **Files:** triagebot/nodes/ingest/eval_sets.py (new), triagebot/profiles.py (new),
  triagebot/experiments.py (new), experiments/registry.json (new),
  data/samples/ (new: pilot, comparison, final-test, their manifests,
  retired_cases.json, README.md), .gitattributes (new), triagebot/config.py,
  triagebot/__main__.py, triagebot/check.py, triagebot/checkpoints.py,
  triagebot/execution.py, triagebot/llm/openrouter.py,
  triagebot/nodes/context/source_context.py, triagebot/nodes/context/vector_store.py,
  triagebot/nodes/review/prompts.py, triagebot/nodes/review/council/analyst.py,
  triagebot/nodes/review/council/skeptic.py, triagebot/nodes/review/council/chair.py,
  triagebot/nodes/review/single_agent/baseline.py, tests/test_eval_sets.py (new),
  tests/test_profiles.py (new), tests/test_experiments.py (new), tests/test_cli.py,
  tests/test_pipeline.py, tests/test_checkpoints.py, EXPERIMENTS.md (new), README.md,
  docs/DESIGN_DECISIONS.md (decisions 23 to 26), FINAL_RESULTS.md (banner only),
  IMPROVEMENT_EXPERIMENT_LOG.md (banner only), ai-log/darren.md
- **Outcome:** TODO (Darren)

### What I asked for

Lay the groundwork for rebuilding the evaluation as a few clean, replayable
experiments, one change per step, on frozen case sets. Build three label-free
case sets (the pilot equal to the checkpoint sample, a 96-case comparison set and
a 120-case final test that avoids every retired case) with fingerprinted
manifests and a retired-case list. Add named profiles that switch the source
window, related source, the reasoning worksheet and retrieval for one run;
remove the per-type checklists for good. Add an experiment runner with a step
registry, a paid `run` that prints a cost estimate and asks first and saves after
every case, and free `show` and `replay` commands, plus menu option 4. Document
it all in EXPERIMENTS.md and the design decisions. No paid model calls, no
commits; changes staged only.

### How I checked it

Ran the full test suite (302 pass) and had the case sets rebuilt independently on a second machine: byte-identical, with fingerprints matching the manifests. Confirmed no answer-key fields in the sample files, checked the four profiles against the plan, and dry-ran the paid command up to the cost confirmation.

### What I kept or changed

Kept as generated.


## 2026-11-08 — Step 4 set-up: fix the semantic retrieval rules before measuring

- **Tool (model):** Claude Code (claude-opus-5-5); prompt written by Darren (PROMPT_02)
- **Files:** triagebot/config.py, triagebot/profiles.py, triagebot/experiments.py,
  triagebot/nodes/context/retrieval.py, triagebot/nodes/context/cwe_catalogue.py,
  triagebot/nodes/context/vector_store.py, triagebot/nodes/review/prompts.py,
  triagebot/nodes/context/kb/scope.json (new),
  triagebot/nodes/context/MITRE_CWE_NOTICE.md (new), triagebot/nodes/context/kb/README.md,
  tests/semantic_fixture.py (new), tests/test_semantic_setup.py (new),
  tests/test_semantic_retrieval.py, tests/test_experiments.py, .gitattributes,
  EXPERIMENTS.md (step 4 set-up), docs/DESIGN_DECISIONS.md (decision 28), README.md,
  ai-log/darren.md
- **Outcome:** The step 4 semantic set-up is fixed and documented; not yet measured.
  With the real catalogue (CWE 5.0, pinned hash verified) and vector store (3,685
  rows: 3,238 chunks plus 447 pieces of 214 split chunks), `--explain` showed:
  CWE-89 original 2 chunks / 2,256 chars, improved MITRE record + 1 chunk / 2,965
  chars (a Python sheet dropped out); CWE-22 original 3 chunks / 3,357 chars, two
  from Laravel (PHP), improved MITRE record + 3 chunks / 3,969 chars, with Laravel,
  Symfony and the C toolchain sheet gone. 6 of the 9 scan CWEs have MITRE
  alternate terms (none for 326, 328, 501). Kept as known limits: filling stops at
  the first chunk that does not fit, and the 1,500-character MITRE cap cuts later
  mitigations. Semantic prompts now label the guidance block MITRE CWE and OWASP;
  map prompts are byte-identical.

### What I asked for

Fix the semantic retrieval set-up for experiment step 4 by rules stated in advance,
each behind its own switch, with all switches off reproducing the decision 21 set-up
exactly and the `semantic` profile turning all on: alternate terms in the query; the
MITRE record attached first by CWE ID within the unchanged 4,000-character budget;
a hand-written `scope.json` that leaves out retired sheets, the attack-string
catalogue and sheets for other platforms, decided from titles and openings only;
oversized chunks split at load time; and a grounding gate that checks for a valid
MITRE record instead of a score. Record the set-up and the scope file's hash in run
manifests, add a free `--explain` command, reproduce MITRE's terms of use (one fetch
of the terms page, nothing else online), offline tests, and document it for the
slides. No model calls, no paid runs, no commits; changes staged only.

### How I checked it

The assistant ran the offline suite: 302 tests before, 351 after (1 skipped), with
the "all switches off" result and the map-mode prompts pinned to output recorded
from the previous code. It then installed the catalogue with the pinned-hash
command, built the vector store and ran `--explain` for CWE-89 and CWE-22 under
both set-ups (no model calls). TODO (Darren): own checks.

### What I kept or changed

TODO (Darren)

## 2026-11-09 — Step 4, item 2: free retrieval-quality check of the set-up rules

- **Tool (model):** Claude Code (claude-opus-5-5); prompt written by Darren (PROMPT_03)
- **Files:** verification/semantic_setup_check.py (new), tests/test_semantic_setup_check.py (new),
  verification/relevance_to_grade.json (new), evidence/retrieval/semantic_setup_check.json (new),
  evidence/retrieval/semantic_setup_check.md (new), EXPERIMENTS.md (step 4, "Retrieval-quality
  check"), ai-log/darren.md
- **Outcome:** Measured, no model calls (local embedder only). Part A, macro over the 9 scan
  CWEs, original → improved: P@3 0.63 → 0.67, P@6 0.54 → 0.57, mean grade 1.33 → 1.44;
  MITRE record in the pack 0 → 9 of 9; wrong-platform chunks in the pack 3 → 0; grade-2
  characters in the pack 2,173 → 1,135 (the MITRE chunk is not graded and takes budget).
  `+R5` matches `original` exactly, as expected. Part B: expected sheet in pack 9 of 10
  (original) vs 10 of 10 (improved). CWE-79 "CSS" check: no chunk about CSS styling; three
  mention CSS as an XSS context, all graded 2. Finding left as TODO for Darren.

### What I asked for

A free check of whether rules R1 to R5 made semantic search return better guidance, and
whether it finds the right sheet for weaknesses outside the benchmark. Seven configurations
(original, each rule alone, improved) through the same code as `retrieve()`. Part A: the 9
scan CWEs, graded, search ranking and pack. Phase 1 lists the ungraded chunks blind (no
configuration, rank or score); the assistant grades nothing; phase 2 merges the grades,
refuses any missing grade and reports precision, pack contents and wrong-platform chunks.
Part B: a fixed list of 10 CWEs outside the scan, each with a dedicated sheet. Provenance,
offline tests, an EXPERIMENTS.md subsection with no finding. No model calls, no network,
no commits; changes staged only.

### How I checked it

The assistant ran the offline suite: 351 tests before, 367 after (1 skipped). Phase 1 listed
24 chunks; they were graded blind in a separate chat (`relevance_labels_added.json`, with
its `_meta` block) and phase 2 was run on the merged labels with Hugging Face forced
offline. TODO (Darren): own checks.

### What I kept or changed

TODO (Darren)

## 2026-11-09 — Step 5: the mutation test is rebuilt (runnable, not run)

- **Tool (model):** Claude Code (claude-opus-5-5); prompt written by Darren (PROMPT_05)
- **Files:** triagebot/nodes/ingest/mutation_set.py (new), triagebot/mutants.py (new),
  triagebot/nodes/ingest/eval_sets.py, triagebot/experiments.py, triagebot/__main__.py,
  triagebot/config.py, triagebot/nodes/context/retrieval.py,
  triagebot/nodes/context/vector_store.py, experiments/registry.json,
  data/samples/mutation.json (new), data/samples/mutation.manifest.json (new),
  data/samples/README.md, tests/test_mutation.py (new), tests/isolated_store.py (new),
  tests/test_vector_store.py, tests/test_experiments.py, every other tests/test_*.py and
  tests/checkpoint_worker.py (one import line), verification/mutation_check.py (docstring),
  EXPERIMENTS.md (step 5, case sets), docs/DESIGN_DECISIONS.md (decision 30), ai-log/darren.md
- **Outcome:** Built and staged; step 5 not run (no model calls). The mutation set holds
  22 pairs, not 24: CWE-22 has 2 eligible real → safe cases and CWE-89 has 2 eligible
  safe → real cases, and the rules were not widened (eligible before selection: CWE-22
  2 + 5, CWE-78 7 + 7, CWE-79 7 + 3, CWE-89 8 + 2). SHA-256 `bbaee0f17903…`. A free
  check on all 22 real pairs found that the two evidence packs differ only on the mutated
  line, that the line and its `int num` are in every pack, and that no comment-only text
  reaches a prompt; the string literal "This should never happen" does (it is code).
  Estimated cost of the run: 176 calls, about US$0.83 (the prompt's 288 calls counted 3
  calls per case for the single agent). Also found the cause of the 8 Nov vector-store
  wipe (the one-chunk checkpoint fixture under the new semantic default) and added the
  guards in decision 30.

### What I asked for

Rebuild the step 5 mutation test without the old test's three faults: one deterministic,
label-free set of constant-condition cases in both directions with a flip proof; mutants
run from an overlay root of the real checkout, so their evidence matches the original's
except the mutated line; step 5 in the registry with the same profile and commit on both
sides and the Week 10 scoring (killed, survived, escalated, the precondition). Offline
tests, documentation, and a fix so that no test can touch the real vector store. No model
calls, no commits; changes staged only.

### How I checked it

The assistant ran the offline suite: 384 tests before, 408 after (2 skipped). It built
the mutation set twice from the recorded scan and the Benchmark checkout (byte-identical),
showed the step 5 plan without running it, and checked the evidence packs of all 22 real
pairs with a stub knowledge base, in a temporary folder outside the repository.
TODO (Darren): own checks.

### What I kept or changed

TODO (Darren)
