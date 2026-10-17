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