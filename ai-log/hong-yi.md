# AI Use Log: Hong Yi

Entries follow the SE201 AI Use Disclosure Policy v1.00: one entry per
significant use, committed with the work it describes.

## 2026-10-17 — Shared contracts and offline KB builder

- **Tool (model):** Claude Code (mimo-v2.6-flash)
- **Files:** triagebot/schemas.py, triagebot/config.py,
  triagebot/nodes/context/kb/build_kb.py, triagebot/nodes/context/kb/README.md
- **Outcome:** Changed

### What I asked for

TypedDict contracts for the pipeline interfaces (NormalisedAlert,
ContextPayload, AgentReport, TriageResult) matching the team document,
plus an offline builder that chunks the downloaded OWASP Cheat Sheet
bundle into a committed KB (docs, CWE map, curated common set).

### How I checked it

Read the downloaded site's HTML structure before trusting the parser;
ran the builder with `py -I` on the untrusted bundle and checked chunk
counts. Querying the first build's CWE map showed CWE-89 and CWE-22 were
missing — the cheat sheets never state their own CWE ids in prose, so
pure mention-detection silently failed for exactly the categories the
benchmark needs most.

### What I kept or changed

Kept the heading-based chunker and the committed-JSON layout. Changed
the CWE map from pure mention-detection to curated category pins unioned
with detected mentions, with filename typo-validation (33 CWE keys
after rebuild).

## 2026-10-17 — CWE-gated keyword retrieval

- **Tool (model):** Claude Code (mimo-v2.6-flash)
- **Files:** triagebot/nodes/context/retrieval.py, triagebot/config.py
- **Outcome:** Changed

### What I asked for

Simple retrieval over the committed KB: CWE gate selects documents,
keyword ranking orders their chunks by alert terms, no frameworks or
embeddings for the checkpoint.

### How I checked it

Offline smoke over the real KB, checking determinism (same alert, same
chunks) and both gate paths. The first run returned a single chunk per
case: the 2000-character budget fit only the top chunk, and the curated
common chunks were silently squeezed out of the result.

### What I kept or changed

Kept the keyword scorer and the gate. Changed the design to mutually
exclusive branches — gate hit sends only matched-document chunks, gate
miss sends only the curated common set and flags `cwe_matched=false` —
and raised the guidance budget to 4000 characters (team decision).

## 2026-10-17 — Context payload and the four review roles

- **Tool (model):** Claude Code (mimo-v2.6-flash)
- **Files:** triagebot/nodes/context/payload.py,
  triagebot/nodes/review/prompts.py, triagebot/nodes/review/report.py,
  triagebot/nodes/review/single_agent/baseline.py,
  triagebot/nodes/review/council/analyst.py,
  triagebot/nodes/review/council/skeptic.py,
  triagebot/nodes/review/council/chair.py,
  triagebot/schemas.py, triagebot/config.py, triagebot/llm/base.py
- **Outcome:** Kept

### What I asked for

One-shot generation of payload assembly (comment stripping, pattern
fact hints, source window, retrieval wiring), the shared evidence-block
renderer and system prompts, a shared report-assembly helper, and the
four review roles (single + Analyst/Skeptic/Chair) on the injectable
caller seam with no retries.

### How I checked it

Offline smoke with a fake caller and a synthetic Java file (the
benchmark repo is not on this machine): comment stripping preserves line
alignment and string literals; facts extracted in all four categories;
guidance retrieved from the real KB; the evidence block is byte-identical
across strategies; the Chair joins both specialist reports; a failed
caller call returns a safe `human_review` report without raising.
Three smoke-test failures along the way were bugs in my test
assertions (wrong line index, quoting), not in the generated code.

### What I kept or changed

Kept the three-function payload module and the role wrappers. Changed
during review: prompts moved from the package root into
`triagebot/nodes/review/prompts.py` (their only consumers are the review
roles), and reports gained an additive `guidance` field so reviewers
declare which retrieved cheat-sheet chunks they relied on, alongside the
team document's source-code `citations`.

## 2026-10-17 — AI-use disclosure setup

- **Tool (model):** Claude Code (mimo-v2.6-flash)
- **Files:** ai-log/hong-yi.md, doc/DESIGN_DECISIONS.md
- **Outcome:** Kept

### What I asked for

Set up disclosure per the SE201 AI Use Disclosure Policy v1.00: read
the policy, create this log with backfilled entries, adopt the
`Assisted-by:` trailer convention for commits and PRs, and record the
related decisions in the design-decision log.

### How I checked it

Extracted and read the policy PDF directly (pymupdf), and matched this
log's entry format, the outcome vocabulary (Kept/Changed/Rejected), and
the trailer form against sections 4.1/4.2 of the policy.

### What I kept or changed

Replaced the team's earlier ad-hoc PR-declaration practice with the
policy's format: `Assisted-by:` trailers on commits and PRs, this log
committed with the work it describes, and a team declaration for the
checkpoint document summarising the logs.

## 2026-10-18 — Live OpenRouter caller and end-to-end verification

- **Tool (model):** Claude Code (mimo-v2.6-flash); live calls to google/gemini-3.8-flash via OpenRouter
- **Files:** triagebot/llm/openrouter.py, triagebot/config.py
- **Outcome:** Changed

### What I asked for

Implement the live caller (seam B: parse JSON in the caller, `{"_error"}`
on failure, no retries, usage recorded on `last_call`) and run the whole
new review path against the real model: real KB → payload → single agent
and full council (Analyst ∥ Skeptic → Chair) on a synthetic CWE-89 case.

### How I checked it

Five paid calls (~$0.011 total). Deterministic checks on every live
report: identity fields stamped by code, every citation an exact
substring of its source line, every guidance ref drawn only from listed
chunks. The first single-agent call returned an unparseable near-cap
answer and degraded to a safe `human_review` report exactly as designed;
a manual re-run returned clean JSON. All three council roles
independently cited the `[0-9]+` regex guard and converged on
false_positive with grounded citations.

### What I kept or changed

Kept the caller and the no-retry failure path (observed working live).
Changed: `REVIEW_MAX_TOKENS` 700 → 900 after the run showed one call
truncating at the cap (analyst spent 676 of 700 tokens).

## 2026-10-18 — Source window widened from ±25 to ±100 lines

- **Tool (model):** Claude Code (mimo-v2.6-flash)
- **Files:** triagebot/config.py
- **Outcome:** Changed

### What I asked for

After the recorded 100-case run reported a 32% human-review rate,
choose and apply a wider `SOURCE_WINDOW_LINES` (100 rather than 85:
round, and quotable as "±100 lines"), then re-run the recorded
evaluation to measure the effect.

### How I checked it

`git blame` traced the ±25 default to my own payload commit (e6b2852),
and the run's report attributes most escalations to helper methods cut
off mid-slice (e.g. BenchmarkTest01004, BenchmarkTest01883). Rebuilt the
same 100-case sample (seed 201) and re-triaged BenchmarkTest01004
through the council: analyst, skeptic and chair all returned
`true_positive` with validation passing — the whole file now fits the
window. The full 100-case re-run was started, then stopped by choice
before any results were written, so the effect on the human-review rate
is not yet measured.

### What I kept or changed

Changed only the constant (25 → 100, with the reason in the comment);
kept the slice-then-extract-facts design. The recorded checkpoint
numbers were produced at ±25 and stand unchanged; a full re-run to
quantify the effect is deferred.

## 2026-10-26 — Council migrated to LangGraph

- **Tool (model):** DeepSeek (v4.1 flash)
- **Files:** triagebot/council_graph.py, triagebot/state.py,
  triagebot/execution.py, triagebot/pipeline.py, tests/test_council_graph.py,
  requirements.txt, README.md, docs/DESIGN_DECISIONS.md,
  docs/IMPLEMENTATION_HANDOVER.md, triagebot/llm/__init__.py
- **Outcome:** Changed

### What I asked for

Move only the Analyst/Skeptic/Chair council onto LangGraph: keep the graph
state in an explicit `CouncilState` TypedDict, and hold the caller factory,
knowledge base, benchmark root and monotonic timer in a runtime context
object outside the state. The graph should run
`START → build_context → {analyst, skeptic} → chair → validate → END`
with one explicit join, while the public `triage()` / `run_sample()`
contracts and the recorded results stay untouched. The single-agent
baseline stays plain Python; no persistence, human-in-the-loop pause,
retries, tools or retrieval changes.

### How I checked it

Audited the implementation as a separate reviewable bundle before
integrating it into this branch: the changed-tree diff was exactly the ten
declared files and every file hash matched the manifest; the full suite
(191 tests) passed against real `langgraph==1.2.17` on Windows/Python 3.12;
a parity probe run on both the pre-migration and migrated trees produced
byte-identical output for twelve scenario × mode cases plus `run_sample`
(latency excluded); an unexpected Python exception in one specialist
propagates identically before and after; nothing reads or writes a
checkpointer and there are no interrupt points. Re-ran the suite in this
repository after copying the files in.

### What I kept or changed

Kept the graph structure, the state/context split, and the unchanged
public contracts; the single-agent path still has no LangGraph dependency
at call time. Changed: the bundle's standalone draft disclosure
(`ai-log/phase1-langgraph.md`, which named an assistant without a model
identifier and had no owning member) was not copied; this per-member entry
replaces it. Cleanup while reviewing: the doc-only `triagebot/llm/base.py`
(no symbols, imported nowhere) became `triagebot/llm/__init__.py`, so its
caller-contract text is now the package docstring, and decision 12's claim
that the package top level holds only `schemas.py` and `config.py` was
corrected after the new orchestration modules moved in. No merge, no PR, and
no metrics re-run are claimed here; checkpointing and human review were not
part of this change.


## 2026-10-26 — SQLite checkpoints for council sessions

- **Tool (model):** DeepSeek (v4.1 flash)
- **Files:** triagebot/checkpoints.py, triagebot/council_graph.py,
  triagebot/state.py, triagebot/execution.py, triagebot/__main__.py,
  triagebot/config.py, triagebot/llm/openrouter.py, tests/test_checkpoints.py,
  tests/checkpoint_worker.py, tests/test_council_graph.py, requirements.txt,
  .gitignore, README.md, docs/DESIGN_DECISIONS.md,
  docs/IMPLEMENTATION_HANDOVER.md
- **Outcome:** Changed

### What I asked for

Add opt-in, file-backed SQLite sessions for the council only, on top of the
existing LangGraph council: a unique UUID per run, `council-start` /
`council-status` / `council-resume`, provenance checks before an unfinished
run is continued, one executor per database, and completed runs readable
without new model calls. Existing `triage` / `evaluate`, the interactive menu
and the single-agent baseline must stay ephemeral and unchanged; no
human-in-the-loop pause, no tools and no automatic retries.

### How I checked it

Audited the delivered review ZIP against its stated base,
`6ec079a1ad4d507acc1ea92565855af9ba4b77fb`: all 16 file hashes matched the
manifest and the patch applied cleanly to that commit. Installed the full
requirements and ran the suite on Windows/Python 3.12 with real LangGraph
1.2.17, SQLite adapter 3.1.2 and `langgraph-checkpoint` 4.3.0: 220 tests pass,
with only the POSIX file-permission test skipped on Windows. Re-ran the suite
in this repository after copying the files in.

The first full runs were intermittent: one recovery test failed in about two of
every three runs. The cause was the subprocess fixture writing its call log
through a fresh `O_APPEND` descriptor per call, which on Windows can lose a
line when the Analyst and Skeptic write at the same time. A standalone probe
reproduced the lost lines in ten of ten rounds; putting a process-wide lock
around that one write made those tests pass in ten consecutive runs, and the
full suite has passed twice in this repository since the fix. The
implementation's tests cover cross-process create/inspect/recover, a hard
process death in Chair, a failed parallel sibling without repeating the
successful one, validation-only recovery, source/KB/model/config/version
drift, executor locking, private DB creation and the CLI guards. No OpenRouter
calls, paid evaluation, rescan, answer-key access or new accuracy claims were
made.

### What I kept or changed

Kept the existing triage/evaluate pipeline, the public result contract, the
single-agent baseline and the existing graph shape. Changed: the fixture
call log is now written under a lock (test-only). The bundle's evidence run was
on Linux/Python 3.13, which is outside the CI matrix (3.10/3.12); this entry
records the Windows/Python 3.12 run repeated here. Exactly-once billing is
still not guaranteed: reported usage covers committed reports only, not every
possibly billed attempt. No push, merge, PR or independent approval is
claimed; the human-review pause remains future work.

## 2026-10-31 — Semantic retrieval over the cheat sheets, keyed by the CWE text

- **Tool (model):** Claude Sonnet 5.5 (claude-sonnet-5-5)
- **Files:** triagebot/config.py, triagebot/nodes/context/cwe_catalogue.py,
  triagebot/nodes/context/embeddings.py, triagebot/nodes/context/retrieval.py,
  triagebot/execution.py, triagebot/nodes/validate/validator.py,
  triagebot/schemas.py, requirements.txt, tests/test_semantic_retrieval.py,
  verification/semantic_measurement.py, docs/DESIGN_DECISIONS.md
- **Outcome:** Changed

### What I asked for

Replace the hand-written CWE-to-cheat-sheet map as the only way to find guidance.
The scanner's CWE should be looked up in the official MITRE CWE catalogue, the
record's text embedded with a local model, and the cheat-sheet chunks ranked by
similarity to it. Any case without grounded guidance (no CWE, an unknown CWE, or
similarity below a threshold) should go to human review. The thresholds belong in
the config file so they can be tuned. The map should remain the default until the
dev-split comparison has been reviewed.

### How I checked it

The full offline suite passes on Windows/Python 3.12: 230 tests, of which 10 are
new and use a fake embedder, a fixture catalogue and a fixture knowledge base. I
installed the official MITRE catalogue (CWE 5.0) through the install step, which
checks it against a pinned SHA-256. It has 984 records, and the 28 deprecated ones
are left out of lookups.

On the dev split only (100 CWE-89 alerts, with the same fixed primary-sheet proxy
as before, and no answer-key labels), the current map gave 0/100 alerts with a
primary SQL sheet in the guidance, the MITRE text as the query gave 100/100 with a
primary-sheet share of 0.50, and the MITRE text plus the alert message gave 0/100.
The threshold could not be set from these results: the top score depends only on
the CWE, and the scores for correct and wrong sheets overlap. I read the top six
sheets for each of the nine CWEs in the scan. The right sheet appeared for CWE-79,
CWE-328 and CWE-643. For CWE-326 it ranked only fourth. The knowledge base has no
path-traversal sheet for CWE-22.

I found that the validator never read the gate flag, although the schema and the
design record both said it did. The gate flag is now enforced: an ungrounded case
gets human_review with a validation error, whatever the model said.

### What I kept or changed

The default remains the curated map, so no existing result changes until the team
reviews the comparison. The threshold stays at a placeholder value of 0.0. In map
mode, 475 of the 1,909 scan findings (all of CWE-326, CWE-328 and CWE-501) now go to
human review, where the earlier code sent them to the model. That change is the rule
as specified, but it will affect any figure that counts human-review cases. The
catalogue is downloaded into the git-ignored Context folder and is not committed,
because its licence terms have not been checked. fastembed is added to the
requirements, so the CI matrix will install it, which has not been verified yet. The
held-out test half of the split was not used. No pull request has been raised.

## 2026-10-31 — Knowledge-base vectors moved into a SQLite store

- **Tool (model):** Claude Haiku 5.5 (claude-haiku-5-5)
- **Files:** triagebot/nodes/context/vector_store.py, triagebot/nodes/context/embeddings.py,
  triagebot/nodes/context/retrieval.py, triagebot/config.py, verification/semantic_measurement.py,
  tests/test_vector_store.py, tests/test_semantic_retrieval.py, docs/DESIGN_DECISIONS.md, README.md
- **Outcome:** Changed

### What I asked for

Store the knowledge-base chunks and their embeddings in a SQLite file, rather than the
temporary NumPy cache I had written. Adding a new document later should only need chunking
and an insert, with no change to the storage design. The search itself stays exact.

### How I checked it

The full offline suite passes on Windows/Python 3.12: 239 tests, including new tests for
incremental sync (unchanged chunks are not re-embedded, changed and new chunks are, removed
chunks are deleted, and a model change re-embeds everything) and round-trip fidelity of the
stored vectors. On the real knowledge base, the first sync embedded 3,238 chunks in about
four and a half minutes, and a second sync embedded nothing.

The check also found that the committed knowledge base repeats 22 chunks verbatim (the same
text and ID within one document). The semantic store refuses a chunk ID that appears with
different content, and drops verbatim repeats. The map path reads the raw JSON, so its
results are unchanged. The duplicates should be removed at source, which is a data change to
review separately.

### What I kept or changed

Kept the exact-search design and the map as the default. Changed: the cache file became a
SQLite store, and the measurement script now uses it. I did not change the committed JSON.
No pull request has been raised.

## 2026-10-31 — Graded relevance study, evaluation script and branch recovery

- **Tool (model):** Claude Haiku 5.5 (claude-haiku-5-5) graded the candidate chunks and ran the
  first comparisons; Claude Sonnet 5.5 (claude-sonnet-5-5) wrote the evaluation script, inspected
  the teammate's open pull request and the branch history, restored the Phase 1 branch and
  prepared the commit
- **Files:** verification/relevance_labels.json, verification/relevance_eval.py,
  verification/retrieval_comparison.py, docs/DESIGN_DECISIONS.md
- **Outcome:** Changed

### What I asked for

Check the retrieval choice against the real cheat-sheet text, not against the map (which was
generated with AI help and never verified) or a guess based on document names. Read the
candidates, judge their relevance, and re-evaluate dense retrieval, BM25 hybrids and rerankers,
including a fair comparison with the map. Then look at a teammate's open pull request and work
out how the two lines of work can be merged.

### How I checked it

The assistant read and graded 130 candidate chunks for the nine CWEs in the scan (2 = about this
weakness, 1 = adjacent, 0 = not relevant). These grades are one reader's judgement and have not
been independently reviewed. `verification/relevance_eval.py` rebuilds the candidate pools from
the labels file and reproduces the table in design decision 21: dense retrieval scores precision@2
of 0.61, BM25 0.33, equal-weight fusion 0.61, and two off-the-shelf rerankers 0.33 and 0.44. The
curated map scores 0.58 on the six CWEs it covers (dense 0.67 on the same six) and 0.39 over all
nine, because it has no entry for three of them. One figure moved between the first ad hoc run and
the committed script: equal-weight fusion at precision@6 went from 0.44 to 0.46, because the first
run counted the 22 duplicated chunks.

For the teammate's pull request, I merged it into a throwaway copy of our branch. Four files
conflict, and four of its tests fail if the `pipeline.py` conflict is resolved by keeping the
LangGraph side, because its consistency-repair step is then silently dropped from council mode.
The copy was deleted and the pull request was not touched. I also found that the remote Phase 1
and Phase 2 branches had been deleted, so I pushed the local Phase 1 branch (which already holds
Phase 2) back to GitHub.

### What I kept or changed

Dense retrieval stays the candidate; neither BM25 nor a reranker is added. The default mode is
still the curated map, the threshold is still a placeholder, and the committed knowledge-base
JSON is unchanged. Left for the team: an independent review of the grades, the disagreement over
the source window (60 or 100 lines), and the merge order with the open pull request. No pull
request has been raised.
