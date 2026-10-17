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
