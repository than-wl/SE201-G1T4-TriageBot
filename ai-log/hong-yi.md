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
