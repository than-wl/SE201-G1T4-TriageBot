# TriageBot feasibility check

Status: **PASS WITH CHANGES**. The proposed scanner-to-model-to-council flow is technically runnable on a small real sample. The planned embedding retrieval stack and full deterministic validator still need implementation during the project.

## Checks completed

- Real OWASP Benchmark Java evidence was reused from the Semgrep/OpenRouter smoke test: five SQL-injection cases, three genuine and two false positives.
- The OWASP SQL Injection Prevention Cheat Sheet was fetched over HTTPS and four relevant guidance passages were retrieved with a standard-library keyword fallback.
- Lightweight evidence helpers ran for all five cases, extracting request-source APIs, SQL sinks, string concatenations, and guard/constant lines.
- Three same-model calls ran with the same evidence pack: Analyst, Skeptic, and Chair. Each returned five structured results with valid source-file, line, and quote citations.
- The Chair matched all five hidden benchmark labels. This is a feasibility smoke result, not a general accuracy estimate.
- The existing offline validator self-test passed: fabricated quotes, unknown file/line, and malformed JSON were rejected. All three council outputs also passed the current citation validator.

## Important limitations

- `sentence_transformers` and `faiss` are not installed in the verification environment. The run proves that guidance can be fetched and retrieved with a fallback, not that the proposed embedding-plus-FAISS implementation works.
- The validator currently checks JSON shape and exact source quotes. It does not yet verify method/identifier relationships, semantic source-to-sink completeness, automatic suppression, or a forced human-review fallback for unsupported claims.
- Five cases and one council pass are insufficient to claim the proposed accuracy or false-positive-reduction targets.

## Evidence

- Raw result: `Context/tmp/feasibility/20261002T112544Z/results.json`
- Raw role responses: the three `*-raw.json` files in that directory
- Reproducible check: `verification/feasibility_checks.py`
- Earlier scanner/API evidence: `docs/feasibility/OPENROUTER_SMOKE_REPORT.md`

## Proposal decision

Proceed with the proposal. Describe the multi-agent flow as feasible based on this smoke test, label embedding retrieval and the stronger validator as planned implementation work, and keep the 95% retention / 25% false-positive-reduction figures as evaluation targets rather than achieved results.
