# TriageBot Checkpoint Report

**Team:** SE201 G1T4
**Members:** Darren, Hong Yi, Lisa, Bradley, Wei Lin
**Checkpoint date:** 18 October 2026

> **Draft status.** This draft was prepared on 17 October and last updated on 18 October against `main` at commit `057e906`, before the integrated run. Every item marked `[TBC: ...]` is waiting on a teammate's component or on the final recorded run, and must be filled in or removed before submission. Search the file for `[TBC` to find them all.

## 1. Summary

TriageBot is a post-processing layer for static-analysis (SAST) alerts. For each Semgrep finding it builds a common evidence pack (alert, comment-stripped source, helper facts and OWASP guidance), asks either a single LLM agent or an Analyst, Skeptic and Chair council for a verdict with exact source citations, checks that verdict with a deterministic validator, and returns `true_positive`, `false_positive` or `human_review`.

For the checkpoint we focused on one reasoning-heavy category, SQL injection (CWE-89), on the OWASP Benchmark Java v1.2 dataset.

`[TBC: two or three sentences on the headline result once the final run is scored, for example the genuine-retained and false-positive-removed rates for configurations C and D against the proposal targets.]`

Evidence is labelled throughout as:

- **Verified:** directly tested, with recorded evidence.
- **Partially verified:** works in a small or limited test.
- **Not yet verified:** planned or built but not tested end to end.
- **Deferred:** intentionally out of checkpoint scope, with the reason stated.

## 2. What the proposal committed to

From section 6 of the proposal, by 18 October the team would:

1. run Semgrep on the OWASP Benchmark, map findings to the official answer key, and produce the conventional baseline scorecard;
2. connect the main pipeline from scanner finding through common evidence, specialist exploration, council decision, validation and final output, documenting simplified or stubbed components;
3. demonstrate one reasoning-heavy category end to end with working security-guidance retrieval and an initial Analyst, Skeptic and Chair workflow;
4. evaluate approximately 100 scanner findings, including a preliminary single-agent versus multi-agent comparison on the same cases, and report initial metrics and failure cases;
5. maintain a shared repository with setup instructions, contributions from all members, and the required AI-use disclosure log.

The proposal's initial success criterion (section 5) is to retain **at least 95% of genuine scanner findings** while removing **at least 25% of false-positive alerts**, without sending the majority of findings to human review. These are targets for the full project; the checkpoint reports progress towards them.

Progress against each item is in section 8.

## 3. Architecture and current implementation

```text
OWASP Benchmark source
  -> Semgrep finding
  -> normalised alert                      (ingest)
  -> common evidence: source, helper facts, OWASP guidance   (context)
  -> single agent  OR  Analyst + Skeptic (concurrent) -> Chair   (review)
  -> deterministic validation              (validate)
  -> final verdict
  -> scoring against the hidden answer key (score, evaluation only)
```

Product code lives in `triagebot/`, one folder per pipeline node. Shared JSON contracts between components are defined in `triagebot/schemas.py`. The original feasibility scripts remain in `verification/` as the record of the feasibility stage (see `docs/DESIGN_DECISIONS.md`, decision 9).

| Component | Owner | Location | Status |
| --- | --- | --- | --- |
| Shared contracts and package layout | Hong Yi | `triagebot/schemas.py`, `triagebot/` | Verified: merged to `main` |
| Semgrep normalisation and answer-key mapping | Darren | `triagebot/nodes/ingest/` | `[TBC: Darren's branch, tests and status]` |
| OWASP guidance retrieval | Hong Yi | `triagebot/nodes/context/` | Partially verified: merged to `main`. Committed knowledge base of 137 OWASP Cheat Sheets (3,238 chunks); a CWE gate selects the mapped cheat sheets, keyword ranking returns up to 6 chunks within a 4,000-character budget, and alerts with no mapped CWE get curated general chunks flagged `cwe_matched=false`. Checked manually on a CWE-89 alert (section 6.4); no automated tests in the repository yet `[TBC: confirm with Hong Yi]` |
| Single agent and council orchestration | Hong Yi | `triagebot/nodes/review/` | `[TBC: Hong Yi's branch, tests and status]` |
| Deterministic validator | Lisa | `triagebot/nodes/validate/validator.py` | Verified offline: 32 tests on `checkpoint/lisa-validation` `[TBC: merge status]` |
| Evaluation harness | Bradley | `triagebot/nodes/score/evaluate.py` | Verified offline: 14 tests, plus a check against the validator's real output `[TBC: merge status]` |
| Pipeline wiring and command line | `[TBC]` | `triagebot/pipeline.py`, `triagebot/__main__.py` | `[TBC: currently a documented stub on main]` |
| Integration and submission | Wei Lin | whole repository | `[TBC]` |

## 4. Simplified, stubbed and deferred components

| Item | What the proposal planned | What the checkpoint uses | Label |
| --- | --- | --- | --- |
| Guidance retrieval | SentenceTransformers and FAISS semantic search | CWE-gated keyword ranking over a committed OWASP Cheat Sheet corpus. The chunk store is the stable interface, so an embedding ranker can replace the keyword ranker later without changing the corpus | Simplified |
| Specialist code exploration | Analyst and Skeptic use lightweight code-exploration tools | `[TBC: confirm with Hong Yi. The shared contract provides precomputed helper facts (source APIs, sink APIs, string concatenations, guards and constants) in the common evidence pack.]` | `[TBC]` |
| Deterministic validation | Checks factual claims against source code | Checks JSON shape, allowed verdicts, exact file, line and quote of every citation, and identifiers named in the explanation. Does not check full source-to-sink reasoning | Simplified |
| Categories | Per-category performance | SQL injection (CWE-89) only | Deferred: one category was agreed for the checkpoint |
| Mutation tests | Small code changes that flip the correct verdict, to detect memorisation | Not run | Deferred |
| Full benchmark run | 2,740 cases | Sample of about 100 CWE-89 findings `[TBC: final count]` | Deferred: cost and time |
| Pipeline command line | One command for the whole flow | `[TBC]` | `[TBC]` |

## 5. Test method

**Dataset.** OWASP Benchmark Java v1.2, pinned to commit `8b67a88d73b2594570fc21150705283de884620b` (see `README.md`, Setup). The official answer key labels 2,740 cases: 1,415 true vulnerabilities and 1,325 false positives.

**Scanner.** Semgrep 1.178.0 with the `p/java` ruleset.

**Sample.** `[TBC: Darren's selection rule, random seed if used, final number of CWE-89 findings, and how many are genuine versus false positives.]`

**Models.** Development runs used `google/gemini-3.5-flash-lite`. The recorded comparison uses the proposal model, `google/gemini-3.8-flash`. `[TBC: confirm the model, date and settings of the final run.]`

**Configurations compared on the same cases:**

- **A. Scanner only.** Every Semgrep finding is kept.
- **B. Single agent.** One LLM call with the combined evidence available to both specialists.
- **C. Council.** Analyst and Skeptic run concurrently on the same evidence; the Chair combines both reports.
- **D. Council plus validation.** Configuration C after the deterministic validator. `[TBC: confirm D was run.]`

**Answer-key isolation.** The answer key is read only by the evaluation harness (`triagebot/nodes/score/evaluate.py`), after all model calls. It never appears in an alert, evidence pack, prompt or saved request. `[TBC: cite Hong Yi's test that checks prompt payloads for answer-key fields.]`

**Metrics.** Computed by the evaluation harness from saved results:

| Metric | Definition |
| --- | --- |
| Genuine findings retained | Real vulnerability, verdict `true_positive` |
| Genuine vulnerabilities wrongly dismissed | Real vulnerability, verdict `false_positive` |
| False-positive alerts removed | Not vulnerable, verdict `false_positive` |
| False positives retained | Not vulnerable, verdict `true_positive` |
| Human-review rate | Share of findings with verdict `human_review` |
| Invalid-output rate | Share of findings whose result was missing, had an unsupported verdict, or failed validation |
| Latency, tokens, cost | As recorded with each saved result |

Two scoring rules matter for reading the results:

- `human_review` is reported on its own and is **never** counted as a removed false positive, because a developer still has to look at the finding.
- A missing, unreadable or unsupported verdict is counted as invalid and scored as `human_review`. It can never count as a correct removal.

**Reproducing the scores.** From the repository root:

```powershell
py -m triagebot.nodes.score.evaluate `
    --labels '.\Context\tmp\BenchmarkJava\expectedresults-1.2.csv' `
    --cases  '[TBC: sample file]' `
    --config 'B-single-agent=[TBC]' `
    --config 'C-council=[TBC]' `
    --config 'D-validated-council=[TBC]'
```

The evaluator is deterministic: the same saved inputs produce a byte-identical report.

## 6. Results

### 6.1 Scanner baseline on the full benchmark

From the proposal's preliminary run: Semgrep flagged 1,515 of the 2,740 test cases, of which 520 (34%) were false positives. This mapping was filename based and is preliminary.

`[TBC: Darren's final baseline scorecard (true positives, false positives, false negatives, true negatives over the full benchmark), with unmapped findings, duplicates and rule or CWE mismatches counted.]`

### 6.2 Checkpoint evaluation on the CWE-89 sample

`[TBC: paste the table printed by the evaluator. Expected shape below.]`

| Metric | A. Scanner only | B. Single agent | C. Council | D. Council + validation | Proposal target |
| --- | --- | --- | --- | --- | --- |
| Evaluated findings | | | | | about 100 |
| Genuine findings retained | | | | | |
| Genuine wrongly dismissed | | | | | |
| False positives removed | | | | | |
| False positives retained | | | | | |
| Genuine retained rate | 100% | | | | at least 95% |
| False-positive removal rate | 0% | | | | at least 25% |
| Human-review rate | 0% | | | | under 50% |
| Invalid-output rate | 0% | | | | |
| Mean latency per finding (s) | n/a | | | | |
| Total cost (USD) | n/a | | | | |

The scanner-only column is fixed by definition: every flagged finding is kept, so all genuine findings are retained and no false positives are removed.

`[TBC: three to five sentences interpreting the table. Does the council beat the single agent on the same cases? Is the 95% retention target met? Is the 25% removal target met? How many findings went to human review and why?]`

This is an initial checkpoint sample of one category. It is not a general accuracy estimate.

### 6.3 Earlier feasibility round (2 October 2026)

Before the checkpoint pipeline existed, the feasibility scripts in `verification/` ran on five hand-selected CWE-89 cases (three genuine, two false positives) with `google/gemini-3.8-flash`:

| Check | Result |
| --- | --- |
| Single-call triage, valid structured JSON | 5 of 5 |
| Citations matching the source file, line and quote | 15 of 15 |
| Verdicts matching the answer key | 5 of 5 |
| Mean latency | 9.87 s (range 8.16 to 11.72 s) |
| Cost | US$0.00993 for five calls |
| Analyst, Skeptic and Chair pass on the same five cases | Chair matched 5 of 5; additional cost about US$0.034 |

These cases were deliberately selected and test names were visible to the model, so memorisation cannot be ruled out. The round showed integration feasibility, not accuracy.

### 6.4 Component test results (offline, no API calls)

| Component | Tests | Result | What the tests show |
| --- | --- | --- | --- |
| Deterministic validator | 32 | Pass | Rejects a fabricated quote, wrong file, out-of-range line, malformed JSON, missing case, duplicate case and unsupported verdict. Each falls back to `human_review` with reasons |
| Evaluation harness | 14 | Pass | Exact counts on a hand-checked five-case dataset; `human_review` never counted as a removal; missing and invalid results handled safely; output byte-identical across runs |
| `[TBC: Darren's ingest tests]` | | | |
| Guidance retrieval (manual check, not an automated test) | 1 alert | Works | A CWE-89 SQL-injection alert matched four cheat sheets (Injection Prevention, Java Security, Query Parameterization, SQL Injection Prevention) and returned 2 chunks (3,866 characters). An alert with no CWE fell back to 6 general chunks flagged `cwe_matched=false` |
| `[TBC: Hong Yi's council tests]` | | | |

The validator and evaluator were also run together: sample model output passed through the validator and then into the evaluator, which scored a fabricated citation and a missing answer as human review with the validator's reasons attached.

## 7. Failures and limitations

### 7.1 Failures observed in the checkpoint run

`[TBC: choose three to five representative cases from the "failures" list in the evaluator's JSON report. Cover at least one wrong verdict, one unsupported or rejected citation, and one human-review case if they occur. For each, give the case ID, the expected and actual verdict, the model's explanation, and the likely cause.]`

| Case | Configuration | Expected | Verdict | What went wrong | Likely cause |
| --- | --- | --- | --- | --- | --- |
| `[TBC]` | | | | | |

### 7.2 Failures found in our own tooling

- **Evaluation test gap.** We deliberately planted four bugs in the evaluation harness to check that its tests notice them. Three were caught at first; counting a clean `human_review` as a correct outcome was not, because it changed no totals and only dropped the case from the failure list. We added a test, and all four planted bugs are now caught.
- **Validator coverage.** In the feasibility stage, the validator checked only JSON shape and exact quotes. The checkpoint validator adds identifier checks and a forced `human_review` fallback, but still does not verify semantic source-to-sink reasoning.

### 7.3 Limitations and threats to validity

- **One category, small sample.** Results for about 100 CWE-89 findings do not generalise to other vulnerability categories or to the full benchmark.
- **Public benchmark.** OWASP Benchmark is public and test names are visible, so the model may recognise cases. Comments and hints are stripped from the LLM-facing copy, but mutation tests that would detect memorisation are deferred.
- **Filename-based mapping.** The preliminary scanner baseline matched findings to cases by file name. `[TBC: state whether Darren's mapping also checks category and CWE.]`
- **Keyword retrieval.** Guidance ranking is keyword based, so relevant guidance worded differently from the alert may be missed. In the manual check on a CWE-89 alert, the 4,000-character budget left room for only 2 of the 6 allowed chunks, and neither came from the SQL Injection Prevention Cheat Sheet, the most directly relevant document. `[TBC: Hong Yi to confirm whether the budget or ranking will be adjusted before the final run.]`
- **Cost and latency for configuration D.** The validator's output records do not carry latency or token usage. `[TBC: either carry these through from configuration C, or state that D's cost equals C's plus negligible validation time.]`
- **Single run.** Model output can vary between runs, and we report one recorded run. `[TBC: temperature and any repeat runs.]`

## 8. Progress against checkpoint targets

| Proposal target | Status | Evidence | If unmet, why |
| --- | --- | --- | --- |
| Semgrep baseline mapped to the answer key | `[TBC]` | `[TBC: Darren's scorecard]` | |
| Main pipeline connected, stubs documented | `[TBC]` | Sections 3 and 4 | |
| One category end to end with retrieval and council | `[TBC]` | `[TBC: demonstration case ID and command]` | |
| About 100 findings, single agent versus council, metrics and failures | `[TBC]` | Sections 6.2 and 7.1 | |
| Repository with setup, all-member contributions, AI-use log | Partially met `[TBC: update]` | README, commit history, `ai-log/` | `[TBC: list any member without a commit or log]` |

## 9. Changes since the proposal

| Area | Proposal | Now | Reason |
| --- | --- | --- | --- |
| Retrieval | SentenceTransformers and FAISS | Committed OWASP Cheat Sheet corpus with CWE gate and keyword ranking | Deterministic, dependency-free and reproducible for the checkpoint. The corpus layout is kept so embeddings can be added later (design decision 3) |
| Where guidance comes from | Retrieved for the common evidence pack | Fetched by our code while building the payload; agents receive no web or browsing tools | Keeps retrieval auditable and reduces prompt-injection exposure from live web content (design decision 2) |
| Specialist tools | Code-exploration tools for Analyst and Skeptic | `[TBC: confirm with Hong Yi]` | `[TBC]` |
| Orchestration | Not specified | Plain Python functions, no agent framework | The flow is a straight sequence with one concurrent stage; a framework adds setup cost without new capability yet (design decision 1) |
| Council flow | Analyst, Skeptic, Chair | Analyst and Skeptic run concurrently and do not see each other's output; only the Chair joins them | Keeps the two perspectives independent and halves wall-clock time (design decision 4) |
| Model | Gemini 3.8 Flash | Gemini 3.5 Flash Lite for development, Gemini 3.8 Flash for the recorded run, selected by configuration | Cheap iteration while keeping recorded results comparable with the proposal (design decision 6) |
| Team roles | Wei Lin on retrieval | Hong Yi built the retrieval knowledge base; Wei Lin owns repository scaffolding, final integration and submission | `[TBC: team to confirm wording]` |
| Scope | Per-category performance and mutation tests | One category (CWE-89); mutation tests deferred | Time to the checkpoint; one reliable end-to-end path was prioritised |
| AI-use disclosure | Disclosure log | One log per member under `ai-log/`, plus the team declaration in section 11 | Required by the SE201 AI Use Disclosure Policy v1.00 |

## 10. Next steps after the checkpoint

- Extend evaluation to further categories and report per-category performance.
- Run mutation tests to check that verdicts follow code evidence rather than memorised benchmark patterns.
- Evaluate whether embedding-based retrieval improves on keyword ranking over the same corpus.
- Strengthen the validator beyond citation checks towards source-to-sink claims.
- Scale the evaluation beyond the checkpoint sample and repeat runs to measure variation.
- `[TBC: team additions]`

## 11. Team contributions

Each member has reviewed the paragraph describing their own work. `[TBC: tick when confirmed]`

- **Darren:** `[TBC]` Semgrep integration, alert normalisation and answer-key mapping. `[ ] confirmed`
- **Hong Yi:** Package scaffold and shared contracts, design decision record, offline OWASP Cheat Sheet knowledge base (137 sheets, 3,238 chunks), CWE-gated keyword retrieval over that knowledge base, `[TBC: council and single-agent orchestration]`. `[ ] confirmed`
- **Lisa:** Deterministic validator with citation, identifier and case-ID checks and a `human_review` fallback, with 32 offline tests. `[ ] confirmed`
- **Bradley:** Evaluation harness that scores all configurations against the hidden answer key, with 14 offline tests; this checkpoint report. `[ ] confirmed`
- **Wei Lin:** Repository setup, checkpoint planning documents, `[TBC: final integration, recorded run and submission]`. `[ ] confirmed`

## 12. AI use declaration

`[TBC: update from every member's ai-log file before submission.]`

We used Claude Code to help write code, tests and documentation, including the evaluation harness, its tests and a first draft of this report. Commits containing AI-assisted work carry a `Co-Authored-By` trailer, and each member records significant AI use in their own file under `ai-log/`. Generated code was reviewed by its owner, run against offline tests, and for the evaluation harness also checked by planting deliberate bugs to confirm the tests catch them. Within the product, TriageBot itself calls `google/gemini-3.8-flash` (and `google/gemini-3.5-flash-lite` for development) through OpenRouter; those calls are part of the system under evaluation, not assistance in writing it. Details are in the `ai-log/` folder.
