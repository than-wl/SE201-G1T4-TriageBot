# TriageBot Checkpoint Report

**Team:** SE201 G1T4
**Members:** Darren, Hong Yi, Lisa, Bradley, Wei Lin
**Checkpoint date:** 18 October 2026

> **Draft status.** Updated on 18 October on `checkpoint/wei-lin-integration`. The connected pipeline, 177 offline tests and recorded 100-case run are complete. Member confirmation boxes still require each member's own review before submission.

## 1. Summary

TriageBot is a post-processing layer for static-analysis (SAST) alerts. For each Semgrep finding it builds a common evidence pack (alert, comment-stripped source, helper facts and OWASP guidance), asks either a single LLM agent or an Analyst, Skeptic and Chair council for a verdict with exact source citations, checks that verdict with a deterministic validator, and returns `true_positive`, `false_positive` or `human_review`.

For the checkpoint we focused on one reasoning-heavy category, SQL injection (CWE-89), on the OWASP Benchmark Java v1.2 dataset.

On the 100-case checkpoint sample, the council removed 35 of 50 false-positive alerts (70%) and wrongly dismissed none of the 50 genuine findings. It automatically confirmed 33 genuine findings and escalated the other 17, giving 100% safe retention when `human_review` is treated as kept for a developer, with a 32% overall human-review rate. This meets the proposal's safety, removal and under-50%-review targets on this preliminary one-category sample, but it is not evidence of general performance.

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

| Component                                    | Owner                                    | Location                                                                     | Status                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shared contracts and package layout          | Hong Yi                                  | `triagebot/schemas.py`, `triagebot/`                                     | Verified: merged to `main`                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Semgrep normalisation and answer-key mapping | Darren                                   | `triagebot/nodes/ingest/`                                                  | Verified: merged to `main`. Normalises all 1,909 Semgrep findings into the shared `NormalisedAlert` contract, maps them to the answer key with CWE matching, computes the full-benchmark scanner baseline, and produces the dev/test split and checkpoint sample. 48 offline tests                                                                                                                                                            |
| OWASP guidance retrieval                     | Hong Yi                                  | `triagebot/nodes/context/`                                                 | Verified in the connected live path. Committed knowledge base of 137 OWASP Cheat Sheets (3,238 chunks); a CWE gate selects mapped cheat sheets and keyword ranking returns up to 6 chunks within a 4,000-character budget. |
| Single agent and council orchestration       | Hong Yi                                  | `triagebot/nodes/review/`                                                  | Verified offline and live. Single-agent review and the concurrent Analyst/Skeptic followed by Chair flow both produced structured, cited reports. |
| Deterministic validator                      | Lisa                                     | `triagebot/nodes/validate/validator.py`                                    | Verified and merged: 41 offline tests; used by both single-agent and council outputs. |
| Evaluation harness                           | Bradley                                  | `triagebot/nodes/score/evaluate.py`                                        | Verified and merged: 14 offline tests, plus integration with the validator's real output shape. |
| Pipeline wiring and command line             | Darren (menu), Wei Lin (pipeline wiring) | `triagebot/pipeline.py`, `triagebot/__main__.py`, `triagebot/check.py` | Verified: all stages are connected; menu options 1-3 and their matching subcommands run the same implementation. |
| Integration and submission                   | Wei Lin                                  | whole repository                                                             | Verified through the recorded run; final team sign-off and eLearn submission remain. |

## 4. Simplified, stubbed and deferred components

| Item                        | What the proposal planned                                                | What the checkpoint uses                                                                                                                                                                              | Label                                                |
| --------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Guidance retrieval          | SentenceTransformers and FAISS semantic search                           | CWE-gated keyword ranking over a committed OWASP Cheat Sheet corpus. The chunk store is the stable interface, so an embedding ranker can replace the keyword ranker later without changing the corpus | Simplified                                           |
| Specialist code exploration | Analyst and Skeptic use lightweight code-exploration tools               | No interactive tools at the checkpoint. Both receive precomputed source/sink, concatenation, guard and constant hints and must verify them against the same source excerpt | Simplified |
| Deterministic validation    | Checks factual claims against source code                                | Checks JSON shape, allowed verdicts, exact file, line and quote of every citation, and identifiers named in the explanation. Does not check full source-to-sink reasoning                             | Simplified                                           |
| Categories                  | Per-category performance                                                 | SQL injection (CWE-89) only                                                                                                                                                                           | Deferred: one category was agreed for the checkpoint |
| Mutation tests              | Small code changes that flip the correct verdict, to detect memorisation | Not run                                                                                                                                                                                               | Deferred                                             |
| Full benchmark run          | 2,740 cases                                                              | Sample of 100 CWE-89 findings (50 real / 50 false alarms, from the development split)                                                                                                       | Deferred: cost and time                              |
| Pipeline command line       | One command for the whole flow                                           | Terminal menu and subcommands run the scanner baseline, one-case triage, and full sample evaluation                                               | Built                                      |

## 5. Test method

**Dataset.** OWASP Benchmark Java v1.2, pinned to commit `8b67a88d73b2594570fc21150705283de884620b` (see `README.md`, Setup). The official answer key labels 2,740 cases: 1,415 true vulnerabilities and 1,325 false positives.

**Scanner.** Semgrep 1.178.0 with the `p/java` ruleset.

**Split and sample.** Every one of the 2,740 Benchmark cases is assigned once to a development or a test split: 50/50, stratified by vulnerability category and by real/not-real label, with a fixed random seed (201). Prompts and settings are tuned only on the development split; the test split is held back for the final evaluation, following the instructor's feedback to evaluate on unseen data.

The checkpoint sample is drawn from the **development split only**:

- **Pool:** SQL injection (CWE-89) cases where Semgrep raised an alert whose CWE matches the test case's category. The development split holds 121 real and 67 non-vulnerable such cases.
- **Draw:** 100 cases, balanced at **50 real vulnerabilities and 50 false alarms**, with one alert per case (the CWE-matching alert; ties go to the lowest line number, then the rule ID). The draw is deterministic, using seed 201.
- **Isolation:** the selection uses the answer key only to pick and balance cases. The sample file the pipeline reads (`selected_alerts.json`) contains alert fields only, with no labels.

**A caveat on the balanced sample.** Among all SQL-injection test cases Semgrep flagged, about 38% (143 of 377) are false alarms. The 50/50 balance therefore makes the per-class rates ("genuine retained" and "false positives removed") easy to compare, but precision measured on the sample is not real-world precision.

**Models.** Development runs used `google/gemini-3.5-flash-lite`. The recorded comparison on 18 October 2026 uses the proposal model, `google/gemini-3.8-flash`, with temperature 0.0, a 900-token response limit and no automatic retries.

**Configurations compared on the same cases:**

- **A. Scanner only.** Every Semgrep finding is kept.
- **B. Single agent.** One LLM call with the combined evidence available to both specialists.
- **C. Council.** Analyst and Skeptic run concurrently on the same evidence; the Chair combines both reports.
- **D. Council plus validation.** Configuration C after the deterministic validator.

**Answer-key isolation.** The answer key is read only by the evaluation harness (`triagebot/nodes/score/evaluate.py`), after all model calls. It never appears in an alert, evidence pack, prompt or saved request. Ingest tests verify that selected alerts contain no answer-key fields; pipeline tests use only the normalised alert contract.

**Metrics.** Computed by the evaluation harness from saved results:

| Metric                                    | Definition                                                                                   |
| ----------------------------------------- | -------------------------------------------------------------------------------------------- |
| Genuine findings retained                 | Real vulnerability, verdict `true_positive`                                                |
| Genuine vulnerabilities wrongly dismissed | Real vulnerability, verdict `false_positive`                                               |
| False-positive alerts removed             | Not vulnerable, verdict `false_positive`                                                   |
| False positives retained                  | Not vulnerable, verdict `true_positive`                                                    |
| Human-review rate                         | Share of findings with verdict `human_review`                                              |
| Invalid-output rate                       | Share of findings whose result was missing, had an unsupported verdict, or failed validation |
| Latency, tokens, cost                     | As recorded with each saved result                                                           |

Two scoring rules matter for reading the results:

- `human_review` is reported on its own and is **never** counted as a removed false positive, because a developer still has to look at the finding.
- A missing, unreadable or unsupported verdict is counted as invalid and scored as `human_review`. It can never count as a correct removal.

**Reproducing the scores.** From the repository root:

```powershell
py -m triagebot.nodes.score.evaluate `
    --labels '.\Context\tmp\BenchmarkJava\expectedresults-1.2.csv' `
    --cases  '.\Context\tmp\checkpoint\selected_alerts.json' `
    --config 'B-single-agent=.\Context\tmp\checkpoint\B-single-agent.json' `
    --config 'C-council=.\Context\tmp\checkpoint\C-council.json' `
    --config 'D-validated-council=.\Context\tmp\checkpoint\D-validated-council.json'
```

The evaluator is deterministic: the same saved inputs produce a byte-identical report.

## 6. Results

### 6.1 Scanner baseline on the full benchmark

**Ingest.** Semgrep 1.178.0 with the `p/java` ruleset produced 1,909 findings, all in Benchmark test files. There were no helper-file findings, unmapped paths, duplicates or findings without a CWE. 1,515 of the 2,740 test cases have at least one alert, and 1,225 have none.

**Scoring method.** A test case counts as flagged by Semgrep only if one of its alerts names the same weakness (CWE) as the case's category in the answer key, which is how the Benchmark's own scoring works. One documented equivalence is accepted: Semgrep labels DES/3DES usage as CWE-326 (inadequate encryption strength), while the Benchmark labels the same code as CWE-327 (broken or risky algorithm). Three other mismatches were reviewed and rejected because the alert concerns a different weakness: an XSS rule (CWE-79) that fires on trust-boundary, SQL-injection and XPath test files.

|                                                           |  TP |  FP |  FN |  TN | Precision | Recall |    F1 |
| --------------------------------------------------------- | --: | --: | --: | --: | --------: | -----: | ----: |
| **Semgrep, CWE-matched (our baseline)**             | 970 | 512 | 445 | 813 |     65.5% |  68.6% | 67.0% |
| Semgrep, filename-matched (proposal's preliminary method) | 995 | 520 | 420 | 805 |     65.7% |  70.3% | 67.9% |

The proposal's filename-based numbers were slightly inflated. The difference sits almost entirely in trust-boundary cases, where Semgrep flagged an unrelated XSS pattern (true positives drop from 68 to 43).

**By category (CWE-matched):**

| Category                 |            Real |        Caught |        Missed |  False alarms |       Precision |          Recall |              F1 |
| ------------------------ | --------------: | ------------: | ------------: | ------------: | --------------: | --------------: | --------------: |
| Command injection        |             126 |           112 |            14 |            96 |           53.8% |           88.9% |           67.1% |
| Cross-site scripting     |             246 |           202 |            44 |           108 |           65.2% |           82.1% |           72.7% |
| Insecure cookie          |              36 |             0 |            36 |             0 |              – |            0.0% |              – |
| LDAP injection           |              27 |            26 |             1 |            28 |           48.1% |           96.3% |           64.2% |
| Path traversal           |             133 |           120 |            13 |           106 |           53.1% |           90.2% |           66.9% |
| SQL injection            |             272 |           234 |            38 |           143 |           62.1% |           86.0% |           72.1% |
| Trust boundary violation |              83 |            43 |            40 |            18 |           70.5% |           51.8% |           59.7% |
| Weak encryption          |             130 |           130 |             0 |             0 |          100.0% |          100.0% |          100.0% |
| Weak hashing             |             129 |            89 |            40 |             0 |          100.0% |           69.0% |           81.7% |
| Weak randomness          |             218 |             0 |           218 |             0 |              – |            0.0% |              – |
| XPath injection          |              15 |            14 |             1 |            13 |           51.9% |           93.3% |           66.7% |
| **All**            | **1,415** | **970** | **445** | **512** | **65.5%** | **68.6%** | **67.0%** |

**What this means for TriageBot.** These results answer the instructor's question about whether the first stage bottlenecks the system:

- **Noise to remove:** 512 of the 1,482 flagged test cases (34.5%) are false alarms. Removing them is TriageBot's job.
- **Recall ceiling:** TriageBot can only filter alerts, never add them. On this scan, the whole system can therefore reach at most **68.6% recall**, even if TriageBot is perfect.
- **Blind spots:** Semgrep's `p/java` ruleset catches no weak-randomness (0 of 218) or insecure-cookie (0 of 36) cases. Together they are 254 of the 445 missed vulnerabilities (57%).
- **Planned next step:** test whether a broader first stage (for example the `p/security-audit` ruleset, or both rulesets combined) raises the recall ceiling, accepting more false alarms for TriageBot to filter, as the instructor suggested.

### 6.2 Checkpoint evaluation on the CWE-89 sample

| Metric                       | A. Scanner only | B. Single agent | C. Council | D. Council + validation | Proposal target |
| ---------------------------- | --------------- | --------------- | ---------- | ----------------------- | --------------- |
| Evaluated findings           | 100             | 100             | 100        | 100                     | about 100       |
| Genuine automatically confirmed | 50          | 29              | 33         | 33                      |                 |
| Genuine sent to human review | 0               | 18              | 17         | 17                      |                 |
| Genuine wrongly dismissed    | 0               | 3               | 0          | 0                       |                 |
| False positives removed      | 0               | 34              | 35         | 35                      |                 |
| False positives retained     | 50              | 1               | 0          | 0                       |                 |
| False positives sent to human review | 0       | 15              | 15         | 15                      |                 |
| Genuine not wrongly dismissed | 100%           | 94%             | 100%       | 100%                    | at least 95%    |
| False-positive removal rate  | 0%              | 68%             | 70%        | 70%                     | at least 25%    |
| Human-review rate            | 0%              | 33%             | 32%        | 32%                     | under 50%       |
| Invalid-output rate          | 0%              | 0%              | 0%         | 6%                      |                 |
| Mean latency per finding (s) | n/a             | 13.812          | 26.696     | 26.696                  |                 |
| Total cost (USD)             | n/a             | 0.355241        | 1.142351   | 1.142351                |                 |

The scanner-only column is fixed by definition: every flagged finding is kept, so all genuine findings are retained and no false positives are removed. Configuration D carries C's latency and cost because validation is local and makes no additional model call.

For a conventional binary view of the filtering pipeline, treating `human_review` as **kept** rather than removed, precision / recall / F1 were 50.0% / 100.0% / 66.7% for scanner only, 74.6% / 94.0% / 83.2% for the single agent, and 76.9% / 100.0% / 87.0% for both council configurations. Thus the council outperformed the single agent on the same cases: it removed one additional false positive, avoided all three unsafe dismissals, and sent one fewer case to review. The council met the proposal's 95% safe-retention and 25% removal targets on this sample, while keeping human review below 50%. However, only 66% of genuine findings were automatically confirmed; 34% still required a developer. Most escalations arose because the source window cut off a helper method or because a model response was not parseable JSON (5 council cases). Validation rejected 6 council outputs—5 missing citations after unparseable model answers and 1 mismatched guidance reference—but all six were already `human_review`, so it improved evidence labelling without changing the outcome counts.

This is an initial checkpoint sample of one category. It is not a general accuracy estimate.

### 6.3 Earlier feasibility round (2 October 2026)

Before the checkpoint pipeline existed, the feasibility scripts in `verification/` ran on five hand-selected CWE-89 cases (three genuine, two false positives) with `google/gemini-3.8-flash`:

| Check                                                  | Result                                               |
| ------------------------------------------------------ | ---------------------------------------------------- |
| Single-call triage, valid structured JSON              | 5 of 5                                               |
| Citations matching the source file, line and quote     | 15 of 15                                             |
| Verdicts matching the answer key                       | 5 of 5                                               |
| Mean latency                                           | 9.87 s (range 8.16 to 11.72 s)                       |
| Cost                                                   | US$0.00993 for five calls                            |
| Analyst, Skeptic and Chair pass on the same five cases | Chair matched 5 of 5; additional cost about US$0.034 |

These cases were deliberately selected and test names were visible to the model, so memorisation cannot be ruled out. The round showed integration feasibility, not accuracy.

### 6.4 Component test results (offline, no API calls)

| Component                                                | Tests   | Result | What the tests show                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------------------------------------------- | ------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Deterministic validator                                  | 41      | Pass   | Rejects a fabricated quote, wrong file, out-of-range line, malformed JSON, missing case, duplicate case and unsupported verdict. Each falls back to `human_review` with reasons                                                                                                                                                                                                                                                                                                                |
| Evaluation harness                                       | 14      | Pass   | Exact counts on a hand-checked five-case dataset; `human_review` never counted as a removal; missing and invalid results handled safely; output byte-identical across runs                                                                                                                                                                                                                                                                                                                     |
| Ingest, answer-key mapping, split and baseline           | 48      | Pass   | Correct alert fields and benchmark-relative paths (including Windows-style input); CWE extraction for all metadata forms; duplicate collapse; helper-file and unmapped findings counted, not lost; **no answer-key field appears in any LLM-side output**; CWE versus filename matching on a wrong-CWE case; precision/recall/F1 on hand-computed counts, including zero denominators; split deterministic, disjoint, complete and stratified; sample dev-only, balanced and deterministic |
| Terminal menu and setup check                            | 63      | Pass   | All three menu options and subcommands call the same functions; paid sample evaluation requires confirmation and checks scoring inputs before calls; friendly errors cover missing inputs; setup and re-scan safety are tested with external commands mocked                                                                                                                                                                                                                                                                       |
| Recorded-scan normaliser                                 | 8       | Pass   | Only path strings are rewritten; no machine-specific paths remain                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Guidance retrieval (manual check, not an automated test) | 1 alert | Works  | A CWE-89 SQL-injection alert matched four cheat sheets (Injection Prevention, Java Security, Query Parameterization, SQL Injection Prevention) and returned 2 chunks (3,866 characters). An alert with no CWE fell back to 6 general chunks flagged `cwe_matched=false`                                                                                                                                                                                                                        |
| Connected pipeline                                       | 3       | Pass   | Single-agent and concurrent council flows use the same payload, validation receives the original source, council usage is summed, and saved configurations match the evaluator's input contract |

The validator and evaluator were also run together: sample model output passed through the validator and then into the evaluator, which scored a fabricated citation and a missing answer as human review with the validator's reasons attached.

## 7. Failures and limitations

### 7.1 Failures observed in the checkpoint run

| Case | Configuration | Expected | Verdict | What went wrong | Likely cause |
| --- | --- | --- | --- | --- | --- |
| `BenchmarkTest00839` | B. Single agent | `true_positive` | `false_positive` | The explanation correctly recalculated the condition to the branch that assigns user input, but still concluded the value was safe | Contradictory reasoning was not caught by citation-only validation; semantic consistency checking is still missing |
| `BenchmarkTest01004` | C. Council | `true_positive` | `human_review` | The Chair could not see the switch branch that determines whether the tainted parameter reaches the SQL query | The fixed source window ended inside the helper method |
| `BenchmarkTest00767` | D. Validated council | `true_positive` | `human_review` | The Chair response was not parseable JSON and therefore carried no citations; validation recorded `Missing citations` | Model-format failure combined with the deliberate no-retry policy |
| `BenchmarkTest01883` | D. Validated council | `true_positive` | `human_review` | The council already escalated because the helper body was truncated; validation also rejected a guidance reference whose document metadata did not match the retrieved chunk | Source-window limit plus inconsistent guidance fields in the model response |

### 7.2 Failures found in our own tooling

- **Evaluation test gap.** We deliberately planted four bugs in the evaluation harness to check that its tests notice them. Three were caught at first; counting a clean `human_review` as a correct outcome was not, because it changed no totals and only dropped the case from the failure list. We added a test, and all four planted bugs are now caught.
- **Validator coverage.** In the feasibility stage, the validator checked only JSON shape and exact quotes. The checkpoint validator adds identifier checks and a forced `human_review` fallback, but still does not verify semantic source-to-sink reasoning.

### 7.3 Limitations and threats to validity

- **One category, small sample.** Results for about 100 CWE-89 findings do not generalise to other vulnerability categories or to the full benchmark.
- **Public benchmark.** OWASP Benchmark is public and test names are visible, so the model may recognise cases. Comments and hints are stripped from the LLM-facing copy, but mutation tests that would detect memorisation are deferred.
- **Scanner matching.** Findings are matched to test cases by file name **and** CWE (section 6.1). The one accepted CWE equivalence is documented in `triagebot/nodes/ingest/mapping.py` and was decided by inspecting the mismatch report, not by tuning for a higher score: the rejected pairs would have raised Semgrep's score.
- **Scanner run-to-run variation.** A later re-scan with the same Semgrep version and ruleset produced 1,908 findings instead of 1,909. Semgrep's taint analysis hits time limits ("fixpoint timeouts") on about 300 file/rule pairs, and which ones time out varies between runs. Here, a timeout suppressed one LDAP finding (BenchmarkTest00530). We therefore score one committed, recorded scan (`data/semgrep/`), so that every result is reproducible.
- **Balanced sample.** See section 5: precision on the 50/50 sample is not real-world precision.
- **Keyword retrieval.** Guidance ranking is keyword based, so relevant guidance worded differently from the alert may be missed. In the manual check on a CWE-89 alert, the 4,000-character budget left room for only 2 of the 6 allowed chunks, and neither came from the SQL Injection Prevention Cheat Sheet, the most directly relevant document. The ranking and budget were kept unchanged for the recorded run to avoid last-minute tuning on evaluation cases.
- **Cost and latency for configuration D.** The validator carries configuration C's model, latency and token/cost metadata through because those resources were already spent. Deterministic validation adds negligible local time and no model cost.
- **Single run.** Model output can vary even at temperature 0.0, and we report one recorded run with no automatic retries.

## 8. Progress against checkpoint targets

| Proposal target                                                       | Status                          | Evidence                                                                                                                      | If unmet, why                                      |
| --------------------------------------------------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Semgrep baseline mapped to the answer key                             | **Met**                   | Section 6.1; `python -m triagebot baseline` (menu option 1); `baseline.json`                                              |                                                    |
| Main pipeline connected, stubs documented                             | **Met**                       | Sections 3 and 4; 177 offline tests                                                                                           |                                                    |
| One category end to end with retrieval and council                    | **Met**                       | `python -m triagebot triage --case BenchmarkTest00008 --mode council`; validated live result                                 |                                                    |
| About 100 findings, single agent versus council, metrics and failures | **Met**                       | Sections 6.2 and 7.1; saved 100-case configurations and `evaluation.json`                                                     |                                                    |
| Repository with setup, all-member contributions, AI-use log           | **Met** | README, commit history, `ai-log/` (all members logged); every member has at least one commit; CI covers Windows, macOS and Linux | |

## 9. Changes since the proposal

| Area                      | Proposal                                           | Now                                                                                                                                | Reason                                                                                                                                             |
| ------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Retrieval                 | SentenceTransformers and FAISS                     | Committed OWASP Cheat Sheet corpus with CWE gate and keyword ranking                                                               | Deterministic, dependency-free and reproducible for the checkpoint. The corpus layout is kept so embeddings can be added later (design decision 3) |
| Where guidance comes from | Retrieved for the common evidence pack             | Fetched by our code while building the payload; agents receive no web or browsing tools                                            | Keeps retrieval auditable and reduces prompt-injection exposure from live web content (design decision 2)                                          |
| Specialist tools          | Code-exploration tools for Analyst and Skeptic     | Deterministic helper-fact extraction in the common evidence pack; no interactive tools at checkpoint                              | Simpler and reproducible within checkpoint time; agents still verify hints against source                                                        |
| Orchestration             | Not specified                                      | Plain Python functions, no agent framework                                                                                         | The flow is a straight sequence with one concurrent stage; a framework adds setup cost without new capability yet (design decision 1)              |
| Council flow              | Analyst, Skeptic, Chair                            | Analyst and Skeptic run concurrently and do not see each other's output; only the Chair joins them                                 | Keeps the two perspectives independent and halves wall-clock time (design decision 4)                                                              |
| Model                     | Gemini 3.8 Flash                                   | Gemini 3.5 Flash Lite for development, Gemini 3.8 Flash for the recorded run, selected by configuration                            | Cheap iteration while keeping recorded results comparable with the proposal (design decision 6)                                                    |
| Team roles                | Wei Lin on retrieval                               | Hong Yi built the retrieval knowledge base; Wei Lin owns repository scaffolding, final integration and submission                  | Reallocated to match the components each member implemented                                                                                     |
| Scope                     | Per-category performance and mutation tests        | One category (CWE-89); mutation tests deferred                                                                                     | Time to the checkpoint; one reliable end-to-end path was prioritised                                                                               |
| AI-use disclosure         | Disclosure log                                     | One log per member under `ai-log/`, plus the team declaration in section 11                                                      | Required by the SE201 AI Use Disclosure Policy v1.00                                                                                               |
| Metrics                   | Retained, removed, wrongly dismissed, human review | Adds precision, recall and F1, with the full-benchmark baseline in both views (given Semgrep's alerts, and end to end)             | Instructor feedback on the proposal                                                                                                                |
| Evaluation data           | About 100 findings                                 | Fixed 50/50 stratified dev/test split (seed 201); the checkpoint sample comes from dev; test is held back for the final evaluation | Instructor feedback: evaluate on unseen data                                                                                                       |
| Scanner baseline method   | Filename-based mapping                             | CWE-matched mapping with one documented equivalence; filename-based figures kept for comparison                                    | Matches the Benchmark's scoring, and ensures TriageBot is scored on the same weakness the answer key labels (design decision 17)                   |
| Scanner input             | Scan run locally by each member                    | One recorded scan committed to the repository; optional re-scan in the menu                                                        | Re-scans vary slightly (section 7.3); a recorded scan makes results reproducible and setup faster                                                  |
| Recall                    | Not analysed                                       | Recall ceiling and per-category blind spots reported; a broader first stage planned                                                | Instructor feedback on first-stage tuning and bottlenecks                                                                                          |

## 10. Next steps after the checkpoint

- Extend evaluation to further categories and report per-category performance.
- Run mutation tests to check that verdicts follow code evidence rather than memorised benchmark patterns.
- Evaluate whether embedding-based retrieval improves on keyword ranking over the same corpus.
- Strengthen the validator beyond citation checks towards source-to-sink claims.
- Scale the evaluation beyond the checkpoint sample and repeat runs to measure variation.
- Tune the first-stage Semgrep rules for higher recall, then measure both Semgrep's ceiling and downstream conditional performance.

## 11. Team contributions

Each member must review the paragraph describing their own work; unchecked boxes still need the named member's confirmation.

- **Darren:** Ingest stage: normalising Semgrep findings into the shared alert contract, CWE-matched mapping to the answer key, the full-benchmark scanner baseline with precision, recall and F1, the shared metrics module, and the stratified dev/test split and checkpoint sample (48 tests). Also the terminal menu and setup check, the recorded-scan setup, and the README Quick start with CI on three operating systems. `[ ] confirmed`
- **Hong Yi:** Package scaffold and shared contracts, design decision record, offline OWASP Cheat Sheet knowledge base (137 sheets, 3,238 chunks), CWE-gated keyword retrieval, single-agent review and Analyst/Skeptic/Chair roles. `[ ] confirmed`
- **Lisa:** Deterministic validator with citation, identifier and case-ID checks and a `human_review` fallback, with 41 offline tests. `[ ] confirmed`
- **Bradley:** Evaluation harness that scores all configurations against the hidden answer key, with 14 offline tests; this checkpoint report. `[ ] confirmed`
- **Wei Lin:** Repository setup, checkpoint planning documents, central pipeline and CLI integration, recorded run and submission review. `[ ] confirmed`

## 12. AI use declaration

Claude Code assisted Darren, Hong Yi, Lisa and Bradley with code, tests and documentation. OpenAI Codex assisted Wei Lin with final pipeline integration, tests, documentation and the recorded run. Commits containing AI-assisted work carry an `Assisted-by:` trailer, and significant retained work is recorded under `ai-log/`. Generated code was reviewed and exercised through the offline suite; the evaluation harness was additionally checked by planting deliberate bugs to confirm its tests catch them. Within the product, TriageBot itself calls `google/gemini-3.8-flash` (and used `google/gemini-3.5-flash-lite` during development) through OpenRouter; those calls are part of the system under evaluation, not assistance in writing it.
